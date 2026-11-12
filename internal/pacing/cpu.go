package pacing

import (
	"strconv"
	"strings"
	"time"
)

// CPUTimes is one CPU's time counters from /proc/stat, in clock ticks.
type CPUTimes struct {
	// Busy is time spent on anything but idling or waiting for I/O,
	// including the softirq time that forwarding mostly runs in.
	Busy uint64
	// Total is all time.
	Total uint64
}

// ParseCPUTimes returns each CPU's counters from the contents of /proc/stat,
// in the order the file lists them. It skips the line that sums all CPUs.
func ParseCPUTimes(stat string) []CPUTimes {
	var cpus []CPUTimes
	for _, line := range strings.Split(stat, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] == "cpu" || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		var times CPUTimes
		// user nice system idle iowait irq softirq steal, then guest times,
		// which user and nice already include.
		for i, field := range fields[1:min(len(fields), 9)] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				break
			}
			times.Total += value
			if i != 3 && i != 4 {
				times.Busy += value
			}
		}
		cpus = append(cpus, times)
	}
	return cpus
}

// BusiestCPU returns the largest share of time any one CPU was busy between
// two readings, from 0 to 1. A NAT forwards on the CPUs that take its network
// interrupts, so one full CPU starves everything else the NAT runs there,
// such as its lease renewals, whatever the other CPUs do. It returns 0 if the
// readings don't match, as when a CPU went offline.
func BusiestCPU(before, after []CPUTimes) float64 {
	if len(before) != len(after) {
		return 0
	}
	var busiest float64
	for i := range after {
		if after[i].Total <= before[i].Total || after[i].Busy < before[i].Busy {
			continue
		}
		share := float64(after[i].Busy-before[i].Busy) / float64(after[i].Total-before[i].Total)
		busiest = max(busiest, min(share, 1))
	}
	return busiest
}

// The CPU cap's tuning.
const (
	// cpuBusyThreshold is how busy the busiest CPU may get before the CPU
	// cap cuts. Past it, the NAT's own work on that CPU, such as lease
	// renewals, DNS lookups and probes, starts to time out. On AWS, a NAT
	// whose CPU ran full stepped down 3 to 4 times a minute.
	cpuBusyThreshold = 0.8
	// cpuStartPerCPU is the CPU cap a NAT starts from, in forwarded packets
	// a second per CPU. On AWS, one CPU forwarded about 600,000 small
	// packets a second at 100%.
	cpuStartPerCPU = 400_000
	// cpuFloorPerCPU is the lowest the CPU cap goes, per CPU. Forwarding
	// that many packets takes 40% of a CPU, half the threshold, so below it
	// forwarding can't be what fills the CPU.
	cpuFloorPerCPU = 250_000
	// packetCPUTime is the CPU time one forwarded packet takes, measured on AWS
	// for small packets. Full-size ones take about 1.1 µs.
	packetCPUTime = 1.6e-6
	// forwardingShare is how much of the busiest CPU's load forwarding must
	// explain before the CPU cap cuts. When conntrackd or receiving traffic
	// the NAT then drops fills the CPU, fewer forwarded packets don't help.
	forwardingShare = 0.5
	// cpuSaturated is how busy a CPU reads when it is full. A full CPU hides
	// how much more work it was offered, so a cut from there only shows
	// once the CPU drops below it.
	cpuSaturated = 0.98
)

// CPUObservation is what a NAT saw of its CPUs over one interval.
type CPUObservation struct {
	Now, Elapsed time.Duration
	// Busiest is the busiest CPU's busy share, from [BusiestCPU].
	Busiest float64
	// Rate is the forwarded packets per second.
	Rate float64
}

// CPUCap keeps forwarded packets a second below what the CPUs carry. It is
// a [Cap] that cuts when the busiest CPU passes cpuBusyThreshold, but only
// when forwarding is to blame: the forwarded rate presses the cap, and at
// packetCPUTime a packet it explains at least forwardingShare of the load. If a
// cut lowered the forwarded rate but the CPU's load fell by less than half
// of what that predicts, or a full CPU stayed full, something else fills
// it. The cap then goes back to where it was and stops cutting until the
// CPU calms down. Without these checks, a CPU kept busy by conntrackd or
// by traffic that senders keep offering drove the cap down to its floor.
//
// Step is a pure function of the cap and one observation.
type CPUCap struct {
	Cap
	cpus int
	// Set at each cut, to judge whether it worked.
	cut           bool
	busyAtCut     float64
	rateAtCut     float64
	limitBefore   float64
	gaveUpCutting bool
}

// NewCPUCap returns the CPU cap for a NAT with cpus CPUs, ignoring the CPUs
// for hold after a cut.
func NewCPUCap(cpus int, hold time.Duration) CPUCap {
	cpus = max(cpus, 1)
	return CPUCap{Cap: NewCap(cpuStartPerCPU*float64(cpus), cpuFloorPerCPU*float64(cpus), hold), cpus: cpus}
}

// Step returns the cap after observation o, and what changed.
func (c CPUCap) Step(o CPUObservation) (CPUCap, Change) {
	if o.Busiest <= cpuBusyThreshold {
		// The last cut worked, or the load went away.
		c.cut, c.gaveUpCutting = false, false
		var change Change
		c.Cap, change = c.Cap.Step(Observation{Now: o.Now, Elapsed: o.Elapsed, Rate: o.Rate})
		return c, change
	}
	if o.Now-c.cutAt < c.hold && c.cut {
		return c, HeldAfterCut
	}
	if c.gaveUpCutting {
		return c, NotForwarding
	}
	binding := o.Rate >= pressureRatio*c.Limit
	explained := o.Rate*packetCPUTime/float64(c.cpus) >= forwardingShare*o.Busiest
	if !binding || !explained {
		return c, NotForwarding
	}
	if c.cut && o.Rate < c.rateAtCut && !c.helped(o) {
		// The last cut forwarded less without freeing the CPU.
		c.Limit, c.cut, c.gaveUpCutting = c.limitBefore, false, true
		return c, GaveUp
	}
	before := c.Limit
	var change Change
	c.Cap, change = c.Cap.Step(Observation{Now: o.Now, Elapsed: o.Elapsed, Exceeded: 1, Rate: o.Rate})
	if change == CutDown {
		c.cut, c.busyAtCut, c.rateAtCut, c.limitBefore = true, o.Busiest, o.Rate, before
	}
	return c, change
}

// helped reports whether the CPU's load since the last cut fell as much as
// the drop in forwarded packets predicts, by at least half.
func (c CPUCap) helped(o CPUObservation) bool {
	if c.busyAtCut >= cpuSaturated {
		return o.Busiest < cpuSaturated
	}
	predicted := (c.rateAtCut - o.Rate) * packetCPUTime / float64(c.cpus)
	return c.busyAtCut-o.Busiest >= predicted/2
}
