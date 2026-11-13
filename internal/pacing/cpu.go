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
	// cpuLowWater is how busy the busiest CPU must stay below for the CPU
	// cap to rise. Between it and cpuBusyThreshold the cap holds. At 1.1 µs
	// a full-size packet, that band spans 14% of the forwarded rate, and one
	// raise step adds 1%, so a rising cap stops in the band instead of
	// overshooting the threshold.
	cpuLowWater = 0.7
	// cpuRaisePerSecond is how fast the CPU cap rises, as a fraction of the
	// cap, while the busiest CPU is below cpuLowWater and forwarded traffic
	// presses the cap. The cost of forwarding grows with the packet rate, so
	// a fractional step is the same distance from the threshold on any
	// instance. A cut to cutFactor takes about 2.3 s to win back, and the
	// floor to 700,000 packets a second about 11 s.
	cpuRaisePerSecond = 0.1
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
	// cpuReadings is how many readings the CPU cap averages. /proc/stat
	// counts each CPU state in hundredths of a second, so one reading over a
	// tenth of a second can be off by a tenth: a CPU 81% busy read from 78%
	// to 90%. Three readings are off by a few percent.
	cpuReadings = 3
)

// CPUObservation is what a NAT saw of its CPUs over one interval.
type CPUObservation struct {
	Now, Elapsed time.Duration
	// Busiest is the busiest CPU's busy share, from [BusiestCPU].
	Busiest float64
	// Rate is the forwarded packets per second.
	Rate float64
}

// CPUCap keeps forwarded packets a second below what the CPUs carry. It
// starts with no cap, and cuts like a [Cap] when the busiest CPU passes
// cpuBusyThreshold, but only when forwarding is to blame: the forwarded rate
// presses the cap, and at packetCPUTime a packet it explains at least
// forwardingShare of the load. If a cut lowered the forwarded rate but the
// CPU's load fell by less than half of what that predicts, or a full CPU
// stayed full, something else fills it. The cap then goes back to where it
// was and stops cutting until the CPU calms down. Without these checks, a
// CPU kept busy by conntrackd or by traffic that senders keep offering drove
// the cap down to its floor.
//
// Unlike an allowance, the CPU shows how much room is left, so the cap
// doesn't remember the rate it cut at. While the busiest CPU is below
// cpuLowWater and forwarded traffic presses the cap, it rises by
// cpuRaisePerSecond, and between cpuLowWater and cpuBusyThreshold it holds.
// On AWS, a cap that settled at 95% of the rate it cut at held a
// c7gn.medium at 280,000 packets a second with its CPU 55% busy, a third of
// what the CPU forwarded unpaced.
//
// The cap judges the average of the last cpuReadings readings, except that
// one reading of a full CPU counts at once, so a flood is cut at the end of
// the first interval it fills a CPU. Each cut is to cutFactor of the
// forwarded rate. One that wasn't enough is followed by another once the
// average covers only readings since, cpuReadings intervals later.
//
// Step is a pure function of the cap and one observation.
type CPUCap struct {
	Cap
	cpus int
	// earlier holds the readings before the latest, oldest first, and seen
	// counts the readings so far.
	earlier [cpuReadings - 1]float64
	seen    int
	// Set at each cut, to judge whether it worked.
	cut           bool
	busyAtCut     float64
	rateAtCut     float64
	limitBefore   float64
	gaveUpCutting bool
}

// NewCPUCap returns the CPU cap for a NAT with cpus CPUs that reads them
// every interval, with no cap until the busiest CPU first passes
// cpuBusyThreshold. After a cut it ignores the CPUs until the average
// covers only readings since.
func NewCPUCap(cpus int, interval time.Duration) CPUCap {
	cpus = max(cpus, 1)
	return CPUCap{Cap: NewCap(0, cpuFloorPerCPU*float64(cpus), cpuReadings*interval), cpus: cpus}
}

// Step returns the cap after observation o, and what changed.
func (c CPUCap) Step(o CPUObservation) (CPUCap, Change) {
	busy := c.record(o.Busiest)
	held := c.Ceiling > 0 && o.Now-c.cutAt < c.hold
	if busy <= cpuBusyThreshold {
		// The last cut worked, or the load went away.
		c.cut, c.gaveUpCutting = false, false
		if c.Limit == 0 || held {
			return c, Unchanged
		}
		if busy >= cpuLowWater || o.Rate < pressureRatio*c.Limit {
			return c, Unchanged
		}
		c.Limit += cpuRaisePerSecond * c.Limit * o.Elapsed.Seconds()
		return c, Raised
	}
	switch {
	case held && c.cut:
		return c, HeldAfterCut
	case c.gaveUpCutting:
		return c, NotForwarding
	}
	binding := o.Rate >= pressureRatio*c.Limit
	explained := o.Rate*packetCPUTime/float64(c.cpus) >= forwardingShare*busy
	if !binding || !explained {
		return c, NotForwarding
	}
	if c.cut && o.Rate < c.rateAtCut && !c.helped(busy, o.Rate) {
		// The last cut forwarded less without freeing the CPU.
		c.Limit, c.cut, c.gaveUpCutting = c.limitBefore, false, true
		return c, GaveUp
	}
	c.cut, c.busyAtCut, c.rateAtCut, c.limitBefore = true, busy, o.Rate, c.Limit
	c.Cap = c.Cap.cut(o.Now, o.Rate, cutFactor)
	return c, CutDown
}

// record adds a reading of the busiest CPU and returns how busy to judge it:
// the reading if it shows a full CPU, or else the average of the last
// cpuReadings readings.
func (c *CPUCap) record(reading float64) float64 {
	n := min(c.seen, len(c.earlier))
	sum := reading
	for _, r := range c.earlier[len(c.earlier)-n:] {
		sum += r
	}
	copy(c.earlier[:], c.earlier[1:])
	c.earlier[len(c.earlier)-1] = reading
	c.seen++
	if reading >= cpuSaturated {
		return reading
	}
	return sum / float64(n+1)
}

// helped reports whether the CPU's load since the last cut fell as much as
// the drop in forwarded packets, now rate, predicts, by at least half.
func (c CPUCap) helped(busy, rate float64) bool {
	if c.busyAtCut >= cpuSaturated {
		return busy < cpuSaturated
	}
	predicted := (c.rateAtCut - rate) * packetCPUTime / float64(c.cpus)
	return c.busyAtCut-busy >= predicted/2
}
