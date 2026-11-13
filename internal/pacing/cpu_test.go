package pacing

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// stat returns /proc/stat for two CPUs, with each CPU's user, idle, iowait,
// softirq and guest ticks.
func stat(cpus ...[5]uint64) string {
	out := "cpu  1 2 3 4 5 6 7 8 9 10\n"
	for i, c := range cpus {
		// user nice system idle iowait irq softirq steal guest guest_nice
		out += fmt.Sprintf("cpu%d %d 0 10 %d %d 2 %d 0 %d 0\n", i, c[0], c[1], c[2], c[3], c[4])
	}
	return out + "intr 123 4 5\nctxt 99\nbtime 1700000000\n"
}

func TestBusiestCPU(t *testing.T) {
	before := ParseCPUTimes(stat([5]uint64{100, 1000, 10, 50, 7}, [5]uint64{100, 1000, 10, 50, 0}))
	assert.Equal(t, []CPUTimes{{Busy: 162, Total: 1172}, {Busy: 162, Total: 1172}}, before)
	{
		// CPU 0 spent 85 of 100 ticks in softirq, CPU 1 idled. Guest time,
		// which user already counts, doesn't count twice.
		after := ParseCPUTimes(stat([5]uint64{105, 1015, 10, 130, 50}, [5]uint64{101, 1099, 10, 50, 0}))
		assert.InDelta(t, 0.85, BusiestCPU(before, after), 1e-9)
	}
	{
		// Waiting for I/O isn't busy
		after := ParseCPUTimes(stat([5]uint64{100, 1050, 60, 50, 7}, [5]uint64{100, 1100, 10, 50, 0}))
		assert.Zero(t, BusiestCPU(before, after))
	}
	{
		// A CPU that went offline makes the readings incomparable
		assert.Zero(t, BusiestCPU(before, before[:1]))
		// No time passed
		assert.Zero(t, BusiestCPU(before, before))
	}
}

// cpuSim simulates a one-CPU NAT as /proc/stat shows it. Each forwarded
// packet costs perPacket seconds of softirq time, everything else takes
// other of the CPU as system time, and the CPU forwards what the cap lets
// through, up to what fits in the time left. The kernel counts each state in
// whole hundredths of a second, so the readings jitter like real ones.
type cpuSim struct {
	perPacket, other, offered float64
	// softirq, system and idle are the seconds spent in each state so far,
	// and forwarded the packets.
	softirq, system, idle, forwarded float64
	// times and observed are the counters at the previous observation.
	times    []CPUTimes
	observed float64
}

func newCPUSim(perPacket, other, offered float64) *cpuSim {
	s := &cpuSim{perPacket: perPacket, other: other, offered: offered}
	s.times = s.read()
	return s
}

func (s *cpuSim) read() []CPUTimes {
	hundredths := func(seconds float64) uint64 { return uint64(seconds * 100) }
	// user nice system idle iowait irq softirq steal guest guest_nice
	return ParseCPUTimes(fmt.Sprintf("cpu0 0 0 %d %d 0 0 %d 0 0 0\n", hundredths(s.system), hundredths(s.idle), hundredths(s.softirq)))
}

// advance runs the CPU for elapsed under the cap, and returns how busy it
// really was.
func (s *cpuSim) advance(c CPUCap, elapsed time.Duration) float64 {
	rate := min(s.offered, (1-s.other)/s.perPacket)
	if c.Limit > 0 {
		rate = min(rate, c.Limit)
	}
	busy := s.other + rate*s.perPacket
	seconds := elapsed.Seconds()
	s.softirq += rate * s.perPacket * seconds
	s.system += s.other * seconds
	s.idle += (1 - busy) * seconds
	s.forwarded += rate * seconds
	return busy
}

// observe returns what the NAT reads at now, elapsed after its previous
// reading.
func (s *cpuSim) observe(now, elapsed time.Duration) CPUObservation {
	previous, forwarded := s.times, s.forwarded-s.observed
	s.times, s.observed = s.read(), s.forwarded
	return CPUObservation{Now: now, Elapsed: elapsed, Busiest: BusiestCPU(previous, s.times), Rate: forwarded / elapsed.Seconds()}
}

// cpuRun is what happened over a stretch of a CPU simulation.
type cpuRun struct {
	// minLimit and maxLimit are the lowest and highest cap.
	minLimit, maxLimit float64
	// maxBusy is how busy the CPU really got.
	maxBusy float64
	cuts    int
	// firstCut is when the first cut happened, or zero.
	firstCut time.Duration
	// settled is when the CPU first got to cpuLowWater, or zero.
	settled time.Duration
}

// run steps the cap every cpuInterval from start until end.
func (s *cpuSim) run(c CPUCap, start, end time.Duration) (CPUCap, cpuRun) {
	r := cpuRun{minLimit: c.Limit, maxLimit: c.Limit}
	for now := start + cpuInterval; now <= end; now += cpuInterval {
		busy := s.advance(c, cpuInterval)
		var change Change
		c, change = c.Step(s.observe(now, cpuInterval))
		r.minLimit, r.maxLimit, r.maxBusy = min(r.minLimit, c.Limit), max(r.maxLimit, c.Limit), max(r.maxBusy, busy)
		if change == CutDown {
			r.cuts++
			if r.firstCut == 0 {
				r.firstCut = now
			}
		}
		if busy >= cpuLowWater && r.settled == 0 {
			r.settled = now
		}
	}
	return c, r
}

func TestCPUCapClimbsToWhatTheCPUCarries(t *testing.T) {
	// On AWS, TCP uploads offered at 8.6 Gbps through a paced c7gn.medium
	// settled at about 280,000 packets a second, 3.25 Gbps, with the busiest
	// CPU at 55%. Forwarding costs 1.1 µs a full-size packet and pacing 0.35
	// µs more, and the rest of the NAT's work takes the 14% left over at
	// 280,000. So the CPU reaches 70% at 383,000 packets a second and 80% at
	// 452,000.
	sim := newCPUSim(1.45e-6, 0.144, 717e3)
	c := NewCPUCap(1, cpuInterval)
	// While the senders' first bursts arrived, the CPU read 86% at 295,000,
	// and the cap cut, here to its 250,000 floor. On AWS, the cap then
	// settled at 95% of that rate, 280,000, and waited 5 minutes before
	// rising.
	c, change := c.Step(CPUObservation{Now: cpuInterval, Elapsed: cpuInterval, Busiest: 0.86, Rate: 295e3})
	assert.Equal(t, CutDown, change)
	assert.Equal(t, 250e3, c.Limit)
	{
		// The cap climbs while the CPU has room, and is in the band within
		// 7 s, with no cut
		var r cpuRun
		c, r = sim.run(c, cpuInterval, 30*time.Second)
		assert.NotZero(t, r.settled)
		assert.Less(t, r.settled, 7*time.Second)
		assert.Zero(t, r.cuts)
		assert.LessOrEqual(t, r.maxBusy, cpuBusyThreshold)
	}
	{
		// and stays there: the next 5 minutes forward 383,000 to 452,000
		// packets a second, 4.5 to 5.3 Gbps, without a cut
		var r cpuRun
		c, r = sim.run(c, 30*time.Second, 330*time.Second)
		assert.Zero(t, r.cuts)
		assert.GreaterOrEqual(t, r.minLimit, 383e3)
		assert.LessOrEqual(t, r.maxBusy, cpuBusyThreshold)
		assert.Less(t, r.maxLimit/r.minLimit, 1.05, "the cap holds still")
	}
}

func TestCPUCapCatchesSmallPacketFlood(t *testing.T) {
	// 64-byte packets cost 1.6 µs each, so one CPU fills at 593,750 a
	// second.
	sim := newCPUSim(1.6e-6, 0.05, 50e3)
	c, r := sim.run(NewCPUCap(1, cpuInterval), 0, time.Second)
	assert.Zero(t, c.Limit, "no cap before the CPU first fills")
	assert.Zero(t, r.cuts)
	// The flood starts halfway through a reading, which shows the CPU 57%
	// busy.
	sim.advance(c, cpuInterval/2)
	sim.offered = 2e6
	sim.advance(c, cpuInterval/2)
	c, change := c.Step(sim.observe(time.Second+cpuInterval, cpuInterval))
	assert.Equal(t, Unchanged, change)
	{
		// The cap cuts at the end of the first reading the CPU spent full,
		// 150 ms after the flood started, to 80% of what it forwarded
		var r cpuRun
		c, r = sim.run(c, time.Second+cpuInterval, time.Second+2*cpuInterval)
		assert.Equal(t, time.Second+2*cpuInterval, r.firstCut)
		assert.InDelta(t, 0.8*593750, c.Limit, 1)
	}
	{
		// One more cut 300 ms later, and it settles with the CPU below 80%
		c, r := sim.run(c, time.Second+2*cpuInterval, 2*time.Second)
		assert.Equal(t, 1, r.cuts)
		_, r = sim.run(c, 2*time.Second, time.Minute)
		assert.Zero(t, r.cuts)
		assert.LessOrEqual(t, r.maxBusy, cpuBusyThreshold)
		assert.GreaterOrEqual(t, r.minLimit, 0.64*593750)
	}
}

func TestCPUCapHoldsForwardingBelowSaturation(t *testing.T) {
	{
		// Small packets: the CPU fills at about 594,000 a second and
		// workers offer 900,000. From no cap, the cap cuts once the CPU fills, then
		// settles where the CPU is 70% to 80% busy, 406,000 to 469,000
		sim := newCPUSim(1.6e-6, 0.05, 900e3)
		c, r := sim.run(NewCPUCap(1, cpuInterval), 0, time.Minute)
		assert.LessOrEqual(t, r.cuts, 3)
		c, r = sim.run(c, time.Minute, 5*time.Minute)
		assert.Zero(t, r.cuts)
		assert.GreaterOrEqual(t, r.minLimit, 406e3)
		assert.LessOrEqual(t, r.maxBusy, cpuBusyThreshold)
		assert.Less(t, r.maxLimit/r.minLimit, 1.05, "the cap holds still")
		{
			// Connection churn makes conntrackd take 30% more of the CPU.
			// The cap follows it down, but not below the 250,000 floor
			sim.other = 0.35
			c, r := sim.run(c, 5*time.Minute, 6*time.Minute)
			assert.GreaterOrEqual(t, r.minLimit, 250e3)
			_, r = sim.run(c, 6*time.Minute, 7*time.Minute)
			assert.Zero(t, r.cuts)
			assert.LessOrEqual(t, r.maxBusy, cpuBusyThreshold)
		}
	}
	{
		// Full-size packets at 1.1 µs, as on AWS without pacing's own cost:
		// the cap settles between 591,000 and 682,000, about 7.1 to 8.2 Gbps
		sim := newCPUSim(1.1e-6, 0.05, 900e3)
		c, _ := sim.run(NewCPUCap(1, cpuInterval), 0, time.Minute)
		_, r := sim.run(c, time.Minute, 5*time.Minute)
		assert.Zero(t, r.cuts)
		assert.GreaterOrEqual(t, r.minLimit, 591e3)
		assert.LessOrEqual(t, r.maxBusy, cpuBusyThreshold)
	}
}

// cpuTrace steps a CPU cap through observations of [busiest, rate], one
// cpuInterval apart.
func cpuTrace(c CPUCap, start time.Duration, steps ...[2]float64) (CPUCap, []Change) {
	var changes []Change
	for i, s := range steps {
		var change Change
		c, change = c.Step(CPUObservation{Now: start + time.Duration(i+1)*cpuInterval, Elapsed: cpuInterval, Busiest: s[0], Rate: s[1]})
		changes = append(changes, change)
	}
	return c, changes
}

func TestCPUCapStopsWhenCutsDontHelp(t *testing.T) {
	// On AWS, TCP uploads offered beyond what a c7gn.medium forwards kept its
	// CPU full after every cut, because receiving what the senders still
	// offered cost as much as forwarding it. The cap cut 400,000 to 320,000,
	// 296,000 and 144,000 a second in 6 s, and uploads fell from 10 to 2.7
	// Gbps. Busiest CPU and forwarded packets a second, in the shape logged:
	c, _ := cpuTrace(NewCPUCap(1, cpuInterval), 0, [2]float64{1, 500e3}, [2]float64{0.75, 300e3}, [2]float64{0.75, 300e3}, [2]float64{0.75, 300e3})
	assert.Equal(t, 400e3, c.Limit)
	c, changes := cpuTrace(c, time.Second,
		[2]float64{0.857, 558.8e3},
		[2]float64{0.86, 560e3},
		// The hold after the cut
		[2]float64{1, 450e3},
		[2]float64{1, 370.3e3},
		[2]float64{1, 350e3},
		[2]float64{1, 290e3},
	)
	assert.Equal(t, []Change{Unchanged, CutDown, HeldAfterCut, HeldAfterCut, GaveUp, NotForwarding}, changes)
	assert.Equal(t, 400e3, c.Limit, "the cut that didn't help is undone")
	{
		// Once the CPU calms down, the cap may cut again
		c, changes := cpuTrace(c, 10*time.Second,
			[2]float64{0.6, 300e3}, [2]float64{0.6, 300e3}, [2]float64{0.6, 300e3},
			[2]float64{0.95, 370e3}, [2]float64{0.95, 370e3})
		assert.Equal(t, []Change{NotForwarding, Unchanged, Unchanged, Unchanged, CutDown}, changes)
		assert.Equal(t, 296e3, c.Limit)
	}
}

func TestCPUCapAveragesReadings(t *testing.T) {
	// A reading over a tenth of a second can be off by a tenth, so one
	// reading past 80% among calmer ones doesn't cut
	c, changes := cpuTrace(NewCPUCap(1, cpuInterval), 0,
		[2]float64{0.7, 500e3},
		[2]float64{0.7, 500e3},
		[2]float64{0.9, 500e3},
		[2]float64{0.9, 500e3},
	)
	assert.Equal(t, []Change{Unchanged, Unchanged, Unchanged, CutDown}, changes)
	assert.Equal(t, 400e3, c.Limit)
	{
		// One reading of a full CPU is enough
		c, changes := cpuTrace(NewCPUCap(1, cpuInterval), 0, [2]float64{0.5, 300e3}, [2]float64{0.5, 300e3}, [2]float64{1, 590e3})
		assert.Equal(t, []Change{Unchanged, Unchanged, CutDown}, changes)
		assert.Equal(t, 472e3, c.Limit)
	}
}

func TestCPUCapIgnoresBusyCPUsItDoesntCause(t *testing.T) {
	// On AWS, 3,000 new connections a second kept conntrackd and the CPU
	// busy while 24,000 to 37,000 packets a second were forwarded, and the
	// cap fell to 19,500. Forwarding that little is 4% of a CPU.
	steps := make([][2]float64, 40)
	for i := range steps {
		steps[i] = [2]float64{1, 24.4e3 + float64(i%5)*3e3}
	}
	c, changes := cpuTrace(NewCPUCap(1, cpuInterval), 0, steps...)
	assert.Zero(t, c.Limit)
	for _, change := range changes {
		assert.Equal(t, NotForwarding, change)
	}
	{
		// Traffic below the cap doesn't make the cap the cause either, even
		// if forwarding alone would explain the load
		c, _ := cpuTrace(NewCPUCap(1, cpuInterval), 0, [2]float64{1, 500e3})
		assert.Equal(t, 400e3, c.Limit)
		c, changes := cpuTrace(c, time.Second, [2]float64{0.9, 350e3}, [2]float64{0.9, 350e3})
		assert.Equal(t, []Change{NotForwarding, NotForwarding}, changes)
		assert.Equal(t, 400e3, c.Limit)
	}
	{
		// A two-CPU NAT splits forwarding over both. 500,000 a second
		// explains 40% of each CPU, less than half of 90%
		_, change := NewCPUCap(2, cpuInterval).Step(CPUObservation{Now: cpuInterval, Elapsed: cpuInterval, Busiest: 0.9, Rate: 500e3})
		assert.Equal(t, NotForwarding, change)
		c, change := NewCPUCap(2, cpuInterval).Step(CPUObservation{Now: cpuInterval, Elapsed: cpuInterval, Busiest: 0.9, Rate: 760e3})
		assert.Equal(t, CutDown, change)
		assert.Equal(t, 608e3, c.Limit)
	}
}
