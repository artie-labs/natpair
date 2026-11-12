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

// TestCPUCapHoldsForwardingBelowSaturation runs the CPU cap against a
// simulated one-CPU NAT. Forwarding costs 1.6 µs a packet on top of 5% for
// everything else, so the CPU fills at about 594,000 packets a second.
// Workers offer 900,000.
func TestCPUCapHoldsForwardingBelowSaturation(t *testing.T) {
	const tick = 250 * time.Millisecond
	other := 0.05
	busy := func(rate float64) float64 { return min(1, other+rate*1.6e-6) }
	c := NewCPUCap(1, 2*tick)
	step := func(start, end time.Duration) (overloaded int) {
		for now := start + tick; now <= end; now += tick {
			rate := min(900e3, c.Limit)
			if busy(rate) > cpuBusyThreshold {
				overloaded++
			}
			c, _ = c.Step(CPUObservation{Now: now, Elapsed: tick, Busiest: busy(rate), Rate: rate})
		}
		return overloaded
	}
	{
		// From the 400,000 start, the cap rises under pressure until the CPU
		// passes 80%, cuts, and settles where the CPU stays under it
		overloaded := step(0, 10*time.Minute)
		assert.Less(t, busy(c.Limit), cpuBusyThreshold)
		assert.Greater(t, busy(c.Limit), 0.7)
		// A probe every 5 minutes goes over for at most a few steps each
		assert.LessOrEqual(t, overloaded, 6)
	}
	{
		// Connection churn makes conntrackd take 30% of the CPU. The cap
		// follows it down, but not below the 250,000 floor
		other = 0.35
		overloaded := step(10*time.Minute, 11*time.Minute)
		assert.GreaterOrEqual(t, c.Limit, 250e3)
		assert.Less(t, busy(c.Limit), cpuBusyThreshold)
		assert.LessOrEqual(t, overloaded, 8)
	}
}

// cpuTrace steps a CPU cap through observations a quarter second apart.
func cpuTrace(c CPUCap, start time.Duration, steps ...[2]float64) (CPUCap, []Change) {
	var changes []Change
	for i, s := range steps {
		var change Change
		c, change = c.Step(CPUObservation{Now: start + time.Duration(i+1)*250*time.Millisecond, Elapsed: 250 * time.Millisecond, Busiest: s[0], Rate: s[1]})
		changes = append(changes, change)
	}
	return c, changes
}

func TestCPUCapStopsWhenCutsDontHelp(t *testing.T) {
	// On AWS, TCP uploads offered beyond what a c7gn.medium forwards kept its
	// CPU full after every cut, because receiving what the senders still
	// offered cost as much as forwarding it. The cap cut 400,000 to 320,000,
	// 296,000 and 144,000 a second in 6 s, and uploads fell from 10 to 2.7
	// Gbps. Busiest CPU and forwarded packets a second, as logged:
	c, changes := cpuTrace(NewCPUCap(1, 500*time.Millisecond), 0,
		[2]float64{0.857, 558.8e3},
		// The hold after the cut
		[2]float64{1, 450e3},
		[2]float64{1, 370.3e3},
		[2]float64{0.96, 287.5e3},
		[2]float64{1, 290e3},
		[2]float64{1, 300e3},
	)
	assert.Equal(t, []Change{CutDown, HeldAfterCut, GaveUp, NotForwarding, NotForwarding, NotForwarding}, changes)
	assert.Equal(t, 400e3, c.Limit, "the cut that didn't help is undone")
	{
		// Once the CPU calms down, the cap may cut again
		c, changes := cpuTrace(c, 10*time.Second, [2]float64{0.5, 380e3}, [2]float64{0.95, 390e3})
		assert.Equal(t, []Change{Unchanged, CutDown}, changes)
		assert.Equal(t, 312e3, c.Limit)
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
	c, changes := cpuTrace(NewCPUCap(1, 500*time.Millisecond), 0, steps...)
	assert.Equal(t, 400e3, c.Limit)
	for _, change := range changes {
		assert.Equal(t, NotForwarding, change)
	}
	{
		// Traffic below the cap doesn't make the cap the cause either, even
		// if forwarding alone would explain the load
		c, change := NewCPUCap(1, 500*time.Millisecond).Step(CPUObservation{Now: time.Second, Elapsed: 250 * time.Millisecond, Busiest: 0.9, Rate: 350e3})
		assert.Equal(t, NotForwarding, change)
		assert.Equal(t, 400e3, c.Limit)
	}
	{
		// A two-CPU NAT splits forwarding over both
		c := NewCPUCap(2, 500*time.Millisecond)
		assert.Equal(t, 800e3, c.Limit)
		_, change := c.Step(CPUObservation{Now: time.Second, Elapsed: 250 * time.Millisecond, Busiest: 0.9, Rate: 760e3})
		assert.Equal(t, CutDown, change)
	}
}
