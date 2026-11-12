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

// TestCPUCapHoldsForwardingBelowSaturation runs a [Cap] on the busiest CPU's
// load, as the daemon does, against a simulated one-CPU NAT. Forwarding costs
// 1.6 µs a packet on top of 5% for everything else, so the CPU fills at
// about 594,000 packets a second. Workers offer 900,000.
func TestCPUCapHoldsForwardingBelowSaturation(t *testing.T) {
	const tick = 250 * time.Millisecond
	other := 0.05
	busy := func(rate float64) float64 { return min(1, other+rate*1.6e-6) }
	c := NewCap(cpuStartPerCPU, packetsFloor, 2*tick)
	step := func(start, end time.Duration) (highest float64, overloaded int) {
		for now := start + tick; now <= end; now += tick {
			rate := min(900e3, c.Limit)
			load := busy(rate)
			highest = max(highest, load)
			var over uint64
			if load > cpuBusyThreshold {
				over = 1
				overloaded++
			}
			c, _ = c.Step(Observation{Now: now, Elapsed: tick, Exceeded: over, Rate: rate})
		}
		return highest, overloaded
	}
	{
		// From the 400,000 start, the cap rises under pressure until the CPU
		// passes 80%, cuts, and settles where the CPU stays under it
		_, overloaded := step(0, 10*time.Minute)
		assert.Less(t, busy(c.Limit), cpuBusyThreshold)
		assert.Greater(t, busy(c.Limit), 0.7)
		// A probe every 5 minutes goes over for at most a few steps each
		assert.LessOrEqual(t, overloaded, 6)
	}
	{
		// Connection churn makes conntrackd take 30% of the CPU. The cap
		// follows it down within a few seconds
		other = 0.35
		_, overloaded := step(10*time.Minute, 11*time.Minute)
		assert.Less(t, busy(c.Limit), cpuBusyThreshold)
		assert.LessOrEqual(t, overloaded, 8)
	}
}
