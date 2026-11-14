package guard

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stat returns /proc/stat for CPUs with each one's user, idle, iowait,
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

// nat simulates a two-CPU NAT as the guard reads it every Interval. CPU 0
// takes the shared ENI's traffic and CPU 1 idles. /proc/stat counts in
// hundredths of a second, 10 ticks per CPU each interval.
type nat struct {
	at                time.Duration
	softirq, idle     uint64
	otherIdle         uint64
	received, dropped uint64
	passed, shed      [2]uint64
}

// load is one interval of traffic: how many of CPU 0's 10 ticks were busy,
// what the shared ENI received and its NIC dropped, and what the program
// passed and dropped on each CPU.
type load struct {
	busyTicks         uint64
	received, dropped uint64
	passed, shed      [2]uint64
}

func (n *nat) next(l load) Reading {
	n.at += Interval
	n.softirq += l.busyTicks
	n.idle += 10 - l.busyTicks
	n.otherIdle += 10
	n.received += l.received
	n.dropped += l.dropped
	for i := range n.passed {
		n.passed[i] += l.passed[i]
		n.shed[i] += l.shed[i]
	}
	return Reading{
		At:       n.at,
		CPUs:     ParseCPUTimes(stat([5]uint64{0, n.idle, 0, n.softirq, 0}, [5]uint64{0, n.otherIdle, 0, 0, 0})),
		Received: n.received,
		Dropped:  n.dropped,
		Passed:   []uint64{n.passed[0], n.passed[1]},
		Shed:     []uint64{n.shed[0], n.shed[1]},
	}
}

// flood is a full CPU 0 whose NIC drops half of what arrives, as 64-byte
// UDP at 1.2 million packets a second does on a c7gn.medium.
var flood = load{busyTicks: 10, received: 50_000, dropped: 50_000}

// steps feeds the controller count readings of l and returns the decisions.
func steps(c *Controller, n *nat, l load, count int) []Decision {
	var decisions []Decision
	for range count {
		decisions = append(decisions, c.Step(n.next(l)))
	}
	return decisions
}

func changed(decisions []Decision) []Decision {
	var out []Decision
	for _, d := range decisions {
		if d.Changed {
			out = append(out, d)
		}
	}
	return out
}

func TestControllerEngagesAndClears(t *testing.T) {
	var c Controller
	var n nat
	// The first reading has nothing to compare, and the drop share needs
	// a full second after it
	assert.Empty(t, changed(steps(&c, &n, flood, 10)))
	assert.Equal(t, Unlimited, c.Mode())

	measure := c.Step(n.next(flood))
	assert.Equal(t, Decision{Mode: Measuring, Changed: true, Budget: math.MaxUint64, Busiest: 1, DropShare: 0.5}, measure)
	// Attaching the program restarted the interface, so the first reading
	// after it only starts the measured interval
	assert.Equal(t, Decision{Mode: Measuring}, c.Step(n.next(flood)))

	// While measuring, CPU 0 passed 50,000 packets in 100 ms and CPU 1
	// 10,000. The budget is 90% of the busiest CPU's 500,000 a second, per
	// 2^20 ns tick: 471.86, rounded down. The decision repeats what engaged it.
	limit := c.Step(n.next(load{busyTicks: 10, received: 60_000, dropped: 40_000, passed: [2]uint64{50_000, 10_000}}))
	assert.Equal(t, Decision{Mode: Limiting, Changed: true, Budget: 471, Rate: 500_000, Busiest: 1, DropShare: 0.5}, limit)

	{
		// The flood goes on, and the budget keeps the CPU at 70%, below
		// where it engaged. It holds while it drops 47% of what it sees,
		// which a rule based on the CPU alone took off after 2 s on AWS.
		flooding := load{busyTicks: 7, received: 95_000, passed: [2]uint64{45_000, 5_000}, shed: [2]uint64{45_000, 0}}
		assert.Empty(t, changed(steps(&c, &n, flooding, 30)))
		assert.Equal(t, Limiting, c.Mode())
	}
	// The flood eases. Dropping 7.5% of what it sees still holds the budget
	tail := load{busyTicks: 5, received: 40_000, passed: [2]uint64{37_000, 0}, shed: [2]uint64{3_000, 0}}
	assert.Empty(t, changed(steps(&c, &n, tail, 20)))
	// It stops. The share over the last second falls below 5% at the fourth
	// quiet reading: 6 readings shedding 3,000 and 4 shedding 10, of 400,000.
	// At the third it is 5.3%.
	quiet := load{busyTicks: 5, received: 40_000, passed: [2]uint64{39_990, 0}, shed: [2]uint64{10, 0}}
	decisions := steps(&c, &n, quiet, 4)
	assert.Empty(t, changed(decisions[:3]))
	cleared := decisions[3]
	assert.Equal(t, Unlimited, cleared.Mode)
	assert.True(t, cleared.Changed)
	assert.Zero(t, cleared.Budget)
	// 30 flooding readings shed 45,000 each, 20 tail ones 3,000 and 4 quiet ones 10
	assert.Equal(t, uint64(30*45_000+20*3_000+4*10), cleared.Shed)
	assert.Equal(t, Unlimited, c.Mode())

	// Flooded again at once, it waits for a second of readings since it
	// cleared, which keeps its own drops out of the drop share
	assert.Empty(t, changed(steps(&c, &n, flood, 9)))
	assert.Equal(t, Measuring, c.Step(n.next(flood)).Mode)
}

func TestControllerNeedsBothAFullCPUAndNICDrops(t *testing.T) {
	{
		// TCP as fast as it goes fills the CPU, but the senders slow down
		// before the NIC drops much: 4.9% isn't enough
		var c Controller
		var n nat
		assert.Empty(t, changed(steps(&c, &n, load{busyTicks: 10, received: 95_100, dropped: 4_900}, 50)))
	}
	{
		// 5% is enough
		var c Controller
		var n nat
		assert.Len(t, changed(steps(&c, &n, load{busyTicks: 10, received: 95_000, dropped: 5_000}, 11)), 1)
	}
	{
		// Drops while the CPU has room, such as from a burst, aren't an
		// overload: 9 of 10 ticks is 90% busy
		var c Controller
		var n nat
		assert.Empty(t, changed(steps(&c, &n, load{busyTicks: 9, received: 50_000, dropped: 50_000}, 50)))
	}
	{
		// The CPU must be full for the last 300 ms, not just the last reading
		var c Controller
		var n nat
		steps(&c, &n, load{received: 50_000, dropped: 50_000}, 9)
		assert.Empty(t, changed(steps(&c, &n, flood, 2)))
		assert.Len(t, changed(steps(&c, &n, flood, 1)), 1)
	}
}

func TestControllerStandsDownWhenNothingReachesIt(t *testing.T) {
	var c Controller
	var n nat
	steps(&c, &n, flood, 12)
	require.Equal(t, Measuring, c.Mode())
	// The CPU is full of something else: the program passed nothing
	assert.Equal(t, Decision{Mode: Unlimited, Changed: true}, c.Step(n.next(flood)))
	// And it doesn't measure again for a second
	assert.Empty(t, changed(steps(&c, &n, flood, 9)))
}

func TestControllerBudgetLetsAtLeastOnePacketThrough(t *testing.T) {
	// 10 packets a second is 0.009 a tick, and a budget of 0 means no limit
	var c Controller
	var n nat
	steps(&c, &n, flood, 12)
	decision := c.Step(n.next(load{busyTicks: 10, received: 1, dropped: 1, passed: [2]uint64{1, 0}}))
	assert.Equal(t, Decision{Mode: Limiting, Changed: true, Budget: 1, Rate: 10, Busiest: 1, DropShare: 0.5}, decision)
}

func TestControllerForgetsReadingsAcrossANICReset(t *testing.T) {
	var c Controller
	var n nat
	steps(&c, &n, flood, 10)
	// The NIC reset its counters, as ENA does when it restarts
	n.received, n.dropped = 0, 0
	assert.Empty(t, changed(steps(&c, &n, flood, 10)))
	assert.Len(t, changed(steps(&c, &n, flood, 1)), 1)
}

func TestControllerLowersTheBudgetWhileTheNICStillDrops(t *testing.T) {
	var c Controller
	var n nat
	steps(&c, &n, flood, 12)
	limit := c.Step(n.next(load{busyTicks: 10, received: 60_000, dropped: 40_000, passed: [2]uint64{50_000, 10_000}}))
	require.Equal(t, uint64(471), limit.Budget)

	// The budget is too high for this flood: the program sheds 4% of what
	// it sees, and the NIC still drops 20% because the CPU stays full. That
	// doesn't clear it, and once a second the budget falls to 90% of itself,
	// down to half the measured rate: 262 a tick
	tooHigh := load{busyTicks: 10, received: 80_000, dropped: 20_000, passed: [2]uint64{48_000, 0}, shed: [2]uint64{2_000, 0}}
	var budgets []uint64
	for _, d := range steps(&c, &n, tooHigh, 80) {
		if d.Changed {
			require.Equal(t, Limiting, d.Mode)
			budgets = append(budgets, d.Budget)
		}
	}
	assert.Equal(t, []uint64{423, 380, 342, 307, 276, 262}, budgets)
	{
		// Once the NIC keeps up, it clears as before
		quiet := load{busyTicks: 5, received: 40_000, passed: [2]uint64{40_000, 0}}
		cleared := changed(steps(&c, &n, quiet, 10))
		require.Len(t, cleared, 1)
		assert.Equal(t, Unlimited, cleared[0].Mode)
	}
}
