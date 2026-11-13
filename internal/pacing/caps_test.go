package pacing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// instance simulates an EC2 instance's allowance for one budget. Forwarded
// traffic wants demand units per second and gets the cap, if there is one.
// The counters grow for every second the rate is above the allowance.
type instance struct {
	allowance func(now time.Duration) float64
	demand    float64
}

// run polls the cap every poll from start until end and returns it, with the
// seconds during which traffic exceeded the allowance and the mean
// forwarded rate.
func (s instance) run(c Cap, start, end, poll time.Duration) (Cap, float64, float64) {
	var exceeded, sum float64
	var polls int
	for now := start + poll; now <= end; now += poll {
		rate := s.demand
		if c.Limit > 0 {
			rate = min(rate, c.Limit)
		}
		var drops uint64
		if rate > s.allowance(now) {
			drops = 100
			exceeded += poll.Seconds()
		}
		sum += rate
		polls++
		c, _ = c.Step(Observation{Now: now, Elapsed: poll, Exceeded: drops, Rate: rate})
	}
	return c, exceeded, sum / float64(polls)
}

func TestCapLearnsTheAllowance(t *testing.T) {
	const floor = 10
	{
		// Without a start, nothing is capped until the instance reports
		c := NewCap(0, floor, 2*time.Second)
		c, change := c.Step(Observation{Now: time.Second, Elapsed: time.Second, Rate: 900})
		assert.Equal(t, Unchanged, change)
		assert.Zero(t, c.Limit)

		c, change = c.Step(Observation{Now: 2 * time.Second, Elapsed: time.Second, Exceeded: 3, Rate: 1000})
		assert.Equal(t, CutDown, change)
		assert.Equal(t, 800.0, c.Limit)
		assert.Equal(t, 1000.0, c.Ceiling)
	}
	{
		// A cut starts from the cap when traffic was measured above it
		c := NewCap(500, floor, 2*time.Second)
		c, change := c.Step(Observation{Now: time.Second, Elapsed: time.Second, Exceeded: 1, Rate: 520})
		assert.Equal(t, CutDown, change)
		assert.Equal(t, 400.0, c.Limit)
		assert.Equal(t, 500.0, c.Ceiling)
	}
	{
		// A cut never goes below the floor
		c := NewCap(12, floor, 2*time.Second)
		c, _ = c.Step(Observation{Now: time.Second, Elapsed: time.Second, Exceeded: 1, Rate: 11})
		assert.Equal(t, 10.0, c.Limit)
	}
	{
		// Reports while forwarded traffic is below the floor, such as on a
		// standby, come from other traffic and leave the cap alone
		c := NewCap(500, floor, 2*time.Second)
		c, change := c.Step(Observation{Now: time.Second, Elapsed: time.Second, Exceeded: 50, Rate: 9})
		assert.Equal(t, IgnoredBelowFloor, change)
		assert.Equal(t, NewCap(500, floor, 2*time.Second), c)
	}
}

func TestCapAfterCut(t *testing.T) {
	cut, _ := NewCap(0, 10, 2*time.Second).Step(Observation{Now: 10 * time.Second, Elapsed: time.Second, Exceeded: 1, Rate: 1000})
	{
		// Reports within the hold may describe traffic from before the cut
		c, change := cut.Step(Observation{Now: 11 * time.Second, Elapsed: time.Second, Exceeded: 5, Rate: 800})
		assert.Equal(t, HeldAfterCut, change)
		assert.Equal(t, cut, c)
	}
	{
		// The cap doesn't recover during the hold
		c, change := cut.Step(Observation{Now: 11 * time.Second, Elapsed: time.Second, Rate: 800})
		assert.Equal(t, Unchanged, change)
		assert.Equal(t, 800.0, c.Limit)
	}
	{
		// Reports that go on right after the hold mean the cut wasn't enough,
		// so the next cut, from the lower rate, is deeper
		c, change := cut.Step(Observation{Now: 12 * time.Second, Elapsed: time.Second, Exceeded: 5, Rate: 800})
		assert.Equal(t, CutDown, change)
		assert.Equal(t, 400.0, c.Limit)
		assert.Equal(t, 800.0, c.Ceiling)
	}
	{
		// After a quiet poll, a new report cuts by the usual factor
		c, _ := cut.Step(Observation{Now: 12 * time.Second, Elapsed: time.Second, Rate: 800})
		c, change := c.Step(Observation{Now: 13 * time.Second, Elapsed: time.Second, Exceeded: 5, Rate: 850})
		assert.Equal(t, CutDown, change)
		assert.Equal(t, 680.0, c.Limit)
		assert.Equal(t, 850.0, c.Ceiling)
	}
	{
		// After the hold, the cap climbs 5% of the ceiling a second and stops
		// at 95% of it, whether or not traffic presses it
		c, change := cut.Step(Observation{Now: 12 * time.Second, Elapsed: time.Second, Rate: 0})
		assert.Equal(t, Recovering, change)
		assert.InDelta(t, 850, c.Limit, 1e-9)
		for now := 13 * time.Second; now <= 20*time.Second; now += time.Second {
			c, _ = c.Step(Observation{Now: now, Elapsed: time.Second, Rate: 0})
		}
		assert.InDelta(t, 950, c.Limit, 1e-9)
	}
}

func TestCapProbes(t *testing.T) {
	cut, _ := NewCap(0, 10, 2*time.Second).Step(Observation{Now: 0, Elapsed: time.Second, Exceeded: 1, Rate: 1000})
	// From the cut to 800, the cap climbs back to 950 in 3 s.
	settled, _, _ := instance{allowance: func(time.Duration) float64 { return 1000 }, demand: 2000}.run(cut, 0, probeInterval-time.Second, time.Second)
	assert.InDelta(t, 950, settled.Limit, 1e-9)
	pressing := Observation{Elapsed: time.Second, Rate: 950}
	{
		// A settled cap stays below the rate that exceeded the allowance
		// until the next probe, even under pressure
		pressing.Now = probeInterval - time.Second
		c, change := settled.Step(pressing)
		assert.Equal(t, Unchanged, change)
		assert.Equal(t, settled, c)
	}
	{
		// Once the probe interval passes, it rises only under pressure
		idle := Observation{Now: probeInterval, Elapsed: time.Second, Rate: 100}
		c, change := settled.Step(idle)
		assert.Equal(t, Unchanged, change)
		assert.Equal(t, settled, c)

		pressing.Now = probeInterval
		c, change = settled.Step(pressing)
		assert.Equal(t, Raised, change)
		assert.InDelta(t, 997.5, c.Limit, 1e-9)

		// When the pressure stops, the probe ends where it got to, and the
		// next one waits a full interval
		idle.Now = probeInterval + time.Second
		c, change = c.Step(idle)
		assert.Equal(t, Unchanged, change)
		assert.InDelta(t, 997.5, c.Limit, 1e-9)
		pressing.Now = 2*probeInterval - time.Second
		c, change = c.Step(pressing)
		assert.Equal(t, Unchanged, change)
		pressing.Now = 2*probeInterval + time.Second
		_, change = c.Step(pressing)
		assert.Equal(t, Raised, change)
	}
}

func TestCapRaisesUnderPressureOnly(t *testing.T) {
	c := NewCap(1000, 10, 2*time.Second)
	{
		c, change := c.Step(Observation{Now: time.Second, Elapsed: time.Second, Rate: 899})
		assert.Equal(t, Unchanged, change)
		assert.Equal(t, 1000.0, c.Limit)
	}
	{
		// A cap that never saw a report rises 5% a second under pressure,
		// scaled by the poll interval
		c, change := c.Step(Observation{Now: 2 * time.Second, Elapsed: 2 * time.Second, Rate: 900})
		assert.Equal(t, Raised, change)
		assert.InDelta(t, 1100, c.Limit, 1e-9)
	}
}

func TestCapFollowsAllowance(t *testing.T) {
	// The allowance is 1000 while burst credits last and falls to 400, the
	// baseline, after 10 minutes.
	allowance := func(now time.Duration) float64 {
		if now < 10*time.Minute {
			return 1000
		}
		return 400
	}
	for _, poll := range []time.Duration{10 * time.Millisecond, 100 * time.Millisecond, time.Second} {
		sim := instance{allowance: allowance, demand: 5000}
		c := NewCap(600, 10, max(2*poll, 50*time.Millisecond))
		// A probe that finds the same allowance goes over it for one poll,
		// so 9 minutes hold at most one first report and 54 probes.
		maxExceeded := (9*time.Minute/probeInterval + 1) * poll
		step := raisePerSecond * poll.Seconds()
		{
			// It rises from the start until the first report, then
			// forwards at least 90% of the allowance, probing every 10 s
			var exceeded, mean float64
			c, exceeded, mean = sim.run(c, 0, 9*time.Minute, poll)
			assert.GreaterOrEqual(t, c.Ceiling, 1000.0, "poll %s", poll)
			assert.LessOrEqual(t, c.Ceiling, 1000*(1+step), "poll %s", poll)
			assert.GreaterOrEqual(t, mean, 0.9*1000, "poll %s", poll)
			assert.LessOrEqual(t, exceeded, maxExceeded.Seconds(), "poll %s", poll)
		}
		{
			// When the burst credits run out, it follows the allowance down
			c, _, _ = sim.run(c, 9*time.Minute, 11*time.Minute, poll)
			assert.GreaterOrEqual(t, c.Ceiling, 400.0, "poll %s", poll)
			assert.LessOrEqual(t, c.Ceiling, 400*(1+step), "poll %s", poll)
		}
		{
			// and then probes the baseline as it did the burst allowance
			var exceeded, mean float64
			c, exceeded, mean = sim.run(c, 11*time.Minute, 20*time.Minute, poll)
			assert.LessOrEqual(t, c.Ceiling, 400*(1+step), "poll %s", poll)
			assert.GreaterOrEqual(t, mean, 0.9*400, "poll %s", poll)
			assert.LessOrEqual(t, exceeded, maxExceeded.Seconds(), "poll %s", poll)
		}
	}
}
