package pacing

import "time"

// The cap controller's tuning. Rates of change are per second, so the
// controller behaves the same at any poll interval.
const (
	// cutFactor is how far a cap drops below the rate at which the instance
	// reported exceeding its allowance.
	cutFactor = 0.8
	// repeatCutFactor replaces cutFactor when the previous cut didn't stop the
	// reports, as when burst credits run out and the allowance falls to the
	// baseline. On a c7g.medium that is 12.5 to 0.52 Gbps, which takes 14
	// cuts at cutFactor and 6 at this one.
	repeatCutFactor = 0.5
	// settleRatio is where a cap settles after a cut, as a fraction of the
	// rate that exceeded the allowance.
	settleRatio = 0.95
	// recoverPerSecond is how fast a cap climbs back from a cut to where it
	// settles, as a fraction of the rate that exceeded the allowance. From the
	// cut to the settle point takes 3 s.
	recoverPerSecond = 0.05
	// raisePerSecond is how fast a cap rises while traffic presses it and the
	// instance reports nothing, as a fraction of the cap. Doubling takes about
	// 14 s. The counters show a drop within one 10 ms poll, so a cap that
	// rises past the allowance overshoots it by about 0.05% before it cuts.
	raisePerSecond = 0.05
	// pressureRatio is how close to the cap traffic must be for the cap to
	// rise. A cap that traffic doesn't reach says nothing about the allowance.
	pressureRatio = 0.9
	// probeInterval is how long after a cut a settled cap waits before rising
	// above the settle point again, to find out whether the allowance went
	// back up, as it does when burst credits refill. A probe that finds the
	// same allowance costs one cut, and the cap is back at its settle point
	// 3 s later.
	probeInterval = 10 * time.Second
)

// Change says what a [Cap.Step] did, for logs.
type Change string

const (
	// Unchanged means the cap stayed where it was.
	Unchanged Change = ""
	// CutDown means the instance reported exceeding its allowance, so the
	// cap dropped below the rate that exceeded it.
	CutDown Change = "cut"
	// Recovering means the cap rose toward its settle point after a cut.
	Recovering Change = "recovering"
	// Raised means traffic pressed the cap and the instance reported
	// nothing, so the cap rose.
	Raised Change = "raised"
	// HeldAfterCut means the instance reported exceeding its allowance within
	// the hold after a cut. Counters refresh late, so those reports may
	// describe traffic from before the cut, and the cap stays.
	HeldAfterCut Change = "held after cut"
	// IgnoredBelowFloor means the instance reported exceeding its allowance
	// while forwarded traffic stayed below the floor, so forwarded traffic
	// didn't cause it, and the cap stays.
	IgnoredBelowFloor Change = "ignored below floor"
	// GaveUp means a cut lowered the forwarded rate without freeing the
	// CPU, so the CPU cap went back to where it was and stopped cutting
	// until the CPU calms down.
	GaveUp Change = "gave up"
	// NotForwarding means the CPU was busy but forwarded packets don't
	// explain it, so the CPU cap stays.
	NotForwarding Change = "not forwarding"
)

// Observation is what a NAT saw during one poll of the allowance counters.
type Observation struct {
	// Now is the time of the poll.
	Now time.Duration
	// Elapsed is the time since the previous poll.
	Elapsed time.Duration
	// Exceeded is how much the instance's allowance counters for this budget
	// grew since the previous poll. Each count is a packet AWS queued or
	// dropped.
	Exceeded uint64
	// Rate is the forwarded traffic that left the NAT, in the budget's units
	// per second, averaged since the previous poll.
	Rate float64
}

// Cap controls one budget, in bytes per second or packets per second. It
// keeps forwarded traffic just under the rate at which the instance last
// reported exceeding its allowance.
//
// While the instance reports nothing and traffic presses the cap, the cap
// rises by raisePerSecond. At the first report, the cap drops to cutFactor of
// the rate that caused it, then climbs back to settleRatio of that rate and
// stays. If the reports go on after the cut, the next cut is deeper.
// probeInterval after a cut, while traffic presses it, the cap rises again to
// learn whether the allowance grew. A falling allowance, such as when burst
// credits run out, causes new reports, and each one cuts again from the lower
// rate.
//
// Step is a pure function of the cap and one observation, so a NAT's history
// is all in the value.
type Cap struct {
	// Limit is the cap in units per second. Zero means no cap.
	Limit float64
	// Ceiling is the forwarded rate at the last cut. Zero means the instance
	// hasn't reported exceeding this allowance.
	Ceiling float64

	floor float64
	hold  time.Duration
	// cutAt is when the last cut happened. It is only meaningful once
	// Ceiling is set.
	cutAt time.Duration
	// settledAt is when the cap last stopped rising above its settle point,
	// at a cut or at the end of a probe. The next probe waits probeInterval
	// from it.
	settledAt time.Duration
	probing   bool
	// quiet is true once a poll after the last cut's hold reported nothing.
	quiet bool
}

// NewCap returns a cap that starts at start units per second, or with no cap
// if start is zero. It never cuts below floor. After a cut it ignores reports
// for hold, which should cover two polls of the counters.
func NewCap(start, floor float64, hold time.Duration) Cap {
	return Cap{Limit: start, floor: floor, hold: hold}
}

// Step returns the cap after observation o, and what changed.
func (c Cap) Step(o Observation) (Cap, Change) {
	held := c.Ceiling > 0 && o.Now-c.cutAt < c.hold
	if o.Exceeded > 0 {
		switch {
		case o.Rate < c.floor:
			return c, IgnoredBelowFloor
		case held:
			return c, HeldAfterCut
		}
		factor := cutFactor
		if c.Ceiling > 0 && !c.quiet {
			factor = repeatCutFactor
		}
		return c.cut(o.Now, o.Rate, factor), CutDown
	}
	if c.Limit == 0 || held {
		return c, Unchanged
	}
	c.quiet = true
	seconds := o.Elapsed.Seconds()
	if settle := settleRatio * c.Ceiling; c.Limit < settle {
		c.Limit = min(settle, c.Limit+recoverPerSecond*c.Ceiling*seconds)
		return c, Recovering
	}
	if o.Rate < pressureRatio*c.Limit {
		if c.probing {
			c.probing, c.settledAt = false, o.Now
		}
		return c, Unchanged
	}
	// A cap that never saw a report rises whenever traffic presses it. One
	// that did waits for the next probe.
	if c.Ceiling > 0 && !c.probing {
		if o.Now-c.settledAt < probeInterval {
			return c, Unchanged
		}
		c.probing = true
	}
	c.Limit += raisePerSecond * c.Limit * seconds
	return c, Raised
}

// cut lowers the cap to factor of rate, or of the cap if traffic was
// measured above it, and remembers that rate as the ceiling.
func (c Cap) cut(now time.Duration, rate, factor float64) Cap {
	if c.Limit > 0 && c.Limit < rate {
		rate = c.Limit
	}
	c.Ceiling = rate
	c.Limit = max(c.floor, factor*rate)
	c.cutAt, c.settledAt, c.probing, c.quiet = now, now, false, false
	return c
}
