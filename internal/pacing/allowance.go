package pacing

import (
	"strconv"
	"strings"
	"time"
)

const (
	// allowanceShare is how much of what the instance sends forwarded
	// traffic must make up before an allowance report cuts its cap. On AWS,
	// conntrackd's copies once made the shared ENI send three times what it
	// received, AWS dropped about 90,000 packets a second, and cutting the
	// workers to the floor didn't help.
	allowanceShare = 0.5
	// helpedRatio is how far the counters' growth must fall after a cut for
	// the cut to count as working.
	helpedRatio = 0.9
)

// AllowanceObservation is what a NAT saw during one poll of an allowance's
// counters.
type AllowanceObservation struct {
	Now, Elapsed time.Duration
	// Exceeded is how much the allowance counters grew since the previous
	// poll, summed over every interface.
	Exceeded uint64
	// Rate is the forwarded traffic that left the NAT, in the cap's units
	// per second.
	Rate float64
	// Share is the part of what AWS counts against this allowance that
	// forwarded traffic makes up, from 0 to 1.
	Share float64
}

// AllowanceCap follows one of the instance's allowances. It is a [Cap] that
// only cuts when forwarded traffic is to blame: it makes up at least
// allowanceShare of what AWS counts. If a cut forwards less but AWS keeps
// dropping at the same rate, something else exceeds the allowance, so the
// cap goes back to where it was and stops cutting until the reports stop.
//
// Step is a pure function of the cap and one observation.
type AllowanceCap struct {
	Cap
	cut           bool
	exceededAtCut float64
	rateAtCut     float64
	limitBefore   float64
	gaveUpCutting bool
}

// NewAllowanceCap returns a cap that starts at start units per second, or
// with no cap if start is zero, and never cuts below floor.
func NewAllowanceCap(start, floor float64, hold time.Duration) AllowanceCap {
	return AllowanceCap{Cap: NewCap(start, floor, hold)}
}

// Step returns the cap after observation o, and what changed.
func (c AllowanceCap) Step(o AllowanceObservation) (AllowanceCap, Change) {
	if o.Exceeded == 0 {
		c.cut, c.gaveUpCutting = false, false
		var change Change
		c.Cap, change = c.Cap.Step(Observation{Now: o.Now, Elapsed: o.Elapsed, Rate: o.Rate})
		return c, change
	}
	if c.cut && o.Now-c.cutAt < c.hold {
		return c, HeldAfterCut
	}
	if c.gaveUpCutting || o.Share < allowanceShare {
		return c, NotForwarding
	}
	exceeded := float64(o.Exceeded) / o.Elapsed.Seconds()
	if c.cut && o.Rate < c.rateAtCut && exceeded >= helpedRatio*c.exceededAtCut {
		// The last cut forwarded less, and AWS dropped as much.
		c.Limit, c.cut, c.gaveUpCutting = c.limitBefore, false, true
		return c, GaveUp
	}
	before := c.Limit
	var change Change
	c.Cap, change = c.Cap.Step(Observation{Now: o.Now, Elapsed: o.Elapsed, Exceeded: o.Exceeded, Rate: o.Rate})
	if change == CutDown {
		c.cut, c.exceededAtCut, c.rateAtCut, c.limitBefore = true, exceeded, o.Rate, before
	}
	return c, change
}

// InterfaceCounters are one interface's totals from /proc/net/dev.
type InterfaceCounters struct {
	RxBytes, RxPackets, TxBytes, TxPackets uint64
}

// ParseNetDev returns each interface's totals from the contents of
// /proc/net/dev, which shows the reading process's network namespace.
func ParseNetDev(dev string) map[string]InterfaceCounters {
	counters := map[string]InterfaceCounters{}
	for _, line := range strings.Split(dev, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 10 {
			continue
		}
		var values [4]uint64
		var err error
		// Receive bytes and packets are the first two fields, transmit bytes
		// and packets the ninth and tenth.
		for i, field := range []string{fields[0], fields[1], fields[8], fields[9]} {
			if values[i], err = strconv.ParseUint(field, 10, 64); err != nil {
				break
			}
		}
		if err != nil {
			continue
		}
		counters[strings.TrimSpace(name)] = InterfaceCounters{RxBytes: values[0], RxPackets: values[1], TxBytes: values[2], TxPackets: values[3]}
	}
	return counters
}
