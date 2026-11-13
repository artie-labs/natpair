package pacing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// allowanceTrace steps an allowance cap through 10 ms polls of
// [exceeded, forwarded rate, forwarded share].
func allowanceTrace(c AllowanceCap, start time.Duration, polls ...[3]float64) (AllowanceCap, []Change) {
	const poll = 10 * time.Millisecond
	var changes []Change
	for i, p := range polls {
		var change Change
		c, change = c.Step(AllowanceObservation{Now: start + time.Duration(i+1)*poll, Elapsed: poll, Exceeded: uint64(p[0]), Rate: p[1], Share: p[2]})
		changes = append(changes, change)
	}
	return c, changes
}

func TestAllowanceCapIgnoresDropsItDoesntCause(t *testing.T) {
	// On AWS, under connection churn, conntrackd's fragmented copies made the
	// shared ENI send about 130,000 packets a second against 40,000
	// received, while workers' forwarded packets were about 20,000 a second
	// each way. pps_allowance_exceeded grew by up to 113,728 in one poll, and
	// the packet cap fell to its floor of 10,000 and stayed there.
	polls := make([][3]float64, 300)
	for i := range polls {
		polls[i] = [3]float64{1000 + float64(i%7)*100, 200e3, 2 * 20e3 / 170e3}
	}
	c, changes := allowanceTrace(NewAllowanceCap(0, packetsFloor, 50*time.Millisecond), 0, polls...)
	assert.Zero(t, c.Limit, "no cap: the drops weren't the workers'")
	for _, change := range changes {
		assert.Equal(t, NotForwarding, change)
	}
}

func TestAllowanceCapStopsWhenCutsDontHelp(t *testing.T) {
	// Forwarded traffic is most of what's sent, but AWS drops just as much
	// after a cut, so something else is over the allowance.
	c, changes := allowanceTrace(NewAllowanceCap(500e3, packetsFloor, 50*time.Millisecond), 0,
		[3]float64{900, 480e3, 0.8},
		// The hold after the cut
		[3]float64{900, 420e3, 0.8},
		[3]float64{900, 410e3, 0.8},
		[3]float64{900, 390e3, 0.8},
		[3]float64{900, 395e3, 0.8},
		[3]float64{900, 395e3, 0.8},
		[3]float64{950, 398e3, 0.8},
	)
	assert.Equal(t, []Change{CutDown, HeldAfterCut, HeldAfterCut, HeldAfterCut, HeldAfterCut, GaveUp, NotForwarding}, changes)
	assert.Equal(t, 500e3, c.Limit, "the cut that didn't help is undone")
	{
		// Once AWS stops dropping, the cap may cut again
		c, changes := allowanceTrace(c, time.Second, [3]float64{0, 450e3, 0.8}, [3]float64{900, 460e3, 0.8})
		assert.Equal(t, []Change{Unchanged, CutDown}, changes)
		assert.Equal(t, 0.8*460e3, c.Limit)
	}
}

// gbps converts gigabits a second to bytes a second.
func gbps(g float64) float64 {
	return g * 1e9 / 8
}

func TestAllowanceCapFollowsBurstCreditsDown(t *testing.T) {
	// On AWS, a c7gn.medium forwarded 8.35 Gbps for 855 s, then its burst
	// credits ran out and AWS dropped everything over 3.1 Gbps, counting
	// each 1,500-byte packet in bw_out_allowance_exceeded. Without a cut, a
	// sender offering 8.35 Gbps loses 63% of its packets.
	const poll = 10 * time.Millisecond
	const cliff = 855 * time.Second
	const refill = cliff + 3*time.Minute
	allowance := func(now time.Duration) float64 {
		if now >= cliff && now < refill {
			return gbps(3.1)
		}
		return gbps(25)
	}
	c := NewAllowanceCap(0, bytesFloor, minAllowanceHold)
	var firstCut, underBaseline, refound time.Duration
	var gaveUp bool
	var exceededPolls int
	var sum float64
	for now := poll; now <= refill+time.Minute; now += poll {
		rate := gbps(8.35)
		if c.Limit > 0 {
			rate = min(rate, c.Limit)
		}
		var exceeded uint64
		if over := rate - allowance(now); over > 0 {
			exceeded = uint64(over * poll.Seconds() / 1500)
		}
		var change Change
		c, change = c.Step(AllowanceObservation{Now: now, Elapsed: poll, Exceeded: exceeded, Rate: rate, Share: 1})
		gaveUp = gaveUp || change == GaveUp
		switch {
		case now < cliff:
			assert.Zero(t, c.Limit, "no cap while AWS drops nothing")
		case change == CutDown && firstCut == 0:
			firstCut = now
		case c.Limit > 0 && c.Limit < gbps(3.1) && underBaseline == 0:
			underBaseline = now
		}
		if now > cliff+time.Minute && now <= cliff+3*time.Minute {
			sum += rate
			if exceeded > 0 {
				exceededPolls++
			}
		}
		if now >= refill && rate == gbps(8.35) && refound == 0 {
			refound = now
		}
	}
	assert.False(t, gaveUp)
	// It cuts at the first poll that counts drops, and is under the
	// baseline after two more cuts, each after a 50 ms hold
	assert.Equal(t, cliff, firstCut)
	assert.LessOrEqual(t, underBaseline-cliff, 100*time.Millisecond)
	// From the second to the third minute after the cliff, it forwards at
	// least 90% of the baseline, and each probe, every 10 s or so, goes
	// over for one poll
	assert.GreaterOrEqual(t, sum/float64(2*time.Minute/poll), 0.9*gbps(3.1))
	assert.LessOrEqual(t, exceededPolls, int(2*time.Minute/probeInterval))
	// When the burst credits come back, the next probe finds them, in
	// seconds rather than minutes
	assert.NotZero(t, refound)
	assert.Less(t, refound-refill, 35*time.Second)
}

func TestAllowanceCapLeavesSilentShapingAlone(t *testing.T) {
	// On AWS, a c7gn.medium's uploads fell from 6.25 to 3.1 Gbps when its
	// burst credits ran out, with no allowance counter moving on any host.
	// Pacing can't see that, so its caps stay where they were.
	polls := make([][3]float64, 0, 7000)
	for range 1000 {
		polls = append(polls, [3]float64{0, gbps(6.25), 1})
	}
	for range 6000 {
		polls = append(polls, [3]float64{0, gbps(3.1), 1})
	}
	{
		// With no cap yet, it stays without one
		c, changes := allowanceTrace(NewAllowanceCap(0, bytesFloor, minAllowanceHold), 0, polls...)
		assert.Zero(t, c.Limit)
		for _, change := range changes {
			assert.Equal(t, Unchanged, change)
		}
	}
	{
		// A cap above the traffic stays put
		c, changes := allowanceTrace(NewAllowanceCap(gbps(7), bytesFloor, minAllowanceHold), 0, polls...)
		assert.Equal(t, gbps(7), c.Limit)
		for _, change := range changes {
			assert.Equal(t, Unchanged, change)
		}
	}
}

func TestAllowanceCapFloor(t *testing.T) {
	// Real cuts stop at the floor, 100,000 packets a second
	c, _ := allowanceTrace(NewAllowanceCap(120e3, packetsFloor, 0), 0, [3]float64{500, 120e3, 1})
	assert.Equal(t, 100e3, c.Limit)
}

func TestParseNetDev(t *testing.T) {
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   43210     321    0    0    0     0          0         0    43210     321    0    0    0     0       0          0
  ens5: 9876543   54321    0    0    0     0          0         0  1234567   12345    0    0    0     0       0          0
  ens6:100000000  90000    0    3    0     0          0         0 200000000 130000    0    0    0     0       0          0
`
	assert.Equal(t, map[string]InterfaceCounters{
		"lo":   {RxBytes: 43210, RxPackets: 321, TxBytes: 43210, TxPackets: 321},
		"ens5": {RxBytes: 9876543, RxPackets: 54321, TxBytes: 1234567, TxPackets: 12345},
		"ens6": {RxBytes: 100000000, RxPackets: 90000, TxBytes: 200000000, TxPackets: 130000},
	}, ParseNetDev(dev))
}
