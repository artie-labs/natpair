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

func TestAllowanceCapFollowsBurstCreditsDown(t *testing.T) {
	// The bandwidth allowance falls from 1,000 to 400 when burst credits run
	// out. AWS drops the excess, so a cut lowers the drops in proportion.
	const poll = 10 * time.Millisecond
	c := NewAllowanceCap(950, 10, 50*time.Millisecond)
	var gaveUp bool
	for now := poll; now <= 30*time.Second; now += poll {
		rate := min(5000, c.Limit)
		var exceeded uint64
		if rate > 400 {
			exceeded = uint64((rate - 400) * 10)
		}
		var change Change
		c, change = c.Step(AllowanceObservation{Now: now, Elapsed: poll, Exceeded: exceeded, Rate: rate, Share: 1})
		gaveUp = gaveUp || change == GaveUp
	}
	assert.False(t, gaveUp)
	assert.Less(t, c.Limit, 400.0)
	assert.Greater(t, c.Limit, 0.9*400)
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
