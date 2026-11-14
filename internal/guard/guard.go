// Package guard sheds worker traffic on the shared ENI when the owner's CPU
// can't forward everything it receives, so the owner's own path probe keeps
// working through a flood.
//
// Without it, a flood of small packets past what the CPU forwards overflows
// the shared ENI's receive ring. The NIC then drops packets at random,
// including the replies to the owner's path probe, which leaves through the
// shared Elastic IP like worker traffic. On AWS, 64-byte UDP at 800,000 to
// 1.2 million packets a second on a 1-vCPU c7gn.medium made the owner fail
// its probes and hand over in 6 of 6 runs, and the new owner then got the
// same flood.
//
// An XDP program on the shared ENI runs before the kernel builds a packet
// buffer. While its budget is 0 it passes everything after one map lookup.
// When the busiest CPU stays full and the NIC drops packets, the daemon
// gives it a per-CPU budget of packets per tick. Past the budget it drops
// worker packets for about 100 ns each, where the kernel's path costs about
// 1,450 ns, so the CPU keeps up again. It still passes everything that isn't
// IPv4, such as ARP, and a bounded number of replies to the shared canary's
// TCP connections, which are the path probes.
//
// The guard only drops. It never decides ownership: the health checks still
// do.
package guard

import (
	"math"
	"net/netip"
	"time"
)

// Interval is how often the daemon reads the CPUs and counters.
const Interval = 100 * time.Millisecond

// Config sets up a Guard.
type Config struct {
	// SharedAddress is the shared ENI's private address. The guard attaches
	// to the interface that holds it.
	SharedAddress netip.Addr
	// PrimaryInterface is the NAT's own interface, which the guard never
	// attaches to. The NAT's lease renewals, DNS lookups and conntrackd
	// copies arrive there.
	PrimaryInterface string
	// ReceiverPort, FirstProbePort and LastProbePort match the replies the
	// guard always lets through: TCP from the probe receiver's port to the
	// shared canary's ports on the shared address.
	ReceiverPort                  uint16
	FirstProbePort, LastProbePort uint16
	// OffPath turns the guard off while it exists.
	OffPath string
}

// The controller's tuning, in readings of Interval.
const (
	// engageBusy and engageReadings: the busiest CPU must be at least 95%
	// busy over the last 300 ms. /proc/stat counts in hundredths of a
	// second, so one 100 ms reading can be off by a tenth.
	engageBusy     = 0.95
	engageReadings = 3
	// engageDropShare and dropReadings: the NIC must also have dropped at
	// least 5% of what reached the shared ENI over the last second. ENA
	// refreshes its drop counter once a second. A full CPU alone isn't
	// enough: TCP as fast as it goes also fills a c7gn.medium's CPU, but TCP
	// senders slow down at the first losses, so the NIC drops little and the
	// probe gets through. A flood that doesn't slow down overflows the
	// receive ring: at 1.2 million packets a second on a c7gn.medium, the
	// NIC dropped more than half.
	engageDropShare = 0.05
	dropReadings    = 10
	// clearBusy and clearReadings: the budget comes off once the busiest
	// CPU's share over the last 300 ms has been below 80% at each reading for
	// 1 s.
	clearBusy     = 0.80
	clearReadings = 10
	// budgetShare is the share of the measured rate the budget lets through.
	// The 10% it drops costs much less than forwarding it would, so the CPU
	// has room again for the probe and the NAT's own work.
	budgetShare = 0.9
)

// The program's windows. They are powers of two of nanoseconds, so the
// program finds the window with a shift instead of a division.
const (
	// tickShift sets the budget's window: 2^20 ns, about 1.05 ms.
	tickShift = 20
)

// measuring is the budget written while the controller measures the rate.
// No CPU passes that many packets in a tick, so the program only counts.
const measuring = math.MaxUint64

// tickSeconds is the length of the budget's window.
var tickSeconds = float64(uint64(1)<<tickShift) / 1e9

// Reading is what the daemon reads every Interval.
type Reading struct {
	// At is the time of the reading on a monotonic clock.
	At time.Duration
	// CPUs are each CPU's counters from /proc/stat.
	CPUs []CPUTimes
	// Received and Dropped are the shared ENI's rx_packets and rx_dropped.
	// ENA counts the packets its NIC dropped, and the program's drops, in
	// rx_dropped.
	Received, Dropped uint64
	// Passed and Shed are the program's per-CPU counters of packets it
	// passed and dropped while it had a budget.
	Passed, Shed []uint64
}

// Mode is what the program is doing.
type Mode int

const (
	// Unlimited passes everything.
	Unlimited Mode = iota
	// Measuring passes everything and counts it, for one Interval.
	Measuring
	// Limiting drops worker packets past the budget.
	Limiting
)

// Decision is the controller's answer to one reading.
type Decision struct {
	// Mode is the mode after the reading.
	Mode Mode
	// Changed is set when Budget must be written to the program.
	Changed bool
	// Budget is the packets each CPU passes per tick, 0 for no limit.
	Budget uint64
	// Busiest is the busiest CPU's busy share over the window the
	// controller judged, and DropShare the share of packets the shared ENI
	// dropped over the last second.
	Busiest, DropShare float64
	// Rate is the busiest CPU's measured packets a second, on Limiting.
	Rate float64
	// Shed is how many packets the program dropped while limiting, on the
	// way back to Unlimited.
	Shed uint64
}

// Controller decides the program's budget from readings. It is a pure
// function of the readings it has seen.
type Controller struct {
	mode Mode
	// history holds the last readings, oldest first, at most
	// dropReadings+1, so it spans dropReadings intervals.
	history []Reading
	// from is the reading where measuring or limiting started.
	from Reading
	// cool counts the readings in a row since then whose busiest CPU was
	// below clearBusy.
	cool int
}

// Mode returns what the program is doing.
func (c *Controller) Mode() Mode {
	return c.mode
}

// Reset forgets every reading, as when the guard moves to another interface
// or detaches. The caller sets the program's budget to 0.
func (c *Controller) Reset() {
	*c = Controller{}
}

// Step takes the next reading and returns what to do.
func (c *Controller) Step(r Reading) Decision {
	c.record(r)
	switch c.mode {
	case Measuring:
		return c.limit(r)
	case Limiting:
		busiest, _ := c.busiest(engageReadings)
		if busiest >= clearBusy {
			c.cool = 0
		} else {
			c.cool++
		}
		if c.cool < clearReadings {
			return Decision{Mode: Limiting, Busiest: busiest}
		}
		shed := sumSince(c.from.Shed, r.Shed)
		// A fresh history makes the next engagement wait for a full second
		// of readings since, and keeps the program's own drops, which ENA
		// adds to rx_dropped, out of the drop share.
		*c = Controller{history: []Reading{r}}
		return Decision{Mode: Unlimited, Changed: true, Busiest: busiest, Shed: shed}
	}
	busiest, hot := c.busiest(engageReadings)
	share, full := c.dropShare()
	if !hot || !full || busiest < engageBusy || share < engageDropShare {
		return Decision{Mode: Unlimited, Busiest: busiest, DropShare: share}
	}
	c.mode, c.from = Measuring, r
	return Decision{Mode: Measuring, Changed: true, Budget: measuring, Busiest: busiest, DropShare: share}
}

// limit sets the budget from what each CPU passed while measuring.
func (c *Controller) limit(r Reading) Decision {
	elapsed := (r.At - c.from.At).Seconds()
	var rate float64
	if elapsed > 0 && len(r.Passed) == len(c.from.Passed) {
		for i := range r.Passed {
			if r.Passed[i] >= c.from.Passed[i] {
				rate = max(rate, float64(r.Passed[i]-c.from.Passed[i])/elapsed)
			}
		}
	}
	if rate == 0 {
		// Nothing reached the program, so the shared ENI's traffic isn't
		// what fills the CPU.
		*c = Controller{history: []Reading{r}}
		return Decision{Mode: Unlimited, Changed: true}
	}
	c.mode, c.from = Limiting, r
	// A budget of 0 would mean no limit, so it lets at least one through.
	budget := max(1, uint64(budgetShare*rate*tickSeconds))
	return Decision{Mode: Limiting, Changed: true, Budget: budget, Rate: rate}
}

// record adds a reading. Counters that went backwards, as when the NIC
// resets, or a CPU that went offline, make the earlier readings useless.
func (c *Controller) record(r Reading) {
	if n := len(c.history); n > 0 {
		last := c.history[n-1]
		if r.Received < last.Received || r.Dropped < last.Dropped || len(r.CPUs) != len(last.CPUs) {
			c.history = c.history[:0]
		}
	}
	c.history = append(c.history, r)
	if len(c.history) > dropReadings+1 {
		c.history = c.history[1:]
	}
}

// busiest returns the busiest CPU's share over the last readings intervals,
// and whether the history spans them.
func (c *Controller) busiest(readings int) (float64, bool) {
	n := len(c.history)
	if n <= readings {
		return 0, false
	}
	return BusiestCPU(c.history[n-1-readings].CPUs, c.history[n-1].CPUs), true
}

// dropShare returns the share of packets the shared ENI dropped over the
// last dropReadings intervals, and whether the history spans them.
func (c *Controller) dropShare() (float64, bool) {
	n := len(c.history)
	if n <= dropReadings {
		return 0, false
	}
	first, last := c.history[n-1-dropReadings], c.history[n-1]
	dropped := float64(last.Dropped - first.Dropped)
	total := dropped + float64(last.Received-first.Received)
	if total == 0 {
		return 0, true
	}
	return dropped / total, true
}

// sumSince returns how much the per-CPU counters grew from before to after.
func sumSince(before, after []uint64) uint64 {
	var sum uint64
	for i := range after {
		if i < len(before) && after[i] >= before[i] {
			sum += after[i] - before[i]
		}
	}
	return sum
}
