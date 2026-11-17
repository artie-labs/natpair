package health_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/conntrackd"
	"github.com/artie-labs/natpair/internal/controller"
	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/network"
	"github.com/artie-labs/natpair/internal/probe"
)

type fakeClock struct {
	now time.Duration
}

func (c *fakeClock) Now() time.Duration {
	return c.now
}

type fixture struct {
	monitor   *health.Monitor
	prober    *mocks.FakeProber
	conntrack *mocks.FakeConntrack
	table     *mocks.FakeConnectionTable
	reports   *mocks.FakeReports
	clock     *fakeClock
	serving   bool
	inhibited bool
	// peer is what the fake board returns. nil means no fresh report.
	peer *health.Report
	// tracked and copied are this NAT's cache sizes in conntrackd's stats.
	// While arriving, each read of the stats counts one more copy added.
	tracked, copied, added int
	arriving               bool
	// statsErr, if set, is what reading the stats fails with.
	statsErr error
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{
		prober:    &mocks.FakeProber{},
		conntrack: &mocks.FakeConntrack{},
		table:     &mocks.FakeConnectionTable{},
		reports:   &mocks.FakeReports{},
		clock:     &fakeClock{now: 100 * time.Second},
		arriving:  true,
	}
	f.prober.UploadReturns(probe.Flow{}, nil)
	f.conntrack.StatsCalls(func(context.Context) (string, error) {
		if f.statsErr != nil {
			return "", f.statsErr
		}
		if f.arriving {
			f.added++
		}
		return stats(f.tracked, f.copied, f.added), nil
	})
	f.table.ReadConnectionTableReturns(network.ConnectionTable{Connections: 1200, Max: 262144}, nil)
	f.reports.ReadCalls(func(context.Context) (*health.Report, error) {
		return f.peer, nil
	})
	f.monitor = health.New(health.Config{
		Probe:        probe.Target{URL: "https://probe.example.invalid/nat", Namespace: "nat-own"},
		ServingProbe: probe.Target{URL: "https://probe.example.invalid/nat", Namespace: "nat-shared"},
		Release:      "v0.2.0",
	}, health.Dependencies{
		Prober:    f.prober,
		Conntrack: f.conntrack,
		Table:     f.table,
		Reports:   f.reports,
		Serving:   func() bool { return f.serving },
		Inhibited: func() bool { return f.inhibited },
		Now:       f.clock.Now,
	})
	return f
}

// rounds runs count rounds, advancing the clock by the round interval after
// each, like Run. A pass over conntrackd's caches that a round starts
// finishes before the next round.
func (f *fixture) rounds(t *testing.T, count int) health.Report {
	var report health.Report
	for range count {
		report = f.monitor.Round(t.Context())
		health.WaitForScans(f.monitor)
		if f.serving {
			f.clock.now += health.ServingInterval
		} else {
			f.clock.now += health.StandbyInterval
		}
	}
	return report
}

func TestRoundForwarding(t *testing.T) {
	{
		// A dead peer does not stop this NAT from serving new connections
		f := newFixture(t)
		report := f.rounds(t, 2)
		assert.True(t, report.PathHealthy)
		assert.True(t, report.CanForward)
		assert.False(t, report.Ready)
		assert.False(t, report.PeerReady)
		assert.True(t, report.CanTakeover)
	}
	{
		// One healthy round is not enough
		f := newFixture(t)
		assert.False(t, f.rounds(t, 1).CanForward)
	}
	{
		// conntrackd isn't needed to forward, but without its copies the NAT is not ready for maintenance
		f := newFixture(t)
		f.conntrack.StatsReturns("", errors.New("no control socket"))
		report := f.rounds(t, 2)
		assert.True(t, report.CanForward)
		assert.True(t, report.CanTakeover)
		assert.False(t, report.Ready)
	}
	{
		// A failed upload resets the success count and counts failures. The NAT
		// can still forward, but only unproven.
		f := newFixture(t)
		f.rounds(t, 2)
		f.prober.UploadReturnsOnCall(2, probe.Flow{}, errors.New("timeout"))
		report := f.rounds(t, 1)
		assert.False(t, report.PathHealthy)
		assert.False(t, report.CanForward)
		assert.True(t, report.CanForwardUnverified)
		assert.Equal(t, 1, report.ConsecutiveFailures)
	}
	{
		// Without conntrackd or a provable path, a NAT can still take over as a last resort
		f := newFixture(t)
		f.prober.UploadReturns(probe.Flow{}, errors.New("timeout"))
		f.conntrack.StatsReturns("", errors.New("no control socket"))
		assert.True(t, f.rounds(t, 2).CanForwardUnverified)
	}
}

// tableReadings makes each reading of the connection table show it holding
// connections of max, with dropped more packets dropped than the last.
func (f *fixture) tableReadings(connections, max int, dropped uint64) {
	var drops uint64
	f.table.ReadConnectionTableCalls(func(context.Context) (network.ConnectionTable, error) {
		drops += dropped
		return network.ConnectionTable{Connections: connections, Max: max, Drops: drops}, nil
	})
}

func TestRoundFullConnectionTable(t *testing.T) {
	// newOwner returns an owner that has run a healthy round, whose uploads
	// now fail, and whose standby proved its own path meanwhile.
	newOwner := func(t *testing.T) *fixture {
		f := newFixture(t)
		f.serving = true
		f.rounds(t, 1)
		f.peer = &health.Report{CanTakeover: true, ProvenWhilePeerFailing: true}
		f.prober.UploadReturns(probe.Flow{}, errors.New("dial tcp 192.0.2.1:443: i/o timeout"))
		return f
	}
	{
		// The kernel drops new connections because the table is full, as on
		// AWS at 262,133 of 262,144. The peer would take over the same copied
		// table, so the owner doesn't step down.
		f := newOwner(t)
		f.tableReadings(262133, 262144, 40)
		report := f.rounds(t, 5)
		assert.False(t, report.PathHealthy)
		assert.Zero(t, report.ConsecutiveFailures)
		assert.False(t, controller.ShouldDemote(report))
		// Once the table has room again, failures count again, and full
		// rounds didn't reset the count.
		f.tableReadings(1200, 262144, 0)
		assert.Equal(t, 1, f.rounds(t, 1).ConsecutiveFailures)
		f.tableReadings(262133, 262144, 40)
		assert.Equal(t, 1, f.rounds(t, 1).ConsecutiveFailures)
		f.tableReadings(1200, 262144, 0)
		assert.True(t, controller.ShouldDemote(f.rounds(t, 1)))
	}
	{
		// One failure, an hour of full table, then one more failure aren't two
		// in a row
		f := newOwner(t)
		f.tableReadings(1200, 262144, 0)
		assert.Equal(t, 1, f.rounds(t, 1).ConsecutiveFailures)
		f.tableReadings(262133, 262144, 40)
		assert.Zero(t, f.rounds(t, 3600).ConsecutiveFailures)
		f.tableReadings(1200, 262144, 0)
		report := f.rounds(t, 1)
		assert.Equal(t, 1, report.ConsecutiveFailures)
		assert.False(t, controller.ShouldDemote(report))
	}
	{
		// Two full rounds between failures still leave them in a row, and a
		// third ends the run
		f := newOwner(t)
		f.tableReadings(1200, 262144, 0)
		f.rounds(t, 1)
		f.tableReadings(262133, 262144, 40)
		assert.Equal(t, 1, f.rounds(t, 2).ConsecutiveFailures)
		f.tableReadings(1200, 262144, 0)
		assert.True(t, controller.ShouldDemote(f.rounds(t, 1)))
		f.tableReadings(262133, 262144, 40)
		assert.Equal(t, 2, f.rounds(t, 2).ConsecutiveFailures)
		assert.Zero(t, f.rounds(t, 1).ConsecutiveFailures)
	}
	{
		// A standby whose table fills while it takes over marks the failure as
		// the table's, so the takeover doesn't fail for it
		f := newFixture(t)
		f.rounds(t, 2)
		f.prober.UploadReturns(probe.Flow{}, errors.New("dial tcp 192.0.2.1:443: i/o timeout"))
		f.tableReadings(262133, 262144, 40)
		report := f.rounds(t, 1)
		assert.False(t, report.PathHealthy)
		assert.True(t, report.TableFull)
		assert.True(t, report.CanForward)
		// A failure the table doesn't explain is the path's
		f.tableReadings(1200, 262144, 0)
		assert.False(t, f.rounds(t, 1).TableFull)
	}
	{
		// Exactly 90% full counts as full
		f := newOwner(t)
		f.tableReadings(900, 1000, 1)
		assert.Zero(t, f.rounds(t, 3).ConsecutiveFailures)
	}
	{
		// Drops below 90% have another cause, so the failure is the path's
		f := newOwner(t)
		f.tableReadings(899, 1000, 1)
		assert.True(t, controller.ShouldDemote(f.rounds(t, 2)))
	}
	{
		// A table at its limit that still finds room drops nothing, so the
		// failure is the path's
		f := newOwner(t)
		f.tableReadings(262144, 262144, 0)
		assert.True(t, controller.ShouldDemote(f.rounds(t, 2)))
	}
	{
		// The first reading has nothing to compare its drops with
		f := newFixture(t)
		f.prober.UploadReturns(probe.Flow{}, errors.New("timeout"))
		f.tableReadings(262133, 262144, 40)
		assert.Equal(t, 1, f.rounds(t, 1).ConsecutiveFailures)
	}
	{
		// One failed reading doesn't blind the next one: drops count from the
		// last good reading
		f := newOwner(t)
		var drops uint64
		f.table.ReadConnectionTableCalls(func(context.Context) (network.ConnectionTable, error) {
			drops += 40
			if f.table.ReadConnectionTableCallCount() == 3 {
				return network.ConnectionTable{}, errors.New("conntrack timed out")
			}
			return network.ConnectionTable{Connections: 262133, Max: 262144, Drops: drops}, nil
		})
		assert.Zero(t, f.rounds(t, 1).ConsecutiveFailures)
		assert.Equal(t, 1, f.rounds(t, 1).ConsecutiveFailures)
		report := f.rounds(t, 1)
		assert.True(t, report.TableFull)
		assert.False(t, controller.ShouldDemote(report))
	}
	{
		// Without a reading, a failure counts as before
		f := newOwner(t)
		f.table.ReadConnectionTableReturns(network.ConnectionTable{}, errors.New("conntrack failed"))
		assert.True(t, controller.ShouldDemote(f.rounds(t, 2)))
	}
	{
		// A healthy round with a full table is still healthy
		f := newFixture(t)
		f.serving = true
		f.tableReadings(262133, 262144, 40)
		report := f.rounds(t, 2)
		assert.True(t, report.PathHealthy)
		assert.True(t, report.CanForward)
	}
}

func TestRoundTakeoverEligibility(t *testing.T) {
	{
		// A NAT that can forward offers to take over, even without recent copies
		f := newFixture(t)
		report := f.rounds(t, 2)
		assert.True(t, report.CanForward)
		assert.False(t, report.Ready)
		assert.True(t, report.CanTakeover)
	}
	{
		// Maintenance or cooldown withdraws the offer
		f := newFixture(t)
		f.inhibited = true
		report := f.rounds(t, 2)
		assert.True(t, report.CanForward)
		assert.False(t, report.CanTakeover)
		assert.False(t, report.Ready)
	}
}

// stats returns `conntrackd -s` output with the given cache sizes and count
// of copies added, in conntrackd 1.4.7's format.
func stats(tracked, copied, added int) string {
	return fmt.Sprintf("cache internal:\ncurrent active connections:\t%12d\nconnections created:\t\t%12d\tfailed:\t%12d\n\n"+
		"cache external:\ncurrent active connections:\t%12d\nconnections created:\t\t%12d\tfailed:\t%12d\n", tracked, tracked, 0, copied, added, 0)
}

func TestRoundReplication(t *testing.T) {
	idle := conntrackd.Tuple{Src: netip.MustParseAddr("172.31.94.10"), Dst: netip.MustParseAddr("192.0.2.3"), SrcPort: 40002, DstPort: 5432}
	// standby returns a standby whose peer's oldest connection is idle, and
	// whose copy holds it if held.
	standby := func(t *testing.T, held bool) *fixture {
		f := newFixture(t)
		f.peer = &health.Report{Ready: true, CanTakeover: true, Oldest: []conntrackd.Tuple{idle}}
		f.conntrack.CopiedReturns(map[conntrackd.Tuple]bool{idle: held}, nil)
		return f
	}
	{
		// conntrackd keeps adding copies of the peer's new connections, and the
		// copy holds the peer's oldest connection
		f := standby(t, true)
		report := f.rounds(t, 2)
		assert.True(t, report.Ready)
		assert.True(t, report.PeerReady)
		assert.True(t, report.PeerCanTakeover)
		// A pass over the copies reads them all, so the peer's oldest
		// connection is checked once, not every round.
		f.rounds(t, 10)
		require.Equal(t, 1, f.conntrack.CopiedCallCount())
		_, wanted := f.conntrack.CopiedArgsForCall(0)
		assert.Equal(t, []conntrackd.Tuple{idle}, wanted)
		// It's checked again after 5 minutes.
		f.rounds(t, 50)
		assert.Equal(t, 2, f.conntrack.CopiedCallCount())
		assert.True(t, f.rounds(t, 1).Ready)
	}
	{
		// When copies stop arriving, as when the peer's conntrackd stops, the
		// NAT stays ready for copyWindow and then replicationRounds more
		f := standby(t, true)
		require.True(t, f.rounds(t, 2).Ready)
		f.arriving = false
		assert.True(t, f.rounds(t, 6).Ready)
		assert.False(t, f.rounds(t, 1).Ready)
	}
	{
		// A count that moved since a read long ago doesn't show copies
		// arriving now. After stats fail for a minute, the NAT is ready again
		// only once the count moves between two reads.
		f := standby(t, true)
		require.True(t, f.rounds(t, 2).Ready)
		f.statsErr = errors.New("timed out")
		require.False(t, f.rounds(t, 12).Ready)
		f.statsErr = nil
		assert.False(t, f.rounds(t, 1).Ready)
		assert.True(t, f.rounds(t, 1).Ready)
	}
	{
		// A copy missing the peer's oldest connection, for example after this
		// NAT's conntrackd restarted and churn alone refilled it, isn't ready,
		// and is checked again every 15 s. After 70 s, longer than the peer
		// takes to stop reporting a connection that closed, the NAT asks for a
		// full copy, then waits 30 s before asking again.
		f := standby(t, false)
		assert.False(t, f.rounds(t, 3).Ready)
		assert.Equal(t, 1, f.conntrack.CopiedCallCount())
		assert.False(t, f.rounds(t, 1).Ready)
		assert.Equal(t, 2, f.conntrack.CopiedCallCount())
		f.rounds(t, 10)
		assert.Zero(t, f.conntrack.RequestResyncCallCount())
		f.rounds(t, 1)
		assert.Equal(t, 1, f.conntrack.RequestResyncCallCount())
		f.rounds(t, 5)
		assert.Equal(t, 1, f.conntrack.RequestResyncCallCount())
		f.rounds(t, 1)
		assert.Equal(t, 2, f.conntrack.RequestResyncCallCount())
		// Once the copy holds it, the next check finds it
		f.conntrack.CopiedReturns(map[conntrackd.Tuple]bool{idle: true}, nil)
		f.rounds(t, 2)
		assert.True(t, f.rounds(t, 1).Ready)
	}
	{
		// An owner doesn't ask, because its copy would hold the former owner's old entries
		f := standby(t, false)
		f.serving = true
		f.rounds(t, 120)
		assert.Zero(t, f.conntrack.RequestResyncCallCount())
	}
	{
		// A NAT whose conntrackd restarted, which starts its count of copies
		// added over, isn't ready until it checks the new copy, even if the
		// copy refilled before the round
		f := standby(t, true)
		require.True(t, f.rounds(t, 2).Ready)
		f.added = 0
		f.conntrack.CopiedReturns(map[conntrackd.Tuple]bool{}, nil)
		assert.False(t, f.rounds(t, 1).Ready)
		f.rounds(t, 3)
		assert.Equal(t, 2, f.conntrack.CopiedCallCount())
	}
	{
		// A NAT that steps down isn't ready until it checks the new owner's full copy
		f := standby(t, true)
		f.serving = true
		require.True(t, f.rounds(t, 2).Ready)
		f.serving = false
		f.conntrack.CopiedReturns(map[conntrackd.Tuple]bool{}, nil)
		assert.False(t, f.rounds(t, 1).Ready)
	}
	{
		// Nor is a standby whose takeover failed after conntrackd flushed its
		// caches. It never served, and the flush doesn't lower conntrackd's
		// count of copies added, but its copy refilled without the peer's
		// idle connection.
		f := standby(t, true)
		require.True(t, f.rounds(t, 2).Ready)
		f.conntrack.FlushesReturns(1)
		f.conntrack.CopiedReturns(map[conntrackd.Tuple]bool{}, nil)
		assert.False(t, f.rounds(t, 1).Ready)
		assert.False(t, f.rounds(t, 20).Ready)
	}
	{
		// A board read that fails for a round keeps what passes found, so the
		// NAT is ready again without another pass over its copies
		f := standby(t, true)
		require.True(t, f.rounds(t, 2).Ready)
		fresh := f.peer
		f.peer = nil
		f.rounds(t, 1)
		f.peer = fresh
		assert.True(t, f.rounds(t, 1).Ready)
		assert.Equal(t, 1, f.conntrack.CopiedCallCount())
	}
	{
		// When passes over the copies keep failing, what they found stops
		// counting 10 minutes after the pass that found it, and the NAT stops
		// being ready replicationRounds later
		f := standby(t, true)
		require.True(t, f.rounds(t, 2).Ready)
		f.conntrack.CopiedReturns(nil, errors.New("conntrackd -e failed"))
		assert.True(t, f.rounds(t, 121).Ready)
		assert.False(t, f.rounds(t, 1).Ready)
	}
	{
		// A stale peer report is not trusted
		f := standby(t, true)
		f.peer.Stale = true
		report := f.rounds(t, 2)
		assert.False(t, report.Ready)
		assert.False(t, report.PeerReady)
		assert.False(t, report.PeerCanTakeover)
	}
}

func TestRoundCopiedShare(t *testing.T) {
	// standby returns a standby whose copy holds copied of the peer's 100,000
	// connections.
	standby := func(t *testing.T, copied int) *fixture {
		f := newFixture(t)
		f.peer = &health.Report{TrackedConnections: 100000}
		f.tracked, f.copied = 3, copied
		return f
	}
	{
		// A copy of 70%, as after a full copy lost part of its burst, is not
		// ready, though it holds the sampled connections. Once it has stayed
		// short for 30 s, longer than a large copy takes to arrive, the
		// standby asks for a full copy.
		f := standby(t, 70000)
		assert.False(t, f.rounds(t, 6).Ready)
		assert.Zero(t, f.conntrack.RequestResyncCallCount())
		assert.False(t, f.rounds(t, 1).Ready)
		assert.Equal(t, 1, f.conntrack.RequestResyncCallCount())
	}
	{
		f := standby(t, 96000)
		assert.True(t, f.rounds(t, 2).Ready)
		assert.Zero(t, f.conntrack.RequestResyncCallCount())
	}
	{
		// Exactly 95% is enough, one connection fewer is not
		assert.True(t, standby(t, 95000).rounds(t, 2).Ready)
		assert.False(t, standby(t, 94999).rounds(t, 2).Ready)
	}
	{
		// In a small table, a copy lacking the few connections opened since the
		// owner's report is still ready, up to 100 of them
		f := standby(t, 8)
		f.peer.TrackedConnections = 9
		assert.True(t, f.rounds(t, 2).Ready)
		f = standby(t, 400)
		f.peer.TrackedConnections = 500
		assert.True(t, f.rounds(t, 2).Ready)
		f = standby(t, 399)
		f.peer.TrackedConnections = 500
		assert.False(t, f.rounds(t, 2).Ready)
	}
	{
		// A ready standby whose copy falls short, as when its conntrackd
		// restarts empty, stops being ready in that round, not
		// replicationRounds later.
		f := standby(t, 96000)
		require.True(t, f.rounds(t, 2).Ready)
		f.copied = 40
		assert.False(t, f.rounds(t, 1).Ready)
	}
	{
		// While a copy is short, passes over it still count, so it isn't read
		// again every 15 s, and the standby is ready in the round its copy
		// reaches 95%.
		idle := conntrackd.Tuple{Src: netip.MustParseAddr("172.31.94.10"), Dst: netip.MustParseAddr("192.0.2.3"), SrcPort: 40002, DstPort: 5432}
		f := standby(t, 70000)
		f.peer.Oldest = []conntrackd.Tuple{idle}
		f.conntrack.CopiedReturns(map[conntrackd.Tuple]bool{idle: true}, nil)
		assert.False(t, f.rounds(t, 12).Ready)
		assert.Equal(t, 1, f.conntrack.CopiedCallCount())
		f.copied = 96000
		assert.True(t, f.rounds(t, 1).Ready)
	}
	{
		// Without its own counts, a standby can't show its copy is complete
		f := standby(t, 96000)
		f.conntrack.StatsReturns("cache internal:\ncurrent active connections: 3\n", nil)
		assert.False(t, f.rounds(t, 2).Ready)
		// Nor does it ask for a full copy over stats it couldn't read
		f.rounds(t, 20)
		assert.Zero(t, f.conntrack.RequestResyncCallCount())
	}
	{
		// Nor without the owner's count. An owner whose conntrackd didn't
		// answer reports 0 connections, which any copy would cover.
		f := standby(t, 40)
		f.peer.TrackedConnections, f.peer.TrackedUnknown = 0, true
		assert.False(t, f.rounds(t, 2).Ready)
		f.rounds(t, 20)
		assert.Zero(t, f.conntrack.RequestResyncCallCount())
	}
	{
		// One round whose counts can't be read, such as a slow conntrackd -s
		// while a large copy arrives, doesn't undo a good copy. The standby
		// stays ready for replicationRounds, as after any failed check.
		f := standby(t, 96000)
		require.True(t, f.rounds(t, 2).Ready)
		f.statsErr = errors.New("timed out")
		report := f.rounds(t, 1)
		assert.True(t, report.Ready)
		// Its report says its own count is unknown, not 0
		assert.True(t, report.TrackedUnknown)
		f.statsErr = nil
		assert.False(t, f.rounds(t, 1).TrackedUnknown)
	}
	{
		// Rounds whose counts can't be read don't restart the 30 s a short
		// copy waits before asking for a full copy again.
		f := standby(t, 70000)
		for range 4 {
			f.rounds(t, 1)
			f.statsErr = errors.New("timed out")
			f.rounds(t, 1)
			f.statsErr = nil
		}
		assert.Equal(t, 1, f.conntrack.RequestResyncCallCount())
	}
	{
		// An owner's copy is of the standby's table, which still counts the
		// owner's old table for 60 s after a handover, so the share doesn't
		// apply.
		f := standby(t, 3)
		f.serving = true
		assert.True(t, f.rounds(t, 2).Ready)
	}
}

func TestRoundOldest(t *testing.T) {
	oldest := []conntrackd.Tuple{{Src: netip.MustParseAddr("10.0.16.5"), Dst: netip.MustParseAddr("192.0.2.9"), SrcPort: 1000, DstPort: 443}}
	{
		// A NAT publishes its oldest connections once a pass reads them, and
		// reads them again only every minute, because a pass has conntrackd
		// write its whole cache
		f := newFixture(t)
		f.serving = true
		f.conntrack.OldestReturns(oldest, nil)
		f.rounds(t, 1)
		assert.Equal(t, oldest, f.rounds(t, 1).Oldest)
		f.rounds(t, 58)
		assert.Equal(t, 1, f.conntrack.OldestCallCount())
		f.rounds(t, 1)
		assert.Equal(t, 2, f.conntrack.OldestCallCount())
	}
	{
		// A NAT that starts or stops serving reads its oldest connections again
		// at once: the ones it read in the other role belong to another table
		f := newFixture(t)
		f.conntrack.OldestReturns(oldest, nil)
		f.rounds(t, 2)
		require.Equal(t, 1, f.conntrack.OldestCallCount())
		f.serving = true
		f.rounds(t, 1)
		assert.Equal(t, 2, f.conntrack.OldestCallCount())
	}
	{
		// A failed pass keeps the previous list, since it may have read only
		// part of the table
		f := newFixture(t)
		f.serving = true
		f.conntrack.OldestReturns(oldest, nil)
		f.rounds(t, 2)
		f.conntrack.OldestReturns(nil, errors.New("conntrackd -i timed out"))
		assert.Equal(t, oldest, f.rounds(t, 60).Oldest)
		assert.Equal(t, 2, f.conntrack.OldestCallCount())
		// but not after a second failure. A connection on a kept list may have
		// closed, and the peer would wait for its copy forever.
		assert.Empty(t, f.rounds(t, 60).Oldest)
	}
	{
		// A round doesn't wait for a pass, however long conntrackd takes to
		// write its cache, and only one pass runs at a time
		f := newFixture(t)
		f.serving = true
		started, release := make(chan struct{}, 2), make(chan struct{})
		f.conntrack.OldestCalls(func(context.Context, int) ([]conntrackd.Tuple, error) {
			started <- struct{}{}
			<-release
			return oldest, nil
		})
		for range 120 {
			f.monitor.Round(t.Context())
			f.clock.now += health.ServingInterval
		}
		<-started
		assert.Empty(t, started, "a second pass started while the first ran")
		close(release)
		health.WaitForScans(f.monitor)
		assert.Equal(t, oldest, f.rounds(t, 1).Oldest)
	}
}

func TestRoundServing(t *testing.T) {
	{
		// The shared identity is probed only while serving
		f := newFixture(t)
		report := f.rounds(t, 1)
		assert.True(t, report.PathHealthy)
		_, target := f.prober.UploadArgsForCall(0)
		assert.Equal(t, "nat-own", target.Namespace)
		assert.Equal(t, 1, f.reports.ReadCallCount())
		// Every round's report is posted for the peer
		require.Equal(t, 1, f.reports.PublishCallCount())
		_, posted, interval := f.reports.PublishArgsForCall(0)
		assert.Equal(t, report, posted)
		assert.Equal(t, health.StandbyInterval, interval)
	}
	{
		// A failed upload through the shared Elastic IP fails the path
		f := newFixture(t)
		f.serving = true
		f.prober.UploadReturnsOnCall(0, probe.Flow{}, errors.New("timeout"))
		assert.False(t, f.rounds(t, 1).PathHealthy)
	}
	{
		// While serving, only the shared identity is probed, and its connection is advertised
		f := newFixture(t)
		f.serving = true
		flow := probe.Flow{Src: netip.MustParseAddr("172.31.94.6"), SrcPort: 40000, DstPort: 443}
		f.prober.UploadReturns(flow, nil)
		report := f.rounds(t, 1)
		require.Equal(t, 1, f.prober.UploadCallCount())
		_, target := f.prober.UploadArgsForCall(0)
		assert.Equal(t, "nat-shared", target.Namespace)
		assert.Equal(t, []probe.Flow{flow}, report.Flows)
	}
}

func TestLatest(t *testing.T) {
	f := newFixture(t)
	assert.True(t, f.monitor.Latest().Stale, "no round has run yet")
	f.rounds(t, 2)
	report := f.monitor.Latest()
	assert.False(t, report.Stale)
	assert.True(t, report.CanTakeover)

	// A monitor that stops completing rounds reports nothing usable.
	f.clock.now += health.StaleAfter(health.StandbyInterval)
	report = f.monitor.Latest()
	assert.True(t, report.Stale)
	assert.False(t, report.CanForward)
	assert.False(t, report.CanTakeover)
	assert.False(t, report.PathHealthy)
}

func TestRoundPeerFailure(t *testing.T) {
	{
		// A standby that proves its path while the owner is failing confirms the
		// owner's failure
		f := newFixture(t)
		f.peer = &health.Report{ConsecutiveFailures: 1}
		report := f.rounds(t, 1)
		assert.True(t, report.ProvenWhilePeerFailing)
	}
	{
		// A standby that cannot prove its path either, as in a receiver outage,
		// does not
		f := newFixture(t)
		f.peer = &health.Report{ConsecutiveFailures: 1}
		f.prober.UploadReturns(probe.Flow{}, errors.New("timeout"))
		assert.False(t, f.rounds(t, 1).ProvenWhilePeerFailing)
	}
	{
		// Without a failing peer there is nothing to confirm
		f := newFixture(t)
		f.peer = &health.Report{}
		assert.False(t, f.rounds(t, 1).ProvenWhilePeerFailing)
	}
	{
		// An owner learns from the standby's report that its failure is its own
		f := newFixture(t)
		f.serving = true
		f.peer = &health.Report{ProvenWhilePeerFailing: true}
		assert.True(t, f.rounds(t, 1).PeerConfirmedFailure)
		f.peer = &health.Report{ProvenWhilePeerFailing: true, Stale: true}
		assert.False(t, f.rounds(t, 1).PeerConfirmedFailure, "a stale peer report confirms nothing")
	}
}

func TestRoundReportsReleases(t *testing.T) {
	{
		f := newFixture(t)
		f.serving = true
		f.peer = &health.Report{Release: "v0.1.0", Serving: false}
		report := f.rounds(t, 1)
		assert.Equal(t, "v0.2.0", report.Release)
		assert.True(t, report.Serving)
		assert.Equal(t, "v0.1.0", report.PeerRelease)
		assert.False(t, report.PeerServing)
	}
	{
		f := newFixture(t)
		f.peer = &health.Report{Release: "v0.1.0", Serving: true}
		report := f.rounds(t, 1)
		assert.False(t, report.Serving)
		assert.True(t, report.PeerServing)
	}
	{
		// Without a fresh peer report, nothing about the peer is known.
		f := newFixture(t)
		f.peer = &health.Report{Release: "v0.1.0", Serving: true, Stale: true}
		report := f.rounds(t, 1)
		assert.Empty(t, report.PeerRelease)
		assert.False(t, report.PeerServing)
	}
}

func TestRoundLogging(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	// loggedRounds returns how many health rounds were logged since the last call.
	loggedRounds := func() int {
		count := strings.Count(logs.String(), `"msg":"health round"`)
		logs.Reset()
		return count
	}

	f := newFixture(t)
	f.serving = true
	{
		// While nothing changes, the owner logs one round a minute, not one a second
		f.rounds(t, 1)
		assert.Contains(t, logs.String(), `"release":"v0.2.0"`)
		assert.Equal(t, 1, loggedRounds())
		f.rounds(t, 59)
		assert.Equal(t, 0, loggedRounds())
		f.rounds(t, 1)
		assert.Equal(t, 1, loggedRounds())
	}
	{
		// A change is logged at once
		f.peer = &health.Report{Ready: true}
		assert.True(t, f.rounds(t, 1).PeerReady)
		assert.Equal(t, 1, loggedRounds())
		f.rounds(t, 1)
		assert.Equal(t, 0, loggedRounds())
	}
	{
		// A table at its limit that drops in some rounds and not others
		// doesn't log every healthy round
		full := false
		f.table.ReadConnectionTableCalls(func(context.Context) (network.ConnectionTable, error) {
			full = !full
			drops := uint64(0)
			if full {
				drops = 40
			}
			return network.ConnectionTable{Connections: 262133, Max: 262144, Drops: drops}, nil
		})
		f.rounds(t, 10)
		assert.Equal(t, 0, loggedRounds())
	}
	{
		// Every failed round is logged, with its probe error
		f.prober.UploadReturns(probe.Flow{}, errors.New("upload timed out"))
		f.table.ReadConnectionTableReturns(network.ConnectionTable{Connections: 1200, Max: 262144}, nil)
		f.rounds(t, 3)
		assert.Equal(t, 3, strings.Count(logs.String(), `"probe_error":"upload timed out"`))
		assert.Equal(t, 3, loggedRounds())
	}
}

func TestConnectionTableWarnings(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	// logged returns how many times msg was logged since the last call.
	logged := func(msg string) int {
		count := strings.Count(logs.String(), `"msg":"`+msg)
		logs.Reset()
		return count
	}

	f := newFixture(t)
	f.serving = true
	{
		// A nearly full table is warned about once a minute
		f.tableReadings(236000, 262144, 0)
		f.rounds(t, 60)
		assert.Equal(t, 1, logged("the connection table is nearly full"))
		f.rounds(t, 1)
		assert.Equal(t, 1, logged("the connection table is nearly full"))
	}
	{
		// So is a full one, and a probe that failed because of it
		f.tableReadings(262133, 262144, 40)
		f.prober.UploadReturns(probe.Flow{}, errors.New("i/o timeout"))
		f.rounds(t, 60)
		output := logs.String()
		assert.Equal(t, 1, strings.Count(output, `"msg":"the connection table is full, so the kernel drops new connections.`))
		assert.Equal(t, 1, strings.Count(output, `"msg":"the health probe failed because this NAT's connection table is full, so it doesn't count as a path failure"`))
		assert.Contains(t, output, `"connections":262133,"max_connections":262144,"dropped":40`)
		// The health round too, like a healthy one's, because a full table
		// can last hours
		assert.Equal(t, 1, strings.Count(output, `"msg":"health round"`))
		assert.Equal(t, 1, strings.Count(output, `"table_full":true`))
		assert.Zero(t, logged("the connection table is nearly full"))
	}
}
