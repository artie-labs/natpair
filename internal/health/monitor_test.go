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
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{
		prober:    &mocks.FakeProber{},
		conntrack: &mocks.FakeConntrack{},
		table:     &mocks.FakeConnectionTable{},
		reports:   &mocks.FakeReports{},
		clock:     &fakeClock{now: 100 * time.Second},
	}
	f.prober.UploadReturns(probe.Flow{}, nil)
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
// each, like Run.
func (f *fixture) rounds(t *testing.T, count int) health.Report {
	var report health.Report
	for range count {
		report = f.monitor.Round(t.Context())
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

// errTimeout is how a lost upload fails: it runs out of time.
var errTimeout = fmt.Errorf("%w: failed to send probe upload: read tcp4 198.18.0.6:35237->192.0.2.1:443: i/o timeout", probe.ErrTimeout)

func TestRoundCongestedPath(t *testing.T) {
	// newOwner returns an owner that has run a healthy round, whose uploads
	// now time out, and whose standby proved its own path meanwhile.
	newOwner := func(t *testing.T) *fixture {
		f := newFixture(t)
		f.serving = true
		f.rounds(t, 1)
		f.peer = &health.Report{CanTakeover: true, ProvenWhilePeerFailing: true}
		f.prober.UploadReturns(probe.Flow{}, errTimeout)
		return f
	}
	{
		// Some handshakes complete, as on AWS when forwarding lost 87% of
		// pings, so the path is alive and the owner keeps serving.
		f := newOwner(t)
		f.prober.HandshakesReturns(5, nil)
		report := f.rounds(t, 30)
		assert.True(t, report.Congested)
		assert.False(t, report.PathHealthy)
		assert.Zero(t, report.ConsecutiveFailures)
		assert.False(t, controller.ShouldDemote(report))
		_, target, attempts := f.prober.HandshakesArgsForCall(0)
		assert.Equal(t, "nat-shared", target.Namespace)
		assert.Equal(t, 40, attempts)
	}
	{
		// No handshake completes, so the path is dead
		f := newOwner(t)
		f.prober.HandshakesReturns(0, nil)
		report := f.rounds(t, 2)
		assert.False(t, report.Congested)
		assert.True(t, controller.ShouldDemote(report))
	}
	{
		// Every handshake completes, so small packets get through without
		// loss, and the upload failed for another reason, such as a path
		// that drops full-size packets
		f := newOwner(t)
		f.prober.HandshakesReturns(40, nil)
		assert.True(t, controller.ShouldDemote(f.rounds(t, 2)))
	}
	{
		// A congested round ends a run of failures, so a dead round on each
		// side of it doesn't demote
		f := newOwner(t)
		f.prober.HandshakesReturnsOnCall(0, 0, nil)
		f.prober.HandshakesReturnsOnCall(1, 5, nil)
		f.prober.HandshakesReturnsOnCall(2, 0, nil)
		assert.Equal(t, 1, f.rounds(t, 1).ConsecutiveFailures)
		assert.Zero(t, f.rounds(t, 1).ConsecutiveFailures)
		report := f.rounds(t, 1)
		assert.Equal(t, 1, report.ConsecutiveFailures)
		assert.False(t, controller.ShouldDemote(report))
	}
	{
		// Without an answer from the check, the failure counts
		f := newOwner(t)
		f.prober.HandshakesReturns(0, errors.New(`failed to resolve probe receiver "probe.example.invalid": i/o timeout`))
		assert.True(t, controller.ShouldDemote(f.rounds(t, 2)))
	}
	{
		// A failure that came back over the path, such as a reply from the
		// wrong address, counts without a check
		f := newOwner(t)
		f.prober.UploadReturns(probe.Flow{}, errors.New("probe receiver saw source IP 192.0.2.7, expected 192.0.2.10"))
		f.prober.HandshakesReturns(5, nil)
		assert.True(t, controller.ShouldDemote(f.rounds(t, 2)))
		assert.Zero(t, f.prober.HandshakesCallCount())
	}
	{
		// A healthy upload needs no check
		f := newFixture(t)
		f.serving = true
		assert.True(t, f.rounds(t, 3).CanForward)
		assert.Zero(t, f.prober.HandshakesCallCount())
	}
	{
		// A standby's load doesn't move with the shared ENI, so its timeouts
		// count without a check
		f := newFixture(t)
		f.prober.UploadReturns(probe.Flow{}, errTimeout)
		f.prober.HandshakesReturns(5, nil)
		report := f.rounds(t, 2)
		assert.Equal(t, 2, report.ConsecutiveFailures)
		assert.False(t, report.CanForward)
		assert.Zero(t, f.prober.HandshakesCallCount())
	}
	{
		// A full table excuses the round first, without a check
		f := newOwner(t)
		f.tableReadings(262133, 262144, 40)
		assert.Zero(t, f.rounds(t, 3).ConsecutiveFailures)
		assert.Zero(t, f.prober.HandshakesCallCount())
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

// stats returns `conntrackd -s` output with the given cache sizes.
func stats(tracked, copied int) string {
	return fmt.Sprintf("cache internal:\ncurrent active connections: %d\n\ncache external:\ncurrent active connections: %d\n", tracked, copied)
}

func TestRoundReplication(t *testing.T) {
	src := netip.MustParseAddr("172.31.94.10")
	flowA := probe.Flow{Src: src, Dst: netip.MustParseAddr("192.0.2.1"), SrcPort: 40000, DstPort: 443}
	flowB := probe.Flow{Src: src, Dst: netip.MustParseAddr("192.0.2.2"), SrcPort: 40001, DstPort: 443}
	cache := "tcp 6 ESTABLISHED src=172.31.94.10 dst=192.0.2.1 sport=40000 dport=443 src=192.0.2.1 dst=192.0.2.200 sport=443 dport=40000\n" +
		"tcp 6 ESTABLISHED src=172.31.94.10 dst=192.0.2.2 sport=40001 dport=443 src=192.0.2.2 dst=192.0.2.200 sport=443 dport=40001\n"

	f := newFixture(t)
	f.peer = &health.Report{Ready: true, CanTakeover: true, Flows: []probe.Flow{flowA, flowB}}
	f.conntrack.ExternalCacheReturns(cache, nil)
	f.conntrack.StatsReturns(stats(4, 2), nil)
	report := f.rounds(t, 2)
	assert.True(t, report.Ready)
	assert.True(t, report.PeerReady)
	assert.True(t, report.PeerCanTakeover)

	// Without new copies, one verification keeps the NAT ready for replicationRounds rounds.
	f.conntrack.ExternalCacheReturns("", nil)
	assert.True(t, f.rounds(t, 3).Ready)
	assert.False(t, f.rounds(t, 1).Ready)

	// A copy missing one of the peer's oldest connections is incomplete, for
	// example after this NAT's conntrackd restarted and churn alone refilled
	// it. After two such rounds it asks for a full copy, then waits 30 s before
	// asking again.
	idle := conntrackd.Tuple{Src: src, Dst: netip.MustParseAddr("192.0.2.3"), SrcPort: 40002, DstPort: 5432}
	f.conntrack.ExternalCacheReturns(cache, nil)
	f.peer = &health.Report{Ready: true, CanTakeover: true, Flows: f.peer.Flows, Oldest: []conntrackd.Tuple{idle}}
	assert.False(t, f.rounds(t, 1).Ready)
	assert.Zero(t, f.conntrack.RequestResyncCallCount())
	assert.False(t, f.rounds(t, 1).Ready)
	assert.Equal(t, 1, f.conntrack.RequestResyncCallCount())
	f.rounds(t, 5)
	assert.Equal(t, 1, f.conntrack.RequestResyncCallCount())
	f.rounds(t, 1)
	assert.Equal(t, 2, f.conntrack.RequestResyncCallCount())
	f.conntrack.ExternalCacheReturns(cache+"tcp 6 ESTABLISHED src=172.31.94.10 dst=192.0.2.3 sport=40002 dport=5432 [ASSURED] [active since 600s]\n", nil)
	assert.True(t, f.rounds(t, 1).Ready)

	// An owner doesn't ask, because its copy would hold the former owner's old entries.
	f.serving = true
	f.conntrack.ExternalCacheReturns(cache, nil)
	f.rounds(t, 3)
	assert.Equal(t, 2, f.conntrack.RequestResyncCallCount())
	f.serving = false

	// A stale peer report is not trusted.
	f.peer = &health.Report{Ready: true, CanTakeover: true, Stale: true}
	report = f.rounds(t, 1)
	assert.False(t, report.PeerReady)
	assert.False(t, report.PeerCanTakeover)
}

func TestRoundOldest(t *testing.T) {
	// A NAT publishes its oldest connections, and reads them from conntrackd
	// again only every StandbyInterval, because that dumps the whole cache.
	f := newFixture(t)
	f.serving = true
	f.conntrack.InternalCacheReturns("tcp 6 ESTABLISHED src=10.0.16.5 dst=192.0.2.9 sport=1000 dport=443 [ASSURED] [active since 90s]\n", nil)
	report := f.rounds(t, 1)
	assert.Equal(t, []conntrackd.Tuple{{Src: netip.MustParseAddr("10.0.16.5"), Dst: netip.MustParseAddr("192.0.2.9"), SrcPort: 1000, DstPort: 443}}, report.Oldest)
	f.rounds(t, 4)
	assert.Equal(t, 1, f.conntrack.InternalCacheCallCount())
	f.rounds(t, 1)
	assert.Equal(t, 2, f.conntrack.InternalCacheCallCount())
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
		// Every failed round is logged, with its probe error
		f.prober.UploadReturns(probe.Flow{}, errors.New("upload timed out"))
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
		assert.Equal(t, 60, strings.Count(output, `"table_full":true`))
		assert.Zero(t, logged("the connection table is nearly full"))
	}
}

func TestCongestedPathWarning(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	f := newFixture(t)
	f.serving = true
	f.prober.UploadReturns(probe.Flow{}, errTimeout)
	f.prober.HandshakesReturns(7, nil)
	f.rounds(t, 61)
	output := logs.String()
	// Once a minute
	assert.Equal(t, 2, strings.Count(output, `"msg":"the health probe failed, but the path is alive, so forwarding is congested and it doesn't count as a path failure"`))
	assert.Contains(t, output, `"handshakes":7,"attempts":40`)
	assert.Equal(t, 61, strings.Count(output, `"congested":true`))
	assert.Equal(t, 61, strings.Count(output, `"handshakes":7}`))
}
