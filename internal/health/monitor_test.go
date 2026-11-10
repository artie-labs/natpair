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
	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/mocks"
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
		reports:   &mocks.FakeReports{},
		clock:     &fakeClock{now: 100 * time.Second},
	}
	f.prober.UploadReturns(probe.Flow{}, nil)
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

func TestRoundOwnerReplicationWindow(t *testing.T) {
	// The standby probes only every StandbyInterval, and each probe's copy
	// leaves the owner's cache once the upload ends. One confirmed copy keeps
	// the owner ready until the standby's next probes, not just for three of
	// the owner's own rounds.
	flow := probe.Flow{Src: netip.MustParseAddr("172.31.94.10"), Dst: netip.MustParseAddr("192.0.2.1"), SrcPort: 40000, DstPort: 443}
	cache := "tcp 6 ESTABLISHED src=172.31.94.10 dst=192.0.2.1 sport=40000 dport=443 src=192.0.2.1 dst=192.0.2.200 sport=443 dport=40000\n"

	f := newFixture(t)
	f.serving = true
	f.peer = &health.Report{Ready: true, CanTakeover: true, Flows: []probe.Flow{flow}}
	f.conntrack.StatsReturns(stats(4, 1), nil)
	f.conntrack.ExternalCacheReturns(cache, nil)
	assert.True(t, f.rounds(t, 2).Ready)

	// Between the standby's probes, no copy is confirmed.
	f.conntrack.ExternalCacheReturns("", nil)
	// Three of the standby's rounds is fifteen of the owner's.
	for i := range 15 {
		assert.True(t, f.rounds(t, 1).Ready, "round %d after the last copy", i+1)
	}
	assert.False(t, f.rounds(t, 1).Ready)
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
