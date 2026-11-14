package controller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/controller"
	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/lease"
	"github.com/artie-labs/natpair/internal/mocks"
)

func TestShouldDemote(t *testing.T) {
	assert.False(t, controller.ShouldDemote(health.Report{ConsecutiveFailures: 5}), "no peer can take over")
	assert.False(t, controller.ShouldDemote(health.Report{ConsecutiveFailures: 1, PeerCanTakeover: true}), "one failure is not corroborated")
	assert.True(t, controller.ShouldDemote(health.Report{ConsecutiveFailures: 2, PeerCanTakeover: true, PeerConfirmedFailure: true}))
	// A failure both NATs share, such as a receiver outage, is not the owner's,
	// even if the peer's last report still offered to take over.
	assert.False(t, controller.ShouldDemote(health.Report{ConsecutiveFailures: 5, PeerCanTakeover: true}), "the peer did not prove its path during the failure")
	assert.False(t, controller.ShouldDemote(health.Report{Stale: true, ConsecutiveFailures: 5, PeerCanTakeover: true}), "a stale monitor never demotes")
}

// fixture runs a controller against fakes and an in-memory lease store.
type fixture struct {
	controller *controller.Controller
	fence      *mocks.FakeFence
	health     *mocks.FakeHealth
	preparer   *mocks.FakePreparer
	store      *mocks.FakeLeaseStore
	stateDir   string

	mu     sync.Mutex
	report health.Report
	// verified records the verify argument of each takeover.
	verified  []bool
	stepDowns int
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{
		fence:    &mocks.FakeFence{},
		health:   &mocks.FakeHealth{},
		preparer: &mocks.FakePreparer{},
		store:    &mocks.FakeLeaseStore{},
		stateDir: t.TempDir(),
		report:   health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true},
	}
	var value []byte
	var storeMu sync.Mutex
	f.store.ReadCalls(func(context.Context) ([]byte, error) {
		storeMu.Lock()
		defer storeMu.Unlock()
		return bytes.Clone(value), nil
	})
	f.store.SwapCalls(func(_ context.Context, expected, replacement []byte) (bool, error) {
		storeMu.Lock()
		defer storeMu.Unlock()
		if !bytes.Equal(expected, value) {
			return false, nil
		}
		value = bytes.Clone(replacement)
		return true, nil
	})
	f.health.LatestCalls(func() health.Report {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.report
	})
	f.controller = controller.New(controller.Config{Node: "nat-a", StateDir: f.stateDir, PrepareTimeout: 5 * time.Second},
		controller.Dependencies{
			Fence:  f.fence,
			Health: f.health,
			Store:  f.store,
			NewHandoff: func(_ func() error, verify bool) controller.Preparer {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.verified = append(f.verified, verify)
				return f.preparer
			},
			StepDown: func(context.Context) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.stepDowns++
				return nil
			},
			Now: bootclock.Now,
		})
	return f
}

func (f *fixture) takeovers() []bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.verified)
}

func (f *fixture) stepDownCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stepDowns
}

func (f *fixture) setReport(report health.Report) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.report = report
}

// start runs the controller until the test ends.
func (f *fixture) start(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.controller.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

const waitFor = 3 * time.Second

// storeDown makes every lease store call fail until the returned function
// restores the store.
func (f *fixture) storeDown() func() {
	read, swap := f.store.ReadStub, f.store.SwapStub
	f.store.ReadCalls(func(context.Context) ([]byte, error) { return nil, errors.New("timeout") })
	f.store.SwapCalls(func(context.Context, []byte, []byte) (bool, error) { return false, errors.New("timeout") })
	return func() {
		f.store.ReadCalls(read)
		f.store.SwapCalls(swap)
	}
}

// released reports whether the stored lease record is marked released.
func (f *fixture) released(t *testing.T) bool {
	raw, err := f.store.Read(t.Context())
	require.NoError(t, err)
	var record lease.Record
	require.NoError(t, json.Unmarshal(raw, &record))
	return record.Released
}

func TestRun(t *testing.T) {
	{
		// Forwarding opens only after the takeover succeeds
		f := newFixture(t)
		release := make(chan struct{})
		f.preparer.PrepareCalls(func(context.Context) error {
			<-release
			return nil
		})
		f.start(t)
		require.Eventually(t, func() bool { return f.preparer.PrepareCallCount() == 1 }, waitFor, 10*time.Millisecond)
		time.Sleep(200 * time.Millisecond)
		assert.Zero(t, f.fence.ArmCallCount())
		assert.False(t, f.controller.Serving())
		assert.True(t, f.controller.Owner(), "the NAT owns the lease during its takeover")

		close(release)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		assert.Equal(t, []bool{true}, f.takeovers(), "a NAT with a proven path verifies the shared Elastic IP")
		deadline := f.fence.ArmArgsForCall(0)
		assert.Greater(t, deadline, bootclock.Now(), "the fence opens with a future deadline")
		// Renewals keep extending the deadline.
		require.Eventually(t, func() bool { return f.fence.ArmCallCount() >= 2 }, waitFor, 10*time.Millisecond)
	}
	{
		// A corroborated path failure ends ownership, closes forwarding, starts a cooldown, then releases the lease
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		closes := f.fence.CloseCallCount()
		var releaseSeen, closedBeforeRelease, cooledBeforeRelease atomic.Bool
		swap := f.store.SwapStub
		f.store.SwapCalls(func(ctx context.Context, expected, replacement []byte) (bool, error) {
			if bytes.Contains(replacement, []byte(`"released":true`)) && !releaseSeen.Swap(true) {
				closedBeforeRelease.Store(f.fence.CloseCallCount() > closes)
				cooledBeforeRelease.Store(f.controller.Inhibited())
			}
			return swap(ctx, expected, replacement)
		})
		f.setReport(health.Report{CanForward: true, ConsecutiveFailures: 2, PeerCanTakeover: true, PeerConfirmedFailure: true})
		require.Eventually(t, func() bool { return !f.controller.Serving() }, waitFor, 10*time.Millisecond)
		assert.True(t, f.released(t))
		assert.True(t, closedBeforeRelease.Load(), "forwarding closes before the release")
		assert.True(t, cooledBeforeRelease.Load(), "the cooldown starts before the release")
		assert.True(t, f.controller.Inhibited())

	}
	{
		// A failed takeover never opens forwarding, and cools down so the peer can take over
		f := newFixture(t)
		f.setReport(health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true, PeerCanTakeover: true})
		f.preparer.PrepareReturns(assert.AnError)
		f.start(t)
		require.Eventually(t, func() bool { return f.preparer.PrepareCallCount() == 1 }, waitFor, 10*time.Millisecond)
		require.Eventually(t, f.controller.Inhibited, waitFor, 10*time.Millisecond)
		assert.Zero(t, f.fence.ArmCallCount())
	}
	{
		// With no peer that can take over, a failed takeover is retried without a cooldown
		f := newFixture(t)
		f.preparer.PrepareReturns(assert.AnError)
		f.start(t)
		require.Eventually(t, func() bool { return f.preparer.PrepareCallCount() >= 2 }, waitFor, 10*time.Millisecond)
		assert.False(t, f.controller.Inhibited())
		assert.Zero(t, f.fence.ArmCallCount())
	}
	{
		// A path failure during takeover ends the session instead of opening forwarding
		f := newFixture(t)
		release := make(chan struct{})
		f.preparer.PrepareCalls(func(context.Context) error {
			<-release
			return nil
		})
		f.start(t)
		require.Eventually(t, func() bool { return f.preparer.PrepareCallCount() == 1 }, waitFor, 10*time.Millisecond)
		f.setReport(health.Report{CanForward: true, PathHealthy: false, PeerCanTakeover: true})
		close(release)
		require.Eventually(t, f.controller.Inhibited, waitFor, 10*time.Millisecond)
		assert.Zero(t, f.fence.ArmCallCount())
	}
	{
		// A takeover keeps going through failed renewals while its grant lasts
		f := newFixture(t)
		release := make(chan struct{})
		f.preparer.PrepareCalls(func(context.Context) error {
			<-release
			return nil
		})
		f.start(t)
		require.Eventually(t, func() bool { return f.preparer.PrepareCallCount() == 1 }, waitFor, 10*time.Millisecond)
		restore := f.storeDown()
		time.Sleep(200 * time.Millisecond)
		close(release)
		time.Sleep(100 * time.Millisecond)
		assert.False(t, f.controller.Serving(), "forwarding opens only with a fresh grant")
		restore()
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		assert.Equal(t, 1, f.preparer.PrepareCallCount())
	}
	{
		// An owner whose record the peer took during the outage closes once the store returns
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		read, swap := f.store.ReadStub, f.store.SwapStub
		restore := f.storeDown()
		time.Sleep(200 * time.Millisecond)
		current, err := read(t.Context())
		require.NoError(t, err)
		taken := bytes.Replace(current, []byte(`"owner":"nat-a/`), []byte(`"owner":"nat-b/`), 1)
		ok, err := swap(t.Context(), current, taken)
		require.True(t, ok)
		require.NoError(t, err)
		assert.True(t, f.controller.Serving(), "the owner cannot see the change yet")
		restore()
		require.Eventually(t, func() bool { return !f.controller.Serving() }, waitFor, 10*time.Millisecond)
		assert.False(t, f.controller.Inhibited())
	}
	{
		// Shutting down closes forwarding and releases the lease, so the peer need not wait
		f := newFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- f.controller.Run(ctx) }()
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		cancel()
		require.NoError(t, <-done)
		assert.False(t, f.controller.Serving())
		assert.True(t, f.released(t))
	}
	{
		// A NAT that cannot prove its path, for example because no receiver is
		// reachable, takes a free lease as a last resort. It waits a little
		// longer first, skips the final uploads, and opens forwarding unproven.
		f := newFixture(t)
		f.setReport(health.Report{CanForwardUnverified: true})
		started := time.Now()
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		assert.GreaterOrEqual(t, time.Since(started), controller.LastResortDelay(), "a NAT with a proven path gets a head start")
		assert.Equal(t, []bool{false}, f.takeovers())
	}
	{
		// A NAT that cannot forward never contends
		f := newFixture(t)
		f.setReport(health.Report{})
		f.start(t)
		time.Sleep(100 * time.Millisecond)
		assert.Zero(t, f.store.SwapCallCount())
		assert.Zero(t, f.preparer.PrepareCallCount())
		assert.Zero(t, f.stepDownCount(), "a NAT that never owned has nothing to clear")
	}
	{
		// Maintenance waits for a ready peer, then hands over and keeps this NAT
		// from contending again
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		require.NoError(t, controller.RequestMaintenance(f.stateDir))
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving(), "the peer is not ready yet")
		f.setReport(health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true, PeerReady: true})
		require.Eventually(t, func() bool { return !f.controller.Serving() }, waitFor, 10*time.Millisecond)
		assert.True(t, f.released(t))
		assert.True(t, f.controller.Inhibited())
		// The former owner clears the connection state it no longer serves.
		require.Eventually(t, func() bool { return f.stepDownCount() == 1 }, waitFor, 10*time.Millisecond)
		require.NoError(t, controller.Resume(f.stateDir))
		_, err := os.Stat(filepath.Join(f.stateDir, "maintenance"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
	{
		// A handover request waits for a ready peer and hands over like
		// maintenance, but leaves this NAT free to take over again
		logs := &syncBuffer{}
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
		defer slog.SetDefault(previous)
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		f.controller.SetHandover(true)
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving(), "the peer is not ready yet")
		stepDowns := f.stepDownCount()
		f.setReport(health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true, PeerReady: true})
		require.Eventually(t, func() bool { return f.stepDownCount() > stepDowns }, waitFor, 10*time.Millisecond)
		assert.False(t, f.controller.MaintenanceRequested())
		assert.Contains(t, logs.String(), `"reason":"handover requested"`)
		// With the request spent, this NAT is eligible again: it takes the
		// released lease back and keeps it while the peer stays ready.
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving())
		assert.False(t, f.controller.Inhibited())
	}
	{
		// A withdrawn handover request doesn't hand over once the peer is ready
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		f.controller.SetHandover(true)
		f.controller.SetHandover(false)
		f.setReport(health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true, PeerReady: true})
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving())
		assert.Zero(t, f.stepDownCount())
	}
	{
		// A handover request made before this NAT owns the lease, such as one
		// that lands just after the previous session ended, doesn't hand over
		// the next session
		f := newFixture(t)
		f.setReport(health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true, PeerReady: true})
		f.controller.SetHandover(true)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving())
		assert.Zero(t, f.stepDownCount())
	}
}

// syncBuffer collects log output from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestCongestedOwnerHandsOver(t *testing.T) {
	// congested is an owner whose uploads time out while some handshakes
	// complete, so it publishes no probe flows, and its peer can't show it
	// copied them.
	congested := health.Report{Ready: true, CanForward: true, CanTakeover: true, Congested: true}
	{
		// Maintenance on a congested owner hands over to a peer that can
		// take over, without waiting for the peer to verify its copies
		logs := &syncBuffer{}
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
		defer slog.SetDefault(previous)
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		report := congested
		report.PeerCanTakeover = true
		f.setReport(report)
		require.NoError(t, controller.RequestMaintenance(f.stateDir))
		require.Eventually(t, func() bool { return !f.controller.Serving() }, waitFor, 10*time.Millisecond)
		assert.True(t, f.released(t))
		assert.Contains(t, logs.String(), "connections the peer hasn't copied may reset")
	}
	{
		// A handover request, which only upgrades make, still waits for a
		// ready peer
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		report := congested
		report.PeerCanTakeover = true
		f.setReport(report)
		f.controller.SetHandover(true)
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving(), "the peer is not ready")
	}
	{
		// An owner that isn't congested still waits for a ready peer
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		f.setReport(health.Report{Ready: true, CanForward: true, CanTakeover: true, PathHealthy: true, PeerCanTakeover: true})
		require.NoError(t, controller.RequestMaintenance(f.stateDir))
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving(), "the peer is not ready")
	}
	{
		// A congested owner waits while its peer can't take over
		f := newFixture(t)
		f.start(t)
		require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
		f.setReport(congested)
		require.NoError(t, controller.RequestMaintenance(f.stateDir))
		time.Sleep(100 * time.Millisecond)
		assert.True(t, f.controller.Serving(), "the peer can't take over")
	}
}

func TestContendWarnings(t *testing.T) {
	// A contender that can't reach the lease store warns once, not on every attempt
	logs := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	f := newFixture(t)
	restore := f.storeDown()
	f.start(t)
	time.Sleep(200 * time.Millisecond)
	assert.Greater(t, f.store.ReadCallCount(), 2, "it kept trying")
	assert.Equal(t, 1, strings.Count(logs.String(), "failed to contend for ownership"))
	restore()
	require.Eventually(t, f.controller.Serving, waitFor, 10*time.Millisecond)
}

func TestMain(m *testing.M) {
	controller.UseFastTiming()
	os.Exit(m.Run())
}
