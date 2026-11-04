package lease_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/lease"
	"github.com/artie-labs/natpair/internal/mocks"
)

// memoryStore returns a fake store that keeps one value in memory and applies
// the same compare-and-swap rule as DynamoDB.
func memoryStore() *mocks.FakeLeaseStore {
	var value []byte
	store := &mocks.FakeLeaseStore{}
	store.ReadCalls(func(context.Context) ([]byte, error) {
		return bytes.Clone(value), nil
	})
	store.SwapCalls(func(_ context.Context, expected, replacement []byte) (bool, error) {
		if !bytes.Equal(expected, value) {
			return false, nil
		}
		value = bytes.Clone(replacement)
		return true, nil
	})
	return store
}

type fakeClock struct {
	now time.Duration
}

func (c *fakeClock) Now() time.Duration {
	return c.now
}

func newLease(t *testing.T, store lease.Store, owner string, clock *fakeClock) *lease.Lease {
	return lease.New(store, owner, clock.Now)
}

func TestAcquire(t *testing.T) {
	{
		// A contender waits the entire takeover interval, then the old owner can no longer renew
		clock, store := &fakeClock{now: 100 * time.Second}, memoryStore()
		a := newLease(t, store, "a", clock)
		b := newLease(t, store, "b", clock)

		grant, err := a.Acquire(t.Context())
		require.NoError(t, err)
		require.NotNil(t, grant)
		assert.Equal(t, int64(1), grant.Record.Epoch)
		assert.Equal(t, 104*time.Second, grant.Deadline)

		grant, err = b.Acquire(t.Context())
		require.NoError(t, err)
		assert.Nil(t, grant)
		clock.now += 5990 * time.Millisecond
		grant, err = b.Acquire(t.Context())
		require.NoError(t, err)
		assert.Nil(t, grant)
		clock.now += 20 * time.Millisecond
		grant, err = b.Acquire(t.Context())
		require.NoError(t, err)
		require.NotNil(t, grant)
		assert.Equal(t, int64(2), grant.Record.Epoch)
		assert.Equal(t, "b", grant.Record.Owner)

		_, err = a.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
	{
		// The deadline counts from when the request started, so a slow reply never gets a fresh deadline
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		swap := store.SwapStub
		store.SwapCalls(func(ctx context.Context, expected, replacement []byte) (bool, error) {
			clock.now += 4100 * time.Millisecond
			return swap(ctx, expected, replacement)
		})
		_, err := newLease(t, store, "a", clock).Acquire(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
	{
		// Both NATs must use the same protocol and timing
		clock, store := &fakeClock{}, memoryStore()
		_, err := store.Swap(t.Context(), nil, []byte(`{"protocol":3,"hold_ms":2000,"takeover_ms":5000,"owner":"a","revision":"r","epoch":1}`))
		require.NoError(t, err)
		_, err = newLease(t, store, "b", clock).Acquire(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
	{
		// A contender that could not read the record waits the full interval again once it can
		clock, store := &fakeClock{}, memoryStore()
		down, applied := false, false
		unreachable(store, &down, &applied)
		_, err := newLease(t, store, "a", clock).Acquire(t.Context())
		require.NoError(t, err)
		b := newLease(t, store, "b", clock)
		grant, err := b.Acquire(t.Context())
		require.NoError(t, err)
		require.Nil(t, grant)
		down = true
		clock.now += time.Minute
		_, err = b.Acquire(t.Context())
		require.Error(t, err)
		down = false
		grant, err = b.Acquire(t.Context())
		require.NoError(t, err)
		assert.Nil(t, grant, "the record was unchanged, but b could not see it the whole time")
		clock.now += 6 * time.Second
		grant, err = b.Acquire(t.Context())
		require.NoError(t, err)
		assert.NotNil(t, grant)
	}
	{
		// A contender that loses the write race keeps waiting
		clock, store := &fakeClock{}, memoryStore()
		store.SwapReturns(false, nil)
		grant, err := newLease(t, store, "a", clock).Acquire(t.Context())
		require.NoError(t, err)
		assert.Nil(t, grant)
	}
}

func TestRenew(t *testing.T) {
	{
		// Each renewal starts a new deadline from the request start
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		l := newLease(t, store, "a", clock)
		_, err := l.Acquire(t.Context())
		require.NoError(t, err)
		clock.now += 500 * time.Millisecond
		grant, err := l.Renew(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 5500*time.Millisecond, grant.Deadline)
		assert.Equal(t, int64(1), grant.Record.Epoch)
	}
	{
		// A slow renewal cannot revive an expired grant, and the Lease stays lost
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		l := newLease(t, store, "a", clock)
		_, err := l.Acquire(t.Context())
		require.NoError(t, err)
		swap := store.SwapStub
		store.SwapCalls(func(ctx context.Context, expected, replacement []byte) (bool, error) {
			clock.now += 4100 * time.Millisecond
			return swap(ctx, expected, replacement)
		})
		_, err = l.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
		_, err = l.Acquire(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
}

// unreachable makes the store's calls fail while down is true. With applied,
// writes still land, as when only the reply is lost.
func unreachable(store *mocks.FakeLeaseStore, down, applied *bool) {
	read, swap := store.ReadStub, store.SwapStub
	store.ReadCalls(func(ctx context.Context) ([]byte, error) {
		if *down {
			return nil, assert.AnError
		}
		return read(ctx)
	})
	store.SwapCalls(func(ctx context.Context, expected, replacement []byte) (bool, error) {
		if *down {
			if *applied {
				_, _ = swap(ctx, expected, replacement)
			}
			return false, assert.AnError
		}
		return swap(ctx, expected, replacement)
	})
}

func TestRenewWhileStoreUnavailable(t *testing.T) {
	{
		// The Lease survives an outage longer than its grant and continues once the store returns
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		down, applied := false, false
		unreachable(store, &down, &applied)
		l := newLease(t, store, "a", clock)
		_, err := l.Acquire(t.Context())
		require.NoError(t, err)
		down = true
		_, err = l.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrUnavailable)
		clock.now += time.Minute
		_, err = l.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrUnavailable, "reads fail too")
		down = false
		grant, err := l.Renew(t.Context())
		require.NoError(t, err)
		assert.Equal(t, clock.now+lease.Hold, grant.Deadline)
		_, err = l.Renew(t.Context())
		require.NoError(t, err, "renewals continue normally")
	}
	{
		// A renewal whose reply was lost after it landed continues from the stored record
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		down, applied := false, true
		unreachable(store, &down, &applied)
		l := newLease(t, store, "a", clock)
		_, err := l.Acquire(t.Context())
		require.NoError(t, err)
		down = true
		_, err = l.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrUnavailable)
		down = false
		_, err = l.Renew(t.Context())
		require.NoError(t, err)
	}
	{
		// A contender that took the record during the outage wins
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		down, applied := false, false
		unreachable(store, &down, &applied)
		a := newLease(t, store, "a", clock)
		b := newLease(t, store, "b", clock)
		_, err := a.Acquire(t.Context())
		require.NoError(t, err)
		down = true
		_, err = a.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrUnavailable)
		down = false
		_, err = b.Acquire(t.Context())
		require.NoError(t, err)
		clock.now += 6 * time.Second
		grant, err := b.Acquire(t.Context())
		require.NoError(t, err)
		require.NotNil(t, grant)
		_, err = a.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
	{
		// An abandoned Lease stays lost after an outage
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		down, applied := false, false
		unreachable(store, &down, &applied)
		l := newLease(t, store, "a", clock)
		_, err := l.Acquire(t.Context())
		require.NoError(t, err)
		down = true
		_, err = l.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrUnavailable)
		l.Abandon()
		down = false
		_, err = l.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
}

func TestValid(t *testing.T) {
	// Expiry follows the boot clock only
	clock, store := &fakeClock{now: 10 * time.Second}, memoryStore()
	l := newLease(t, store, "a", clock)
	_, err := l.Acquire(t.Context())
	require.NoError(t, err)
	_, err = l.Valid()
	require.NoError(t, err)
	clock.now = 14 * time.Second
	_, err = l.Valid()
	assert.ErrorIs(t, err, lease.ErrLost)
	assert.NotNil(t, l.Current())
}

func TestAbandon(t *testing.T) {
	clock, store := &fakeClock{now: time.Second}, memoryStore()
	l := newLease(t, store, "a", clock)
	_, err := l.Acquire(t.Context())
	require.NoError(t, err)
	l.Abandon()
	_, err = l.Valid()
	assert.ErrorIs(t, err, lease.ErrLost)
	_, err = l.Renew(t.Context())
	assert.ErrorIs(t, err, lease.ErrLost)
}

func TestRelease(t *testing.T) {
	{
		// A contender takes a released record at once, and the releaser stays lost
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		a := newLease(t, store, "a", clock)
		b := newLease(t, store, "b", clock)
		_, err := a.Acquire(t.Context())
		require.NoError(t, err)
		require.NoError(t, a.Release(t.Context()))

		grant, err := b.Acquire(t.Context())
		require.NoError(t, err)
		require.NotNil(t, grant)
		assert.Equal(t, "b", grant.Record.Owner)
		assert.Equal(t, int64(2), grant.Record.Epoch)
		assert.False(t, grant.Record.Released)
		_, err = a.Renew(t.Context())
		assert.ErrorIs(t, err, lease.ErrLost)
	}
	{
		// A record that changed since this Lease wrote it stays as it is, so the next contender waits the full interval
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		a := newLease(t, store, "a", clock)
		b := newLease(t, store, "b", clock)
		_, err := a.Acquire(t.Context())
		require.NoError(t, err)
		_, err = b.Acquire(t.Context())
		require.NoError(t, err)
		clock.now += 6 * time.Second
		_, err = b.Acquire(t.Context())
		require.NoError(t, err)

		require.NoError(t, a.Release(t.Context()))
		_, err = b.Renew(t.Context())
		require.NoError(t, err, "the new owner's record was not released")
	}
	{
		// A Lease that never acquired the record writes nothing
		store := memoryStore()
		require.NoError(t, newLease(t, store, "a", &fakeClock{}).Release(t.Context()))
		assert.Zero(t, store.SwapCallCount())
	}
	{
		// A failed write is reported
		clock, store := &fakeClock{now: time.Second}, memoryStore()
		a := newLease(t, store, "a", clock)
		_, err := a.Acquire(t.Context())
		require.NoError(t, err)
		store.SwapReturns(false, assert.AnError)
		assert.ErrorIs(t, a.Release(t.Context()), assert.AnError)
	}
}
