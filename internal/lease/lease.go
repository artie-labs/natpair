// Package lease gives one NAT exclusive, renewable permission to forward.
//
// The holder renews with a compare-and-swap write, which only succeeds if the
// record has not changed since the holder last wrote it. A renewal allows
// forwarding until Hold after the renewal request started, so a slow reply
// never extends permission. For example, with a 4 s Hold, a renewal sent at
// 10.0 s allows forwarding until 14.0 s, even if the reply arrives at 10.4 s.
//
// A NAT trying to take over (a contender) must see the same record unchanged
// for takeover before it may replace it. Because Hold is shorter than
// takeover, the old holder's permission has always expired, by its own boot
// clock, before a new holder gets it. The gap between them covers small
// differences in clock speed between hosts.
//
// A holder that has stopped forwarding can [Lease.Release] the record. A
// contender takes a released record at once, without the takeover wait,
// because the old holder already stopped before writing it.
//
// When the store can't be reached, a renewal fails with [ErrUnavailable]
// instead of losing the Lease. The record may or may not hold the failed
// write, so the next renewal reads it first and continues only if it still
// names this Lease's owner. A contender that took the record in the meantime
// wrote its own owner, so this Lease is then lost. The holder decides whether
// to keep forwarding while the store is unreachable.
//
// Each [Lease] is single-use. Once it loses ownership it stays lost. To try
// again, the caller creates a new Lease with a new owner ID.
package lease

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// protocolVersion changes whenever the record format or timing rules change.
// Both NATs in a pair must run the same version.
const protocolVersion = 3

// requestTimeout bounds each store request. It is no longer than the
// controller's renewInterval, so a stuck request is abandoned in time for the
// next renewal.
const requestTimeout = 500 * time.Millisecond

var (
	// ErrLost means this Lease no longer holds the record and can never get
	// it back.
	ErrLost = errors.New("lease lost")
	// ErrUnavailable means a renewal could not reach the store. The Lease is
	// not lost: the next [Lease.Renew] checks whether it still holds the
	// record.
	ErrUnavailable = errors.New("lease store unavailable")
)

// Store reads and conditionally replaces the lease record.
type Store interface {
	Read(ctx context.Context) ([]byte, error)
	Swap(ctx context.Context, expected, replacement []byte) (bool, error)
}

// takeover is longer than Hold to leave room for clock drift between hosts.
const (
	Hold     = 4 * time.Second
	takeover = 6 * time.Second
)

// Record is the JSON stored for the lease.
type Record struct {
	Protocol       int    `json:"protocol"`
	HoldMillis     int64  `json:"hold_ms"`
	TakeoverMillis int64  `json:"takeover_ms"`
	Owner          string `json:"owner"`
	Revision       string `json:"revision"`
	Epoch          int64  `json:"epoch"`
	// Released means the owner stopped forwarding and handed the record over.
	Released bool `json:"released,omitempty"`
}

// Grant is permission to forward until Deadline, measured on the boot clock.
type Grant struct {
	Record   Record
	Deadline time.Duration
	raw      []byte
}

// Lease is one attempt to hold the shared lease record. Acquire and Renew must
// be called from a single goroutine. Valid and Current may be called from any
// goroutine.
type Lease struct {
	store Store
	owner string
	now   func() time.Duration

	// observed and observedAt track the record a contender is waiting on.
	observed   []byte
	observedAt time.Duration

	mu    sync.Mutex
	grant *Grant
	lost  bool
	// unavailable means the last renewal could not reach the store, so the
	// record may hold either its old or its attempted value.
	unavailable bool
}

// New returns a Lease for owner. now must return the time since boot.
func New(store Store, owner string, now func() time.Duration) *Lease {
	return &Lease{store: store, owner: owner, now: now}
}

// Acquire takes the lease if it is free, released, or its record has stayed
// unchanged for the takeover interval. It returns nil without an error while
// waiting.
func (l *Lease) Acquire(ctx context.Context) (*Grant, error) {
	if l.isLost() {
		return nil, fmt.Errorf("%w: this Lease is lost, so the caller must create a new one", ErrLost)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	raw, err := l.store.Read(ctx)
	if err != nil {
		// A contender that can't read the record can't tell whether the owner
		// is still renewing, so it waits the full takeover interval again
		// once it can. Otherwise, after an outage that both NATs saw, it
		// would take the record at its first read, racing the owner's
		// first renewal.
		l.observed = nil
		return nil, err
	}
	now := l.now()
	var epoch int64
	if raw != nil {
		var current Record
		if err := json.Unmarshal(raw, &current); err != nil {
			return nil, fmt.Errorf("failed to decode lease record: %w", err)
		}
		if current.Protocol != protocolVersion || current.HoldMillis != Hold.Milliseconds() || current.TakeoverMillis != takeover.Milliseconds() {
			return nil, fmt.Errorf("%w: the other NAT uses a different lease protocol or timing", ErrLost)
		}
		if !current.Released {
			if !bytes.Equal(raw, l.observed) {
				l.observed, l.observedAt = raw, now
				return nil, nil
			}
			if now-l.observedAt < takeover {
				return nil, nil
			}
		}
		epoch = current.Epoch
	}

	replacement := Record{
		Protocol:       protocolVersion,
		HoldMillis:     Hold.Milliseconds(),
		TakeoverMillis: takeover.Milliseconds(),
		Owner:          l.owner,
		Revision:       rand.Text(),
		Epoch:          epoch + 1,
	}
	encoded, err := json.Marshal(replacement)
	if err != nil {
		return nil, fmt.Errorf("failed to encode lease record: %w", err)
	}
	started := l.now()
	ok, err := l.store.Swap(ctx, raw, encoded)
	if err != nil {
		return nil, err
	}
	if !ok {
		l.observed = nil
		return nil, nil
	}
	return l.accept(replacement, encoded, started)
}

// Renew extends the current grant. If the store can't be reached, it returns
// [ErrUnavailable] and the next call checks whether this Lease still holds the
// record, even after the grant expired. Any other failure ends this Lease.
func (l *Lease) Renew(ctx context.Context) (*Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	expected, record, err := l.renewable(ctx)
	if err != nil {
		return nil, err
	}
	record.Revision = rand.Text()
	encoded, err := json.Marshal(record)
	if err != nil {
		l.markLost()
		return nil, fmt.Errorf("failed to encode lease record: %w", err)
	}
	started := l.now()
	ok, err := l.store.Swap(ctx, expected, encoded)
	if err != nil {
		l.setUnavailable(true)
		return nil, fmt.Errorf("%w: renewal failed: %w", ErrUnavailable, err)
	}
	if !ok {
		l.markLost()
		return nil, fmt.Errorf("%w: ownership changed during renewal", ErrLost)
	}
	l.setUnavailable(false)
	return l.accept(record, encoded, started)
}

// renewable returns the stored value a renewal must replace, and its record.
// After the store was unavailable, it reads the record and requires that it
// still names this Lease's owner.
func (l *Lease) renewable(ctx context.Context) ([]byte, Record, error) {
	l.mu.Lock()
	unavailable, lost := l.unavailable, l.lost
	l.mu.Unlock()
	if !unavailable {
		grant, err := l.Valid()
		if err != nil {
			return nil, Record{}, err
		}
		return grant.raw, grant.Record, nil
	}
	if lost {
		return nil, Record{}, fmt.Errorf("%w: this Lease was abandoned", ErrLost)
	}
	raw, err := l.store.Read(ctx)
	if err != nil {
		return nil, Record{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	var current Record
	if raw != nil {
		if err := json.Unmarshal(raw, &current); err != nil {
			l.markLost()
			return nil, Record{}, fmt.Errorf("failed to decode lease record: %w", err)
		}
	}
	if current.Owner != l.owner || current.Released {
		l.markLost()
		return nil, Record{}, fmt.Errorf("%w: another owner took the lease while the store was unavailable", ErrLost)
	}
	return raw, current, nil
}

// Valid returns the current grant if it has not expired. Once it expires, this
// Lease is lost.
func (l *Lease) Valid() (*Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lost || l.grant == nil || l.now() >= l.grant.Deadline {
		l.lost = true
		return nil, fmt.Errorf("%w: forwarding permission expired", ErrLost)
	}
	return l.grant, nil
}

// Current returns the latest grant without checking expiry, or nil if this
// Lease never acquired the record.
func (l *Lease) Current() *Grant {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.grant
}

// Abandon ends this Lease locally without touching the stored record.
// Code still holding the lease, such as a running takeover, then fails its
// next [Lease.Valid] check. The next owner still waits the full takeover
// interval unless the record is released.
func (l *Lease) Abandon() {
	l.markLost()
}

// Release ends this Lease and marks its record as released, so a contender
// can take it at once. Call it only after this NAT has stopped forwarding:
// the next owner starts forwarding without waiting for this Lease's deadline.
//
// Release does nothing if this Lease never acquired the record, and writes
// nothing if the record changed since this Lease last wrote it. Then the next
// owner waits the full takeover interval, as it would without a release.
func (l *Lease) Release(ctx context.Context) error {
	l.markLost()
	grant := l.Current()
	if grant == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	replacement := grant.Record
	replacement.Revision = rand.Text()
	replacement.Released = true
	encoded, err := json.Marshal(replacement)
	if err != nil {
		return fmt.Errorf("failed to encode lease record: %w", err)
	}
	if _, err := l.store.Swap(ctx, grant.raw, encoded); err != nil {
		return fmt.Errorf("failed to release the lease: %w", err)
	}
	return nil
}

func (l *Lease) accept(record Record, raw []byte, started time.Duration) (*Grant, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	deadline := started + Hold
	if l.now() >= deadline {
		l.lost = true
		return nil, fmt.Errorf("%w: the store replied after the forwarding deadline", ErrLost)
	}
	l.grant = &Grant{Record: record, Deadline: deadline, raw: raw}
	return l.grant, nil
}

func (l *Lease) isLost() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lost
}

func (l *Lease) setUnavailable(unavailable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.unavailable = unavailable
}

func (l *Lease) markLost() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lost = true
}
