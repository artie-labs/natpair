package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

const (
	natPrefix = "nat:"
	// forgetAfter is how long a writer's report may stay unchanged before it is
	// deleted, for example after its instance was replaced.
	forgetAfter = time.Hour
)

// Board stores each writer's latest report in one shared place, such as a
// DynamoDB item. IAM decides who may write, so reports need no signing.
type Board interface {
	Post(ctx context.Context, name string, value []byte) error
	Remove(ctx context.Context, name string) error
	Read(ctx context.Context) (map[string][]byte, error)
}

// posted wraps a report with a counter that changes on every post. Readers
// judge freshness by when the counter last changed on their own clock, because
// boot clocks on different hosts cannot be compared.
type posted[T any] struct {
	Seq        uint64 `json:"seq"`
	IntervalMS int64  `json:"interval_ms"`
	Report     T      `json:"report"`
}

// sighting is when a reader last saw a writer's counter change.
type sighting struct {
	seq     uint64
	changed time.Duration
	// moved is false until the counter changes once after the reader starts,
	// so a report left behind by a dead writer never looks fresh.
	moved bool
}

// Exchange posts this NAT's reports and reads its peer's.
type Exchange struct {
	board Board
	name  string
	now   func() time.Duration
	seq   uint64
	seen  map[string]sighting
}

// NewNATExchange returns the exchange for the NAT with the given instance ID.
func NewNATExchange(board Board, instanceID string, now func() time.Duration) *Exchange {
	return &Exchange{board: board, name: natPrefix + instanceID, now: now, seen: map[string]sighting{}}
}

// Publish posts report, which is refreshed every interval.
func (e *Exchange) Publish(ctx context.Context, report any, interval time.Duration) error {
	e.seq++
	value, err := json.Marshal(posted[any]{Seq: e.seq, IntervalMS: interval.Milliseconds(), Report: report})
	if err != nil {
		return fmt.Errorf("failed to encode report: %w", err)
	}
	return e.board.Post(ctx, e.name, value)
}

// Read returns the peer NAT's report, or nil if no other NAT posts fresh
// reports.
func (e *Exchange) Read(ctx context.Context) (*Report, error) {
	values, err := e.board.Read(ctx)
	if err != nil {
		return nil, err
	}
	now := e.now()
	var peer *Report
	for name, value := range values {
		if name == e.name {
			continue
		}
		var meta posted[json.RawMessage]
		if err := json.Unmarshal(value, &meta); err != nil {
			slog.Warn("ignoring an unreadable report", slog.String("writer", name), slog.Any("err", err))
			continue
		}
		last, known := e.seen[name]
		if !known || meta.Seq != last.seq {
			last = sighting{seq: meta.Seq, changed: now, moved: known}
			e.seen[name] = last
		}
		if now-last.changed > forgetAfter {
			e.forget(ctx, name)
			continue
		}
		if !last.moved || now-last.changed > StaleAfter(time.Duration(meta.IntervalMS)*time.Millisecond) {
			continue
		}
		if strings.HasPrefix(name, natPrefix) {
			var report Report
			if err := json.Unmarshal(meta.Report, &report); err == nil {
				peer = &report
			}
		}
	}
	return peer, nil
}

func (e *Exchange) forget(ctx context.Context, name string) {
	if err := e.board.Remove(ctx, name); err != nil {
		slog.Warn("failed to delete an old report", slog.String("writer", name), slog.Any("err", err))
		return
	}
	delete(e.seen, name)
}
