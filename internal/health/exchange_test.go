package health_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/health"
)

// memoryBoard keeps the board in memory, like the shared DynamoDB item.
type memoryBoard map[string][]byte

func (b memoryBoard) Post(_ context.Context, name string, value []byte) error {
	b[name] = value
	return nil
}

func (b memoryBoard) Remove(_ context.Context, name string) error {
	delete(b, name)
	return nil
}

func (b memoryBoard) Read(context.Context) (map[string][]byte, error) {
	values := map[string][]byte{}
	for name, value := range b {
		values[name] = value
	}
	return values, nil
}

func TestExchange(t *testing.T) {
	clock := &fakeClock{now: 100 * time.Second}
	board := memoryBoard{}
	a := health.NewNATExchange(board, "i-a", clock.Now)
	b := health.NewNATExchange(board, "i-b", clock.Now)
	read := func() *health.Report {
		peer, err := a.Read(t.Context())
		require.NoError(t, err)
		return peer
	}

	// A report from before this reader started could be left behind by a
	// dead writer, so it only counts once its counter changes.
	require.NoError(t, b.Publish(t.Context(), health.Report{Ready: true}, health.ServingInterval))
	assert.Nil(t, read())

	require.NoError(t, b.Publish(t.Context(), health.Report{Ready: true}, health.ServingInterval))
	peer := read()
	require.NotNil(t, peer)
	assert.True(t, peer.Ready)

	// A NAT never reads its own report as the peer's
	require.NoError(t, a.Publish(t.Context(), health.Report{CanForward: true}, health.ServingInterval))
	peer = read()
	assert.True(t, peer.Ready)
	assert.False(t, peer.CanForward)

	// A writer that stops posting goes stale after StaleAfter of its interval, on
	// the reader's clock
	clock.now += health.StaleAfter(health.ServingInterval) + time.Millisecond
	assert.Nil(t, read())

	// A report unchanged for forgetAfter is deleted
	clock.now += time.Hour
	read()
	assert.NotContains(t, board, "nat:i-b")
	assert.Contains(t, board, "nat:i-a", "a NAT never deletes its own report")

	// An unreadable report is ignored
	board["nat:i-c"] = []byte("not json")
	assert.Nil(t, read())
}
