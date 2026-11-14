//go:build linux && privileged

package napi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/command"
)

func run(t *testing.T, name string, args ...string) {
	_, err := command.Run(t.Context(), 2*time.Second, name, args...)
	require.NoError(t, err)
}

// TestSetThreaded writes a real kernel's threaded files. A veth has no
// device link, so Enable never picks one, but it has a receive queue while
// GRO is on, like an ENI that is up. Its peer, with GRO off, has none, like
// an ENI that isn't up yet.
func TestSetThreaded(t *testing.T) {
	run(t, "ip", "link", "add", "napi-test0", "type", "veth", "peer", "name", "napi-test1")
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", "napi-test0")
		assert.NoError(t, err)
	})
	run(t, "ip", "link", "set", "napi-test0", "up")
	run(t, "ip", "link", "set", "napi-test1", "up")
	run(t, "ethtool", "-K", "napi-test0", "gro", "on")
	assert.True(t, listed("napi-test0"))
	assert.False(t, listed("napi-test2"))

	{
		path := "/sys/class/net/napi-test0/threaded"
		switched, err := setThreaded(path)
		require.NoError(t, err)
		assert.True(t, switched)
		assert.Equal(t, "1\n", readThreaded(t, "/sys/class/net", "napi-test0"))

		switched, err = setThreaded(path)
		require.NoError(t, err)
		assert.False(t, switched)
	}
	{
		// The kernel refuses the write with EOPNOTSUPP, which is skipped
		path := "/sys/class/net/napi-test1/threaded"
		switched, err := setThreaded(path)
		require.NoError(t, err)
		assert.False(t, switched)
		assert.Equal(t, "0\n", readThreaded(t, "/sys/class/net", "napi-test1"))
	}
}
