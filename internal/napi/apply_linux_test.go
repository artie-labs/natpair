//go:build linux && privileged

package napi

import (
	"context"
	"os"
	"strconv"
	"strings"
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

// TestThreadedReceive turns on threaded NAPI for a veth, which has receive
// queues while GRO is on, and raises its receive thread as if the veth were
// the primary interface. The kernel's threads are only visible from the
// host's PID namespace, so in a container only the first half runs. Run the
// whole test in a VM: build it with
// `GOOS=linux go test -c -tags privileged ./internal/napi` and run the binary
// as root.
func TestThreadedReceive(t *testing.T) {
	run(t, "ip", "link", "add", "napi-test0", "type", "veth", "peer", "name", "napi-test1")
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", "napi-test0")
		assert.NoError(t, err)
	})
	run(t, "ip", "link", "set", "napi-test0", "up")
	run(t, "ip", "link", "set", "napi-test1", "up")
	run(t, "ethtool", "-K", "napi-test0", "gro", "on")

	path := "/sys/class/net/napi-test0/threaded"
	{
		// Already off.
		switched, err := setThreaded(path, false)
		require.NoError(t, err)
		assert.False(t, switched)
	}
	{
		switched, err := setThreaded(path, true)
		require.NoError(t, err)
		assert.True(t, switched)
		assertFile(t, path, "1\n")
	}
	{
		// Already on.
		switched, err := setThreaded(path, true)
		require.NoError(t, err)
		assert.False(t, switched)
	}

	threads := receiveThreads(t, "napi-test0")
	if len(threads) == 0 {
		t.Skip("the kernel's receive threads aren't visible in this PID namespace")
	}
	for _, thread := range threads {
		assert.Equal(t, 0, thread.nice)
	}
	{
		raised, err := raise("napi-test0")
		require.NoError(t, err)
		assert.Equal(t, len(threads), raised)
		for _, thread := range receiveThreads(t, "napi-test0") {
			assert.Equal(t, -10, thread.nice)
		}
	}
	{
		// Already raised.
		raised, err := raise("napi-test0")
		require.NoError(t, err)
		assert.Equal(t, 0, raised)
	}
	{
		// The switch for benchmarks turns it back off.
		switched, err := setThreaded(path, false)
		require.NoError(t, err)
		assert.True(t, switched)
		assertFile(t, path, "0\n")
	}
}

func assertFile(t *testing.T, path, want string) {
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, string(contents))
}

// receiveThreads returns the kernel threads named for the interface.
func receiveThreads(t *testing.T, name string) []task {
	entries, err := os.ReadDir("/proc")
	require.NoError(t, err)
	var threads []task
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		contents, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		parsed, err := parseStat(string(contents))
		require.NoError(t, err)
		if parsed.kernel && strings.HasPrefix(parsed.name, "napi/"+name+"-") {
			threads = append(threads, parsed)
		}
	}
	return threads
}
