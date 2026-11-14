//go:build linux && privileged

package guard

import (
	"context"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
)

func ip(t *testing.T, args ...string) string {
	output, err := command.Run(t.Context(), 5*time.Second, "ip", args...)
	require.NoError(t, err)
	return output
}

func attached(t *testing.T) bool {
	return regexp.MustCompile(`prog/xdp id \d+`).MatchString(ip(t, "-d", "link", "show", "guard-shared"))
}

// pings sends count pings from the peer namespace to the shared address and
// returns how many were answered.
func pings(t *testing.T, count int) int {
	// ping exits with an error when replies are missing, so its output is
	// read whatever the exit status.
	output, _ := exec.CommandContext(t.Context(), "ip", "netns", "exec", "guard-peer", "ping", "-c", strconv.Itoa(count), "-i", "0.01", "-W", "1", "10.99.0.1").CombinedOutput()
	match := regexp.MustCompile(`(\d+) received`).FindSubmatch(output)
	require.NotNil(t, match, output)
	received, err := strconv.Atoi(string(match[1]))
	require.NoError(t, err)
	return received
}

// TestGuard attaches the guard to a veth that holds the shared address, as
// the shared ENI does on an owner, and sends it pings from a namespace.
func TestGuard(t *testing.T) {
	ip(t, "netns", "add", "guard-peer")
	ip(t, "link", "add", "guard-shared", "type", "veth", "peer", "name", "guard-peer0")
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		ctx := context.WithoutCancel(t.Context())
		_, err := command.Run(ctx, 5*time.Second, "ip", "link", "del", "guard-shared")
		assert.NoError(t, err)
		_, err = command.Run(ctx, 5*time.Second, "ip", "netns", "del", "guard-peer")
		assert.NoError(t, err)
	})
	ip(t, "link", "set", "guard-peer0", "netns", "guard-peer")
	ip(t, "-n", "guard-peer", "addr", "add", "10.99.0.2/24", "dev", "guard-peer0")
	ip(t, "-n", "guard-peer", "link", "set", "guard-peer0", "up")
	ip(t, "link", "set", "guard-shared", "up")

	off := filepath.Join(t.TempDir(), "overload-guard-off")
	g := New(Config{SharedAddress: netip.MustParseAddr("10.99.0.1"), PrimaryInterface: "guard-primary", ReceiverPort: 443, FirstProbePort: 61000, LastProbePort: 65535, OffPath: off})
	// An 18-minute budget window, so the pings below all fall in one
	g.match.tickShift, g.match.exemptShift = 40, 44
	t.Cleanup(func() { g.close(context.WithoutCancel(t.Context())) })

	// No interface holds the shared address yet, as on a standby
	require.NoError(t, g.ensure(t.Context()))
	assert.Empty(t, g.name)

	ip(t, "addr", "add", "10.99.0.1/24", "dev", "guard-shared")
	require.NoError(t, g.ensure(t.Context()))
	assert.Equal(t, "guard-shared", g.name)
	// Watching attaches nothing: ENA's receive path costs more with any
	// program attached
	assert.False(t, attached(t))

	// Engaging attaches it with a budget, here 1 per CPU in an 18-minute
	// window, so at most one ping per CPU passes. ARP isn't IPv4, so the
	// neighbor lookups still work.
	_, err := g.attach(t.Context(), 1)
	require.NoError(t, err)
	assert.True(t, attached(t))
	ip(t, "-n", "guard-peer", "neigh", "flush", "all")
	assert.LessOrEqual(t, pings(t, 20), runtime.NumCPU())
	require.NoError(t, g.prog.setBudget(math.MaxUint64))
	assert.Equal(t, 5, pings(t, 5), "measuring passes everything")
	{
		// While limiting, the shared interface's threaded NAPI receive
		// threads run at nice -10, and go back to 0 after
		require.NoError(t, os.WriteFile("/sys/class/net/guard-shared/threaded", []byte("1"), 0o644))
		pids, err := receiveThreads("/proc", "guard-shared")
		require.NoError(t, err)
		require.NotEmpty(t, pids)
		require.NoError(t, g.prioritize(receiveNice))
		for _, pid := range pids {
			nice, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
			require.NoError(t, err)
			// The raw value is 20 - nice
			assert.Equal(t, 30, nice)
		}
		require.NoError(t, g.prioritize(0))
		for _, pid := range pids {
			nice, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
			require.NoError(t, err)
			assert.Equal(t, 20, nice)
		}
	}
	require.NoError(t, g.detach(t.Context()))
	assert.False(t, attached(t))
	assert.Equal(t, 5, pings(t, 5))
	{
		// The off switch stops the watching and detaches the program, and
		// removing it starts watching again
		_, err := g.attach(t.Context(), 1)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(off, nil, 0o600))
		require.NoError(t, g.ensure(t.Context()))
		assert.False(t, attached(t))
		assert.Empty(t, g.name)
		require.NoError(t, os.Remove(off))
		require.NoError(t, g.ensure(t.Context()))
		assert.Equal(t, "guard-shared", g.name)
	}
	{
		// It never watches the primary interface, even if that holds the
		// shared address
		g.cfg.PrimaryInterface = "guard-shared"
		assert.EqualError(t, g.ensure(t.Context()), "the primary interface guard-shared holds the shared address 10.99.0.1, so the overload guard stays off it")
		assert.Empty(t, g.name)
		g.cfg.PrimaryInterface = "guard-primary"
		require.NoError(t, g.ensure(t.Context()))
	}
	{
		// The shared ENI goes away while the program is on it, as on a
		// handover: the next reading stops watching
		_, err := g.attach(t.Context(), 1)
		require.NoError(t, err)
		ip(t, "link", "del", "guard-shared")
		require.NoError(t, g.step(t.Context()))
		assert.Nil(t, g.attached)
		assert.Empty(t, g.name)
		// A new one comes back with the shared address
		ip(t, "link", "add", "guard-shared", "type", "veth", "peer", "name", "guard-peer0")
		ip(t, "link", "set", "guard-peer0", "netns", "guard-peer")
		ip(t, "addr", "add", "10.99.0.1/24", "dev", "guard-shared")
		ip(t, "link", "set", "guard-shared", "up")
		require.NoError(t, g.ensure(t.Context()))
		assert.Equal(t, "guard-shared", g.name)
	}
	{
		// A handover takes the shared address away
		_, err := g.attach(t.Context(), 1)
		require.NoError(t, err)
		ip(t, "addr", "del", "10.99.0.1/24", "dev", "guard-shared")
		require.NoError(t, g.ensure(t.Context()))
		assert.False(t, attached(t))
		assert.Empty(t, g.name)
	}
}
