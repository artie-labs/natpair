//go:build linux && privileged

package fence

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/command"
)

func TestFence(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, unix.Mount("bpf", dir, "bpf", 0, ""))
	t.Cleanup(func() { assert.NoError(t, unix.Unmount(dir, 0)) })

	f, err := New(dir, []netip.Prefix{netip.MustParsePrefix("10.94.1.0/24")})
	require.NoError(t, err)
	// Restarts reinstall the fence. Guard jumps must not stack up.
	for range 3 {
		require.NoError(t, f.Install(t.Context()))
	}
	rules, err := command.Run(t.Context(), 2*time.Second, "iptables", "-S", "FORWARD")
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(rules, "-j "+chain), rules)
	assert.Contains(t, rules, "-P FORWARD DROP")

	program, err := ebpf.LoadPinnedProgram(f.programPath, nil)
	require.NoError(t, err)
	defer program.Close()
	matches := func() bool {
		result, err := program.Run(&ebpf.RunOptions{Data: make([]byte, 64)})
		require.NoError(t, err)
		return result == 1
	}

	assert.False(t, matches(), "a fresh install must start closed")
	require.NoError(t, f.Arm(bootclock.Now()+2*time.Second))
	assert.True(t, matches())
	{
		// A delayed write of an old absolute deadline cannot reopen forwarding
		require.NoError(t, f.writeDeadline(uint64(bootclock.Now()-time.Second)))
		assert.False(t, matches())
	}
	assert.ErrorContains(t, f.Arm(bootclock.Now()-time.Second), "an expired grant cannot open forwarding")
	{
		// The guard closes by itself once the deadline passes
		require.NoError(t, f.Arm(bootclock.Now()+200*time.Millisecond))
		assert.True(t, matches())
		time.Sleep(300 * time.Millisecond)
		assert.False(t, matches())
	}
	require.NoError(t, f.Arm(bootclock.Now()+2*time.Second))
	require.NoError(t, f.Close())
	assert.False(t, matches())
}
