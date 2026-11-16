//go:build linux && privileged

package fence

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/netns"
)

// TestNFTablesFence forwards a worker's connections, from nf-worker, through
// a NAT, nf-nat, whose only rules are the fence's, to a host in nf-out.
func TestNFTablesFence(t *testing.T) {
	run := func(args ...string) string {
		output, err := command.Run(t.Context(), 2*time.Second, args[0], args[1:]...)
		require.NoError(t, err)
		return output
	}
	ctx := context.WithoutCancel(t.Context())
	for _, namespace := range []string{"nf-worker", "nf-nat", "nf-out"} {
		run("ip", "netns", "add", namespace)
		t.Cleanup(func() {
			_, err := command.Run(ctx, 2*time.Second, "ip", "netns", "del", namespace)
			assert.NoError(t, err)
		})
	}
	run("ip", "link", "add", "lan", "netns", "nf-nat", "type", "veth", "peer", "name", "lan", "netns", "nf-worker")
	run("ip", "link", "add", "wan", "netns", "nf-nat", "type", "veth", "peer", "name", "wan", "netns", "nf-out")
	for _, step := range [][]string{
		{"nf-nat", "addr", "add", "10.94.12.1/24", "dev", "lan"},
		{"nf-nat", "addr", "add", "10.94.13.1/24", "dev", "wan"},
		{"nf-worker", "addr", "add", "10.94.12.2/24", "dev", "lan"},
		{"nf-out", "addr", "add", "10.94.13.2/24", "dev", "wan"},
		{"nf-nat", "link", "set", "lan", "up"},
		{"nf-nat", "link", "set", "wan", "up"},
		{"nf-worker", "link", "set", "lan", "up"},
		{"nf-out", "link", "set", "wan", "up"},
		{"nf-worker", "route", "add", "default", "via", "10.94.12.1"},
		{"nf-out", "route", "add", "default", "via", "10.94.13.1"},
	} {
		run(append([]string{"ip", "-n"}, step...)...)
	}
	run("ip", "netns", "exec", "nf-nat", "sysctl", "-qw", "net.ipv4.ip_forward=1")
	var listener net.Listener
	require.NoError(t, netns.Do("nf-out", func() error {
		var err error
		listener, err = net.Listen("tcp4", "10.94.13.2:8080")
		return err
	}))
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	// forwards reports whether a new worker connection gets through.
	forwards := func() bool {
		err := netns.Do("nf-worker", func() error {
			conn, err := net.DialTimeout("tcp4", "10.94.13.2:8080", 300*time.Millisecond)
			if err != nil {
				return err
			}
			return conn.Close()
		})
		return err == nil
	}
	inNAT := func(fn func() error) {
		t.Helper()
		require.NoError(t, netns.Do("nf-nat", fn))
	}

	// The VPC CIDR and one of its subnets overlap, as protected CIDRs may.
	f, err := NewNFTables([]netip.Prefix{netip.MustParsePrefix("10.94.12.0/24"), netip.MustParsePrefix("10.94.12.0/25")})
	require.NoError(t, err)
	// Restarts reinstall the fence. Its rules must not stack up.
	var listings []string
	for range 3 {
		inNAT(func() error { return f.Install(t.Context()) })
		listings = append(listings, run("ip", "netns", "exec", "nf-nat", "nft", "list", "table", "ip", nftTable))
	}
	assert.Equal(t, listings[0], listings[2])
	assert.Equal(t, 2, strings.Count(listings[2], " drop\n"), listings[2])
	assert.False(t, forwards(), "a fresh install must start closed")

	inNAT(func() error { return f.Arm(bootclock.Now() + 2*time.Second) })
	assert.True(t, forwards())
	{
		// The element's timeout alone closes it, with nothing of natpair's
		// running: the wall clock cap here is an hour away
		deadline := bootclock.Now() + time.Second
		inNAT(func() error {
			return runNFT(t.Context(), armCommands("ip", "forward", closedRules, time.Second, time.Now().Add(time.Hour)))
		})
		assert.True(t, forwards())
		time.Sleep(deadline - bootclock.Now() + 100*time.Millisecond)
		assert.False(t, forwards())
	}
	{
		// A grant from Arm closes at its deadline
		deadline := bootclock.Now() + time.Second
		inNAT(func() error { return f.Arm(deadline) })
		assert.True(t, forwards())
		time.Sleep(deadline - bootclock.Now() + 100*time.Millisecond)
		assert.False(t, forwards())
	}
	{
		// A write delayed past the grant's end can't reopen forwarding: the
		// element below has 10 s left, but the wall clock cap was written as
		// if Arm had run 11 s ago
		inNAT(func() error {
			return runNFT(t.Context(), armCommands("ip", "forward", closedRules, 10*time.Second, time.Now().Add(-11*time.Second)))
		})
		assert.Contains(t, run("ip", "netns", "exec", "nf-nat", "nft", "list", "set", "ip", nftTable, "grant"), "elements = { 4 timeout 10s")
		assert.False(t, forwards())
	}
	{
		// Arming after an expired grant fails without opening anything
		assert.EqualError(t, f.Arm(bootclock.Now()-time.Second), "an expired grant cannot open forwarding")
		assert.False(t, forwards())
	}
	inNAT(func() error { return f.Arm(bootclock.Now() + 2*time.Second) })
	require.True(t, forwards())
	inNAT(f.Close)
	assert.False(t, forwards())
	{
		// A reinstall closes an open fence
		inNAT(func() error { return f.Arm(bootclock.Now() + 2*time.Second) })
		require.True(t, forwards())
		inNAT(func() error { return f.Install(t.Context()) })
		assert.False(t, forwards())
	}
	{
		// Traffic outside the protected CIDRs is not the fence's to stop
		run("ip", "-n", "nf-nat", "addr", "add", "10.94.14.1/24", "dev", "lan")
		run("ip", "-n", "nf-worker", "addr", "add", "10.94.14.2/24", "dev", "lan")
		err := netns.Do("nf-worker", func() error {
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.94.14.2")}, Timeout: 300 * time.Millisecond}
			conn, err := dialer.Dial("tcp4", "10.94.13.2:8080")
			if err != nil {
				return err
			}
			return conn.Close()
		})
		assert.NoError(t, err)
	}
	// Removing the table leaves nothing behind.
	run("ip", "netns", "exec", "nf-nat", "nft", "delete", "table", "ip", nftTable)
	assert.Empty(t, run("ip", "netns", "exec", "nf-nat", "nft", "list", "ruleset"))
}
