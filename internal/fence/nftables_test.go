package fence

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/bootclock"
)

func TestNFTablesClosedRuleset(t *testing.T) {
	{
		_, err := NewNFTables(nil)
		assert.EqualError(t, err, "protected worker CIDRs are required")
	}
	f, err := NewNFTables([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("10.0.16.0/20")})
	require.NoError(t, err)
	// The table is replaced as a whole with an empty grant set, and its chain
	// runs before the network package's forward chain at priority filter.
	assert.Equal(t, "table ip natpair_fence\ndelete table ip natpair_fence\ntable ip natpair_fence {\n"+
		"\tset protected {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 10.0.0.0/16, 10.0.16.0/20 }\n\t}\n"+
		"\tset grant {\n\t\ttypeof ip version\n\t\tflags timeout\n\t}\n"+
		"\tcounter dropped {\n\t}\n"+
		"\tchain forward {\n\t\ttype filter hook forward priority filter - 10; policy accept;\n"+
		"\t\tip saddr @protected counter name \"dropped\" drop\n"+
		"\t\tip daddr @protected counter name \"dropped\" drop\n\t}\n}\n", f.closedRuleset())
}

func TestNFTablesArmCommands(t *testing.T) {
	// 2026-11-16 10:00:00.700 UTC
	wall := time.Unix(1794823200, 700_000_000)
	{
		// The element times out after the grant's remaining time, and the
		// wall clock cap, in whole seconds, is rounded up: 10:00:04.200
		// becomes 10:00:05.
		assert.Equal(t, "flush set ip natpair_fence grant\n"+
			"add element ip natpair_fence grant { 4 timeout 3500ms }\n"+
			"flush chain ip natpair_fence forward\n"+
			"add rule ip natpair_fence forward ip version @grant meta time < 1794823205 accept\n"+
			"add rule ip natpair_fence forward ip saddr @protected counter name \"dropped\" drop\n"+
			"add rule ip natpair_fence forward ip daddr @protected counter name \"dropped\" drop\n", armCommands(3500*time.Millisecond, wall))
	}
	{
		// A grant that ends on a whole second keeps that second
		assert.Contains(t, armCommands(300*time.Millisecond, wall), "{ 4 timeout 300ms }")
		assert.Contains(t, armCommands(300*time.Millisecond, wall), "meta time < 1794823201 accept")
	}
	{
		assert.Contains(t, armCommands(301*time.Millisecond, wall), "meta time < 1794823202 accept")
	}
}

func TestNFTablesArmRejectsExpiredGrant(t *testing.T) {
	f, err := NewNFTables([]netip.Prefix{netip.MustParsePrefix("10.0.16.0/20")})
	require.NoError(t, err)
	// Both fail before running nft, so this needs no root.
	assert.EqualError(t, f.Arm(bootclock.Now()-time.Second), "an expired grant cannot open forwarding")
	// Less than a millisecond would be written as timeout 0ms, which
	// nftables takes as no timeout at all.
	assert.EqualError(t, f.Arm(bootclock.Now()+500*time.Microsecond), "an expired grant cannot open forwarding")
}
