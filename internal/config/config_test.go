package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/probe"
)

func TestLoadNAT(t *testing.T) {
	cfg, err := LoadNAT("testdata/nat.json")
	require.NoError(t, err)
	assert.Equal(t, "example/v3/ownership", cfg.LeaseRecordID("ownership"))

	// OwnProbe expects the public IP read from the instance metadata service.
	cfg.Instance = instance.Facts{PublicIP: netip.MustParseAddr("192.0.2.10")}
	assert.Equal(t, probe.Target{URL: "https://probe.example.invalid/nat", ExpectedIP: netip.MustParseAddr("192.0.2.10"), Namespace: "natpair-own", Source: netip.MustParseAddr("198.18.0.2")}, cfg.OwnProbe())
	assert.Equal(t, probe.Target{URL: "https://probe.example.invalid/nat", ExpectedIP: netip.MustParseAddr("192.0.2.100"), Namespace: "natpair-shared", Source: netip.MustParseAddr("198.18.0.6")}, cfg.SharedProbe())
	assert.Equal(t, netip.MustParseAddr("198.18.0.5"), cfg.SharedCanary().Host())
}

func TestLoadNATRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nat.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"pair":"example","probe_commands":[]}`), 0o600))
	_, err := LoadNAT(path)
	assert.ErrorContains(t, err, `unknown field "probe_commands"`)
}

func TestValidate(t *testing.T) {
	valid, err := LoadNAT("testdata/nat.json")
	require.NoError(t, err)
	edit := func(change func(*NAT)) error {
		contents, err := json.Marshal(valid)
		require.NoError(t, err)
		var cfg NAT
		require.NoError(t, json.Unmarshal(contents, &cfg))
		change(&cfg)
		return cfg.Validate()
	}
	assert.ErrorContains(t, edit(func(c *NAT) { c.Pair = "" }), "pair is required")
	assert.ErrorContains(t, edit(func(c *NAT) { c.SharedAddress = netip.MustParsePrefix("10.0.1.100/32") }), "shared_address must be an IPv4 address with its subnet prefix length")
	assert.ErrorContains(t, edit(func(c *NAT) { c.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.16.1/20")} }), "must be an IPv4 network address")
	assert.ErrorContains(t, edit(func(c *NAT) { c.ProbeURL = "" }), "must be an HTTPS URL")
	assert.ErrorContains(t, edit(func(c *NAT) { c.ProbeURL = "http://probe.example.invalid/nat" }), "must be an HTTPS URL")
	assert.ErrorContains(t, edit(func(c *NAT) { c.SharedPublicIP = netip.Addr{} }), "shared_public_ip must be an IPv4 address")
	assert.ErrorContains(t, edit(func(c *NAT) { c.PeerIP = netip.Addr{} }), "peer_ip must be an IPv4 address")
	assert.ErrorContains(t, edit(func(c *NAT) { c.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")} }), "overlaps the canary subnets")
	assert.EqualError(t, edit(func(c *NAT) { c.MaxConnections = 300000 }), "max_connections must be one of [65536 131072 262144 524288 1048576 2097152 4194304]")
	assert.NoError(t, edit(func(c *NAT) { c.MaxConnections = 524288 }))
	assert.EqualError(t, edit(func(c *NAT) { c.ReleaseURL = "http://example.com/releases" }), "release_url must start with https:// or s3://")
	assert.NoError(t, edit(func(c *NAT) { c.ReleaseURL = "s3://example-mirror/natpair" }))
}

func TestReleases(t *testing.T) {
	{
		// Unset uses natpair's GitHub releases
		assert.Equal(t, "https://github.com/artie-labs/natpair/releases/download", NAT{}.Releases())
	}
	{
		// A trailing slash is dropped, so URLs join with exactly one
		assert.Equal(t, "s3://example-mirror/natpair", NAT{ReleaseURL: "s3://example-mirror/natpair/"}.Releases())
	}
}

func TestConnectionLimit(t *testing.T) {
	// limit returns the limit for a NAT with memory bytes and no max_connections.
	limit := func(memory uint64) int {
		return NAT{Instance: instance.Facts{MemoryBytes: memory}}.ConnectionLimit()
	}
	{
		// MemTotal on 2, 4 and 8 GiB instances, less what the kernel keeps
		assert.Equal(t, 262144, limit(1903976*1024))
		assert.Equal(t, 524288, limit(3898756*1024))
		assert.Equal(t, 1048576, limit(7906060*1024))
		// and exactly 2, 4 and 8 GiB
		assert.Equal(t, 262144, limit(2<<30))
		assert.Equal(t, 524288, limit(4<<30))
		assert.Equal(t, 1048576, limit(8<<30))
	}
	{
		// A limit is chosen when its peak, 2,600 bytes a connection, fits in
		// half the memory exactly, and not one byte short
		assert.Equal(t, 262144, limit(2*262144*2600))
		assert.Equal(t, 131072, limit(2*262144*2600-1))
	}
	{
		// The limit stays within the values max_connections accepts
		assert.Equal(t, 65536, limit(256<<20))
		assert.Equal(t, 4194304, limit(1<<40))
	}
	{
		// Without a memory reading, the limit is v0.1.1's default, not 0 or
		// the largest
		assert.Equal(t, 262144, NAT{}.ConnectionLimit())
	}
	{
		// An explicit max_connections wins over memory
		assert.Equal(t, 1048576, NAT{MaxConnections: 1048576, Instance: instance.Facts{MemoryBytes: 2 << 30}}.ConnectionLimit())
		assert.Equal(t, 65536, NAT{MaxConnections: 65536, Instance: instance.Facts{MemoryBytes: 8 << 30}}.ConnectionLimit())
	}
}
