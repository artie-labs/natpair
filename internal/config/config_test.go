package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	assert.EqualError(t, edit(func(c *NAT) { c.Pacing = &Pacing{Enabled: true, StartMbps: -1} }), "pacing start_mbps and start_kpps must not be negative")
	assert.EqualError(t, edit(func(c *NAT) { c.Pacing = &Pacing{Enabled: true, PollIntervalMS: -1} }), "pacing poll_interval_ms must be from 1 to 60000")
	assert.EqualError(t, edit(func(c *NAT) { c.Pacing = &Pacing{Enabled: true, PollIntervalMS: 60001} }), "pacing poll_interval_ms must be from 1 to 60000")
	assert.NoError(t, edit(func(c *NAT) { c.Pacing = &Pacing{Enabled: true, StartMbps: 4750, PollIntervalMS: 1} }))
}

func TestPacing(t *testing.T) {
	{
		// Configurations without the setting load with pacing off
		var unset *Pacing
		assert.False(t, unset.On())
		assert.Equal(t, 10*time.Millisecond, unset.Poll())
	}
	assert.False(t, (&Pacing{}).On())
	assert.True(t, (&Pacing{Enabled: true}).On())
	assert.Equal(t, 2500*time.Millisecond, (&Pacing{PollIntervalMS: 2500}).Poll())
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
	{
		// Unset uses the default, so configurations without the setting still load
		assert.Equal(t, 262144, NAT{}.ConnectionLimit())
	}
	{
		assert.Equal(t, 524288, NAT{MaxConnections: 524288}.ConnectionLimit())
	}
}
