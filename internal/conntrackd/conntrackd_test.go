package conntrackd

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedTuples(t *testing.T) {
	tuples := CachedTuples("tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=10 dport=443 src=10.0.0.2 dst=192.0.2.100 sport=443 dport=10 [ASSURED]\n" +
		"tcp      6 TIME_WAIT src=10.0.0.1 dst=10.0.0.3 sport=11 dport=443 src=10.0.0.3 dst=192.0.2.100 sport=443 dport=11\n" +
		"not an entry\n")
	// Only the original direction of each entry is recorded.
	assert.Equal(t, map[Tuple]bool{
		{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), SrcPort: 10, DstPort: 443}: true,
		{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.3"), SrcPort: 11, DstPort: 443}: true,
	}, tuples)
}

func TestOldestTuples(t *testing.T) {
	// Lines in the format of conntrackd 1.4.6's `-i` and `-e` output.
	output := "tcp      6 TIME_WAIT src=10.0.0.1 dst=10.0.0.3 sport=11 dport=443 [ASSURED] mark=0 [active since 30s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=10 dport=443 [ASSURED] mark=0 [active since 1184s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.4 sport=12 dport=443 [ASSURED] mark=0 [active since 412s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.5 sport=13 dport=443 [ASSURED] mark=0\n" +
		"not an entry\n"
	tuple := func(dst string, port uint16) Tuple {
		return Tuple{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr(dst), SrcPort: port, DstPort: 443}
	}
	assert.Equal(t, []Tuple{tuple("10.0.0.2", 10), tuple("10.0.0.4", 12)}, OldestTuples(output, 2))
	// Entries without an age are skipped, and a small table returns what it has.
	assert.Equal(t, []Tuple{tuple("10.0.0.2", 10), tuple("10.0.0.4", 12), tuple("10.0.0.3", 11)}, OldestTuples(output, 16))
	assert.Empty(t, OldestTuples("", 16))
}

func TestCacheSizes(t *testing.T) {
	{
		// Real `conntrackd -s` output from conntrackd 1.4.7
		tracked, copied, ok := CacheSizes("cache internal:\ncurrent active connections:\t           12\n" +
			"connections created:\t\t           40\tfailed:\t           0\n\n" +
			"cache external:\ncurrent active connections:\t            9\n" +
			"connections created:\t\t           31\tfailed:\t           0\n")
		assert.True(t, ok)
		assert.Equal(t, 12, tracked)
		assert.Equal(t, 9, copied)
	}
	{
		// Output without both caches is not trusted
		_, _, ok := CacheSizes("cache internal:\ncurrent active connections: 12\n")
		assert.False(t, ok)
	}
}

func TestWriteConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conntrackd.conf")
	require.NoError(t, WriteConfig(path, netip.MustParseAddr("10.0.1.10"), netip.MustParseAddr("10.0.1.11"), netip.MustParseAddr("10.0.1.100"), "ens5", dir, 262144))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, line := range []string{
		"StartupResync on", "IPv4_address 10.0.1.10", "IPv4_Destination_Address 10.0.1.11", "Interface ens5",
		"LockFile " + dir + "/conntrackd.lock", "Path " + dir + "/conntrackd.ctl",
		// The same limit sizes the kernel's connection table.
		"HashSize 65536", "HashLimit 262144",
	} {
		assert.Contains(t, string(contents), line)
	}
	// The NAT's own connections are not copied: loopback, its address and the shared address.
	assert.Contains(t, string(contents), "Address Ignore {\n            IPv4_address 127.0.0.1\n            IPv6_address ::1\n            IPv4_address 10.0.1.10\n            IPv4_address 10.0.1.100\n        }")
	assert.NotContains(t, string(contents), "Backlog", "conntrackd 1.4.6 ignores it and logs a warning")
}
