package conntrackd

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadCopied(t *testing.T) {
	tuple := func(dst string, port uint16) Tuple {
		return Tuple{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr(dst), SrcPort: port, DstPort: 443}
	}
	// Lines in the format of conntrackd 1.4.6's `-e` output.
	output := "tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=10 dport=443 src=10.0.0.2 dst=192.0.2.100 sport=443 dport=10 [ASSURED] mark=0 [active since 30s]\n" +
		"tcp      6 TIME_WAIT src=10.0.0.1 dst=10.0.0.3 sport=11 dport=443 src=10.0.0.3 dst=192.0.2.100 sport=443 dport=11 mark=0 [active since 2s]\n" +
		// Only the original direction counts: this entry's reply matches 10.0.0.4:12.
		"tcp      6 ESTABLISHED src=10.0.0.9 dst=10.0.0.8 sport=99 dport=443 src=10.0.0.1 dst=10.0.0.4 sport=12 dport=443 [ASSURED] mark=0 [active since 30s]\n" +
		"not an entry\n"
	found, err := readCopied(strings.NewReader(output), []Tuple{tuple("10.0.0.2", 10), tuple("10.0.0.3", 11), tuple("10.0.0.4", 12), tuple("10.0.0.2", 1)})
	require.NoError(t, err)
	assert.Equal(t, map[Tuple]bool{tuple("10.0.0.2", 10): true, tuple("10.0.0.3", 11): true}, found)

	// A line cut off mid-entry, as when a pass is stopped, is skipped. One
	// ending at its last field still counts.
	found, err = readCopied(strings.NewReader("tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0\n"+
		"tcp      6 ESTABLISHED src=10.0.0.1\n"+
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=10 dport=443"), []Tuple{tuple("10.0.0.2", 10)})
	require.NoError(t, err)
	assert.Equal(t, map[Tuple]bool{tuple("10.0.0.2", 10): true}, found)

	// A port that only starts with the wanted one doesn't match
	found, err = readCopied(strings.NewReader(output), []Tuple{tuple("10.0.0.2", 1)})
	require.NoError(t, err)
	assert.Empty(t, found)

	// Output that isn't conntrackd's fails rather than finding nothing
	_, err = readCopied(strings.NewReader(strings.Repeat("x", 100000)), []Tuple{tuple("10.0.0.2", 10)})
	assert.ErrorIs(t, err, bufio.ErrTooLong)
}

func TestReadOldest(t *testing.T) {
	// Lines in the format of conntrackd 1.4.6's `-i` output.
	output := "tcp      6 TIME_WAIT src=10.0.0.1 dst=10.0.0.3 sport=11 dport=443 [ASSURED] mark=0 [active since 5000s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=10 dport=443 [ASSURED] mark=0 [active since 1184s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.4 sport=12 dport=443 [ASSURED] mark=0 [active since 412s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.6 sport=14 dport=443 [ASSURED] mark=0 [active since 412s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.7 sport=15 dport=443 [ASSURED] mark=0 [active since 30s]\n" +
		"tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.5 sport=13 dport=443 [ASSURED] mark=0\n" +
		"not an entry\n"
	tuple := func(dst string, port uint16) Tuple {
		return Tuple{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr(dst), SrcPort: port, DstPort: 443}
	}
	oldest := func(count int) []Tuple {
		tuples, err := readOldest(strings.NewReader(output), count)
		require.NoError(t, err)
		return tuples
	}
	// Only established connections count, so the older TIME_WAIT entry,
	// which leaves the table soon, isn't among them. Of two entries the same
	// age, the first one read wins.
	assert.Equal(t, []Tuple{tuple("10.0.0.2", 10), tuple("10.0.0.4", 12)}, oldest(2))
	assert.Equal(t, []Tuple{tuple("10.0.0.2", 10), tuple("10.0.0.4", 12), tuple("10.0.0.6", 14)}, oldest(3))
	// Entries without an age are skipped, and a small table returns what it has.
	assert.Equal(t, []Tuple{tuple("10.0.0.2", 10), tuple("10.0.0.4", 12), tuple("10.0.0.6", 14), tuple("10.0.0.7", 15)}, oldest(16))
	assert.Empty(t, oldest(0))
	tuples, err := readOldest(strings.NewReader(""), 16)
	require.NoError(t, err)
	assert.Empty(t, tuples)
}

func TestParseStats(t *testing.T) {
	{
		// Real `conntrackd -s` output from conntrackd 1.4.7
		stats, ok := ParseStats("cache internal:\ncurrent active connections:\t           12\n" +
			"connections created:\t\t           40\tfailed:\t           0\n\n" +
			"cache external:\ncurrent active connections:\t            9\n" +
			"connections created:\t\t           31\tfailed:\t           0\n")
		assert.True(t, ok)
		assert.Equal(t, Stats{Tracked: 12, Copied: 9, CopiesAdded: 31}, stats)
	}
	{
		// Output without both caches is not trusted
		_, ok := ParseStats("cache internal:\ncurrent active connections: 12\nconnections created: 40\n")
		assert.False(t, ok)
	}
}

// syntheticCache returns conntrackd output for entries connections, in the
// format of `conntrackd -i` and `-e`.
func syntheticCache(entries int) []byte {
	var output bytes.Buffer
	for i := range entries {
		fmt.Fprintf(&output, "tcp      6 ESTABLISHED src=10.%d.%d.%d dst=198.51.100.%d sport=%d dport=443 "+
			"src=198.51.100.%d dst=10.0.1.100 sport=443 dport=%d [ASSURED] mark=0 [active since %ds]\n",
			i>>16&255, i>>8&255, i&255, i%200, 1024+i%60000, i%200, 1024+i%60000, i%100000)
	}
	return output.Bytes()
}

// The previous parser read the whole cache into a string and built a map or
// slice of every entry: on AWS, natpair's memory reached 600 MB from 512k
// connections. These read a million entries while keeping only what they
// look for, so their allocations don't grow with the input.

func BenchmarkReadOldest(b *testing.B) {
	cache := syntheticCache(1_000_000)
	for b.Loop() {
		oldest, err := readOldest(bytes.NewReader(cache), 16)
		require.NoError(b, err)
		require.Len(b, oldest, 16)
	}
}

func BenchmarkReadCopied(b *testing.B) {
	cache := syntheticCache(1_000_000)
	wanted := []Tuple{{Src: netip.MustParseAddr("10.0.0.7"), Dst: netip.MustParseAddr("198.51.100.7"), SrcPort: 1031, DstPort: 443}}
	for b.Loop() {
		found, err := readCopied(bytes.NewReader(cache), wanted)
		require.NoError(b, err)
		require.Len(b, found, 1)
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
		// One hash bucket per connection, as in the kernel's table.
		"HashSize 262144", "HashLimit 262144",
		// A full copy's updates stay queued for resending until the peer
		// acknowledges them, and its burst fits in the socket buffers: 64
		// bytes a connection, which the kernel doubles.
		"ResendQueueSize 262144",
		"SndSocketBuffer 16777216", "RcvSocketBuffer 16777216",
		"NetlinkBufferSize 16777216", "NetlinkBufferSizeMaxGrowth 33554432",
	} {
		assert.Contains(t, string(contents), line)
	}
	// The NAT's own connections are not copied: loopback, its address and the shared address.
	assert.Contains(t, string(contents), "Address Ignore {\n            IPv4_address 127.0.0.1\n            IPv6_address ::1\n            IPv4_address 10.0.1.10\n            IPv4_address 10.0.1.100\n        }")
	assert.NotContains(t, string(contents), "Backlog", "conntrackd 1.4.6 ignores it and logs a warning")

	// A small limit keeps conntrackd's default resend queue
	require.NoError(t, WriteConfig(path, netip.MustParseAddr("10.0.1.10"), netip.MustParseAddr("10.0.1.11"), netip.MustParseAddr("10.0.1.100"), "ens5", dir, 65536))
	contents, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(contents), "ResendQueueSize 131072")
	assert.Contains(t, string(contents), "HashLimit 65536")
}
