//go:build linux && privileged

package pacing

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
)

// veth creates a veth pair with the given number of queues and removes it
// when the test ends.
func veth(t *testing.T, name, peer string, queues int) {
	q := strconv.Itoa(queues)
	_, err := command.Run(t.Context(), 2*time.Second, "ip", "link", "add", name, "numtxqueues", q, "type", "veth", "peer", "name", peer, "numtxqueues", q)
	require.NoError(t, err)
	// The test's context ends before its cleanups run.
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		_, err := command.Run(ctx, 2*time.Second, "ip", "link", "del", name)
		assert.NoError(t, err)
	})
}

func tc(t *testing.T, args ...string) string {
	output, err := command.Run(t.Context(), 2*time.Second, "tc", args...)
	require.NoError(t, err, "tc %v", args)
	return output
}

func TestReadStats(t *testing.T) {
	veth(t, "pst0", "pst1", 1)
	peer, err := net.InterfaceByName("pst1")
	require.NoError(t, err)
	{
		// veth reports its peer's index among its driver statistics
		values, found, err := readStats("pst0", []string{"peer_ifindex"})
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, []uint64{uint64(peer.Index)}, values)
	}
	{
		// Only ENA interfaces have the allowance counters
		_, found, err := (&kernel{}).allowances("pst0")
		require.NoError(t, err)
		assert.False(t, found)
	}
	{
		_, _, err := readStats("missing0", []string{"peer_ifindex"})
		assert.ErrorIs(t, err, unix.ENODEV)
	}
}

func TestAttachAndRemove(t *testing.T) {
	veth(t, "pfq0", "pfq1", 1)
	if output, err := command.Run(t.Context(), 2*time.Second, "tc", "qdisc", "replace", "dev", "pfq0", "root", "fq"); err != nil {
		t.Skipf("this kernel lacks sch_fq, which pacing needs: %v %s", err, output)
	}
	tc(t, "qdisc", "del", "dev", "pfq0", "root")
	veth(t, "pmq0", "pmq1", 2)

	dir := t.TempDir()
	require.NoError(t, unix.Mount("bpf", dir, "bpf", 0, ""))
	t.Cleanup(func() { assert.NoError(t, unix.Unmount(dir, 0)) })
	k := newKernel(filepath.Join(dir, "pacing"), testProtected)
	require.NoError(t, k.load())
	// Daemon restarts load and attach again.
	for range 2 {
		require.NoError(t, k.attach(t.Context(), "pfq0"))
		require.NoError(t, k.attach(t.Context(), "pmq0"))
		require.NoError(t, k.load())
	}
	require.NoError(t, k.attach(t.Context(), "pmq0"))

	qdiscs, err := parseTC[struct {
		Kind   string `json:"kind"`
		Handle string `json:"handle"`
		Parent string `json:"parent"`
	}](tc(t, "-j", "qdisc", "show", "dev", "pmq0"))
	require.NoError(t, err)
	kinds := map[string]string{}
	for _, q := range qdiscs {
		kinds[q.Handle+"@"+q.Parent] = q.Kind
	}
	assert.Equal(t, "mq", kinds["7a01:@"])
	assert.Contains(t, tc(t, "qdisc", "show", "dev", "pmq0"), "parent 7a01:2 limit 100000p flow_limit 10000p")
	assert.Contains(t, tc(t, "qdisc", "show", "dev", "pfq0"), "qdisc fq 7a01: root")
	assert.Contains(t, tc(t, "filter", "show", "dev", "pmq0", "egress"), "natpair_pace")
	assert.Contains(t, tc(t, "filter", "show", "dev", "pmq0", "ingress"), "natpair_mark")

	// Another tool's filter on the same clsact qdisc.
	tc(t, "filter", "add", "dev", "pfq0", "egress", "protocol", "all", "pref", "9", "matchall", "action", "pass")
	require.NoError(t, k.remove(t.Context()))
	assert.NotContains(t, tc(t, "qdisc", "show", "dev", "pmq0"), "7a01:")
	assert.NotContains(t, tc(t, "qdisc", "show", "dev", "pmq0"), "clsact")
	assert.NotContains(t, tc(t, "qdisc", "show", "dev", "pfq0"), "7a01:")
	assert.Contains(t, tc(t, "qdisc", "show", "dev", "pfq0"), "clsact")
	assert.Empty(t, tc(t, "filter", "show", "dev", "pfq0", "ingress"))
	assert.Contains(t, tc(t, "filter", "show", "dev", "pfq0", "egress"), "matchall")
	_, err = os.Stat(k.dir)
	assert.ErrorIs(t, err, os.ErrNotExist)
	{
		// Removing again, as a daemon with pacing off does at every start,
		// does nothing
		require.NoError(t, k.remove(t.Context()))
	}
}
