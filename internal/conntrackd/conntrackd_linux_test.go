//go:build linux && privileged

package conntrackd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/command"
)

// replica is one NAT's conntrackd in its own network namespace.
type replica struct {
	ns     string
	dir    string
	client Client
}

// TestHandover runs two real conntrackd replicas with natpair's
// configuration. Each namespace translates connections to 203.0.113.9:443 to
// the shared address and port 40000, as the NATs' SNAT rules do, and sends
// them out through a dummy interface.
func TestHandover(t *testing.T) {
	shared := netip.MustParseAddr("10.99.1.100")
	a := startReplica(t, "a", netip.MustParseAddr("10.99.0.1"), netip.MustParseAddr("10.99.0.2"), shared)
	b := startReplica(t, "b", netip.MustParseAddr("10.99.0.2"), netip.MustParseAddr("10.99.0.1"), shared)
	run(t, "ip", "link", "add", a.ns+"-s", "type", "veth", "peer", "name", b.ns+"-s")
	for _, r := range []replica{a, b} {
		run(t, "ip", "link", "set", r.ns+"-s", "netns", r.ns)
	}
	nsRun(t, a.ns, "ip", "addr", "add", "10.99.0.1/24", "dev", a.ns+"-s")
	nsRun(t, b.ns, "ip", "addr", "add", "10.99.0.2/24", "dev", b.ns+"-s")
	for _, r := range []replica{a, b} {
		nsRun(t, r.ns, "ip", "link", "set", r.ns+"-s", "up")
		r.start(t)
	}

	{
		// Translated worker connections are copied. The NAT's own connections are not.
		connect(t, a.ns, "10.0.16.5", 1000)
		connect(t, a.ns, "10.99.0.1", 3000)
		require.Eventually(t, func() bool { return strings.Contains(b.copies(t), "sport=1000 ") }, 5*time.Second, 100*time.Millisecond)
		assert.NotContains(t, b.copies(t), "sport=3000 ")
		// A lists the connection among its oldest, which needs conntrackd's ages.
		internal, err := a.client.InternalCache(t.Context())
		require.NoError(t, err)
		worker := Tuple{Src: netip.MustParseAddr("10.0.16.5"), Dst: netip.MustParseAddr("203.0.113.9"), SrcPort: 1000, DstPort: 443}
		assert.Contains(t, OldestTuples(internal, 16), worker)
	}
	{
		// After B takes over, A holds copies of the connections B committed without asking for them.
		assert.NotContains(t, a.copies(t), "sport=1000 ")
		require.NoError(t, b.client.TakeOver(t.Context()))
		assert.Contains(t, nsRun(t, b.ns, "conntrack", "-L", "-p", "tcp"), "dst=10.99.1.100 sport=443 dport=40000")
		require.Eventually(t, func() bool { return strings.Contains(a.copies(t), "sport=1000 ") }, 5*time.Second, 100*time.Millisecond)
	}
	{
		// A, the former owner, flushes its old entries, so they can't clash with a
		// connection B later translates to the same shared port.
		require.NoError(t, a.client.StepDown(t.Context()))
		nsRun(t, b.ns, "conntrack", "-D", "-p", "tcp", "--orig-port-src", "1000")
		connect(t, b.ns, "10.0.16.6", 2000)
		require.Eventually(t, func() bool { return strings.Contains(a.copies(t), "sport=2000 ") }, 5*time.Second, 100*time.Millisecond)
		// B asks for A's whole table, which still holds A's old entry.
		require.NoError(t, b.client.RequestResync(t.Context()))
		require.Eventually(t, func() bool { return strings.Contains(b.copies(t), "sport=1000 ") }, 5*time.Second, 100*time.Millisecond)
		// conntrackd flushes 60 s after stepping down.
		require.Eventually(t, func() bool {
			return !strings.Contains(nsRun(t, a.ns, "conntrack", "-L", "-p", "tcp"), "sport=1000 ")
		}, 70*time.Second, time.Second)
		require.NoError(t, a.client.TakeOver(t.Context()))
		assert.Contains(t, nsRun(t, a.ns, "conntrack", "-L", "-p", "tcp"), "sport=2000 ")
		log, err := os.ReadFile(filepath.Join(a.dir, "conntrackd.log"))
		require.NoError(t, err)
		assert.NotContains(t, string(log), "commit-create")
		// A's flush didn't remove B's copy of the old entry.
		assert.Contains(t, b.copies(t), "sport=1000 ")
	}
	{
		// B, now the former owner, replaces its copies with A's table, so a later
		// takeover can't commit the old entry as a dead connection.
		require.NoError(t, b.client.StepDown(t.Context()))
		require.Eventually(t, func() bool { return strings.Contains(b.copies(t), "sport=2000 ") }, 5*time.Second, 100*time.Millisecond)
		assert.NotContains(t, b.copies(t), "sport=1000 ")
	}
	{
		// A flush scheduled when A's daemon stopped, as fence-close does, is
		// cancelled when A takes over again before it runs, so A keeps the
		// connections it serves.
		nsRun(t, a.ns, "conntrack", "-D", "-p", "tcp", "--orig-port-src", "2000")
		connect(t, a.ns, "10.0.16.6", 4000)
		require.NoError(t, a.client.ScheduleFlush(t.Context()))
		require.NoError(t, a.client.TakeOver(t.Context()))
		time.Sleep(65 * time.Second)
		assert.Contains(t, nsRun(t, a.ns, "conntrack", "-L", "-p", "tcp"), "sport=4000 ")
	}
	{
		// B serves, and the connection on port 4000 ends there, but A's own
		// entry for it stays. B gives a new connection the same shared port.
		// Before A takes over again, it drops its out-of-date worker entries, as
		// the takeover does when the shared ENI is on the other NAT. Otherwise
		// the copy of the new connection can't install over the old entry.
		require.NoError(t, b.client.TakeOver(t.Context()))
		nsRun(t, b.ns, "conntrack", "-D", "-p", "tcp", "--orig-port-src", "4000")
		connect(t, b.ns, "10.0.16.5", 5000)
		require.Eventually(t, func() bool { return strings.Contains(a.copies(t), "sport=5000 ") }, 5*time.Second, 100*time.Millisecond)
		assert.Contains(t, nsRun(t, a.ns, "conntrack", "-L", "-p", "tcp"), "sport=4000 ")
		nsRun(t, a.ns, "conntrack", "-D", "-s", "10.0.16.0/24")
		require.NoError(t, a.client.TakeOver(t.Context()))
		assert.Contains(t, nsRun(t, a.ns, "conntrack", "-L", "-p", "tcp"), "sport=5000 ")
	}
}

// startReplica creates a namespace with a dummy route and SNAT rule, and
// writes its conntrackd configuration.
func startReplica(t *testing.T, name string, local, peer, shared netip.Addr) replica {
	r := replica{ns: fmt.Sprintf("ctd-%s-%d", name, os.Getpid()), dir: t.TempDir()}
	r.client = Client{ConfigPath: filepath.Join(r.dir, "conntrackd.conf")}
	run(t, "ip", "netns", "add", r.ns)
	t.Cleanup(func() {
		_, _ = command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "netns", "delete", r.ns)
	})
	nsRun(t, r.ns, "ip", "link", "set", "lo", "up")
	nsRun(t, r.ns, "ip", "link", "add", "d0", "type", "dummy")
	nsRun(t, r.ns, "ip", "link", "set", "d0", "up")
	for _, addr := range []string{"10.0.16.5/32", "10.0.16.6/32"} {
		nsRun(t, r.ns, "ip", "addr", "add", addr, "dev", "d0")
	}
	nsRun(t, r.ns, "ip", "route", "add", "203.0.113.0/24", "dev", "d0")
	// Only worker traffic is translated, as on the NATs.
	nsRun(t, r.ns, "iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "tcp", "-s", "10.0.16.0/24", "-d", "203.0.113.9", "-j", "SNAT", "--to-source", shared.String()+":40000")
	require.NoError(t, WriteConfig(r.client.ConfigPath, local, peer, shared, r.ns+"-s", r.dir, 262144))
	return r
}

// start runs conntrackd in the replica's namespace until the test ends.
func (r replica) start(t *testing.T) {
	cmd := exec.Command("ip", "netns", "exec", r.ns, "conntrackd", "-C", r.client.ConfigPath)
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, err = r.client.Stats(t.Context()); err == nil {
			return
		}
	}
	t.Fatalf("conntrackd did not start: %v\n%s", err, output.String())
}

func (r replica) copies(t *testing.T) string {
	copies, err := r.client.ExternalCache(t.Context())
	require.NoError(t, err)
	return copies
}

// connect opens a TCP connection from addr:port in namespace ns. Its SYN
// leaves through the dummy interface, which creates a connection entry.
func connect(t *testing.T, ns, addr string, port int) {
	_, _ = command.Run(t.Context(), 3*time.Second, "ip", "netns", "exec", ns, "curl", "-s", "--max-time", "1",
		"--interface", addr, "--local-port", fmt.Sprint(port), "http://203.0.113.9:443/")
	require.Eventually(t, func() bool {
		return strings.Contains(nsRun(t, ns, "conntrack", "-L", "-p", "tcp"), fmt.Sprintf("sport=%d ", port))
	}, 2*time.Second, 50*time.Millisecond)
}

func run(t *testing.T, name string, args ...string) string {
	output, err := command.Run(t.Context(), 5*time.Second, name, args...)
	require.NoError(t, err, "%s %v", name, args)
	return output
}

func nsRun(t *testing.T, ns string, args ...string) string {
	return run(t, "ip", append([]string{"netns", "exec", ns}, args...)...)
}
