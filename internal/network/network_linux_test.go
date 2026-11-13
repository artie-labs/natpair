//go:build linux && privileged

package network_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/netns"
	"github.com/artie-labs/natpair/internal/network"
)

func run(t *testing.T, name string, args ...string) string {
	output, err := command.Run(t.Context(), 2*time.Second, name, args...)
	require.NoError(t, err)
	return output
}

func TestSharedPath(t *testing.T) {
	cfg := testConfig(t)
	cfg.SharedAddress = netip.MustParsePrefix("10.94.2.100/24")

	run(t, "ip", "link", "add", "shared-test", "type", "dummy")
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", "shared-test")
		assert.NoError(t, err)
	})
	var links []struct {
		Address string `json:"address"`
	}
	require.NoError(t, json.Unmarshal([]byte(run(t, "ip", "-j", "link", "show", "shared-test")), &links))
	mac := links[0].Address

	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	require.NoError(t, n.ActivateShared(t.Context(), mac))
	assert.Contains(t, run(t, "ip", "-4", "addr", "show", "dev", "shared-test"), "10.94.2.100/24")
	assert.Contains(t, run(t, "ip", "route", "show", "table", "7001"), "default via 10.94.2.1 dev shared-test")
}

func TestSharedRules(t *testing.T) {
	cfg := testConfig(t)
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	// Running twice must not fail on rules that already exist.
	for range 2 {
		require.NoError(t, n.PrepareNetwork(t.Context()))
	}
	rules := run(t, "ip", "rule", "show", "table", "7001")
	assert.Contains(t, rules, "from 10.0.16.0/20 lookup 7001")
	assert.Contains(t, rules, "from 198.18.0.6 lookup 7001")
}

func TestOwnTrafficStaysOnMain(t *testing.T) {
	// The protected CIDRs are the whole VPC, so they hold the NAT's own
	// address, and the shared table sends everything out another interface.
	cfg := testConfig(t)
	cfg.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}
	for _, link := range []string{"own-test", "shared-test2"} {
		run(t, "ip", "link", "add", link, "type", "dummy")
		run(t, "ip", "link", "set", link, "up")
		t.Cleanup(func() {
			_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", link)
			assert.NoError(t, err)
		})
	}
	run(t, "ip", "addr", "add", "10.0.1.10/24", "dev", "own-test")
	run(t, "ip", "addr", "add", "10.0.1.100/24", "dev", "own-test")
	run(t, "ip", "route", "add", "default", "dev", "shared-test2", "table", "7001")
	t.Cleanup(func() {
		for _, rule := range [][]string{{"from", "10.0.0.0/16", "lookup", "7001"}, {"from", "10.0.1.100", "lookup", "7001", "priority", "6999"}} {
			_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", append([]string{"rule", "del"}, rule...)...)
			assert.NoError(t, err)
		}
	})

	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	require.NoError(t, n.PrepareNetwork(t.Context()))
	assert.NotContains(t, run(t, "ip", "route", "get", "203.0.113.9", "from", "10.0.1.10"), "shared-test2")
	// Its traffic from the shared address, such as resets to remote servers,
	// leaves through the shared table.
	assert.Contains(t, run(t, "ip", "route", "get", "203.0.113.9", "from", "10.0.1.100"), "shared-test2")

	// Without the local rule, the NAT's own traffic would leave through the
	// shared table.
	run(t, "ip", "rule", "del", "iif", "lo", "lookup", "main", "priority", "7000")
	assert.Contains(t, run(t, "ip", "route", "get", "203.0.113.9", "from", "10.0.1.10"), "shared-test2")
}

func TestPeerRoute(t *testing.T) {
	// Two links in one subnet, as a NAT's own interface and the shared ENI.
	for _, link := range []struct{ name, address string }{{"own-test", "10.94.5.10/24"}, {"shared-test", "10.94.5.100/24"}} {
		run(t, "ip", "link", "add", link.name, "type", "dummy")
		t.Cleanup(func() {
			_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", link.name)
			assert.NoError(t, err)
		})
		run(t, "ip", "addr", "add", link.address, "dev", link.name)
		run(t, "ip", "link", "set", link.name, "up")
	}
	// The shared address's subnet route wins, as on AWS once the shared ENI
	// is attached.
	run(t, "ip", "route", "replace", "10.94.5.0/24", "dev", "shared-test", "src", "10.94.5.100")
	cfg := testConfig(t)
	cfg.PeerIP = netip.MustParseAddr("10.94.5.11")
	cfg.Instance.Interface, cfg.Instance.PrivateIP = "own-test", netip.MustParseAddr("10.94.5.10")
	require.NoError(t, network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{}).RoutePeer(t.Context()))
	var routes []struct {
		Dev     string `json:"dev"`
		PrefSrc string `json:"prefsrc"`
	}
	require.NoError(t, json.Unmarshal([]byte(run(t, "ip", "-j", "route", "get", "10.94.5.11")), &routes))
	require.Len(t, routes, 1)
	assert.Equal(t, "own-test", routes[0].Dev)
	assert.Equal(t, "10.94.5.10", routes[0].PrefSrc)
}

func TestOwnTrafficIsUntracked(t *testing.T) {
	run(t, "ip", "link", "add", "own-test", "type", "dummy")
	t.Cleanup(func() {
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", "own-test")
		assert.NoError(t, err)
	})
	run(t, "ip", "addr", "add", "10.94.6.10/24", "dev", "own-test")
	run(t, "ip", "link", "set", "own-test", "up")
	cfg := testConfig(t)
	cfg.Instance.PrivateIP = netip.MustParseAddr("10.94.6.10")
	require.NoError(t, network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{}).UntrackOwnTraffic(t.Context()))

	tracked := func(port string) bool {
		output, err := command.Run(t.Context(), 2*time.Second, "conntrack", "-L", "-p", "tcp", "--dport", port)
		return err == nil && strings.Contains(output, "dport="+port)
	}
	connect := func(port string) {
		listener, err := net.Listen("tcp4", "10.94.6.10:"+port)
		require.NoError(t, err)
		defer listener.Close()
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.94.6.10")}, Timeout: time.Second}
		conn, err := dialer.Dial("tcp4", "10.94.6.10:"+port)
		require.NoError(t, err)
		defer conn.Close()
		accepted, err := listener.Accept()
		require.NoError(t, err)
		_ = accepted.Close()
	}
	// A connection of the NAT's own takes no entry in the connection table,
	// so a full table can't drop it.
	connect("40123")
	assert.False(t, tracked("40123"))
	// Replies to the own canary's ports stay tracked, which only traffic from
	// outside the host shows. The campaign's own-path probes cover it.
}

func TestReadConnectionTableFromKernel(t *testing.T) {
	// The real tools' output parses, with the count before the limit.
	table, err := network.New(testConfig(t), &mocks.FakeNetworkFence{}, network.SystemRunner{}).ReadConnectionTable(t.Context())
	require.NoError(t, err)
	assert.Positive(t, table.Max)
	assert.Less(t, table.Connections, table.Max)
}

// sendTCP sends one TCP segment with the given flags from inside namespace,
// built by hand so it needn't belong to a connection.
func sendTCP(t *testing.T, namespace string, from, to netip.Addr, port uint16, flags byte) {
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:], 44444)
	binary.BigEndian.PutUint16(segment[2:], port)
	binary.BigEndian.PutUint32(segment[4:], 1000)
	binary.BigEndian.PutUint32(segment[8:], 2000)
	segment[12] = 5 << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:], 8192)
	// The checksum covers a pseudo-header of the addresses, protocol and
	// length.
	source, destination := from.As4(), to.As4()
	pseudo := append(append(append(source[:], destination[:]...), 0, unix.IPPROTO_TCP, 0, 20), segment...)
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(segment[16:], ^uint16(sum))
	require.NoError(t, netns.Do(namespace, func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Sendto(fd, segment, 0, &unix.SockaddrInet4{Addr: destination})
	}))
}

// ruleCount returns how many packets the NATPAIR_INPUT rule containing all
// of parts has matched.
func ruleCount(t *testing.T, parts ...string) int {
	for line := range strings.SplitSeq(run(t, "iptables", "-w", "1", "-L", "NATPAIR_INPUT", "-v", "-x", "-n"), "\n") {
		matches := true
		for _, part := range parts {
			matches = matches && strings.Contains(line, part)
		}
		if fields := strings.Fields(line); matches && len(fields) > 0 {
			count, err := strconv.Atoi(fields[0])
			require.NoError(t, err)
			return count
		}
	}
	t.Fatalf("no NATPAIR_INPUT rule with %v", parts)
	return 0
}

func TestHostFirewallForUntrackedReplies(t *testing.T) {
	// The NAT's own address, and a host outside the VPC in a namespace.
	own, outside := netip.MustParseAddr("10.94.7.10"), netip.MustParseAddr("10.94.7.20")
	run(t, "ip", "netns", "add", "fw-out")
	run(t, "ip", "link", "add", "fw-nat", "type", "veth", "peer", "name", "fw-out", "netns", "fw-out")
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		for _, args := range [][]string{{"iptables", "-w", "1", "-D", "INPUT", "-j", "NATPAIR_INPUT"}, {"iptables", "-w", "1", "-t", "raw", "-D", "PREROUTING", "-j", "NATPAIR_UNTRACK_IN"}, {"iptables", "-w", "1", "-t", "raw", "-D", "OUTPUT", "-j", "NATPAIR_UNTRACK_OUT"}, {"ip", "link", "del", "fw-nat"}, {"ip", "netns", "del", "fw-out"}} {
			_, err := command.Run(ctx, 2*time.Second, args[0], args[1:]...)
			assert.NoError(t, err)
		}
	})
	run(t, "ip", "addr", "add", own.String()+"/24", "dev", "fw-nat")
	run(t, "ip", "link", "set", "fw-nat", "up")
	run(t, "ip", "-n", "fw-out", "addr", "add", outside.String()+"/24", "dev", "fw-out")
	run(t, "ip", "-n", "fw-out", "link", "set", "fw-out", "up")
	cfg := testConfig(t)
	cfg.Instance.PrivateIP = own
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	require.NoError(t, n.ProtectHost(t.Context()))
	require.NoError(t, n.UntrackOwnTraffic(t.Context()))

	const ack, syn = 0x10, 0x02
	accepted := func() int { return ruleCount(t, "ACCEPT", "dpts:32768:60999", "UNTRACKED") }
	reset := func() int { return ruleCount(t, "REJECT", "tcp", "reset") }
	{
		// A non-SYN packet to a well-known port gets the reset it got before
		// the NAT's own connections went untracked, as every port does, so a
		// scan learns nothing.
		before, resets := accepted(), reset()
		sendTCP(t, "fw-out", outside, own, 22, ack)
		assert.Equal(t, before, accepted())
		assert.Equal(t, resets+1, reset())
	}
	{
		// The canary's ports stay tracked
		before, resets := accepted(), reset()
		sendTCP(t, "fw-out", outside, own, 61234, ack)
		assert.Equal(t, before, accepted())
		assert.Equal(t, resets+1, reset())
	}
	{
		// A reply to one of the NAT's own ephemeral ports reaches its sockets
		before := accepted()
		sendTCP(t, "fw-out", outside, own, 40000, ack)
		assert.Equal(t, before+1, accepted())
	}
	{
		// A SYN can't use that rule to open a connection
		before, resets := accepted(), reset()
		sendTCP(t, "fw-out", outside, own, 40001, syn)
		assert.Equal(t, before, accepted())
		assert.Equal(t, resets+1, reset())
	}
}
