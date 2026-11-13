//go:build linux && privileged

package network_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
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

// ruleCount returns how many packets the rule of chain, in namespace's
// filter table, that contains all of parts has matched.
func ruleCount(t *testing.T, namespace, chain string, parts ...string) int {
	for line := range strings.SplitSeq(run(t, "ip", "netns", "exec", namespace, "iptables", "-w", "1", "-L", chain, "-v", "-x", "-n"), "\n") {
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
	t.Fatalf("no %s rule with %v", chain, parts)
	return 0
}

// TestHostFirewall runs the NAT's firewall in its own namespace, fw-nat,
// between a host outside the VPC, in fw-out, and the peer inside it, in
// fw-vpc.
func TestHostFirewall(t *testing.T) {
	own, shared, outside := netip.MustParseAddr("10.94.7.10"), netip.MustParseAddr("10.94.7.100"), netip.MustParseAddr("10.94.7.20")
	cfg := testConfig(t)
	cfg.Instance.PrivateIP = own
	cfg.SharedAddress = netip.PrefixFrom(shared, 24)
	peer := cfg.PeerIP.String()
	ctx := context.WithoutCancel(t.Context())
	for _, namespace := range []string{"fw-nat", "fw-out", "fw-vpc"} {
		run(t, "ip", "netns", "add", namespace)
		t.Cleanup(func() {
			_, err := command.Run(ctx, 2*time.Second, "ip", "netns", "del", namespace)
			assert.NoError(t, err)
		})
	}
	nat := func(args ...string) string {
		return run(t, "ip", append([]string{"netns", "exec", "fw-nat"}, args...)...)
	}
	run(t, "ip", "link", "add", "fw-nat-out", "netns", "fw-nat", "type", "veth", "peer", "name", "fw-out", "netns", "fw-out")
	run(t, "ip", "link", "add", "fw-nat-vpc", "netns", "fw-nat", "type", "veth", "peer", "name", "fw-vpc", "netns", "fw-vpc")
	nat("ip", "addr", "add", own.String()+"/24", "dev", "fw-nat-out")
	nat("ip", "addr", "add", shared.String()+"/24", "dev", "fw-nat-out")
	nat("ip", "addr", "add", "10.0.1.1/24", "dev", "fw-nat-vpc")
	run(t, "ip", "-n", "fw-out", "addr", "add", outside.String()+"/24", "dev", "fw-out")
	run(t, "ip", "-n", "fw-vpc", "addr", "add", peer+"/24", "dev", "fw-vpc")
	run(t, "ip", "-n", "fw-vpc", "link", "set", "fw-vpc", "up")
	run(t, "ip", "-n", "fw-vpc", "route", "add", "default", "via", "10.0.1.1")
	run(t, "ip", "-n", "fw-out", "link", "set", "fw-out", "up")
	for _, link := range []string{"fw-nat-out", "fw-nat-vpc", "lo"} {
		nat("ip", "link", "set", link, "up")
	}
	// As Bootstrap sets it: a packet without SYN that matches no tracked
	// connection is INVALID instead of starting one.
	nat("sysctl", "-qw", "net.netfilter.nf_conntrack_tcp_loose=0")
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	require.NoError(t, netns.Do("fw-nat", func() error {
		if err := n.ProtectHost(t.Context()); err != nil {
			return err
		}
		return n.UntrackOwnTraffic(t.Context())
	}))
	// Counts the TCP packets the NAT sends outside, such as resets.
	nat("iptables", "-w", "1", "-A", "OUTPUT", "-o", "fw-nat-out", "-p", "tcp")
	replies := func() int { return ruleCount(t, "fw-nat", "OUTPUT", "fw-nat-out") }
	dropped := func() int { return ruleCount(t, "fw-nat", "NATPAIR_INPUT", "DROP") }
	// silent sends one probe from outside the VPC and checks that the final
	// rule dropped it and nothing answered it.
	silent := func(to netip.Addr, port uint16, flags byte) {
		t.Helper()
		drops, sent := dropped(), replies()
		sendTCP(t, "fw-out", outside, to, port, flags)
		assert.Equal(t, drops+1, dropped(), "%s port %d flags %#x", to, port, flags)
		assert.Equal(t, sent, replies(), "%s port %d flags %#x", to, port, flags)
	}

	const ack, syn = 0x10, 0x02
	{
		// Probes to the NAT's own address get no answer on any port, including
		// its ephemeral ports when no socket owns the port, and the own
		// canary's ports.
		for _, port := range []uint16{22, 3780, 8080, 40000, 50000, 61500} {
			silent(own, port, syn)
			silent(own, port, ack)
		}
	}
	{
		// A socket listening on any address doesn't let an ACK through
		var listener net.Listener
		require.NoError(t, netns.Do("fw-nat", func() error {
			var err error
			listener, err = net.Listen("tcp4", ":50001")
			return err
		}))
		defer listener.Close()
		silent(own, 50001, ack)
	}
	{
		// Probes to the shared address get no answer either, except TCP
		// without SYN, which gets the reset for connections this NAT doesn't
		// know
		silent(shared, 22, syn)
		silent(shared, 40000, syn)
		resets, sent := ruleCount(t, "fw-nat", "NATPAIR_INPUT", "REJECT", "reset"), replies()
		sendTCP(t, "fw-out", outside, shared, 40000, ack)
		assert.Equal(t, resets+1, ruleCount(t, "fw-nat", "NATPAIR_INPUT", "REJECT", "reset"))
		assert.Equal(t, sent+1, replies())
	}
	{
		// The NAT's own connections, which aren't tracked, still get their
		// replies, through the socket match
		var listener net.Listener
		require.NoError(t, netns.Do("fw-out", func() error {
			var err error
			listener, err = net.Listen("tcp4", outside.String()+":8443")
			return err
		}))
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
		accepted := ruleCount(t, "fw-nat", "NATPAIR_INPUT", "socket")
		require.NoError(t, netns.Do("fw-nat", func() error {
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: own.AsSlice()}, Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp4", outside.String()+":8443")
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("ping")); err != nil {
				return err
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(conn, echo); err != nil {
				return err
			}
			assert.Equal(t, "ping", string(echo))
			return nil
		}))
		// At least the SYN-ACK and the echo
		assert.GreaterOrEqual(t, ruleCount(t, "fw-nat", "NATPAIR_INPUT", "socket"), accepted+2)
	}
	{
		// The peer, inside the VPC, still gets the kernel's reset from a
		// closed port, so it fails fast
		for _, port := range []string{"22", "40000"} {
			err := netns.Do("fw-vpc", func() error {
				conn, err := net.DialTimeout("tcp4", own.String()+":"+port, 5*time.Second)
				if err == nil {
					_ = conn.Close()
				}
				return err
			})
			assert.ErrorIs(t, err, syscall.ECONNREFUSED, "port %s", port)
		}
	}
}
