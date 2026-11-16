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
	"github.com/artie-labs/natpair/internal/config"
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
	// PrepareNetwork routes to the peer through the own interface.
	cfg.Instance.Interface = "own-test"
	run(t, "ip", "link", "add", "own-test", "type", "dummy")
	t.Cleanup(func() {
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", "own-test")
		assert.NoError(t, err)
	})
	run(t, "ip", "addr", "add", "10.0.1.10/24", "dev", "own-test")
	run(t, "ip", "link", "set", "own-test", "up")
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	// Running twice must not fail on rules or routes that already exist.
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
	cfg.Instance.Interface = "own-test"
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
	require.Contains(t, run(t, "ip", "route", "get", "10.94.5.11"), "shared-test")
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

// firewalls are the ways a NAT can install its rules. The privileged tests
// run the same checks against each.
var firewalls = []config.Firewall{config.FirewallIPTables, config.FirewallNFTables}

func TestOwnTrafficIsUntracked(t *testing.T) {
	for _, firewall := range firewalls {
		t.Run(string(firewall), func(t *testing.T) { testOwnTrafficIsUntracked(t, firewall) })
	}
}

func testOwnTrafficIsUntracked(t *testing.T, firewall config.Firewall) {
	// The NAT runs in its own namespace with its firewall, whose state
	// matches put the connection table in use, as on a NAT.
	run(t, "ip", "netns", "add", "own-test")
	t.Cleanup(func() {
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "netns", "del", "own-test")
		assert.NoError(t, err)
	})
	nat := func(args ...string) string {
		return run(t, "ip", append([]string{"netns", "exec", "own-test"}, args...)...)
	}
	nat("ip", "link", "set", "lo", "up")
	nat("ip", "link", "add", "own-test", "type", "dummy")
	nat("ip", "addr", "add", "10.94.6.10/24", "dev", "own-test")
	nat("ip", "link", "set", "own-test", "up")
	// Packets to 10.94.7.0/24 leave through the dummy interface, as to a
	// host outside the NAT, and vanish there.
	nat("ip", "route", "add", "10.94.7.0/24", "dev", "own-test")
	cfg := testConfig(t)
	cfg.Firewall = firewall
	cfg.Instance.PrivateIP = netip.MustParseAddr("10.94.6.10")
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	inNAT := func(fn func() error) {
		require.NoError(t, netns.Do("own-test", fn))
	}
	inNAT(func() error { return n.InstallFirewall(t.Context()) })
	// tracked reports whether the connection table holds an entry for
	// protocol to port.
	tracked := func(protocol, port string) bool {
		return strings.Contains(nat("conntrack", "-L", "-p", protocol, "--dport", port), "dport="+port)
	}
	{
		// A connection of the NAT's own takes no entry in the connection
		// table, so a full table can't drop it
		inNAT(func() error {
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.94.6.10")}, Timeout: 100 * time.Millisecond}
			_, err := dialer.Dial("tcp4", "10.94.7.1:40123")
			assert.Error(t, err)
			return nil
		})
		assert.False(t, tracked("tcp", "40123"))
	}
	{
		// UDP to outside the VPC stays tracked, which also shows the table
		// is in use here
		inNAT(func() error {
			conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.94.6.10")}, &net.UDPAddr{IP: net.ParseIP("10.94.7.1"), Port: 40124})
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte("x"))
			return err
		})
		assert.True(t, tracked("udp", "40124"))
	}
	{
		// Traffic within the host takes no entry either, such as DNS through
		// a local stub resolver on 127.0.0.53
		inNAT(func() error {
			listener, err := net.Listen("tcp4", "127.0.0.1:40125")
			if err != nil {
				return err
			}
			defer listener.Close()
			conn, err := net.DialTimeout("tcp4", "127.0.0.1:40125", time.Second)
			if err != nil {
				return err
			}
			return conn.Close()
		})
		assert.False(t, tracked("tcp", "40125"))
	}
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
func sendTCP(t *testing.T, namespace string, from, to netip.Addr, sourcePort, port uint16, flags byte) {
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment[0:], sourcePort)
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
	binary.BigEndian.PutUint16(segment[16:], checksum(pseudo))
	sendRaw(t, namespace, unix.IPPROTO_TCP, source, destination, segment)
}

// sendICMP sends one ICMP error of kind and code from inside namespace, about
// a UDP datagram that to sent to from.
func sendICMP(t *testing.T, namespace string, from, to netip.Addr, kind, code byte) {
	// The quoted datagram's IP header and the first 8 bytes of its UDP header.
	quoted := make([]byte, 28)
	quoted[0], quoted[8], quoted[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(quoted[2:], 28)
	source, destination := to.As4(), from.As4()
	copy(quoted[12:], source[:])
	copy(quoted[16:], destination[:])
	binary.BigEndian.PutUint16(quoted[10:], checksum(quoted[:20]))
	binary.BigEndian.PutUint16(quoted[20:], 40000)
	binary.BigEndian.PutUint16(quoted[22:], 33434)
	binary.BigEndian.PutUint16(quoted[24:], 8)
	message := append([]byte{kind, code, 0, 0, 0, 0, 0, 0}, quoted...)
	binary.BigEndian.PutUint16(message[2:], checksum(message))
	sendRaw(t, namespace, unix.IPPROTO_ICMP, from.As4(), to.As4(), message)
}

// checksum is the Internet checksum of data, which has an even length.
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// sendRaw sends payload over IPv4 with protocol from source to destination,
// inside namespace. The kernel adds the IP header.
func sendRaw(t *testing.T, namespace string, protocol int, source, destination [4]byte, payload []byte) {
	require.NoError(t, netns.Do(namespace, func() error {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, protocol)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		// Without the bind, the kernel picks the source address.
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: source}); err != nil {
			return err
		}
		return unix.Sendto(fd, payload, 0, &unix.SockaddrInet4{Addr: destination})
	}))
}

// ruleCount returns how many packets the rule of chain, in namespace's
// iptables filter table, that contains all of parts has matched.
func ruleCount(t *testing.T, namespace, chain string, parts ...string) int {
	return countLine(t, run(t, "ip", "netns", "exec", namespace, "iptables", "-w", "1", "-L", chain, "-v", "-x", "-n"), func(line string) (string, bool) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", false
		}
		return fields[0], true
	}, parts...)
}

// nftCount returns the packet count of the rule of chain, in namespace's
// nftables table, that contains all of parts.
func nftCount(t *testing.T, namespace, table, chain string, parts ...string) int {
	return countLine(t, run(t, "ip", "netns", "exec", namespace, "nft", "list", "chain", "ip", table, chain), func(line string) (string, bool) {
		_, after, found := strings.Cut(line, "counter packets ")
		count, _, _ := strings.Cut(after, " ")
		return count, found
	}, parts...)
}

// countLine returns the count that count reads from the first line of listing
// that contains all of parts.
func countLine(t *testing.T, listing string, count func(line string) (string, bool), parts ...string) int {
	for line := range strings.SplitSeq(listing, "\n") {
		matches := true
		for _, part := range parts {
			matches = matches && strings.Contains(line, part)
		}
		if !matches {
			continue
		}
		if value, ok := count(line); ok {
			parsed, err := strconv.Atoi(value)
			require.NoError(t, err)
			return parsed
		}
	}
	t.Fatalf("no rule with %v in:\n%s", parts, listing)
	return 0
}

// TestHostFirewall runs the NAT's firewall in its own namespace, fw-nat,
// between hosts outside the VPC, in fw-out, and the peer inside it, in
// fw-vpc.
func TestHostFirewall(t *testing.T) {
	for _, firewall := range firewalls {
		t.Run(string(firewall), func(t *testing.T) { testHostFirewall(t, firewall) })
	}
}

func testHostFirewall(t *testing.T, firewall config.Firewall) {
	own, shared, outside := netip.MustParseAddr("10.94.7.10"), netip.MustParseAddr("10.94.7.100"), netip.MustParseAddr("10.94.7.20")
	// scanner is a second host outside, so its resets are limited apart
	// from outside's.
	scanner := netip.MustParseAddr("10.94.7.21")
	cfg := testConfig(t)
	cfg.Firewall = firewall
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
	run(t, "ip", "-n", "fw-out", "addr", "add", scanner.String()+"/24", "dev", "fw-out")
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
	require.NoError(t, netns.Do("fw-nat", func() error { return n.InstallFirewall(t.Context()) }))
	// Counts the TCP packets the NAT sends outside, such as resets, in a
	// table of the test's own, the same for both firewalls.
	nat("nft", "add table ip probe; add chain ip probe out { type filter hook output priority 0; }; add rule ip probe out oifname fw-nat-out meta l4proto tcp counter")
	replies := func() int { return nftCount(t, "fw-nat", "probe", "out", "fw-nat-out") }
	dropped := func() int { return ruleCount(t, "fw-nat", "NATPAIR_INPUT", "DROP") }
	resets := func() int { return ruleCount(t, "fw-nat", "NATPAIR_INPUT", "REJECT", "reset") }
	if firewall == config.FirewallNFTables {
		dropped = func() int {
			return countLine(t, nat("nft", "list", "counter", "ip", "natpair", "dropped"), func(line string) (string, bool) {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return "", false
				}
				return fields[1], true
			}, "packets")
		}
		resets = func() int { return nftCount(t, "fw-nat", "natpair", "input", "reject with tcp reset") }
	}
	// silent sends one probe from outside the VPC and checks that the final
	// rule dropped it and nothing answered it.
	silent := func(to netip.Addr, port uint16, flags byte) {
		t.Helper()
		drops, sent := dropped(), replies()
		sendTCP(t, "fw-out", outside, to, 44444, port, flags)
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
		// Probes to the shared address get no answer either: any SYN, and
		// TCP without SYN outside the ports workers' connections use
		for _, port := range []uint16{22, 1023, 40000, 61000, 65535} {
			silent(shared, port, syn)
		}
		for _, port := range []uint16{22, 1023, 61000, 61500, 65535} {
			silent(shared, port, ack)
		}
	}
	{
		// TCP without SYN on a worker port, for a connection this NAT
		// doesn't know, gets the reset, as after a takeover
		before, sent := resets(), replies()
		sendTCP(t, "fw-out", outside, shared, 44444, 40000, ack)
		assert.Equal(t, before+1, resets())
		assert.Equal(t, sent+1, replies())
	}
	{
		// An ACK scan of the worker ports gets the burst of 50 resets, then
		// 10 a second, and silence for the rest
		before, drops := resets(), dropped()
		started := time.Now()
		for port := range uint16(200) {
			sendTCP(t, "fw-out", scanner, shared, 44444, 2000+port, ack)
		}
		// The bucket refills at 10 a second while the scan runs.
		refilled := int(time.Since(started).Seconds()*10) + 1
		answered := resets() - before
		assert.GreaterOrEqual(t, answered, 50)
		assert.LessOrEqual(t, answered, 50+refilled)
		assert.Equal(t, 200-answered, dropped()-drops)
	}
	{
		// ICMP errors to the NAT's own address get through at 100 at once and
		// then 50 a second for each kind, and the rest are dropped. Each kind
		// has its own limit.
		for _, kind := range []struct{ kind, code byte }{{3, 4}, {3, 1}, {3, 3}, {11, 0}} {
			drops := dropped()
			started := time.Now()
			for range 300 {
				sendICMP(t, "fw-out", outside, own, kind.kind, kind.code)
			}
			refilled := int(time.Since(started).Seconds()*50) + 1
			accepted := 300 - (dropped() - drops)
			assert.GreaterOrEqual(t, accepted, 100, "type %d code %d", kind.kind, kind.code)
			assert.LessOrEqual(t, accepted, 100+refilled, "type %d code %d", kind.kind, kind.code)
		}
		// Other ICMP errors, such as a redirect, are dropped
		drops := dropped()
		sendICMP(t, "fw-out", outside, own, 5, 1)
		assert.Equal(t, drops+1, dropped())
	}
	{
		// The NAT's own connections, which aren't tracked, still get their
		// replies, through the socket match, and so does the connection's
		// socket once it waits in TIME_WAIT
		var listener net.Listener
		require.NoError(t, netns.Do("fw-out", func() error {
			var err error
			listener, err = net.Listen("tcp4", outside.String()+":8443")
			return err
		}))
		defer listener.Close()
		served := make(chan struct{})
		go func() {
			defer close(served)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
		var accepted int
		if firewall == config.FirewallIPTables {
			accepted = ruleCount(t, "fw-nat", "NATPAIR_INPUT", "socket")
		}
		var localPort uint16
		require.NoError(t, netns.Do("fw-nat", func() error {
			dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: own.AsSlice()}, Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp4", outside.String()+":8443")
			if err != nil {
				return err
			}
			defer conn.Close()
			localPort = uint16(conn.LocalAddr().(*net.TCPAddr).Port)
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
		if firewall == config.FirewallIPTables {
			// At least the SYN-ACK and the echo
			assert.GreaterOrEqual(t, ruleCount(t, "fw-nat", "NATPAIR_INPUT", "socket"), accepted+2)
		}
		// The NAT closed first, so once the server's FIN arrives its socket
		// waits in TIME_WAIT.
		<-served
		port := strconv.Itoa(int(localPort))
		require.Eventually(t, func() bool {
			return strings.Contains(nat("ss", "-Htn", "state", "time-wait", "sport", "=", ":"+port), port)
		}, 5*time.Second, 10*time.Millisecond)
		drops := dropped()
		sendTCP(t, "fw-out", outside, own, 8443, localPort, ack)
		assert.Equal(t, drops, dropped(), "an ACK for a socket in TIME_WAIT is accepted")
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

// TestSNAT forwards a worker's connections through the NAT, in sn-nat, to a
// host outside, in sn-out, which sees where they come from.
func TestSNAT(t *testing.T) {
	for _, firewall := range firewalls {
		t.Run(string(firewall), func(t *testing.T) { testSNAT(t, firewall) })
	}
}

func testSNAT(t *testing.T, firewall config.Firewall) {
	worker, own, shared, outside := netip.MustParseAddr("10.94.10.2"), netip.MustParseAddr("10.94.11.1"), netip.MustParseAddr("10.94.11.100"), netip.MustParseAddr("10.94.11.2")
	ctx := context.WithoutCancel(t.Context())
	for _, namespace := range []string{"sn-worker", "sn-nat", "sn-out"} {
		run(t, "ip", "netns", "add", namespace)
		t.Cleanup(func() {
			_, err := command.Run(ctx, 2*time.Second, "ip", "netns", "del", namespace)
			assert.NoError(t, err)
		})
	}
	run(t, "ip", "link", "add", "lan", "netns", "sn-nat", "type", "veth", "peer", "name", "lan", "netns", "sn-worker")
	run(t, "ip", "link", "add", "wan", "netns", "sn-nat", "type", "veth", "peer", "name", "wan", "netns", "sn-out")
	for _, step := range [][]string{
		{"sn-nat", "addr", "add", "10.94.10.1/24", "dev", "lan"},
		{"sn-nat", "addr", "add", own.String() + "/24", "dev", "wan"},
		{"sn-nat", "addr", "add", shared.String() + "/24", "dev", "wan"},
		{"sn-worker", "addr", "add", worker.String() + "/24", "dev", "lan"},
		{"sn-out", "addr", "add", outside.String() + "/24", "dev", "wan"},
		{"sn-nat", "link", "set", "lan", "up"},
		{"sn-nat", "link", "set", "wan", "up"},
		{"sn-nat", "link", "set", "lo", "up"},
		{"sn-worker", "link", "set", "lan", "up"},
		{"sn-out", "link", "set", "wan", "up"},
		{"sn-worker", "route", "add", "default", "via", "10.94.10.1"},
	} {
		run(t, "ip", append([]string{"-n"}, step...)...)
	}
	run(t, "ip", "netns", "exec", "sn-nat", "sysctl", "-qw", "net.ipv4.ip_forward=1")
	cfg := testConfig(t)
	cfg.Firewall = firewall
	// The protected CIDRs hold the NAT's own address, as when they are the
	// whole VPC. The host outside is not in the VPC, so the NAT's own UDP to
	// it stays tracked and passes the SNAT rules.
	cfg.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.94.10.0/24"), netip.MustParsePrefix("10.94.11.0/24")}
	cfg.SharedAddress = netip.PrefixFrom(shared, 24)
	cfg.PeerIP = netip.MustParseAddr("10.94.11.3")
	cfg.Instance.PrivateIP, cfg.Instance.Interface = own, "wan"
	cfg.Instance.VPCCIDRs = []netip.Prefix{netip.MustParsePrefix("10.94.10.0/24")}
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	require.NoError(t, netns.Do("sn-nat", func() error { return n.PrepareNetwork(t.Context()) }))

	var tcp net.Listener
	var udp net.PacketConn
	require.NoError(t, netns.Do("sn-out", func() error {
		var err error
		if tcp, err = net.Listen("tcp4", outside.String()+":8080"); err != nil {
			return err
		}
		udp, err = net.ListenPacket("udp4", outside.String()+":8081")
		return err
	}))
	defer tcp.Close()
	defer udp.Close()
	// seenTCP connects from namespace and source, and returns where the host
	// outside saw the connection come from.
	seenTCP := func(namespace string, source netip.AddrPort) netip.AddrPort {
		t.Helper()
		require.NoError(t, netns.Do(namespace, func() error {
			dialer := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(source), Timeout: 5 * time.Second}
			conn, err := dialer.Dial("tcp4", outside.String()+":8080")
			if err != nil {
				return err
			}
			return conn.Close()
		}))
		conn, err := tcp.Accept()
		require.NoError(t, err)
		defer conn.Close()
		return conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	}
	seenUDP := func(namespace string, source netip.Addr) netip.Addr {
		t.Helper()
		require.NoError(t, netns.Do(namespace, func() error {
			conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: source.AsSlice()}, &net.UDPAddr{IP: outside.AsSlice(), Port: 8081})
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte("x"))
			return err
		}))
		require.NoError(t, udp.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, from, err := udp.ReadFrom(make([]byte, 16))
		require.NoError(t, err)
		return from.(*net.UDPAddr).AddrPort().Addr().Unmap()
	}
	{
		// Worker TCP leaves from the shared address on ports 1024 to 60999,
		// so a worker's port below or above that range is moved into it, and
		// one inside it is kept
		for _, port := range []uint16{500, 61500} {
			seen := seenTCP("sn-worker", netip.AddrPortFrom(worker, port))
			assert.Equal(t, shared, seen.Addr())
			assert.GreaterOrEqual(t, seen.Port(), uint16(1024), "worker port %d", port)
			assert.LessOrEqual(t, seen.Port(), uint16(60999), "worker port %d", port)
		}
		assert.Equal(t, netip.AddrPortFrom(shared, 40000), seenTCP("sn-worker", netip.AddrPortFrom(worker, 40000)))
	}
	{
		// Worker UDP leaves from the shared address too
		assert.Equal(t, shared, seenUDP("sn-worker", worker))
	}
	{
		// The NAT's own traffic keeps its own address, though the protected
		// CIDRs hold it
		assert.Equal(t, own, seenUDP("sn-nat", own))
	}
}
