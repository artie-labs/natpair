// Package network configures Linux forwarding on a NAT: canary namespaces,
// source NAT (SNAT) to the shared ENI's address, and the shared ENI after
// takeover.
//
// The forwarding fence is installed first and stays in front of every accept
// rule here, so nothing in this package can open worker forwarding by itself.
package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/config"
)

const (
	snatChain  = "NATPAIR_SNAT"
	inputChain = "NATPAIR_INPUT"
	// untrackOutChain and untrackInChain, in the raw table, exempt the NAT's
	// own connections from connection tracking.
	untrackOutChain = "NATPAIR_UNTRACK_OUT"
	untrackInChain  = "NATPAIR_UNTRACK_IN"
	// localPorts is the ephemeral port range this NAT's own sockets use, in
	// iptables' form, and canaryPorts the range the own canary's probes are
	// translated to. They don't overlap, so a reply to the NAT's address says
	// by its port whether it goes to a socket or back to the canary.
	localPorts  = "32768:60999"
	canaryPorts = "61000-65535"
	// workerPorts is the range worker TCP connections are translated to on
	// the shared address. A port already in it is kept. It leaves out the
	// well-known ports below 1024 and the canary's range, so a scan of
	// those on the shared address gets no answer (see protectHost), and
	// still offers 59,976 ports for each remote address and port.
	workerPorts = "1024-60999"
	// resetLimit and resetBurst bound the resets the shared address sends
	// to each remote address, for connections this NAT doesn't know. A
	// burst of 50 resets at once the connections one remote server most
	// often loses in a takeover: the few opened just before it, which
	// conntrackd hadn't copied yet. After that, 10 a second still resets
	// 500 within 45 s, when the takeover ran without copies. A scan gets
	// at most 50 answers and then 10 a second, so almost all of its
	// probes go unanswered.
	resetLimit = "10/second"
	resetBurst = "50"
	// syncPort is where conntrackd receives the peer's copies, as its
	// configuration sets.
	syncPort = "3780"
	// timeSync and resolver are the link-local AWS services the NAT itself
	// uses over UDP: Amazon Time Sync, which chrony uses on Amazon Linux,
	// and the Route 53 Resolver's link-local address. The instance metadata
	// service is TCP, so the rules for the NAT's TCP connections cover it.
	timeSync       = "169.254.169.123"
	resolver       = "169.254.169.253"
	commandTimeout = 2 * time.Second
	// sharedTable is the route table, and the priority of the rules that use
	// it, for traffic leaving through the shared ENI.
	sharedTable = "7001"
	// sharedSourcePriority and localPriority order the rules for traffic this
	// NAT sends itself. Packets from the shared address use the shared table,
	// and everything else it sends uses the main table. Both come before the
	// shared table's rules for forwarded traffic.
	sharedSourcePriority = 6999
	localPriority        = 7000
	interfaceWaitPeriod  = 3 * time.Second
	// networkdFile tells systemd-networkd to leave the shared ENI alone. Its
	// low number makes it the first file that matches the interface.
	networkdFile = "/etc/systemd/network/10-natpair-shared.network"
)

var macPattern = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$`)

// Runner runs system commands.
type Runner interface {
	Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error)
	RunWithInput(ctx context.Context, timeout time.Duration, input, name string, args ...string) (string, error)
}

// SystemRunner runs real commands.
type SystemRunner struct{}

// Run runs a command with [command.Run].
func (SystemRunner) Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	return command.Run(ctx, timeout, name, args...)
}

// RunWithInput runs a command with [command.RunWithInput].
func (SystemRunner) RunWithInput(ctx context.Context, timeout time.Duration, input, name string, args ...string) (string, error) {
	return command.RunWithInput(ctx, timeout, input, name, args...)
}

// Fence installs the forwarding guard.
type Fence interface {
	Install(ctx context.Context) error
}

// Network configures this NAT.
type Network struct {
	cfg   config.NAT
	fence Fence
	run   Runner
}

// New returns a Network. Production uses [SystemRunner].
func New(cfg config.NAT, fence Fence, runner Runner) *Network {
	return &Network{cfg: cfg, fence: fence, run: runner}
}

// Bootstrap prepares a freshly booted NAT with forwarding closed: it installs
// the fence, sets kernel parameters, creates the canary namespaces, enables
// IPv4 forwarding and installs SNAT rules.
func (n *Network) Bootstrap(ctx context.Context) error {
	if err := n.fence.Install(ctx); err != nil {
		return err
	}
	if err := n.protectHost(ctx); err != nil {
		return err
	}
	if err := n.untrackOwnTraffic(ctx); err != nil {
		return err
	}
	// The conntrack settings below exist only once this module is loaded. On
	// a fresh boot nothing has loaded it yet. A container can't load modules,
	// but its host may already have, as in natpair's own tests.
	if _, err := n.run.Run(ctx, commandTimeout, "modprobe", "nf_conntrack"); err != nil {
		if _, statErr := os.Stat("/proc/sys/net/netfilter/nf_conntrack_tcp_loose"); statErr != nil {
			return err
		}
	}
	if _, err := n.run.Run(ctx, commandTimeout, "sysctl", "-qw",
		"net.ipv6.conf.all.forwarding=0",
		// Linux's strict reverse-path filter drops packets that arrive on a
		// different interface than the one their reply would leave from.
		// Worker traffic arrives on the shared ENI but replies to workers
		// leave through the public interface, so strict filtering is turned
		// off.
		"net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0",
		// Only conntrack entries copied by conntrackd may resume mid-stream.
		"net.netfilter.nf_conntrack_tcp_loose=0",
		// Copied entries carry stale TCP sequence numbers. Strict window
		// checking would mark the next packets of a copied connection invalid,
		// and the INVALID reset rule in PrepareNetwork would then reset a
		// connection that should survive.
		"net.netfilter.nf_conntrack_tcp_be_liberal=1",
		// conntrackd replicates entries from conntrack events.
		"net.netfilter.nf_conntrack_events=1",
		// A cleanly closed connection keeps its entry this long, in
		// TIME_WAIT, so the table fills at the rate of new connections times
		// this period. At 30 s instead of Linux's 120 s, the same table holds
		// 4 times as many new connections a second. The entry has to outlast
		// late retransmits of the final FIN and ACK, and each one restarts
		// the 30 s. A packet that comes even later gets the reset for unknown
		// connections, which only closes a connection that is already
		// closed. The cost: once the entry is gone, the NAT may give the same
		// address and port to a new worker connection to the same server
		// while that server still holds the old connection in its own
		// TIME_WAIT, 60 s on Linux. A server that closed first and rejects
		// the new SYN answers it for the old connection, and the worker's
		// connect then takes a reset and a SYN retry, about 1 s.
		"net.netfilter.nf_conntrack_tcp_timeout_time_wait=30"); err != nil {
		return err
	}
	if err := n.sizeConnectionTable(ctx); err != nil {
		return err
	}
	for index, canary := range []config.Canary{n.cfg.OwnCanary(), n.cfg.SharedCanary()} {
		if err := n.createCanary(ctx, index, canary); err != nil {
			return err
		}
	}
	if _, err := n.run.Run(ctx, commandTimeout, "sysctl", "-qw", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	return n.PrepareNetwork(ctx)
}

// protectHost blocks new connections to the NAT's own services, such as SSH
// and conntrackd, from outside the VPC, and drops other traffic from outside
// the VPC without an answer, except the resets below. The security group
// can't do it: it must allow all TCP and UDP, or AWS tracks connections
// through the NAT and, after a takeover, drops replies to the ones it tracked
// on the old owner. Traffic the NAT forwards doesn't pass through this chain.
func (n *Network) protectHost(ctx context.Context) error {
	rules := "*filter\n:" + inputChain + " - [0:0]\n-F " + inputChain + "\n"
	rules += "-A " + inputChain + " -i lo -j ACCEPT\n"
	rules += "-A " + inputChain + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"
	for _, source := range append(slices.Clone(n.cfg.Instance.VPCCIDRs), netip.PrefixFrom(n.cfg.PeerIP, 32)) {
		rules += fmt.Sprintf("-A %s -s %s -j ACCEPT\n", inputChain, source)
	}
	// The NAT's own connections aren't tracked (see untrackOwnTraffic), so
	// their replies are accepted by what they are instead of by state, as
	// narrowly as they allow. UDP replies from the VPC and the peer are
	// accepted above.
	own := n.cfg.Instance.PrivateIP.String()
	// TCP replies, from anywhere, to the NAT's own connections: packets
	// without SYN, which can't open a connection, to its ephemeral ports, that
	// belong to one of its sockets. The socket match finds the socket by the
	// packet's addresses and ports, which needs no connection tracking. It
	// ignores sockets listening on any address, so only a connected socket,
	// one in TIME_WAIT, or a listener on the NAT's own address matches.
	// Other packets, such as an ACK to a port with no connection, are
	// dropped below without an answer.
	rules += fmt.Sprintf("-A %s -d %s -p tcp ! --syn --dport %s -m conntrack --ctstate UNTRACKED -m socket -j ACCEPT\n", inputChain, own, localPorts)
	// UDP replies from the link-local services. Nothing outside the
	// instance can send from a link-local address.
	for _, service := range []struct{ address, port string }{{timeSync, "123"}, {resolver, "53"}} {
		rules += fmt.Sprintf("-A %s -s %s/32 -d %s -p udp --sport %s --dport %s -m conntrack --ctstate UNTRACKED -j ACCEPT\n", inputChain, service.address, own, service.port, localPorts)
	}
	// ICMP errors about the NAT's untracked connections: path MTU discovery
	// and unreachable or expired destinations. Errors about tracked
	// connections are RELATED and accepted above. The limit bounds what
	// forged errors can cost.
	for _, kind := range []string{"fragmentation-needed", "host-unreachable", "port-unreachable", "time-exceeded"} {
		rules += fmt.Sprintf("-A %s -d %s -p icmp --icmp-type %s -m limit --limit 50/second --limit-burst 100 -j ACCEPT\n", inputChain, own, kind)
	}
	// Reset TCP to the shared address that belongs to no connection this NAT
	// knows, instead of dropping it. A remote server still sending on a
	// connection the new owner never copied then closes it at once. Dropped,
	// it waits for its own timeout. A Postgres server, for example, keeps a
	// dead replication connection, so its slot stays in use and the client
	// can't reconnect. Such a packet never has SYN, goes to a port in
	// workerPorts, which PrepareNetwork translates worker connections to,
	// and without nf_conntrack_tcp_loose the connection table marks it
	// INVALID. The resets are limited for each remote address. Packets over
	// the limit, and from more remote addresses than the limit's table
	// holds, are dropped.
	rules += fmt.Sprintf("-A %s -d %s/32 -p tcp ! --syn --dport %s -m conntrack --ctstate INVALID "+
		"-m hashlimit --hashlimit-upto %s --hashlimit-burst %s --hashlimit-mode srcip --hashlimit-name natpair_reset "+
		"--hashlimit-htable-size 4096 --hashlimit-htable-max 65536 --hashlimit-htable-expire 60000 "+
		"-j REJECT --reject-with tcp-reset\n", inputChain, n.cfg.SharedAddress.Addr(), strings.Replace(workerPorts, "-", ":", 1), resetLimit, resetBurst)
	// Everything else from outside the VPC is dropped without an answer. VPC
	// sources and the peer were accepted above, so they still get the
	// kernel's reset from a closed port and fail fast.
	rules += "-A " + inputChain + " -j DROP\nCOMMIT\n"
	if _, err := n.run.RunWithInput(ctx, commandTimeout, rules, "iptables-restore", "--noflush", "-w", "1"); err != nil {
		return err
	}
	return n.ensureRule(ctx, "filter", "INPUT", "-j", inputChain)
}

// untrackOwnTraffic exempts the NAT's own connections from connection
// tracking. A full connection table drops every new tracked connection. On
// AWS, 3,000 new worker connections a second filled a 262,144-entry table,
// and the owner's DNS lookups failed with the workers' connections.
//
// It exempts, both ways, only what protectHost can accept without state:
// traffic within the host, such as DNS through a local stub resolver like
// systemd-resolved's 127.0.0.53; TCP on the NAT's own ephemeral ports, which
// covers lease renewals, AWS API calls and the metadata service; UDP between
// those ports and the VPC, for DNS and conntrackd's copies; conntrackd's
// copies arriving from the peer; and UDP with the link-local services.
// Anything else the NAT sends, such as UDP to the internet, stays tracked, as
// before.
//
// The own canary's probes are translated to the NAT's address on
// canaryPorts, outside the ephemeral range, so their replies stay tracked
// and are translated back. The probes test the forwarding path, which needs
// the table, so they still fail when it is full, as new worker connections
// do.
func (n *Network) untrackOwnTraffic(ctx context.Context) error {
	if _, err := n.run.Run(ctx, commandTimeout, "sysctl", "-qw", "net.ipv4.ip_local_port_range="+strings.Replace(localPorts, ":", " ", 1)); err != nil {
		return err
	}
	own := n.cfg.Instance.PrivateIP.String()
	rules := "*raw\n:" + untrackOutChain + " - [0:0]\n:" + untrackInChain + " - [0:0]\n"
	rules += "-F " + untrackOutChain + "\n-F " + untrackInChain + "\n"
	out := func(match string) {
		rules += fmt.Sprintf("-A %s -s %s %s -j CT --notrack\n", untrackOutChain, own, match)
	}
	in := func(match string) {
		rules += fmt.Sprintf("-A %s -d %s %s -j CT --notrack\n", untrackInChain, own, match)
	}
	// The firewall accepts everything on the loopback interface.
	rules += "-A " + untrackOutChain + " -o lo -j CT --notrack\n"
	rules += "-A " + untrackInChain + " -i lo -j CT --notrack\n"
	out("-p tcp --sport " + localPorts)
	in("-p tcp --dport " + localPorts)
	for _, cidr := range n.cfg.Instance.VPCCIDRs {
		out(fmt.Sprintf("-d %s -p udp --sport %s", cidr, localPorts))
		in(fmt.Sprintf("-s %s -p udp --dport %s", cidr, localPorts))
	}
	in(fmt.Sprintf("-s %s/32 -p udp --dport %s", n.cfg.PeerIP, syncPort))
	for _, service := range []struct{ address, port string }{{timeSync, "123"}, {resolver, "53"}} {
		out(fmt.Sprintf("-d %s/32 -p udp --sport %s --dport %s", service.address, localPorts, service.port))
		in(fmt.Sprintf("-s %s/32 -p udp --sport %s --dport %s", service.address, service.port, localPorts))
	}
	rules += "COMMIT\n"
	if _, err := n.run.RunWithInput(ctx, commandTimeout, rules, "iptables-restore", "--noflush", "-w", "1"); err != nil {
		return err
	}
	if err := n.ensureRule(ctx, "raw", "OUTPUT", "-j", untrackOutChain); err != nil {
		return err
	}
	return n.ensureRule(ctx, "raw", "PREROUTING", "-j", untrackInChain)
}

// ConnectionTable is one reading of the kernel's connection table.
type ConnectionTable struct {
	// Connections is how many entries the table holds, and Max how many it
	// may hold.
	Connections, Max int
	// Drops counts the packets the kernel dropped since boot because it
	// couldn't track them, summed over CPUs. Almost always the table was
	// full, so a new connection had no room for its entry.
	Drops uint64
}

// ReadConnectionTable reads the kernel's connection table. The drop counter
// comes from `conntrack -S`, which asks the kernel over netlink, because
// /proc/net/stat/nf_conntrack exists only in kernels built with
// CONFIG_NF_CONNTRACK_PROCFS.
func (n *Network) ReadConnectionTable(ctx context.Context) (ConnectionTable, error) {
	output, err := n.run.Run(ctx, commandTimeout, "sysctl", "-n", "net.netfilter.nf_conntrack_count", "net.netfilter.nf_conntrack_max")
	if err != nil {
		return ConnectionTable{}, err
	}
	var table ConnectionTable
	sizes := strings.Fields(output)
	if len(sizes) != 2 {
		return ConnectionTable{}, fmt.Errorf("failed to parse the connection table's size from %q", output)
	}
	for i, target := range []*int{&table.Connections, &table.Max} {
		if *target, err = strconv.Atoi(sizes[i]); err != nil {
			return ConnectionTable{}, fmt.Errorf("failed to parse the connection table's size: %w", err)
		}
	}
	stats, err := n.run.Run(ctx, commandTimeout, "conntrack", "-S")
	if err != nil {
		return ConnectionTable{}, err
	}
	// One line per CPU, such as "cpu=0 found=0 invalid=3 insert=0
	// insert_failed=0 drop=12 early_drop=0 error=0 search_restart=0".
	var found bool
	for _, field := range strings.Fields(stats) {
		value, ok := strings.CutPrefix(field, "drop=")
		if !ok {
			continue
		}
		drops, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return ConnectionTable{}, fmt.Errorf("failed to parse the connection table's drop counter: %w", err)
		}
		table.Drops, found = table.Drops+drops, true
	}
	if !found {
		return ConnectionTable{}, fmt.Errorf("no drop counter in the connection table's statistics %q", stats)
	}
	return table, nil
}

// sizeConnectionTable matches the kernel's connection table to conntrackd's
// limit. The kernel sizes the table and its hash buckets from memory, 7,680 on
// a t4g.micro. Closed connections stay in the table for 30 s, so about 250
// new connections a second would fill that, and then new worker connections
// fail. A quarter as many buckets as entries keeps lookups short.
func (n *Network) sizeConnectionTable(ctx context.Context) error {
	_, err := n.run.Run(ctx, commandTimeout, "sysctl", "-qw",
		fmt.Sprintf("net.netfilter.nf_conntrack_max=%d", n.cfg.ConnectionLimit()),
		fmt.Sprintf("net.netfilter.nf_conntrack_buckets=%d", n.cfg.ConnectionLimit()/4))
	// Only the host's network namespace can change these. In a container,
	// such as natpair's own tests, the host's setting applies.
	if info, statErr := os.Stat("/proc/sys/net/netfilter/nf_conntrack_max"); err != nil && statErr == nil && info.Mode().Perm()&0o222 == 0 {
		return nil
	}
	return err
}

func (n *Network) createCanary(ctx context.Context, index int, canary config.Canary) error {
	host, guest := fmt.Sprintf("nat-can%d", index), fmt.Sprintf("nat-peer%d", index)
	namespaces, err := n.run.Run(ctx, commandTimeout, "ip", "netns", "list")
	if err != nil {
		return err
	}
	// Lines look like "natpair-own (id: 0)".
	exists := slices.ContainsFunc(strings.Split(namespaces, "\n"), func(line string) bool {
		fields := strings.Fields(line)
		return len(fields) > 0 && fields[0] == canary.Namespace
	})
	if !exists {
		if _, err := n.run.Run(ctx, commandTimeout, "ip", "netns", "add", canary.Namespace); err != nil {
			return err
		}
	}
	links, err := n.links(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(links, func(l link) bool { return l.Name == host }) {
		if _, err := n.run.Run(ctx, commandTimeout, "ip", "link", "add", host, "type", "veth", "peer", "name", guest); err != nil {
			return err
		}
		if _, err := n.run.Run(ctx, commandTimeout, "ip", "link", "set", guest, "netns", canary.Namespace); err != nil {
			return err
		}
	}
	bits := strconv.Itoa(canary.CIDR.Bits())
	steps := [][]string{
		{"ip", "addr", "replace", canary.Host().String() + "/" + bits, "dev", host},
		{"ip", "link", "set", host, "up"},
		{"ip", "-n", canary.Namespace, "addr", "replace", canary.Guest().String() + "/" + bits, "dev", guest},
		{"ip", "-n", canary.Namespace, "link", "set", guest, "mtu", "1500", "up"},
		{"ip", "-n", canary.Namespace, "link", "set", "lo", "up"},
		{"ip", "-n", canary.Namespace, "route", "replace", "default", "via", canary.Host().String()},
	}
	for _, step := range steps {
		if _, err := n.run.Run(ctx, commandTimeout, step[0], step[1:]...); err != nil {
			return err
		}
	}
	guestHost := canary.Guest().String() + "/32"
	if err := n.ensureRule(ctx, "filter", "FORWARD", "-s", guestHost, "-j", "ACCEPT"); err != nil {
		return err
	}
	return n.ensureRule(ctx, "filter", "FORWARD", "-d", guestHost, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
}

// PrepareNetwork installs SNAT and routing rules for the shared ENI. It is
// safe to run repeatedly, and before the shared ENI is attached.
//
// Worker traffic and the shared canary are translated to the shared ENI's
// private IP and routed out through the shared ENI, because the Internet
// gateway only maps that IP to the shared Elastic IP when packets leave
// through that ENI. The own canary leaves through the public interface with
// this NAT's own IP. The NAT is a dedicated instance, so these are its only
// POSTROUTING rules.
func (n *Network) PrepareNetwork(ctx context.Context) error {
	cfg := n.cfg
	shared := cfg.SharedAddress.Addr()
	rules := "*nat\n:" + snatChain + " - [0:0]\n-F " + snatChain + "\n"
	// The protected CIDRs may hold this NAT's own addresses, such as when they
	// are the whole VPC. Its own connections keep their own address.
	rules += "-A " + snatChain + " -m addrtype --src-type LOCAL -j RETURN\n"
	for _, source := range n.sharedSources() {
		// TCP takes ports in workerPorts, the only ones that get a reset for
		// an unknown connection (see protectHost).
		rules += fmt.Sprintf("-A %s -s %s -p tcp -j SNAT --to-source %s:%s\n", snatChain, source, shared, workerPorts)
		rules += fmt.Sprintf("-A %s -s %s -j SNAT --to-source %s\n", snatChain, source, shared)
	}
	// The own canary's probes take ports the NAT's own sockets never use, so
	// their replies stay tracked (see untrackOwnTraffic).
	for _, protocol := range []string{"tcp", "udp"} {
		rules += fmt.Sprintf("-A %s -s %s/32 -o %s -p %s -j SNAT --to-source %s:%s\n", snatChain, cfg.OwnCanary().Guest(), cfg.Instance.Interface, protocol, cfg.Instance.PrivateIP, canaryPorts)
	}
	rules += fmt.Sprintf("-A %s -s %s/32 -o %s -j SNAT --to-source %s\n", snatChain, cfg.OwnCanary().Guest(), cfg.Instance.Interface, cfg.Instance.PrivateIP)
	rules += "-F POSTROUTING\n-A POSTROUTING -j " + snatChain + "\nCOMMIT\n"
	if _, err := n.run.RunWithInput(ctx, commandTimeout, rules, "iptables-restore", "--noflush", "-w", "1"); err != nil {
		return err
	}
	if err := n.ensureSharedRules(ctx); err != nil {
		return err
	}
	for _, prefix := range cfg.ProtectedCIDRs {
		if err := n.ensureRule(ctx, "filter", "FORWARD", "-s", prefix.String(), "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := n.ensureRule(ctx, "filter", "FORWARD", "-d", prefix.String(), "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return err
		}
		// A worker packet from a connection this NAT does not know, such as one
		// opened on the peer moments before a takeover, would otherwise be
		// dropped in silence, and the client would hang until its own timeout.
		// A reset makes it reconnect at once.
		if err := n.ensureRule(ctx, "filter", "FORWARD", "-s", prefix.String(), "-p", "tcp", "-m", "conntrack", "--ctstate", "INVALID", "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
			return err
		}
	}
	return nil
}

// sharedSources are the sources that leave through the shared ENI.
func (n *Network) sharedSources() []netip.Prefix {
	return append(slices.Clone(n.cfg.ProtectedCIDRs), netip.PrefixFrom(n.cfg.SharedCanary().Guest(), 32))
}

// ensureSharedRules routes traffic from the shared sources through the shared
// ENI's route table. Until the ENI is attached the table is empty, so lookups
// fall through to the main table, while the fence keeps worker traffic closed.
func (n *Network) ensureSharedRules(ctx context.Context) error {
	output, err := n.run.Run(ctx, commandTimeout, "ip", "-j", "rule", "show", "table", sharedTable)
	if err != nil {
		return err
	}
	existing, err := parseRules(output)
	if err != nil {
		return err
	}
	if err := n.ensureLocalRules(ctx, existing); err != nil {
		return err
	}
	for _, source := range n.sharedSources() {
		present := slices.ContainsFunc(existing, func(rule routingRule) bool {
			return rule.Src == source.Addr().String() && rule.prefixLength() == source.Bits()
		})
		if present {
			continue
		}
		if _, err := n.run.Run(ctx, commandTimeout, "ip", "rule", "add", "from", source.String(), "lookup", sharedTable, "priority", sharedTable); err != nil {
			return err
		}
	}
	return nil
}

// ensureLocalRules routes traffic this NAT sends itself. The shared table's
// rules match sources, and the protected CIDRs may hold this NAT's own
// addresses, such as when they are the whole VPC. Its AWS API calls, lease
// renewals and conntrackd traffic must not leave through the shared ENI, so
// `iif lo`, which matches only packets that start on this host, sends them to
// the main table. Packets from the shared address, such as the resets
// protectHost sends remote servers after a takeover, must leave through the
// shared ENI, the only path where AWS maps that address to the shared Elastic
// IP. On a standby the shared table is empty, so they fall through.
// sharedRules lists the shared table's rules.
func (n *Network) ensureLocalRules(ctx context.Context, sharedRules []routingRule) error {
	shared := n.cfg.SharedAddress.Addr().String()
	if !slices.ContainsFunc(sharedRules, func(rule routingRule) bool {
		return rule.Priority == sharedSourcePriority && rule.Src == shared && rule.prefixLength() == 32
	}) {
		if _, err := n.run.Run(ctx, commandTimeout, "ip", "rule", "add", "from", shared, "lookup", sharedTable, "priority", strconv.Itoa(sharedSourcePriority)); err != nil {
			return err
		}
	}
	output, err := n.run.Run(ctx, commandTimeout, "ip", "-j", "rule", "show", "table", "main")
	if err != nil {
		return err
	}
	mainRules, err := parseRules(output)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(mainRules, func(rule routingRule) bool { return rule.Priority == localPriority && rule.Iif == "lo" }) {
		return nil
	}
	_, err = n.run.Run(ctx, commandTimeout, "ip", "rule", "add", "iif", "lo", "lookup", "main", "priority", strconv.Itoa(localPriority))
	return err
}

func parseRules(output string) ([]routingRule, error) {
	var rules []routingRule
	if output == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(output), &rules); err != nil {
		return nil, fmt.Errorf("failed to parse routing rules: %w", err)
	}
	return rules, nil
}

// EnsureForwarding turns IPv4 forwarding back on if something turned it off,
// such as a sysctl reload that restores the boot default. The fence still
// decides whether worker traffic passes, so this is safe on a standby too. It
// reports whether forwarding had been off.
func (n *Network) EnsureForwarding(ctx context.Context) (bool, error) {
	current, err := n.run.Run(ctx, commandTimeout, "sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil {
		return false, err
	}
	if current == "1" {
		return false, nil
	}
	_, err = n.run.Run(ctx, commandTimeout, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	return true, err
}

// ClaimShared stops systemd-networkd from configuring the shared ENI, so only
// natpair does. On Amazon Linux, networkd and amazon-ec2-net-utils
// otherwise run DHCP and their own routes on every attached interface, which
// replaces or removes the shared ENI's address and route. Run it before the
// ENI attaches: marking an attached interface unmanaged makes networkd remove
// its address. The file matches only the shared ENI's MAC, so it can never
// affect the primary interface.
func (n *Network) ClaimShared(ctx context.Context, mac string) error {
	if !macPattern.MatchString(mac) {
		return fmt.Errorf("invalid shared ENI MAC %q", mac)
	}
	contents := fmt.Sprintf("# Written by natpair, which configures the shared ENI itself.\n[Match]\nMACAddress=%s\n\n[Link]\nUnmanaged=yes\n", strings.ToLower(mac))
	// networkd reads its files as an unprivileged user, so the file must be
	// world-readable despite natpair.service's strict umask.
	if _, err := n.run.RunWithInput(ctx, commandTimeout, contents, "install", "-m", "0644", "/dev/stdin", networkdFile); err != nil {
		return err
	}
	_, err := n.run.Run(ctx, commandTimeout, "networkctl", "reload")
	return err
}

// DropStale deletes this NAT's own entries for connections translated to the
// shared address. A takeover runs it when the shared ENI is on the other NAT,
// which has served since this NAT last did, so these entries are out of date.
// An entry for a connection that has since ended can hold a shared address
// and port that the other NAT gave a new connection, and the copy of that
// connection then fails to install. On AWS, a NAT whose daemon was killed
// reset such a connection when ownership came back to it.
//
// Matching the translated address, not the protected CIDRs, leaves this
// NAT's own connections alone when the CIDRs hold its own address.
func (n *Network) DropStale(ctx context.Context) error {
	shared := n.cfg.SharedAddress.Addr().String()
	_, err := n.run.Run(ctx, commandTimeout, "conntrack", "-D", "--reply-dst", shared)
	// conntrack fails when it finds nothing to delete.
	if err != nil && !strings.Contains(err.Error(), "0 flow entries have been deleted") {
		return fmt.Errorf("failed to drop out-of-date connections to %s: %w", shared, err)
	}
	return nil
}

// ActivateShared configures the shared ENI after it attaches: its address,
// and the default route in the shared route table.
func (n *Network) ActivateShared(ctx context.Context, mac string) error {
	if !macPattern.MatchString(mac) {
		return fmt.Errorf("invalid shared ENI MAC %q", mac)
	}
	mac = strings.ToLower(mac)
	name, err := n.waitForInterface(ctx, mac)
	if err != nil {
		return err
	}
	gateway := n.gateway()
	steps := [][]string{
		{"ip", "link", "set", name, "up"},
		{"ip", "addr", "replace", n.cfg.SharedAddress.String(), "dev", name},
		// Replies to workers leave through the public interface, so the
		// strict reverse-path filter would drop their requests here.
		{"sysctl", "-qw", "net.ipv4.conf." + name + ".rp_filter=0"},
		{"ip", "route", "replace", "default", "via", gateway.String(), "dev", name, "table", sharedTable},
	}
	for _, step := range steps {
		if _, err := n.run.Run(ctx, commandTimeout, step[0], step[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// gateway is the VPC router of the shared ENI's subnet, which AWS always
// places at the first address of the subnet.
func (n *Network) gateway() netip.Addr {
	return n.cfg.SharedAddress.Masked().Addr().Next()
}

// link is one entry of `ip -j link`.
type link struct {
	Name    string `json:"ifname"`
	Address string `json:"address"`
}

// routingRule is one entry of `ip -j rule show`.
type routingRule struct {
	Priority int    `json:"priority"`
	Iif      string `json:"iif"`
	Src      string `json:"src"`
	SrcLen   int    `json:"srclen"`
}

// prefixLength returns the rule's source prefix length. `ip` leaves out
// srclen for a single host, such as "from 172.31.94.6".
func (r routingRule) prefixLength() int {
	if r.SrcLen == 0 {
		return 32
	}
	return r.SrcLen
}

func (n *Network) links(ctx context.Context) ([]link, error) {
	output, err := n.run.Run(ctx, commandTimeout, "ip", "-j", "link")
	if err != nil {
		return nil, err
	}
	var links []link
	if err := json.Unmarshal([]byte(output), &links); err != nil {
		return nil, fmt.Errorf("failed to parse interface list: %w", err)
	}
	return links, nil
}

// waitForInterface waits for the attached ENI to appear in Linux.
func (n *Network) waitForInterface(ctx context.Context, mac string) (string, error) {
	deadline := time.Now().Add(interfaceWaitPeriod)
	for {
		links, err := n.links(ctx)
		if err != nil {
			return "", err
		}
		for _, l := range links {
			if strings.ToLower(l.Address) == mac {
				return l.Name, nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("attached worker interface %s did not appear in Linux", mac)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (n *Network) ensureRule(ctx context.Context, table, chain string, rule ...string) error {
	check := append([]string{"-w", "1", "-t", table, "-C", chain}, rule...)
	if _, err := n.run.Run(ctx, commandTimeout, "iptables", check...); err == nil {
		return nil
	}
	add := append([]string{"-w", "1", "-t", table, "-A", chain}, rule...)
	_, err := n.run.Run(ctx, commandTimeout, "iptables", add...)
	return err
}
