package network

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// nftTable is the native nftables table that holds all of this package's
// rules when the configuration picks [config.FirewallNFTables]. The fence
// keeps its own table, so replacing this one never opens forwarding.
const nftTable = "natpair"

// nftPortRange returns an iptables port range, such as "32768:60999", in
// nftables' form, "32768-60999".
func nftPortRange(ports string) string {
	return strings.Replace(ports, ":", "-", 1)
}

// Flow offload. The flowtable forwards a connection's packets from the ingress
// hook of its devices, where it looks them up by addresses, ports and the
// device they arrive on. To fill in both directions, the kernel takes the
// route of the packet that offloads the connection, and looks up the route
// back as if the replies left through the device that packet arrived on. A
// worker's request arrives on the shared ENI, so the kernel asks for a route
// to the worker through the shared ENI. The main table has none, because
// replies to workers leave through the own interface, so the kernel takes
// the worker for a neighbor on the shared ENI's link, which never answers.
// In a local test, a stream stalled after 14 KB. So the forward chain marks
// the packet with offloadMark, and a routing rule sends lookups with the mark
// to the shared table, whose default route through the VPC router reaches
// the worker. Offloaded replies leave through the shared ENI, as replies of a
// NAT instance with one interface do.
const (
	offloadMark         = "0x10000"
	offloadMarkPriority = 6998
	// flowtable is the flowtable's name in the natpair table.
	flowtable = "fastpath"
)

// OffloadThrough lets the flowtable forward established worker connections
// that arrive on devices. It first puts the fence on those devices, so the
// fence stops offloaded packets as it stops the rest. If that fails, it
// installs no flowtable. Each takeover's PrepareNetwork removes the
// flowtable again.
func (n *Network) OffloadThrough(ctx context.Context, devices []string) error {
	if err := n.fence.CoverDevices(ctx, devices); err != nil {
		return err
	}
	n.offloadDevices = slices.Clone(devices)
	if err := n.applyNFTables(ctx); err != nil {
		n.offloadDevices = nil
		return err
	}
	return nil
}

// nonSYN matches TCP packets without SYN in nftables, as iptables' "! --syn"
// does: those whose SYN, RST, ACK and FIN flags are anything but SYN alone.
const nonSYN = "tcp flags & (fin|syn|rst|ack) != syn"

// applyNFTables replaces the natpair table with nftRuleset in one nftables
// transaction, so packets see either the old rules or the new ones, never a
// mix or none. Running it again with the same configuration installs the same
// rules, and resets the per-address reset limits and the counters.
func (n *Network) applyNFTables(ctx context.Context) error {
	_, err := n.run.RunWithInput(ctx, commandTimeout, n.nftRuleset(), "nft", "-f", "-")
	return err
}

// nftRuleset returns an nft script that replaces the natpair table with every
// rule this package installs with iptables: the host firewall of
// protectHost, the exemptions of untrackOwnTraffic, the canaries' forwarding
// rules of createCanary, and the forwarding and SNAT rules of PrepareNetwork.
// The comments there explain each rule. The script creates the table before
// deleting it, so the delete never fails on a NAT without one.
func (n *Network) nftRuleset() string {
	cfg := n.cfg
	own := cfg.Instance.PrivateIP.String()
	shared := cfg.SharedAddress.Addr().String()
	local := nftPortRange(localPorts)
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, "\t\t"+format+"\n", args...)
	}
	fmt.Fprintf(&b, "table ip %[1]s\ndelete table ip %[1]s\ntable ip %[1]s {\n", nftTable)
	// The remote addresses that got resets from the shared address recently,
	// each with its own limit, as iptables' hashlimit keeps them. An address
	// is forgotten 60 s after its last packet. When the set is full, packets
	// from new addresses get no reset and are dropped.
	b.WriteString("\tset reset_sources {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\ttimeout 60s\n\t}\n")
	// dropped counts what the host firewall drops without an answer.
	b.WriteString("\tcounter dropped {\n\t}\n")
	if len(n.offloadDevices) > 0 {
		// The fence's ingress chain on the same devices runs at priority
		// -10, before this.
		fmt.Fprintf(&b, "\tflowtable %s {\n\t\thook ingress priority 0\n\t\tdevices = { \"%s\" }\n\t}\n", flowtable, strings.Join(n.offloadDevices, `", "`))
	}

	// The raw priority runs before connection tracking, as the raw table does.
	b.WriteString("\tchain untrack_out {\n\t\ttype filter hook output priority raw; policy accept;\n")
	line(`oifname "lo" notrack`)
	line("ip saddr %s tcp sport %s notrack", own, local)
	for _, cidr := range cfg.Instance.VPCCIDRs {
		line("ip saddr %s ip daddr %s udp sport %s notrack", own, cidr, local)
	}
	for _, service := range linkLocalServices {
		line("ip saddr %s ip daddr %s udp sport %s udp dport %s notrack", own, service.address, local, service.port)
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain untrack_in {\n\t\ttype filter hook prerouting priority raw; policy accept;\n")
	line(`iifname "lo" notrack`)
	line("ip daddr %s tcp dport %s notrack", own, local)
	for _, cidr := range cfg.Instance.VPCCIDRs {
		line("ip daddr %s ip saddr %s udp dport %s notrack", own, cidr, local)
	}
	line("ip daddr %s ip saddr %s udp dport %s notrack", own, cfg.PeerIP, syncPort)
	for _, service := range linkLocalServices {
		line("ip daddr %s ip saddr %s udp sport %s udp dport %s notrack", own, service.address, service.port, local)
	}
	b.WriteString("\t}\n")

	// The policy drops what no rule accepts. The last rule does the same,
	// counted, as iptables' final DROP is.
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n")
	line(`iifname "lo" accept`)
	line("ct state established,related accept")
	for _, source := range append(slices.Clone(cfg.Instance.VPCCIDRs), netip.PrefixFrom(cfg.PeerIP, 32)) {
		line("ip saddr %s accept", source)
	}
	// iptables' socket match ignores sockets listening on any address, and
	// matches sockets in TIME_WAIT. nftables' socket expression has no key
	// that does both: its wildcard key never matches a socket in TIME_WAIT,
	// and its transparent key matches every socket it finds. So the first
	// rule drops packets for a listener on any address, and the second
	// accepts the rest. A socket with IP_TRANSPARENT set, which the NAT
	// doesn't use, gets nothing, where iptables would accept.
	ownReply := fmt.Sprintf("ip daddr %s tcp dport %s %s ct state untracked", own, local, nonSYN)
	line(`%s socket wildcard 1 counter name "dropped" drop`, ownReply)
	line("%s socket transparent 0 accept", ownReply)
	for _, service := range linkLocalServices {
		line("ip saddr %s ip daddr %s udp sport %s udp dport %s ct state untracked accept", service.address, own, service.port, local)
	}
	// Each kind has its own limit, as each iptables rule has.
	for _, kind := range []string{
		"destination-unreachable icmp code frag-needed",
		"destination-unreachable icmp code host-unreachable",
		"destination-unreachable icmp code port-unreachable",
		"time-exceeded",
	} {
		line("ip daddr %s icmp type %s limit rate 50/second burst 100 packets accept", own, kind)
	}
	line("ip daddr %s tcp dport %s %s ct state invalid update @reset_sources { ip saddr limit rate %s burst %s packets } counter reject with tcp reset",
		shared, workerPorts, nonSYN, resetLimit, resetBurst)
	line(`counter name "dropped" drop`)
	b.WriteString("\t}\n")

	// The fence's own forward chain runs first, at a lower priority, and drops
	// worker traffic while it's closed, before the reset below can answer it.
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n")
	// A connection is offloaded by a worker's packet once both directions
	// were seen, and TCP once the kernel tracks it as established. The
	// canaries' connections aren't offloaded: their replies leave through
	// the canary's own device, not the route the mark picks.
	if len(n.offloadDevices) > 0 {
		for _, prefix := range cfg.ProtectedCIDRs {
			line("ip saddr %s ct direction original ct state established meta l4proto { tcp, udp } meta mark set meta mark | %s flow add @%s", prefix, offloadMark, flowtable)
		}
	}
	for _, canary := range []netip.Addr{cfg.OwnCanary().Guest(), cfg.SharedCanary().Guest()} {
		line("ip saddr %s accept", canary)
		line("ip daddr %s ct state established,related accept", canary)
	}
	for _, prefix := range cfg.ProtectedCIDRs {
		line("ip saddr %s ct state new,established,related accept", prefix)
		line("ip daddr %s ct state established,related accept", prefix)
		line("ip saddr %s meta l4proto tcp ct state invalid reject with tcp reset", prefix)
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	line("fib saddr type local return")
	if cfg.FlowOffload {
		// The fence tells the shared canary's replies from workers' by their
		// ports on the shared address, so workers' UDP keeps out of
		// CanaryPorts too.
		for _, prefix := range cfg.ProtectedCIDRs {
			line("ip saddr %s meta l4proto { tcp, udp } snat to %s:%s", prefix, shared, workerPorts)
			line("ip saddr %s snat to %s", prefix, shared)
		}
		sharedCanary := netip.PrefixFrom(cfg.SharedCanary().Guest(), 32)
		line("ip saddr %s meta l4proto { tcp, udp } snat to %s:%s", sharedCanary, shared, CanaryPorts)
		line("ip saddr %s snat to %s", sharedCanary, shared)
	} else {
		for _, source := range n.sharedSources() {
			line("ip saddr %s meta l4proto tcp snat to %s:%s", source, shared, workerPorts)
			line("ip saddr %s snat to %s", source, shared)
		}
	}
	ownCanary := cfg.OwnCanary().Guest()
	for _, protocol := range []string{"tcp", "udp"} {
		line(`ip saddr %s oifname "%s" meta l4proto %s snat to %s:%s`, ownCanary, cfg.Instance.Interface, protocol, own, CanaryPorts)
	}
	line(`ip saddr %s oifname "%s" snat to %s`, ownCanary, cfg.Instance.Interface, own)
	b.WriteString("\t}\n}\n")
	return b.String()
}
