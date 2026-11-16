package fence

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/command"
)

const (
	// nftTable holds the fence when the firewall is native nftables. It's
	// apart from the network package's table, so replacing that one never
	// opens forwarding.
	nftTable = "natpair_fence"
	// nftTimeout bounds each nft command.
	nftTimeout = 2 * time.Second
)

// NFTables is the fence for the native nftables firewall. nftables can't run
// a BPF program as a match, so the deadline lives in the kernel as a set
// element with a timeout instead of in a BPF map.
//
// Its forward chain runs before the network package's forward chain, at a
// lower priority, and drops packets to or from a protected CIDR, except while
// the grant set holds an element and the wall clock is before the deadline in
// the rule. A drop in any chain is final, so no accept elsewhere, in natpair's
// tables or another tool's, can let a packet past it.
//
// The kernel checks an element's timeout on every lookup, so forwarding
// stops when it runs out even if the daemon is frozen or killed. The timeout
// counts from when the kernel commits the element, though, so a write that
// is delayed after Arm computed it, such as by a freeze in between, would
// extend the grant by the delay. The wall clock deadline in the rule is
// absolute, so it caps that. nft only takes whole seconds for it, so it's
// rounded up: the timeout still ends a grant on time, and a delayed write
// extends it by less than 1 s, within the 2 s between the lease's hold and
// the peer's takeover wait. Rounded down, it closed forwarding up to 1 s
// early whenever renewals stopped, and in the local fault campaign 3 of 6
// crashed or frozen owners then paused an upload for 6.4 s instead of 3.2 s,
// because TCP's next retry came after the takeover. A wall clock step
// backwards can only extend the grant if a write is delayed too. A step
// forwards closes forwarding until the next renewal writes a new cap.
//
// With flow offload, a flowtable forwards established worker connections
// from the ingress hook of the devices it lists, before the forward hook, so
// the forward chain never sees them. The fence then also keeps a netdev table
// of the same name whose ingress chain runs on those devices before the
// flowtable and checks a second grant set, written in the same transactions.
// See [FastPath].
type NFTables struct {
	protected []netip.Prefix
	// fastPath is set when the NAT offloads connections to a flowtable.
	fastPath *FastPath
}

// FastPath says which packets the fence's ingress chain drops while closed:
// every TCP and UDP packet that a flowtable could forward. At the ingress
// hook, before connection tracking and address translation, those are
// packets from a protected CIDR to anywhere but Shared, which are worker
// connections leaving, and packets to Shared, which are their replies. Only
// the shared canary's replies get through, by their ports on Shared, so a
// takeover can check its path before the fence opens. Other packets to
// Shared, such as those for connections the NAT doesn't know, are dropped
// too while the fence is closed, instead of answered with a reset.
type FastPath struct {
	// Shared is the shared ENI's private address.
	Shared netip.Addr
	// CanaryPorts is the range, such as "61000-65535", that the shared
	// canary's connections are translated to on Shared. Worker connections
	// must never use it.
	CanaryPorts string
}

// NewNFTables returns the nftables fence for the protected worker CIDRs.
func NewNFTables(protected []netip.Prefix) (*NFTables, error) {
	if len(protected) == 0 {
		return nil, fmt.Errorf("protected worker CIDRs are required")
	}
	return &NFTables{protected: protected}, nil
}

// NewNFTablesWithFastPath returns the nftables fence for a NAT that offloads
// connections to a flowtable.
func NewNFTablesWithFastPath(protected []netip.Prefix, fastPath FastPath) (*NFTables, error) {
	if !fastPath.Shared.Is4() || !portRangePattern.MatchString(fastPath.CanaryPorts) {
		return nil, fmt.Errorf("the fast path fence needs the shared IPv4 address and the canary's port range")
	}
	f, err := NewNFTables(protected)
	if err != nil {
		return nil, err
	}
	f.fastPath = &fastPath
	return f, nil
}

var (
	portRangePattern = regexp.MustCompile(`^[0-9]{1,5}-[0-9]{1,5}$`)
	// devicePattern accepts the interface names Linux gives ENIs and veths,
	// and nothing that could change the meaning of an nft script.
	devicePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
)

// Install replaces the fence's table with a closed one in one transaction.
// Installing again is safe and closes forwarding. With a fast path, the same
// transaction closes the netdev table's ingress chain, but leaves the devices
// it runs on as they were, because a flowtable may still list them.
func (f *NFTables) Install(ctx context.Context) error {
	return runNFT(ctx, f.installScript())
}

func (f *NFTables) installScript() string {
	script := f.closedRuleset()
	if f.fastPath != nil {
		script += f.closedFastPath()
	}
	return script
}

// CoverDevices puts the netdev table's ingress chain on devices, closed, so
// that a flowtable can list them. Without a fast path it fails, because then
// nothing would stop the flowtable's packets.
func (f *NFTables) CoverDevices(ctx context.Context, devices []string) error {
	script, err := f.coverScript(devices)
	if err != nil {
		return err
	}
	return runNFT(ctx, script)
}

// coverScript returns an nft script that replaces the netdev table with a
// closed one whose ingress chain runs on devices.
func (f *NFTables) coverScript(devices []string) (string, error) {
	if f.fastPath == nil {
		return "", fmt.Errorf("this fence has no fast path to cover devices with")
	}
	if len(devices) == 0 {
		return "", fmt.Errorf("no devices to cover")
	}
	quoted := make([]string, len(devices))
	for i, device := range devices {
		if !devicePattern.MatchString(device) {
			return "", fmt.Errorf("invalid device name %q", device)
		}
		quoted[i] = `"` + device + `"`
	}
	return fmt.Sprintf("table netdev %[1]s\ndelete table netdev %[1]s\ntable netdev %[1]s {\n", nftTable) +
		f.protectedSet() + grantAndCounter +
		"\tchain check {\n\t\t" + strings.Join(f.fastPathClosedRules(), "\n\t\t") + "\n\t}\n" +
		// The flowtable hooks in at priority 0, so this chain runs first.
		"\tchain ingress {\n\t\ttype filter hook ingress devices = { " + strings.Join(quoted, ", ") + " } priority -10; policy accept;\n" +
		"\t\tjump check\n\t}\n}\n", nil
}

// Arm allows forwarding until deadline, measured on the boot clock.
func (f *NFTables) Arm(deadline time.Duration) error {
	remaining := deadline - bootclock.Now()
	// The timeout is written in whole milliseconds, and nftables takes
	// "timeout 0ms" as no timeout at all.
	if remaining < time.Millisecond {
		return fmt.Errorf("an expired grant cannot open forwarding")
	}
	// The controller's Fence interface has no context, because the BPF
	// fence's writes are system calls. The command timeout bounds this one.
	return runNFT(context.Background(), f.armScript(remaining, time.Now()))
}

// armScript returns an nft script that opens forwarding for remaining from
// wall, the wall clock time Arm read, in one transaction: through the forward
// chain, and with a fast path, through its ingress chain too.
func (f *NFTables) armScript(remaining time.Duration, wall time.Time) string {
	script := armCommands("ip", "forward", closedRules, remaining, wall)
	if f.fastPath != nil {
		script += armCommands("netdev", "check", f.fastPathClosedRules(), remaining, wall)
	}
	return script
}

// Close stops forwarding immediately.
func (f *NFTables) Close() error {
	return runNFT(context.Background(), f.closeScript())
}

func (f *NFTables) closeScript() string {
	script := fmt.Sprintf("flush set ip %s grant\n", nftTable)
	if f.fastPath != nil {
		script += fmt.Sprintf("flush set netdev %s grant\n", nftTable)
	}
	return script
}

func runNFT(ctx context.Context, script string) error {
	_, err := command.RunWithInput(ctx, nftTimeout, script, "nft", "-f", "-")
	return err
}

// closedRuleset returns an nft script that replaces the fence's table with
// one whose grant set is empty. It creates the table before deleting it, so
// the delete never fails on a NAT without one.
func (f *NFTables) closedRuleset() string {
	return fmt.Sprintf("table ip %[1]s\ndelete table ip %[1]s\ntable ip %[1]s {\n", nftTable) +
		f.protectedSet() + grantAndCounter +
		"\tchain forward {\n\t\ttype filter hook forward priority filter - 10; policy accept;\n" +
		"\t\t" + strings.Join(closedRules, "\n\t\t") + "\n\t}\n}\n"
}

// protectedSet declares the set of protected CIDRs. They may overlap, such
// as a VPC CIDR and one of its subnets, which auto-merge allows.
func (f *NFTables) protectedSet() string {
	return "\tset protected {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n" +
		"\t\telements = { " + f.protectedElements() + " }\n\t}\n"
}

func (f *NFTables) protectedElements() string {
	elements := make([]string, len(f.protected))
	for i, prefix := range f.protected {
		elements[i] = prefix.String()
	}
	return strings.Join(elements, ", ")
}

// grantAndCounter declare the grant set and the dropped counter, the same in
// both tables. Every IPv4 packet's version is 4, so the grant set matches all
// of them while it holds 4.
const grantAndCounter = "\tset grant {\n\t\ttypeof ip version\n\t\tflags timeout\n\t}\n" +
	"\tcounter dropped {\n\t}\n"

// closedRules drop protected traffic, counted in the dropped counter.
var closedRules = []string{
	`ip saddr @protected counter name "dropped" drop`,
	`ip daddr @protected counter name "dropped" drop`,
}

// fastPathClosedRules drop, in the netdev table's check chain, the packets
// [FastPath] describes.
func (f *NFTables) fastPathClosedRules() []string {
	shared := f.fastPath.Shared.String()
	return []string{
		fmt.Sprintf(`ip saddr @protected ip daddr != %s meta l4proto { tcp, udp } counter name "dropped" drop`, shared),
		fmt.Sprintf(`ip daddr %s meta l4proto { tcp, udp } th dport != %s counter name "dropped" drop`, shared, f.fastPath.CanaryPorts),
	}
}

// closedFastPath returns an nft script that creates the netdev table if it's
// missing, and empties its grant set and rewrites its check chain closed. It
// never deletes the table, so the ingress chain that [NFTables.CoverDevices]
// put on the flowtable's devices stays on them. The set definitions match
// CoverDevices', which "add" requires of a set that already exists.
func (f *NFTables) closedFastPath() string {
	script := fmt.Sprintf("add table netdev %[1]s\n"+
		"add set netdev %[1]s protected { type ipv4_addr; flags interval; auto-merge; }\n"+
		"flush set netdev %[1]s protected\n"+
		"add element netdev %[1]s protected { %[2]s }\n"+
		"add set netdev %[1]s grant { typeof ip version; flags timeout; }\n"+
		"flush set netdev %[1]s grant\n"+
		"add counter netdev %[1]s dropped\n"+
		"add chain netdev %[1]s check\n"+
		"flush chain netdev %[1]s check\n", nftTable, f.protectedElements())
	for _, rule := range f.fastPathClosedRules() {
		script += "add rule netdev " + nftTable + " check " + rule + "\n"
	}
	return script
}

// armCommands returns the nft commands that open chain, in the fence's table
// of family, for remaining from wall, and drop with closed after the grant.
// The rule's accept only ends this chain: the network package's forward
// chain, or the flowtable, still decides what is forwarded.
func armCommands(family, chain string, closed []string, remaining time.Duration, wall time.Time) string {
	end := wall.Add(remaining)
	limit := end.Unix()
	if end.Nanosecond() > 0 {
		limit++
	}
	script := fmt.Sprintf("flush set %[1]s %[2]s grant\n"+
		"add element %[1]s %[2]s grant { 4 timeout %[3]dms }\n"+
		"flush chain %[1]s %[2]s %[4]s\n"+
		"add rule %[1]s %[2]s %[4]s ip version @grant meta time < %[5]d accept\n", family, nftTable, remaining.Milliseconds(), chain, limit)
	for _, rule := range closed {
		script += fmt.Sprintf("add rule %s %s %s %s\n", family, nftTable, chain, rule)
	}
	return script
}
