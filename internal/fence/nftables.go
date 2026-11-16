package fence

import (
	"context"
	"fmt"
	"net/netip"
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
// absolute, so it caps that. The nft command only takes whole seconds, so it's
// rounded down, and the cap closes forwarding up to 1 s before the grant ends
// once renewals stop. A wall clock step backwards can only extend the grant
// if a write is delayed too. A step forwards closes forwarding until the next
// renewal writes a new cap.
type NFTables struct {
	protected []netip.Prefix
}

// NewNFTables returns the nftables fence for the protected worker CIDRs.
func NewNFTables(protected []netip.Prefix) (*NFTables, error) {
	if len(protected) == 0 {
		return nil, fmt.Errorf("protected worker CIDRs are required")
	}
	return &NFTables{protected: protected}, nil
}

// Install replaces the fence's table with a closed one in one transaction.
// Installing again is safe and closes forwarding.
func (f *NFTables) Install(ctx context.Context) error {
	return runNFT(ctx, f.closedRuleset())
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
	return runNFT(context.Background(), armCommands(remaining, time.Now()))
}

// Close stops forwarding immediately.
func (f *NFTables) Close() error {
	return runNFT(context.Background(), fmt.Sprintf("flush set ip %s grant\n", nftTable))
}

func runNFT(ctx context.Context, script string) error {
	_, err := command.RunWithInput(ctx, nftTimeout, script, "nft", "-f", "-")
	return err
}

// closedRuleset returns an nft script that replaces the fence's table with
// one whose grant set is empty. It creates the table before deleting it, so
// the delete never fails on a NAT without one. Protected CIDRs may overlap,
// such as a VPC CIDR and one of its subnets, which auto-merge allows.
func (f *NFTables) closedRuleset() string {
	elements := make([]string, len(f.protected))
	for i, prefix := range f.protected {
		elements[i] = prefix.String()
	}
	return fmt.Sprintf("table ip %[1]s\ndelete table ip %[1]s\ntable ip %[1]s {\n", nftTable) +
		"\tset protected {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n" +
		"\t\telements = { " + strings.Join(elements, ", ") + " }\n\t}\n" +
		// Every IPv4 packet's version is 4, so this set matches all of them
		// while it holds 4.
		"\tset grant {\n\t\ttypeof ip version\n\t\tflags timeout\n\t}\n" +
		"\tcounter dropped {\n\t}\n" +
		"\tchain forward {\n\t\ttype filter hook forward priority filter - 10; policy accept;\n" +
		"\t\t" + strings.Join(closedRules, "\n\t\t") + "\n\t}\n}\n"
}

// closedRules drop protected traffic, counted in the dropped counter.
var closedRules = []string{
	`ip saddr @protected counter name "dropped" drop`,
	`ip daddr @protected counter name "dropped" drop`,
}

// armCommands returns an nft script that opens forwarding for remaining from
// wall, the wall clock time Arm read, in one transaction. The rule's accept
// only ends this chain: the network package's forward chain still decides
// what is forwarded.
func armCommands(remaining time.Duration, wall time.Time) string {
	script := fmt.Sprintf("flush set ip %[1]s grant\n"+
		"add element ip %[1]s grant { 4 timeout %[2]dms }\n"+
		"flush chain ip %[1]s forward\n"+
		"add rule ip %[1]s forward ip version @grant meta time < %[3]d accept\n", nftTable, remaining.Milliseconds(), wall.Add(remaining).Unix())
	for _, rule := range closedRules {
		script += "add rule ip " + nftTable + " forward " + rule + "\n"
	}
	return script
}
