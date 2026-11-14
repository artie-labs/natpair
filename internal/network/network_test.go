package network_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/network"
)

const sharedMAC = "02:00:00:00:00:01"

func testConfig(t *testing.T) config.NAT {
	cfg, err := config.LoadNAT("../config/testdata/nat.json")
	require.NoError(t, err)
	cfg.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.16.0/20"), netip.MustParsePrefix("10.0.32.0/20")}
	cfg.Instance = instance.Facts{ID: "i-test", PrivateIP: netip.MustParseAddr("10.0.1.10"), PublicIP: netip.MustParseAddr("192.0.2.10"), Interface: "ens5", VPCCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}}
	return cfg
}

// commandLog records commands and answers the ones whose output matters.
type commandLog struct {
	commands  []string
	inputs    []string
	responses map[string]string
	fail      map[string]error
}

func (l *commandLog) runner() *mocks.FakeRunner {
	runner := &mocks.FakeRunner{}
	respond := func(name string, args []string, input string) (string, error) {
		line := strings.Join(append([]string{name}, args...), " ")
		l.commands = append(l.commands, line)
		if input != "" {
			l.inputs = append(l.inputs, input)
		}
		if err, ok := l.fail[line]; ok {
			delete(l.fail, line)
			return "", err
		}
		if response, ok := l.responses[line]; ok {
			return response, nil
		}
		switch line {
		case "ip -j link":
			return `[{"ifname":"lo","address":"00:00:00:00:00:00"},{"ifname":"ens6","address":"` + sharedMAC + `"}]`, nil
		case "ip -j rule show table 7001":
			// Two rules already exist from an earlier run. `ip` leaves out
			// srclen for a single host.
			return `[{"priority":7001,"src":"10.0.16.0","srclen":20,"table":"7001"},{"priority":7001,"src":"198.18.0.6","table":"7001"}]`, nil
		}
		return "", nil
	}
	runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		return respond(name, args, "")
	})
	runner.RunWithInputCalls(func(_ context.Context, _ time.Duration, input, name string, args ...string) (string, error) {
		return respond(name, args, input)
	})
	return runner
}

func TestBootstrap(t *testing.T) {
	log := &commandLog{}
	fence := &mocks.FakeNetworkFence{}
	runner := log.runner()
	runner.RunCalls(func(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
		require.Equal(t, 1, fence.InstallCallCount(), "the fence must close forwarding before anything else")
		return log.runner().Run(ctx, timeout, name, args...)
	})
	require.NoError(t, network.New(testConfig(t), fence, runner).Bootstrap(t.Context()))
	assert.Contains(t, log.commands, "ip netns add natpair-own")
	assert.Contains(t, log.commands, "ip -n natpair-shared route replace default via 198.18.0.5")
	// Forwarding turns on only after the canaries exist, before SNAT is installed.
	forwarding := slices.Index(log.commands, "sysctl -qw net.ipv4.ip_forward=1")
	assert.Greater(t, forwarding, slices.Index(log.commands, "ip -n natpair-shared route replace default via 198.18.0.5"))
	// The host firewall's restore comes first, and SNAT's last.
	var restores []int
	for i, c := range log.commands {
		if c == "iptables-restore --noflush -w 1" {
			restores = append(restores, i)
		}
	}
	require.Len(t, restores, 2)
	assert.Less(t, forwarding, restores[1])
	// The conntrack settings exist only once the module is loaded.
	conntrackSettings := slices.IndexFunc(log.commands, func(c string) bool { return strings.Contains(c, "nf_conntrack_tcp_loose") })
	require.Contains(t, log.commands, "modprobe nf_conntrack")
	// The connection table matches conntrackd's limit, not the kernel's default from memory.
	assert.Contains(t, log.commands, "sysctl -qw net.netfilter.nf_conntrack_max=262144 net.netfilter.nf_conntrack_buckets=65536")
	// New inbound connections to the NAT itself come only from the VPC or the
	// peer, because its security group lets the whole Internet through.
	require.NotEmpty(t, log.inputs)
	assert.Equal(t, "*filter\n:NATPAIR_INPUT - [0:0]\n-F NATPAIR_INPUT\n"+
		"-A NATPAIR_INPUT -i lo -j ACCEPT\n"+
		"-A NATPAIR_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n"+
		"-A NATPAIR_INPUT -s 10.0.0.0/16 -j ACCEPT\n"+
		"-A NATPAIR_INPUT -s 10.0.1.11/32 -j ACCEPT\n"+
		// TCP gets a reset, so a remote server learns at once that a connection is gone.
		"-A NATPAIR_INPUT -p tcp -j REJECT --reject-with tcp-reset\n"+
		"-A NATPAIR_INPUT -j DROP\nCOMMIT\n", log.inputs[0])
	assert.Contains(t, log.commands, "iptables -w 1 -t filter -C INPUT -j NATPAIR_INPUT")
	assert.Less(t, slices.Index(log.commands, "modprobe nf_conntrack"), conntrackSettings)
}

func TestClaimShared(t *testing.T) {
	{
		log := &commandLog{}
		n := network.New(testConfig(t), &mocks.FakeNetworkFence{}, log.runner())
		require.NoError(t, n.ClaimShared(t.Context(), "02:FF:CB:C7:B2:EB"))
		// networkd reads the file as an unprivileged user.
		assert.Equal(t, []string{"install -m 0644 /dev/stdin /etc/systemd/network/10-natpair-shared.network", "networkctl reload"}, log.commands)
		require.Len(t, log.inputs, 1)
		// Only the shared ENI matches, never the primary interface.
		assert.Contains(t, log.inputs[0], "[Match]\nMACAddress=02:ff:cb:c7:b2:eb\n")
		assert.Contains(t, log.inputs[0], "[Link]\nUnmanaged=yes\n")
	}
	{
		log := &commandLog{}
		n := network.New(testConfig(t), &mocks.FakeNetworkFence{}, log.runner())
		assert.ErrorContains(t, n.ClaimShared(t.Context(), ""), `invalid shared ENI MAC ""`)
		assert.Empty(t, log.commands)
	}
}

func TestDropStale(t *testing.T) {
	{
		// Only entries translated to the shared address are deleted, so the
		// NAT's own connections survive even when the protected CIDRs are the
		// whole VPC and hold its own address. None to delete isn't an error.
		cfg := testConfig(t)
		cfg.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}
		log := &commandLog{fail: map[string]error{
			"conntrack -D --reply-dst 10.0.1.100": errors.New("conntrack failed: exit status 1: conntrack v1.4.6 (conntrack-tools): 0 flow entries have been deleted."),
		}}
		n := network.New(cfg, &mocks.FakeNetworkFence{}, log.runner())
		require.NoError(t, n.DropStale(t.Context()))
		assert.Equal(t, []string{"conntrack -D --reply-dst 10.0.1.100"}, log.commands)
	}
	{
		// Any other failure is reported
		log := &commandLog{fail: map[string]error{"conntrack -D --reply-dst 10.0.1.100": errors.New("conntrack failed: exit status 1: operation not permitted")}}
		n := network.New(testConfig(t), &mocks.FakeNetworkFence{}, log.runner())
		assert.EqualError(t, n.DropStale(t.Context()), "failed to drop out-of-date connections to 10.0.1.100: conntrack failed: exit status 1: operation not permitted")
	}
}

func TestPrepareNetwork(t *testing.T) {
	log := &commandLog{}
	require.NoError(t, network.New(testConfig(t), &mocks.FakeNetworkFence{}, log.runner()).PrepareNetwork(t.Context()))
	require.Len(t, log.inputs, 1)
	assert.Equal(t, "*nat\n:NATPAIR_SNAT - [0:0]\n-F NATPAIR_SNAT\n"+
		// The NAT's own connections keep their own address.
		"-A NATPAIR_SNAT -m addrtype --src-type LOCAL -j RETURN\n"+
		// Workers and the shared canary leave with the shared ENI's IP.
		"-A NATPAIR_SNAT -s 10.0.16.0/20 -j SNAT --to-source 10.0.1.100\n"+
		"-A NATPAIR_SNAT -s 10.0.32.0/20 -j SNAT --to-source 10.0.1.100\n"+
		"-A NATPAIR_SNAT -s 198.18.0.6/32 -j SNAT --to-source 10.0.1.100\n"+
		// The own canary leaves through this NAT's own interface and IP.
		"-A NATPAIR_SNAT -s 198.18.0.2/32 -o ens5 -j SNAT --to-source 10.0.1.10\n"+
		// The chain is the only POSTROUTING rule.
		"-F POSTROUTING\n-A POSTROUTING -j NATPAIR_SNAT\nCOMMIT\n", log.inputs[0])
	// Only the missing routing rule is added.
	assert.NotContains(t, log.commands, "ip rule add from 10.0.16.0/20 lookup 7001 priority 7001")
	assert.NotContains(t, log.commands, "ip rule add from 198.18.0.6/32 lookup 7001 priority 7001")
	assert.Contains(t, log.commands, "ip rule add from 10.0.32.0/20 lookup 7001 priority 7001")
	// The NAT's own traffic from the shared address uses the shared table, and
	// the rest of its own traffic the main table, both ahead of the shared rules.
	shared := slices.Index(log.commands, "ip rule add from 10.0.1.100 lookup 7001 priority 6999")
	local := slices.Index(log.commands, "ip rule add iif lo lookup main priority 7000")
	require.GreaterOrEqual(t, shared, 0)
	assert.Less(t, shared, local)
	assert.Less(t, local, slices.Index(log.commands, "ip rule add from 10.0.32.0/20 lookup 7001 priority 7001"))
	assert.Contains(t, log.commands, "iptables -w 1 -t filter -C FORWARD -s 10.0.16.0/20 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT")
	// Worker packets from unknown connections are reset, not dropped in silence.
	assert.Contains(t, log.commands, "iptables -w 1 -t filter -C FORWARD -s 10.0.32.0/20 -p tcp -m conntrack --ctstate INVALID -j REJECT --reject-with tcp-reset")
	// conntrackd's copies to the peer leave through the own interface from
	// the own address, never through the shared ENI. Every takeover sets the
	// route again, in case the kernel dropped it since boot.
	assert.Contains(t, log.commands, "ip route replace 10.0.1.11/32 dev ens5 src 10.0.1.10")
}

func TestActivateShared(t *testing.T) {
	{
		cfg := testConfig(t)
		log := &commandLog{}
		n := network.New(cfg, &mocks.FakeNetworkFence{}, log.runner())
		require.NoError(t, n.ActivateShared(t.Context(), "02:00:00:00:00:01"))
		assert.Contains(t, log.commands, "ip addr replace 10.0.1.100/24 dev ens6")
		// The VPC router is always the subnet's first address.
		assert.Contains(t, log.commands, "ip route replace default via 10.0.1.1 dev ens6 table 7001")
	}
	{
		n := network.New(testConfig(t), &mocks.FakeNetworkFence{}, (&commandLog{}).runner())
		assert.ErrorContains(t, n.ActivateShared(t.Context(), "not-a-mac"), `invalid shared ENI MAC "not-a-mac"`)
	}
	{
		// A failed step is returned
		log := &commandLog{fail: map[string]error{"ip link set ens6 up": errors.New("no such device")}}
		n := network.New(testConfig(t), &mocks.FakeNetworkFence{}, log.runner())
		assert.ErrorContains(t, n.ActivateShared(t.Context(), sharedMAC), "no such device")
	}
}

func TestEnsureForwarding(t *testing.T) {
	{
		log := &commandLog{}
		runner := log.runner()
		runner.RunReturnsOnCall(0, "0", nil)
		runner.RunReturnsOnCall(1, "", nil)
		restored, err := network.New(testConfig(t), &mocks.FakeNetworkFence{}, runner).EnsureForwarding(t.Context())
		require.NoError(t, err)
		assert.True(t, restored)
		_, _, name, args := runner.RunArgsForCall(1)
		assert.Equal(t, "sysctl -qw net.ipv4.ip_forward=1", strings.Join(append([]string{name}, args...), " "))
	}
	{
		runner := (&commandLog{}).runner()
		runner.RunReturns("1", nil)
		restored, err := network.New(testConfig(t), &mocks.FakeNetworkFence{}, runner).EnsureForwarding(t.Context())
		require.NoError(t, err)
		assert.False(t, restored)
		assert.Equal(t, 1, runner.RunCallCount())
	}
}
