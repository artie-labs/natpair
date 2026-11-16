//go:build linux && privileged

package network_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/fence"
	"github.com/artie-labs/natpair/internal/netns"
	"github.com/artie-labs/natpair/internal/network"
)

// natFence is the part of either fence the benchmarks use.
type natFence interface {
	Install(ctx context.Context) error
	Arm(deadline time.Duration) error
}

// benchLab is a worker, bn-worker, forwarding through a NAT, bn-nat, to a
// host outside the VPC, bn-out, with the NAT's rules from cfg.
type benchLab struct {
	cfg    config.NAT
	run    func(args ...string) string
	fence  natFence
	worker netip.Addr
	out    netip.Addr
}

// newBenchLab builds the namespaces.
func newBenchLab(b *testing.B, firewall config.Firewall) *benchLab {
	// Cleanups run after b.Context is cancelled.
	ctx := context.WithoutCancel(b.Context())
	run := func(args ...string) string {
		output, err := command.Run(ctx, time.Minute, args[0], args[1:]...)
		require.NoError(b, err)
		return output
	}
	for _, namespace := range []string{"bn-worker", "bn-nat", "bn-out"} {
		// The benchmark framework can call a benchmark again before the
		// cleanups of its earlier call run.
		_, _ = command.Run(ctx, 5*time.Second, "ip", "netns", "del", namespace)
		run("ip", "netns", "add", namespace)
		b.Cleanup(func() { _, _ = command.Run(ctx, 5*time.Second, "ip", "netns", "del", namespace) })
	}
	run("ip", "link", "add", "lan", "netns", "bn-nat", "type", "veth", "peer", "name", "lan", "netns", "bn-worker")
	run("ip", "link", "add", "wan", "netns", "bn-nat", "type", "veth", "peer", "name", "wan", "netns", "bn-out")
	for _, step := range [][]string{
		{"bn-nat", "addr", "add", "10.94.20.1/24", "dev", "lan"},
		{"bn-nat", "addr", "add", "10.94.21.1/24", "dev", "wan"},
		{"bn-nat", "addr", "add", "10.94.21.100/24", "dev", "wan"},
		{"bn-worker", "addr", "add", "10.94.20.2/24", "dev", "lan"},
		{"bn-out", "addr", "add", "10.94.21.2/24", "dev", "wan"},
		{"bn-nat", "link", "set", "lan", "up"},
		{"bn-nat", "link", "set", "wan", "up"},
		{"bn-nat", "link", "set", "lo", "up"},
		{"bn-worker", "link", "set", "lan", "up"},
		{"bn-worker", "link", "set", "lo", "up"},
		{"bn-out", "link", "set", "wan", "up"},
		{"bn-out", "link", "set", "lo", "up"},
		{"bn-worker", "route", "add", "default", "via", "10.94.20.1"},
	} {
		run(append([]string{"ip", "-n"}, step...)...)
	}
	run("ip", "netns", "exec", "bn-nat", "sysctl", "-qw", "net.ipv4.ip_forward=1")
	cfg, err := config.LoadNAT("../config/testdata/nat.json")
	require.NoError(b, err)
	cfg.Firewall = firewall
	cfg.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("10.94.20.0/24")}
	cfg.SharedAddress = netip.MustParsePrefix("10.94.21.100/24")
	cfg.PeerIP = netip.MustParseAddr("10.94.21.3")
	cfg.Instance.PrivateIP, cfg.Instance.Interface = netip.MustParseAddr("10.94.21.1"), "wan"
	cfg.Instance.VPCCIDRs = []netip.Prefix{netip.MustParsePrefix("10.94.20.0/24")}
	l := &benchLab{cfg: cfg, run: run, worker: netip.MustParseAddr("10.94.20.2"), out: netip.MustParseAddr("10.94.21.2")}
	switch firewall {
	case config.FirewallNFTables:
		l.fence, err = fence.NewNFTables(cfg.ProtectedCIDRs)
	case config.FirewallIPTables:
		dir := b.TempDir()
		require.NoError(b, unix.Mount("bpf", dir, "bpf", 0, ""))
		b.Cleanup(func() { _ = unix.Unmount(dir, 0) })
		l.fence, err = fence.New(dir, cfg.ProtectedCIDRs)
	}
	require.NoError(b, err)
	return l
}

// install installs the fence and every rule Bootstrap and a takeover
// install, then opens the fence for an hour.
func (l *benchLab) install(b *testing.B) {
	n := network.New(l.cfg, l.fence, network.SystemRunner{})
	require.NoError(b, netns.Do("bn-nat", func() error {
		if err := l.fence.Install(b.Context()); err != nil {
			return err
		}
		if err := n.InstallFirewall(b.Context()); err != nil {
			return err
		}
		if err := n.PrepareNetwork(b.Context()); err != nil {
			return err
		}
		return l.fence.Arm(bootclock.Now() + time.Hour)
	}))
}

// BenchmarkFirewallInstall times what Bootstrap's firewall steps and the
// takeover after it run, in a fresh namespace each time: installing the
// fence, the host firewall, the exemptions, SNAT and forwarding, and opening
// the fence. The namespaces' setup isn't timed.
func BenchmarkFirewallInstall(b *testing.B) {
	for _, firewall := range firewalls {
		b.Run(string(firewall), func(b *testing.B) {
			for range b.N {
				b.StopTimer()
				l := newBenchLab(b, firewall)
				b.StartTimer()
				l.install(b)
				b.StopTimer()
				for _, namespace := range []string{"bn-worker", "bn-nat", "bn-out"} {
					l.run("ip", "netns", "del", namespace)
				}
				b.StartTimer()
			}
		})
	}
}

// BenchmarkPrepareNetwork times a takeover's PrepareNetwork on a NAT whose
// rules are already installed, which is on the takeover's path.
func BenchmarkPrepareNetwork(b *testing.B) {
	for _, firewall := range firewalls {
		b.Run(string(firewall), func(b *testing.B) {
			l := newBenchLab(b, firewall)
			l.install(b)
			n := network.New(l.cfg, l.fence, network.SystemRunner{})
			b.ResetTimer()
			require.NoError(b, netns.Do("bn-nat", func() error {
				for range b.N {
					if err := n.PrepareNetwork(b.Context()); err != nil {
						return err
					}
				}
				return nil
			}))
		})
	}
}

// BenchmarkArm times one renewal's write of the fence's deadline, which the
// owner does every 500 ms.
func BenchmarkArm(b *testing.B) {
	for _, firewall := range firewalls {
		b.Run(string(firewall), func(b *testing.B) {
			l := newBenchLab(b, firewall)
			l.install(b)
			b.ResetTimer()
			require.NoError(b, netns.Do("bn-nat", func() error {
				for range b.N {
					if err := l.fence.Arm(bootclock.Now() + 4*time.Second); err != nil {
						return err
					}
				}
				return nil
			}))
		})
	}
}

// BenchmarkForwarding measures how many small UDP packets a second, and how
// much TCP, the NAT forwards from the worker to the host outside, with each
// firewall's full rules. The worker, the NAT and the host share the
// machine's CPUs, so the numbers compare the firewalls on this machine only.
// It needs iperf3, and runs once per count: -benchtime 1x. Run it several
// times rather than with -count, so the firewalls alternate.
func BenchmarkForwarding(b *testing.B) {
	for _, firewall := range firewalls {
		b.Run(string(firewall), func(b *testing.B) {
			l := newBenchLab(b, firewall)
			l.install(b)
			server := exec.Command("ip", "netns", "exec", "bn-out", "iperf3", "-s", "-B", l.out.String())
			require.NoError(b, server.Start())
			b.Cleanup(func() {
				_ = server.Process.Kill()
				_ = server.Wait()
			})
			// The server takes a moment to listen.
			require.Eventually(b, func() bool {
				output, err := command.Run(b.Context(), time.Second, "ip", "netns", "exec", "bn-out", "ss", "-Htln", "sport", "=", ":5201")
				return err == nil && strings.Contains(output, "5201")
			}, 5*time.Second, 50*time.Millisecond)
			iperf := func(args ...string) map[string]any {
				output := l.run(append([]string{"ip", "netns", "exec", "bn-worker", "iperf3", "-c", l.out.String(), "-J", "-t", "10"}, args...)...)
				var result struct {
					End map[string]any `json:"end"`
				}
				require.NoError(b, json.Unmarshal([]byte(output), &result))
				return result.End
			}
			b.ResetTimer()
			for range b.N {
				udp := iperf("-u", "-b", "0", "-l", "64", "-P", "2")["sum"].(map[string]any)
				received := udp["packets"].(float64) - udp["lost_packets"].(float64)
				b.ReportMetric(received/udp["seconds"].(float64), "udp-pps")
				tcp := iperf("-P", "2")["sum_received"].(map[string]any)
				b.ReportMetric(tcp["bits_per_second"].(float64)/1e9, "tcp-Gbps")
			}
		})
	}
}

// BenchmarkRulesetSize reports, for each firewall's full rules, how many
// nftables rules and expressions the kernel holds, how many of those
// expressions run an iptables match or target through nftables'
// compatibility layer, and the size of `nft list ruleset`.
func BenchmarkRulesetSize(b *testing.B) {
	for _, firewall := range firewalls {
		b.Run(string(firewall), func(b *testing.B) {
			l := newBenchLab(b, firewall)
			l.install(b)
			var listing struct {
				NFTables []struct {
					Rule *struct {
						Expressions []map[string]any `json:"expr"`
					} `json:"rule"`
				} `json:"nftables"`
			}
			require.NoError(b, json.Unmarshal([]byte(l.run("ip", "netns", "exec", "bn-nat", "nft", "-j", "list", "ruleset")), &listing))
			var rules, expressions, compat int
			for _, object := range listing.NFTables {
				if object.Rule == nil {
					continue
				}
				rules++
				expressions += len(object.Rule.Expressions)
				for _, expression := range object.Rule.Expressions {
					if _, ok := expression["xt"]; ok {
						compat++
					}
				}
			}
			for range b.N {
			}
			b.ReportMetric(float64(rules), "rules")
			b.ReportMetric(float64(expressions), "expressions")
			b.ReportMetric(float64(compat), "xt-expressions")
			b.ReportMetric(float64(len(l.run("ip", "netns", "exec", "bn-nat", "nft", "list", "ruleset"))), "listing-bytes")
		})
	}
}
