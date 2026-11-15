//go:build linux && campaign

// Package campaign runs fault tests against two real natpair NATs inside
// one disposable privileged container.
//
// Network namespaces stand in for the hosts: NATs "a" and "b", a "worker",
// and a "receiver" outside the pair. Each NAT also has its own mount
// namespace, so like a separate instance it has its own /var/lib/natpair,
// BPF filesystem and named network namespaces. conntrackd really copies
// connection state between the NATs, the kernel forwarding deadline is real,
// and the NATs run the real binary built with the localfixture tag. The lease
// uses a fake DynamoDB endpoint, and a takeover moves neighbor entries instead
// of EC2 interfaces, so EC2 latency and IAM are not covered.
package campaign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/lease"
	"github.com/artie-labs/natpair/internal/netns"
	"github.com/artie-labs/natpair/internal/probe/probetest"
)

var (
	outFlag   = flag.String("out", "", "directory for results and logs (default: a temporary directory)")
	casesFlag = flag.String("cases", "", "comma-separated case names to run (default: all)")
)

const (
	// machinesDir holds each NAT's mount namespace and BPF filesystem.
	machinesDir = "/run/natpair-campaign"
	sharedLAN   = "10.94.1.100"
	sharedWAN   = "10.94.2.100"
	uploadAddr  = "10.94.2.10:8444"
	// receiverAddr is the probe receiver, on the same host as the upload sink.
	receiverAddr = "10.94.2.10:8443"
)

type process struct {
	cmd  *exec.Cmd
	done chan error
}

// stop kills the process and everything it started.
func (p *process) stop() {
	if p == nil {
		return
	}
	// The process may already have exited, so a failed kill is expected.
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}

func (p *process) signal(t *testing.T, sig syscall.Signal) {
	require.NoError(t, syscall.Kill(-p.cmd.Process.Pid, sig))
}

type lab struct {
	t          *testing.T
	out        string
	binary     string
	caseName   string
	configs    map[string]config.NAT
	paths      map[string]string
	daemons    map[string]*process
	conntrackd map[string]*process
	dynamo     *fakeDynamoDB
	all        []*process
	results    []map[string]any
}

func TestCampaign(t *testing.T) {
	out := *outFlag
	if out == "" {
		out = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(out, 0o755))
	l := &lab{t: t, out: out, configs: map[string]config.NAT{}, paths: map[string]string{}, daemons: map[string]*process{}, conntrackd: map[string]*process{}}
	t.Cleanup(func() {
		for _, p := range l.all {
			p.stop()
		}
	})
	l.setup()

	l.runCase("healthy-renewal-and-standby-readiness", func() map[string]any {
		l.restartPair()
		time.Sleep(5 * time.Second)
		l.require(l.active("a") && !l.active("b"), "a serves and b stands by")
		l.require(l.fresh(), "new connections work")
		l.require(l.report("a").Ready && l.report("b").Ready, "both NATs hold copied connections")
		return map[string]any{"both_paths_verified": true, "copied_probe_tuples_verified": true}
	})

	// A stopped owner closes forwarding and releases the lease, so b takes over
	// without the takeover wait. A killed or frozen owner cannot, so b waits.
	for _, fault := range []string{"stop", "kill", "pause"} {
		l.runCase("controller-"+fault, func() map[string]any {
			l.restartPair()
			upload := l.stream()
			injected := bootclock.Now()
			switch fault {
			case "stop":
				l.daemons["a"].signal(l.t, syscall.SIGTERM)
			case "kill":
				l.daemons["a"].signal(l.t, syscall.SIGKILL)
			default:
				l.daemons["a"].signal(l.t, syscall.SIGSTOP)
			}
			l.wait(func() bool { return l.active("b") }, 15*time.Second, "b takes over")
			recovery := (bootclock.Now() - injected).Seconds()
			l.require(l.fresh(), "new connections work through b")
			if fault == "pause" {
				// A frozen owner that wakes up finds its grant expired and stays closed.
				l.daemons["a"].signal(l.t, syscall.SIGCONT)
				time.Sleep(2 * time.Second)
				l.require(!l.active("a"), "the resumed owner stays closed")
			} else {
				l.launch("a")
			}
			result := l.streamResult(upload)
			time.Sleep(2 * time.Second)
			l.require(l.active("b") && !l.active("a"), "a recovered NAT does not displace a healthy owner")
			return map[string]any{"local_takeover_s": recovery, "restarted_owner_stayed_standby": true, "upload": result}
		})
	}

	l.runCase("large-packet-active-path-failure", func() map[string]any {
		l.restartPair()
		upload := l.stream()
		injected := bootclock.Now()
		dropLarge := []string{"FORWARD", "-o", "wan", "-m", "length", "--length", "1200:65535", "-j", "DROP"}
		l.ns("a", append([]string{"iptables", "-I"}, dropLarge...)...)
		l.wait(func() bool { return l.active("b") }, 16*time.Second, "b takes over after large packets fail on a")
		recovery := (bootclock.Now() - injected).Seconds()
		l.require(l.fresh(), "new connections work through b")
		result := l.streamResult(upload)
		l.ns("a", append([]string{"iptables", "-D"}, dropLarge...)...)
		return map[string]any{"automatic_payload_detection": true, "local_takeover_s": recovery, "upload": result}
	})

	l.runCase("planned-maintenance", func() map[string]any {
		l.restartPair()
		upload := l.stream()
		injected := bootclock.Now()
		l.ns("a", l.binary, "maintenance")
		l.wait(func() bool { return l.active("b") }, 15*time.Second, "b takes over")
		recovery := (bootclock.Now() - injected).Seconds()
		result := l.streamResult(upload)
		l.launch("a")
		time.Sleep(2 * time.Second)
		l.require(!l.active("a") && l.active("b"), "maintenance survives a restart")
		return map[string]any{"local_takeover_s": recovery, "maintenance_survived_restart": true, "upload": result}
	})

	l.runCase("worker-side-path-failure-does-not-trigger-switch", func() map[string]any {
		// The NATs only probe from their canaries, so a failure that only
		// affects worker traffic goes unnoticed. Egress checks on the workers
		// alert a human instead.
		l.restartPair()
		l.ns("a", "iptables", "-I", "FORWARD", "1", "-i", "lan", "-j", "DROP")
		time.Sleep(10 * time.Second)
		l.require(l.active("a") && !l.active("b") && l.report("a").PathHealthy, "a keeps serving")
		l.require(!l.fresh(), "worker connections fail through a")
		l.ns("a", "iptables", "-D", "FORWARD", "-i", "lan", "-j", "DROP")
		l.require(l.fresh(), "worker connections work again once the rule is removed")
		return map[string]any{"takeover": false}
	})

	l.runCase("large-inbound-packet-active-path-failure", func() map[string]any {
		l.restartPair()
		injected := bootclock.Now()
		// Large replies coming back from the Internet are dropped, as on a path
		// that only loses full-size packets in one direction.
		dropLarge := []string{"FORWARD", "-i", "wan", "-m", "length", "--length", "1200:65535", "-j", "DROP"}
		l.ns("a", append([]string{"iptables", "-I"}, dropLarge...)...)
		l.wait(func() bool { return l.active("b") }, 16*time.Second, "b takes over after large inbound packets fail on a")
		recovery := (bootclock.Now() - injected).Seconds()
		l.ns("a", append([]string{"iptables", "-D"}, dropLarge...)...)
		l.require(l.fresh(), "new connections work through b")
		return map[string]any{"inbound_payload_detection": true, "local_takeover_s": recovery}
	})

	l.runCase("lossy-path-keeps-owner", func() map[string]any {
		// a loses 80% of the packets it forwards out, as on AWS when more
		// traffic arrived than the owner could forward. Its uploads time out,
		// but some handshakes complete, so it keeps serving instead of
		// handing b the same traffic. Only forwarded packets are dropped, so
		// a's lease renewals and copies to b still work.
		l.restartPair()
		lossy := []string{"FORWARD", "-o", "wan", "-m", "statistic", "--mode", "random", "--probability", "0.8", "-j", "DROP"}
		l.ns("a", append([]string{"iptables", "-I"}, lossy...)...)
		l.wait(func() bool { return l.report("a").Congested }, 10*time.Second, "a reports its path congested")
		// Long enough for b to prove its path and a to step down many times
		// over, were the failures counted.
		time.Sleep(20 * time.Second)
		stayed := l.active("a") && !l.active("b")
		l.ns("a", append([]string{"iptables", "-D"}, lossy...)...)
		l.require(stayed, "a keeps serving while its path is congested")
		l.wait(func() bool { return l.report("a").PathHealthy }, 10*time.Second, "a's uploads pass once the loss stops")
		return map[string]any{"owner_kept_while_congested": true}
	})

	l.runCase("dead-path-fails-over", func() map[string]any {
		l.restartPair()
		injected := bootclock.Now()
		dead := []string{"FORWARD", "-o", "wan", "-j", "DROP"}
		l.ns("a", append([]string{"iptables", "-I"}, dead...)...)
		l.wait(func() bool { return l.active("b") }, 16*time.Second, "b takes over after a's path goes dead")
		recovery := (bootclock.Now() - injected).Seconds()
		l.ns("a", append([]string{"iptables", "-D"}, dead...)...)
		l.require(l.fresh(), "new connections work through b")
		return map[string]any{"dead_path_detection": true, "local_takeover_s": recovery}
	})

	l.runCase("unknown-connection-is-reset", func() map[string]any {
		l.restartPair()
		// b stops receiving copies, so the upload below is unknown to it.
		blockCopies := []string{"INPUT", "-i", "wan", "-p", "udp", "--dport", "3780", "-j", "DROP"}
		l.ns("b", append([]string{"iptables", "-I"}, blockCopies...)...)
		results := make(chan uploadResult, 1)
		go func() { results <- upload("worker", uploadAddr, 60*time.Second, 30*time.Second, nil) }()
		time.Sleep(2 * time.Second)
		l.daemons["a"].signal(l.t, syscall.SIGKILL)
		l.wait(func() bool { return l.active("b") }, 20*time.Second, "b takes over without a copy of the upload")
		tookOver := bootclock.Now()
		var result uploadResult
		select {
		case result = <-results:
		case <-time.After(45 * time.Second):
			l.t.Fatalf("%s: upload neither failed nor finished", l.caseName)
		}
		failedAfter := (bootclock.Now() - tookOver).Seconds()
		l.ns("b", append([]string{"iptables", "-D"}, blockCopies...)...)
		// A reset lets the client reconnect at once. Without it, the client
		// waits for its own timeout, which some clients never set.
		l.require(strings.Contains(result.Error, "reset"), "the unknown connection is reset instead of hanging: "+result.Error)
		return map[string]any{"unknown_connection_reset": true, "failed_after_takeover_s": failedAfter, "upload_error": result.Error}
	})

	l.runCase("restarted-standby-keeps-idle-connections", func() map[string]any {
		l.restartPair()
		idle, err := dialUpload("worker", uploadAddr, 10*time.Second)
		l.require(err == nil, fmt.Sprintf("the idle connection opens: %v", err))
		l.require(idle.send(0) == nil, "the idle connection sends its first frame")
		l.waitCopied(idle.result.LocalPort)
		// A restarted conntrackd starts with no copies. The idle connection
		// sends nothing, so no update would copy it again.
		l.restartConntrackd("b")
		l.wait(func() bool { return l.report("b").Ready }, 30*time.Second, "b is ready again after its conntrackd restarted")
		l.wait(func() bool { return l.report("a").PeerReady }, 10*time.Second, "a sees that b is ready")
		l.ns("a", l.binary, "maintenance")
		l.wait(func() bool { return l.active("b") }, 15*time.Second, "b takes over")
		idle.skipIdle()
		if err := idle.send(2 * time.Second); err != nil {
			l.require(false, "the idle connection keeps working after the handover: "+err.Error())
		}
		result := idle.finish()
		l.require(result.OK && result.SameConnection, fmt.Sprintf("the idle connection finished on its original connection: %+v", result))
		return map[string]any{"idle_connection_survived_standby_restart": true, "upload": result}
	})

	// Blocking only the receiver port leaves worker traffic and the upload sink
	// working, as when the receiver goes down.
	blockReceiver := []string{"INPUT", "-p", "tcp", "--dport", "8443", "-j", "DROP"}

	l.runCase("receiver-outage-keeps-owner", func() map[string]any {
		l.restartPair()
		l.ns("receiver", append([]string{"iptables", "-I"}, blockReceiver...)...)
		// Long enough for several failed rounds on both NATs.
		time.Sleep(3 * health.StandbyInterval)
		stayed := l.active("a") && !l.active("b")
		works := l.fresh()
		l.ns("receiver", append([]string{"iptables", "-D"}, blockReceiver...)...)
		l.require(stayed, "a keeps serving while the receiver is down, because b cannot prove its path either")
		l.require(works, "workers still reach the Internet through a")
		return map[string]any{"owner_kept_during_receiver_outage": true}
	})

	l.runCase("standby-without-conntrackd-takes-over", func() map[string]any {
		l.restartPair()
		// b's conntrackd stays down, so b holds no copies, then a dies.
		l.conntrackd["b"].stop()
		injected := bootclock.Now()
		l.daemons["a"].signal(l.t, syscall.SIGKILL)
		l.wait(func() bool { return l.active("b") }, 25*time.Second, "b takes over without conntrackd")
		recovery := (bootclock.Now() - injected).Seconds()
		l.require(l.fresh(), "new connections work through b")
		l.startConntrackd("b")
		return map[string]any{"took_over_without_conntrackd": true, "local_takeover_s": recovery}
	})

	l.runCase("receiver-outage-during-owner-crash", func() map[string]any {
		l.restartPair()
		l.ns("receiver", append([]string{"iptables", "-I"}, blockReceiver...)...)
		l.wait(func() bool { return !l.report("b").CanForward && l.report("b").CanForwardUnverified }, 3*health.StandbyInterval, "b sees that it cannot prove its path")
		injected := bootclock.Now()
		l.daemons["a"].signal(l.t, syscall.SIGKILL)
		l.wait(func() bool { return l.active("b") }, 20*time.Second, "b takes over as a last resort")
		recovery := (bootclock.Now() - injected).Seconds()
		works := l.fresh()
		l.ns("receiver", append([]string{"iptables", "-D"}, blockReceiver...)...)
		l.require(works, "new connections work through b")
		l.wait(func() bool { return l.report("b").PathHealthy }, 10*time.Second, "b proves its path once the receiver is back")
		return map[string]any{"last_resort_takeover": true, "local_takeover_s": recovery}
	})

	l.runCase("maintenance-waits-for-ready-standby", func() map[string]any {
		l.restartPair()
		l.ns("b", "iptables", "-I", "FORWARD", "1", "-o", "wan", "-j", "DROP")
		// A standby checks its path every health.StandbyInterval.
		l.wait(func() bool { return !l.report("b").CanForward }, 3*health.StandbyInterval, "b reports it cannot forward")
		l.wait(func() bool { return !l.report("a").PeerReady }, 3*health.StandbyInterval, "a sees b is not ready")
		l.ns("a", l.binary, "maintenance")
		time.Sleep(3 * time.Second)
		l.require(l.fresh() && l.active("a") && !l.active("b"), "a keeps serving while b is not ready")
		l.ns("b", "iptables", "-D", "FORWARD", "-o", "wan", "-j", "DROP")
		l.wait(func() bool { return l.active("b") }, 6*health.StandbyInterval, "a hands over once b is ready")
		l.require(l.fresh(), "new connections work through b")
		return map[string]any{"waited_for_ready_standby": true, "handed_over_once_ready": true}
	})

	blockLease := []string{"OUTPUT", "-d", "10.94.3.1", "-p", "tcp", "--dport", "8080", "-j", "DROP"}

	l.runCase("lease-outage-keeps-owner", func() map[string]any {
		l.restartPair()
		upload := l.stream()
		for _, name := range []string{"a", "b"} {
			l.ns(name, append([]string{"iptables", "-I"}, blockLease...)...)
		}
		// Longer than both the 4 s hold and the 6 s takeover wait.
		time.Sleep(10 * time.Second)
		l.require(l.active("a") && !l.active("b") && l.fresh(), "a keeps forwarding while neither NAT reaches the lease service")
		for _, name := range []string{"a", "b"} {
			l.ns(name, append([]string{"iptables", "-D"}, blockLease...)...)
		}
		revision := l.leaseRecord().Revision
		l.wait(func() bool {
			record := l.leaseRecord()
			return record.Revision != revision && strings.HasPrefix(record.Owner, "i-a/")
		}, 5*time.Second, "a renews its own lease once the service returns")
		result := l.streamResult(upload)
		l.require(l.active("a") && !l.active("b"), "a still serves")
		return map[string]any{"owner_kept_forwarding": true, "renewed_after_outage": true, "upload": result}
	})

	l.runCase("owner-loses-lease-service", func() map[string]any {
		l.restartPair()
		upload := l.stream()
		injected := bootclock.Now()
		l.ns("a", append([]string{"iptables", "-I"}, blockLease...)...)
		l.wait(func() bool { return l.active("b") }, 20*time.Second, "b takes the lease and moves the shared path")
		recovery := (bootclock.Now() - injected).Seconds()
		l.require(l.fresh(), "new connections work through b")
		result := l.streamResult(upload)
		l.ns("a", append([]string{"iptables", "-D"}, blockLease...)...)
		l.wait(func() bool { return !l.active("a") }, 5*time.Second, "a closes once it sees b took the lease")
		return map[string]any{"local_takeover_s": recovery, "old_owner_closed_after_service_returned": true, "upload": result}
	})

	l.runCase("kernel-expiry-without-controller", func() map[string]any {
		owner := "b"
		if l.active("a") {
			owner = "a"
		}
		for _, name := range []string{"a", "b"} {
			l.daemons[name].stop()
		}
		for range 3 {
			l.ns(owner, l.binary, "fence-close", "--config", l.paths[owner])
		}
		rules := l.ns(owner, "iptables", "-S", "FORWARD")
		// One jump each way per protected CIDR, however often the fence restarts.
		jumps := 2 * len(l.configs[owner].ProtectedCIDRs)
		l.require(strings.Count(rules, "-j NATPAIR") == jumps, "guard jumps do not stack after restarts: "+rules)
		l.require(!l.fresh(), "the fence starts closed")
		deadline := bootclock.Now() + 1500*time.Millisecond
		l.writeDeadline(owner, deadline)
		l.require(l.fresh(), "forwarding works before the deadline")
		time.Sleep(deadline - bootclock.Now() + 100*time.Millisecond)
		l.require(!l.fresh(), "forwarding stops at the deadline without a controller")
		l.writeDeadline(owner, deadline)
		l.require(!l.fresh(), "rewriting the expired deadline keeps forwarding closed")
		return map[string]any{"guard_jumps_after_three_restarts": jumps, "forwarded_before_deadline": true, "blocked_after_deadline": true, "expired_rewrite_blocked": true, "controller_running": false}
	})
}

// runCase runs one fault case and records its result.
func (l *lab) runCase(name string, fn func() map[string]any) {
	if *casesFlag != "" && !slices.Contains(strings.Split(*casesFlag, ","), name) {
		return
	}
	l.caseName = name
	started := bootclock.Now()
	result := fn()
	result["case"], result["passed"], result["elapsed_s"] = name, true, (bootclock.Now() - started).Seconds()
	l.results = append(l.results, result)
	encoded, _ := json.MarshalIndent(l.results, "", "  ")
	require.NoError(l.t, os.WriteFile(filepath.Join(l.out, "results.json"), encoded, 0o644))
	line, _ := json.Marshal(result)
	l.t.Log(string(line))
}

func (l *lab) setup() {
	l.binary = filepath.Join(l.out, "natpair")
	// The checkout is mounted into the container, so on a Linux host it belongs
	// to another user than the container's root, and git refuses to read it.
	// The test binary needs no version control stamp.
	l.run("go", "build", "-buildvcs=false", "-tags", "localfixture", "-o", l.binary, "../../cmd/natpair")
	// Persistent mount namespaces must be pinned on a private mount.
	require.NoError(l.t, os.MkdirAll(machinesDir, 0o700))
	require.NoError(l.t, syscall.Mount(machinesDir, machinesDir, "", syscall.MS_BIND, ""))
	require.NoError(l.t, syscall.Mount("", machinesDir, "", syscall.MS_PRIVATE, ""))

	for subnet, label := range []string{"lan", "wan", "sync"} {
		l.run("ip", "link", "add", "br-"+label, "type", "bridge")
		l.run("ip", "addr", "add", fmt.Sprintf("10.94.%d.1/24", subnet+1), "dev", "br-"+label)
		l.run("ip", "link", "set", "br-"+label, "up")
	}
	type edge struct {
		label  string
		subnet int
		host   int
	}
	hosts := map[string][]edge{
		"a":        {{"lan", 1, 2}, {"wan", 2, 2}, {"sync", 3, 2}},
		"b":        {{"lan", 1, 3}, {"wan", 2, 3}, {"sync", 3, 3}},
		"worker":   {{"lan", 1, 10}},
		"receiver": {{"wan", 2, 10}},
	}
	for name := range hosts {
		l.run("ip", "netns", "add", name)
	}
	// The fixture's takeover changes neighbor entries on the worker and the
	// receiver, standing in for the EC2 API. The NAT machines reach those hosts
	// through handles under machinesDir, because each machine has its own
	// /run/netns.
	for _, name := range []string{"worker", "receiver"} {
		handle := filepath.Join(machinesDir, "hosts", name)
		require.NoError(l.t, os.MkdirAll(filepath.Dir(handle), 0o700))
		require.NoError(l.t, os.WriteFile(handle, nil, 0o600))
		require.NoError(l.t, syscall.Mount("/run/netns/"+name, handle, "", syscall.MS_BIND, ""))
	}
	for name := range nats {
		l.addMachine(name)
	}
	for name, edges := range hosts {
		l.ns(name, "ip", "link", "set", "lo", "up")
		for _, e := range edges {
			outside := name + "-" + e.label
			l.run("ip", "link", "add", outside, "type", "veth", "peer", "name", outside+"p")
			l.run("ip", "link", "set", outside, "master", "br-"+e.label)
			l.run("ip", "link", "set", outside, "up")
			l.run("ip", "link", "set", outside+"p", "netns", name)
			l.ns(name, "ip", "link", "set", outside+"p", "name", e.label)
			l.ns(name, "ip", "addr", "add", fmt.Sprintf("10.94.%d.%d/24", e.subnet, e.host), "dev", e.label)
			l.ns(name, "ip", "link", "set", e.label, "up")
		}
	}
	l.ns("worker", "ip", "route", "add", "10.94.2.0/24", "via", sharedLAN)

	caFile, certificate := l.writeCertificate()

	l.dynamo = newFakeDynamoDB()
	l.serve("", "10.94.3.1:8080", l.dynamo, nil)
	// Every process the campaign starts reaches its fakes through the AWS SDK's
	// and Go's standard variables, so the NAT configs carry no test settings.
	// Each NAT's namespace has its own metadata server at the same address.
	for name, value := range map[string]string{
		"AWS_ENDPOINT_URL_DYNAMODB":         "http://10.94.3.1:8080",
		"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://127.0.0.1:8081",
		"AWS_ACCESS_KEY_ID":                 "campaign",
		"AWS_REGION":                        "us-east-1",
		"AWS_SECRET_ACCESS_KEY":             "campaign",
		"SSL_CERT_FILE":                     caFile,
	} {
		l.t.Setenv(name, value)
	}
	// The probe receiver, standing in for the Lambda.
	l.serve("receiver", receiverAddr, probetest.Handler(), &certificate)
	var sink net.Listener
	require.NoError(l.t, netns.Do("receiver", func() error {
		var err error
		sink, err = net.Listen("tcp4", "0.0.0.0:8444")
		return err
	}))
	go serveUploads(sink)
	l.t.Cleanup(func() { _ = sink.Close() })

	for _, nat := range []struct {
		name       string
		host, peer int
	}{{"a", 2, 3}, {"b", 3, 2}} {
		dir := filepath.Join(l.out, nat.name)
		l.configs[nat.name] = config.NAT{
			LeaseTable: "campaign", SharedENI: "eni-shared", SharedAddress: netip.MustParsePrefix(sharedWAN + "/24"),
			SharedPublicIP: netip.MustParseAddr(sharedWAN),
			// The sync subnet holds each NAT's own address for its lease calls,
			// as a VPC-wide protected CIDR holds the NAT's own address on AWS.
			// Its own traffic must still leave from that address.
			ProtectedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.94.1.0/24"), netip.MustParsePrefix("10.94.3.0/24")},
			ProbeURL:       "https://" + receiverAddr + "/nat",
			PeerIP:         netip.MustParseAddr(fmt.Sprintf("10.94.2.%d", nat.peer)),
		}
		l.paths[nat.name] = filepath.Join(l.out, nat.name+".json")
		l.writeConfig(nat.name, "setup")

		var links []struct {
			Address string `json:"address"`
		}
		lanMAC, wanMAC := "", ""
		for _, iface := range []string{"lan", "wan"} {
			require.NoError(l.t, json.Unmarshal([]byte(l.ns(nat.name, "ip", "-j", "link", "show", iface)), &links))
			if iface == "lan" {
				lanMAC = links[0].Address
			} else {
				wanMAC = links[0].Address
			}
		}
		neighbors, _ := json.Marshal([]map[string]string{
			{"netns": filepath.Join(machinesDir, "hosts", "worker"), "interface": "lan", "address": sharedLAN, "mac": lanMAC},
			{"netns": filepath.Join(machinesDir, "hosts", "receiver"), "interface": "wan", "address": sharedWAN, "mac": wanMAC},
		})
		require.NoError(l.t, os.WriteFile(filepath.Join(dir, "neighbors.json"), neighbors, 0o644))
		management := fmt.Sprintf("10.94.2.%d", nat.host)
		l.serve(nat.name, "127.0.0.1:8081", fakeMetadata(map[string]string{
			"instance-id": "i-" + nat.name, "placement/region": "us-east-1",
			"local-ipv4": management, "public-ipv4": management, "mac": wanMAC,
			"network/interfaces/macs/" + wanMAC + "/vpc-ipv4-cidr-blocks": "10.94.0.0/16",
		}), nil)

		// Both NATs hold the shared addresses. A takeover points the worker's and
		// receiver's neighbor entries at the owner, standing in for the ENI move.
		l.ns(nat.name, "ip", "addr", "add", sharedLAN+"/32", "dev", "lan")
		l.ns(nat.name, "ip", "addr", "add", sharedWAN+"/32", "dev", "wan")
		l.ns(nat.name, l.binary, "bootstrap", "--config", l.paths[nat.name])
		// bootstrap wrote conntrackd's configuration.
		l.conntrackd[nat.name] = l.spawn(nat.name, nat.name+"-conntrackd.log", nil, "conntrackd", "-C", config.ConntrackdConfigPath)
	}

	environment, _ := json.MarshalIndent(map[string]string{
		"kernel":     l.run("uname", "-r"),
		"conntrackd": l.run("conntrackd", "-v"),
		"go":         l.run("go", "version"),
		"scope":      "Local Linux namespaces in one privileged container, one network and mount namespace per NAT, no AWS APIs",
	}, "", "  ")
	require.NoError(l.t, os.WriteFile(filepath.Join(l.out, "environment.json"), environment, 0o644))
}

// restartPair restarts both NATs on a fresh lease record, with a serving and
// b standing by.
func (l *lab) restartPair() {
	for _, name := range []string{"a", "b"} {
		l.daemons[name].stop()
		l.ns(name, l.binary, "fence-close", "--config", l.paths[name])
		if err := os.Remove(filepath.Join(l.out, name, "maintenance")); err != nil && !errors.Is(err, os.ErrNotExist) {
			require.NoError(l.t, err)
		}
		l.writeConfig(name, l.caseName)
	}
	l.launch("a")
	l.wait(func() bool { return l.active("a") }, 20*time.Second, "a takes ownership")
	l.launch("b")
	l.wait(func() bool { return l.report("b").Ready }, 20*time.Second, "b holds copied connections")
	l.wait(func() bool { return l.report("a").PeerCanTakeover && l.report("a").PeerReady }, 10*time.Second, "a sees that b is ready")
	l.require(l.fresh(), "new connections work through a")
}

// launch starts a NAT's daemon, stopping any daemon already running for it.
func (l *lab) launch(name string) {
	l.daemons[name].stop()
	env := []string{
		"NATPAIR_FIXTURE_NEIGHBORS=" + filepath.Join(config.StateDir, "neighbors.json"),
	}
	l.daemons[name] = l.spawn(name, l.caseName+"-"+name+".log", env, l.binary, "run", "--config", l.paths[name])
}

// stream starts an 18-second paced upload from the worker and waits until the
// standby holds a copy of its connection.
func (l *lab) stream() chan uploadResult {
	results := make(chan uploadResult, 1)
	ports := make(chan int, 1)
	go func() {
		results <- upload("worker", uploadAddr, 18*time.Second, 20*time.Second, func(port int) { ports <- port })
	}()
	var port int
	select {
	case port = <-ports:
	case result := <-results:
		l.t.Fatalf("%s: upload failed to start: %s", l.caseName, result.Error)
	}
	l.waitCopied(port)
	return results
}

// waitCopied waits until b holds a copy of the worker connection from port.
func (l *lab) waitCopied(port int) {
	l.wait(func() bool {
		cache, err := command.Run(l.t.Context(), 2*time.Second, "nsenter", append(l.enter("b"), "conntrackd", "-C", config.ConntrackdConfigPath, "-e")...)
		return err == nil && strings.Contains(cache, fmt.Sprintf("sport=%d ", port))
	}, 10*time.Second, "b holds a copy of the worker connection")
}

// restartConntrackd restarts a NAT's conntrackd, which starts with empty
// caches, as after a reboot or an upgrade.
func (l *lab) restartConntrackd(name string) {
	old := l.conntrackd[name]
	old.signal(l.t, syscall.SIGTERM)
	select {
	case <-old.done:
	case <-time.After(5 * time.Second):
		old.stop()
	}
	l.startConntrackd(name)
}

// startConntrackd starts a NAT's conntrackd with empty caches.
func (l *lab) startConntrackd(name string) {
	if err := os.Remove(filepath.Join(l.out, name, "conntrackd.lock")); err != nil && !errors.Is(err, os.ErrNotExist) {
		require.NoError(l.t, err)
	}
	l.conntrackd[name] = l.spawn(name, l.caseName+"-"+name+"-conntrackd.log", nil, "conntrackd", "-C", config.ConntrackdConfigPath)
}

func (l *lab) streamResult(results chan uploadResult) uploadResult {
	select {
	case result := <-results:
		l.require(result.OK && result.SameConnection, fmt.Sprintf("the upload finished on its original connection: %+v", result))
		return result
	case <-time.After(30 * time.Second):
		l.t.Fatalf("%s: upload did not finish", l.caseName)
		return uploadResult{}
	}
}

// fresh reports whether a new connection from the worker can upload 8 KiB,
// which spans several full-size packets.
func (l *lab) fresh() bool {
	return upload("worker", uploadAddr, 0, 500*time.Millisecond, nil).OK
}

// report returns a NAT's latest health report from the board, or an empty
// report if its latest post is stale.
func (l *lab) report(name string) health.Report {
	var current struct {
		IntervalMS int64         `json:"interval_ms"`
		Report     health.Report `json:"report"`
	}
	posted := l.dynamo.attributes(l.configs[name].LeaseRecordID(config.BoardRecord), "nat:i-"+name)["nat:i-"+name]
	if json.Unmarshal([]byte(posted.value), &current) != nil || time.Since(posted.at) > health.StaleAfter(time.Duration(current.IntervalMS)*time.Millisecond) {
		return health.Report{}
	}
	return current.Report
}

// leaseRecord returns the current case's lease record from the fake DynamoDB.
func (l *lab) leaseRecord() lease.Record {
	var record lease.Record
	posted := l.dynamo.attributes(l.configs["a"].LeaseRecordID("ownership"), "value")["value"]
	_ = json.Unmarshal([]byte(posted.value), &record)
	return record
}

// active reports whether a NAT's fence is open: its kernel forwarding
// deadline is still ahead.
func (l *lab) active(name string) bool {
	deadlines, err := ebpf.LoadPinnedMap(l.deadlinePath(name), nil)
	if err != nil {
		return false
	}
	defer deadlines.Close()
	var deadline uint64
	return deadlines.Lookup(uint32(0), &deadline) == nil && time.Duration(deadline) > bootclock.Now()
}

func (l *lab) deadlinePath(name string) string {
	return filepath.Join(machinesDir, name, "bpf", "natpair", "deadline")
}

func (l *lab) writeDeadline(name string, deadline time.Duration) {
	deadlines, err := ebpf.LoadPinnedMap(l.deadlinePath(name), nil)
	require.NoError(l.t, err)
	defer deadlines.Close()
	require.NoError(l.t, deadlines.Put(uint32(0), uint64(deadline)))
}

// writeConfig writes a NAT's configuration with a lease record for pair, so
// each case starts from a fresh lease.
func (l *lab) writeConfig(name, pair string) {
	cfg := l.configs[name]
	cfg.Pair = pair
	l.configs[name] = cfg
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	require.NoError(l.t, err)
	require.NoError(l.t, os.WriteFile(l.paths[name], encoded, 0o600))
}

func (l *lab) writeCertificate() (string, tls.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(l.t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "natpair campaign receiver"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("10.94.2.10")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(l.t, err)
	caFile := filepath.Join(l.out, "receiver.pem")
	require.NoError(l.t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	return caFile, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve answers HTTP on address inside namespace, with TLS if certificate is set.
func (l *lab) serve(namespace, address string, handler http.Handler, certificate *tls.Certificate) {
	var listener net.Listener
	require.NoError(l.t, netns.Do(namespace, func() error {
		var err error
		listener, err = net.Listen("tcp4", address)
		return err
	}))
	if certificate != nil {
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{*certificate}})
	}
	// Probes through a NAT that is failing on purpose leave half-open TLS
	// handshakes, which are expected here.
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.Serve(listener) }()
	l.t.Cleanup(func() { _ = server.Close() })
}

func (l *lab) spawn(namespace, logName string, env []string, args ...string) *process {
	if namespace != "" {
		args = append(append([]string{"nsenter"}, l.enter(namespace)...), args...)
	}
	output, err := os.Create(filepath.Join(l.out, logName))
	require.NoError(l.t, err)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = output, output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(l.t, cmd.Start())
	p := &process{cmd: cmd, done: make(chan error, 1)}
	go func() {
		p.done <- cmd.Wait()
		_ = output.Close()
	}()
	l.all = append(l.all, p)
	return p
}

func (l *lab) run(name string, args ...string) string {
	output, err := command.Run(l.t.Context(), 2*time.Minute, name, args...)
	require.NoError(l.t, err, "%s: %s %v", l.caseName, name, args)
	return output
}

func (l *lab) ns(name string, args ...string) string {
	return l.run("nsenter", append(l.enter(name), args...)...)
}

// nats are the hosts that run a NAT, each on its own machine.
var nats = map[string]bool{"a": true, "b": true}

// enter returns nsenter's arguments for running a command on a host. A NAT
// also enters its machine's mount namespace.
func (l *lab) enter(name string) []string {
	args := []string{"--net=/run/netns/" + name}
	if nats[name] {
		args = append(args, "--mount="+filepath.Join(machinesDir, name, "mnt"))
	}
	return append(args, "--")
}

// addMachine gives a NAT its own mount namespace, pinned under machinesDir.
// Its /var/lib/natpair is the NAT's directory in the results, its BPF
// filesystem is also mounted under machinesDir so the campaign can write the
// kernel deadline, and its named network namespaces are its own.
func (l *lab) addMachine(name string) {
	dir := filepath.Join(machinesDir, name)
	state := filepath.Join(l.out, name)
	for _, path := range []string{filepath.Join(dir, "bpf"), state, config.StateDir} {
		require.NoError(l.t, os.MkdirAll(path, 0o700))
	}
	require.NoError(l.t, syscall.Mount("bpf", filepath.Join(dir, "bpf"), "bpf", 0, ""))
	require.NoError(l.t, os.WriteFile(filepath.Join(dir, "mnt"), nil, 0o600))
	l.run("unshare", "--mount="+filepath.Join(dir, "mnt"), "--propagation", "private", "sh", "-ec", fmt.Sprintf(
		"mount --bind %s %s && mount --bind %s /sys/fs/bpf && mkdir -p /run/netns && mount -t tmpfs tmpfs /run/netns",
		state, config.StateDir, filepath.Join(dir, "bpf")))
}

func (l *lab) wait(condition func() bool, timeout time.Duration, description string) {
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			l.t.Fatalf("%s: timed out waiting until %s", l.caseName, description)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (l *lab) require(ok bool, description string) {
	if !ok {
		l.t.Fatalf("%s: expected %s", l.caseName, description)
	}
}

// fakeMetadata serves the instance metadata paths natpair reads, with the
// IMDSv2 token exchange.
func fakeMetadata(values map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", "21600")
			_, _ = w.Write([]byte("token"))
			return
		}
		value, ok := values[strings.TrimPrefix(r.URL.Path, "/latest/meta-data/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(value))
	})
}
