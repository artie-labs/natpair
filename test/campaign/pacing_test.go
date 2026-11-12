//go:build linux && campaign

package campaign

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/netns"
)

const (
	// sinkAddr counts the bytes of heavy uploads, and sourceAddr streams
	// heavy downloads. Both are on the receiver host.
	sinkAddr   = "10.94.2.10:8445"
	sourceAddr = "10.94.2.10:8446"
	// pacingStartMbps is the bandwidth cap the NATs start from. There are no
	// AWS allowance counters here, so the cap only rises, by 1% a second
	// while traffic presses it.
	pacingStartMbps = 200
)

// lightWorkers send little and often. heavyWorker sends as fast as it can.
var (
	heavyWorker  = netip.MustParseAddr("10.94.1.10")
	lightWorkers = []netip.Addr{
		netip.MustParseAddr("10.94.1.11"), netip.MustParseAddr("10.94.1.12"),
		netip.MustParseAddr("10.94.1.13"), netip.MustParseAddr("10.94.1.14"),
	}
)

// pacingCases runs the traffic pacing cases. They need sch_fq, which some
// kernels, such as Docker Desktop's, lack.
func (l *lab) pacingCases() {
	l.setupPacing()

	l.runCase("pacing-off-installs-nothing", func() map[string]any {
		l.pacing = nil
		l.restartPair()
		for _, name := range []string{"a", "b"} {
			l.require(!l.pacingInstalled(name), name+" has no pacing qdiscs, filters or pinned programs")
		}
		l.pacing = &config.Pacing{Enabled: true, StartMbps: pacingStartMbps}
		l.restartPair()
		l.wait(func() bool { return l.pacingInstalled("a") && l.pacingInstalled("b") }, 5*time.Second, "both NATs pace")
		// A restart with pacing off in the configuration removes it.
		l.pacing = nil
		l.restartPair()
		l.wait(func() bool { return !l.pacingInstalled("a") && !l.pacingInstalled("b") }, 5*time.Second, "both NATs remove pacing")
		return map[string]any{"installed_when_off": false, "removed_when_turned_off": true}
	})

	l.runCase("pacing-heavy-and-light-workers", func() map[string]any {
		l.pacing = &config.Pacing{Enabled: true, StartMbps: pacingStartMbps}
		l.restartPair()
		l.wait(func() bool { return l.pacingInstalled("a") }, 5*time.Second, "a paces")
		stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		require.NoError(l.t, err)
		defer stats.Close()

		baseline := l.lightRun(10 * time.Second)
		before := l.paceRunTime("a")
		heavy := make(chan transfer, 1)
		go func() { heavy <- blast("worker", heavyWorker, sinkAddr, 25*time.Second, 4) }()
		// Leave time for the fair shares to settle.
		time.Sleep(5 * time.Second)
		loaded := l.lightRun(15 * time.Second)
		heavyResult := <-heavy
		after := l.paceRunTime("a")
		capMbps := l.capMbps("a")

		l.require(heavyResult.Error == "", "the heavy upload finished: "+heavyResult.Error)
		// The cap rose under pressure, from 200 Mbit/s to at most 1.01^30 of that.
		l.require(heavyResult.Mbps() <= capMbps*1.05, fmt.Sprintf("the heavy worker stays under the cap: %.0f Mbit/s, cap %.0f", heavyResult.Mbps(), capMbps))
		l.require(heavyResult.Mbps() >= 0.5*pacingStartMbps, fmt.Sprintf("the heavy worker gets most of the cap: %.0f Mbit/s", heavyResult.Mbps()))
		for i, light := range loaded {
			l.require(light.Error == "", "a light worker's upload finished: "+light.Error)
			l.require(light.Mbps() >= 0.9*baseline[i].Mbps(), fmt.Sprintf("light worker %s keeps its throughput: %.2f Mbit/s, %.2f alone", lightWorkers[i], light.Mbps(), baseline[i].Mbps()))
		}
		perPacket := float64(after.runtime-before.runtime) / float64(after.runs-before.runs)
		return map[string]any{
			"cap_mbps": capMbps, "heavy_mbps": heavyResult.Mbps(),
			"light_alone": baseline, "light_with_heavy": loaded,
			"pace_program_ns_per_packet": perPacket, "pace_program_runs": after.runs - before.runs,
		}
	})

	l.runCase("pacing-leaves-nat-traffic-alone", func() map[string]any {
		l.pacing = &config.Pacing{Enabled: true, StartMbps: pacingStartMbps}
		l.restartPair()
		l.wait(func() bool { return l.pacingInstalled("a") }, 5*time.Second, "a paces")
		quiet := steady("a", netip.Addr{}, uploadAddr, 5*time.Second)
		up := make(chan transfer, 1)
		down := make(chan transfer, 1)
		go func() { up <- blast("worker", heavyWorker, sinkAddr, 20*time.Second, 4) }()
		go func() { down <- drain("worker", lightWorkers[0], sourceAddr, 20*time.Second, 4) }()
		time.Sleep(3 * time.Second)
		// The NAT's own upload leaves through the same interface as the
		// paced worker uploads.
		own := steady("a", netip.Addr{}, uploadAddr, 10*time.Second)
		ready := l.report("a").PathHealthy && l.report("b").Ready && l.active("a") && !l.active("b")
		upResult, downResult := <-up, <-down
		capMbps := l.capMbps("a")
		workers := l.pacedWorkers("a")

		l.require(quiet.Error == "" && own.Error == "", "the NAT's own uploads finished: "+quiet.Error+own.Error)
		l.require(ready, "a keeps serving with healthy probes, and b keeps its copies, while workers saturate the cap")
		l.require(own.P99Millis < max(5, 2*quiet.P99Millis), fmt.Sprintf("the NAT's own traffic doesn't wait: p99 %.2f ms, %.2f ms when idle", own.P99Millis, quiet.P99Millis))
		l.require(upResult.Error == "" && downResult.Error == "", "worker transfers finished: "+upResult.Error+downResult.Error)
		total := upResult.Mbps() + downResult.Mbps()
		l.require(total <= capMbps*1.05, fmt.Sprintf("uploads and downloads share one cap: %.0f + %.0f Mbit/s, cap %.0f", upResult.Mbps(), downResult.Mbps(), capMbps))
		for _, worker := range workers {
			l.require(worker == heavyWorker || worker == lightWorkers[0], "only worker traffic is paced, not "+worker.String())
		}
		return map[string]any{
			"own_rtt_idle": quiet, "own_rtt_saturated": own, "cap_mbps": capMbps,
			"upload_mbps": upResult.Mbps(), "download_mbps": downResult.Mbps(), "paced_workers": workers,
		}
	})

	l.runCase("pacing-changes-keep-connections", func() map[string]any {
		l.pacing = &config.Pacing{Enabled: true, StartMbps: pacingStartMbps}
		l.restartPair()
		l.wait(func() bool { return l.pacingInstalled("a") }, 5*time.Second, "a paces")
		upload := l.stream()
		heavy := make(chan transfer, 1)
		go func() { heavy <- blast("worker", heavyWorker, sinkAddr, 16*time.Second, 4) }()
		time.Sleep(4 * time.Second)
		startCap := l.capMbps("a")
		time.Sleep(4 * time.Second)
		raisedCap := l.capMbps("a")
		// Turning pacing off and on swaps the qdiscs under the connections.
		l.ns("a", l.binary, "pacing-off")
		l.wait(func() bool { return !l.pacingInstalled("a") }, 3*time.Second, "a removes pacing")
		time.Sleep(time.Second)
		l.ns("a", l.binary, "pacing-on")
		l.wait(func() bool { return l.pacingInstalled("a") }, 3*time.Second, "a paces again")
		// Pacing-on starts again from the configured cap.
		resumedCap := l.capMbps("a")
		paced := l.pacedMbps("a", 2*time.Second)
		result := l.streamResult(upload)
		heavyResult := <-heavy
		l.require(raisedCap > startCap, fmt.Sprintf("the cap rises under pressure: %.0f to %.0f Mbit/s", startCap, raisedCap))
		l.require(resumedCap < raisedCap && resumedCap >= pacingStartMbps, fmt.Sprintf("pacing resumes from the configured cap: %.0f Mbit/s, %.0f before", resumedCap, raisedCap))
		l.require(paced <= 1.1*resumedCap, fmt.Sprintf("the resumed cap holds: %.0f Mbit/s paced, cap %.0f", paced, resumedCap))
		l.require(heavyResult.Error == "", "the heavy upload kept its connections: "+heavyResult.Error)
		return map[string]any{"cap_before_mbps": startCap, "cap_raised_mbps": raisedCap, "cap_resumed_mbps": resumedCap, "paced_after_resume_mbps": paced, "upload": result}
	})

	l.runCase("pacing-takeover", func() map[string]any {
		l.pacing = &config.Pacing{Enabled: true, StartMbps: pacingStartMbps}
		l.restartPair()
		l.wait(func() bool { return l.pacingInstalled("a") && l.pacingInstalled("b") }, 5*time.Second, "both NATs pace")
		heavy := make(chan transfer, 1)
		go func() { heavy <- blast("worker", heavyWorker, sinkAddr, 12*time.Second, 4) }()
		time.Sleep(2 * time.Second)
		injected := time.Now()
		l.daemons["a"].signal(l.t, syscall.SIGKILL)
		l.wait(func() bool { return l.active("b") }, 15*time.Second, "b takes over while workers saturate the cap")
		recovery := time.Since(injected).Seconds()
		l.require(l.fresh(), "new connections work through b")
		l.wait(func() bool { return slices.Contains(l.pacedWorkers("b"), heavyWorker) }, 10*time.Second, "b paces the heavy worker")
		<-heavy
		l.launch("a")
		return map[string]any{"local_takeover_s": recovery, "new_owner_paces": true}
	})
	l.pacing = nil
}

// setupPacing adds the light workers' addresses and the receiver's sink and
// source.
func (l *lab) setupPacing() {
	for _, addr := range lightWorkers {
		l.ns("worker", "ip", "addr", "replace", addr.String()+"/24", "dev", "lan")
	}
	for address, serve := range map[string]func(net.Conn){sinkAddr: sink, sourceAddr: source} {
		var listener net.Listener
		require.NoError(l.t, netns.Do("receiver", func() error {
			var err error
			listener, err = net.Listen("tcp4", address)
			return err
		}))
		l.t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go serve(conn)
			}
		}()
	}
}

// pacingInstalled reports whether a NAT paces: its pinned programs exist and
// its lan and wan interfaces run them.
func (l *lab) pacingInstalled(name string) bool {
	if _, err := os.Stat(l.pacePin(name)); err != nil {
		return false
	}
	for _, iface := range []string{"lan", "wan"} {
		output, err := l.tryNS(name, "tc", "filter", "show", "dev", iface, "egress")
		if err != nil || !strings.Contains(output, "natpair_pace") {
			return false
		}
		// The root is mq or, on a single-queue link, fq itself.
		output, err = l.tryNS(name, "tc", "qdisc", "show", "dev", iface)
		if err != nil || !strings.Contains(output, " 7a01: root") || !strings.Contains(output, "qdisc fq ") {
			return false
		}
	}
	return true
}

func (l *lab) pacePin(name string) string {
	return filepath.Join(machinesDir, name, "bpf", "natpair", "pacing", "pace")
}

// paceMap opens one of the maps the NAT's pinned pace program uses.
func (l *lab) paceMap(name, mapName string) *ebpf.Map {
	program, err := ebpf.LoadPinnedProgram(l.pacePin(name), nil)
	require.NoError(l.t, err)
	defer program.Close()
	info, err := program.Info()
	require.NoError(l.t, err)
	ids, _ := info.MapIDs()
	for _, id := range ids {
		m, err := ebpf.NewMapFromID(id)
		require.NoError(l.t, err)
		if mapInfo, err := m.Info(); err == nil && mapInfo.Name == mapName {
			return m
		}
		_ = m.Close()
	}
	l.t.Fatalf("%s: %s's pace program has no %s map", l.caseName, name, mapName)
	return nil
}

// pacedMbps returns the worker traffic a NAT paced in both directions,
// averaged over the given time.
func (l *lab) pacedMbps(name string, over time.Duration) float64 {
	read := func() uint64 {
		stats := l.paceMap(name, "natpair_stats")
		defer stats.Close()
		var total uint64
		for _, direction := range []uint32{0, 1} {
			var perCPU [][4]uint64
			require.NoError(l.t, stats.Lookup(direction, &perCPU))
			for _, cpu := range perCPU {
				total += cpu[0]
			}
		}
		return total
	}
	before := read()
	time.Sleep(over)
	return float64(read()-before) * 8 / over.Seconds() / 1e6
}

// capMbps returns the bandwidth cap a NAT's kernel enforces.
func (l *lab) capMbps(name string) float64 {
	limits := l.paceMap(name, "natpair_limits")
	defer limits.Close()
	// The kernel's costs, then the time until which they apply.
	var costs [5]uint64
	require.NoError(l.t, limits.Lookup(uint32(0), &costs))
	if costs[0] == 0 {
		return 0
	}
	return 1e9 * 65536 / float64(costs[0]) * 8 / 1e6
}

// pacedWorkers returns the workers a NAT's pace program has seen.
func (l *lab) pacedWorkers(name string) []netip.Addr {
	workers := l.paceMap(name, "natpair_workers")
	defer workers.Close()
	var key [4]byte
	var value [6]uint64
	var addrs []netip.Addr
	for iter := workers.Iterate(); iter.Next(&key, &value); {
		addrs = append(addrs, netip.AddrFrom4(key))
	}
	return addrs
}

type runTime struct {
	runtime time.Duration
	runs    uint64
}

// paceRunTime returns how long a NAT's pace program has run, and how often.
func (l *lab) paceRunTime(name string) runTime {
	program, err := ebpf.LoadPinnedProgram(l.pacePin(name), nil)
	require.NoError(l.t, err)
	defer program.Close()
	stats, err := program.Stats()
	require.NoError(l.t, err)
	return runTime{runtime: stats.Runtime, runs: stats.RunCount}
}

// tryNS runs a command on a host and returns its error instead of failing.
func (l *lab) tryNS(name string, args ...string) (string, error) {
	return command.Run(l.t.Context(), 2*time.Second, "nsenter", append(l.enter(name), args...)...)
}

// lightRun runs a steady upload from each light worker at once.
func (l *lab) lightRun(duration time.Duration) []transfer {
	results := make([]transfer, len(lightWorkers))
	var group sync.WaitGroup
	for i, addr := range lightWorkers {
		group.Go(func() { results[i] = steady("worker", addr, uploadAddr, duration) })
	}
	group.Wait()
	return results
}

// transfer is the result of one timed transfer.
type transfer struct {
	Bytes     int64   `json:"bytes"`
	Seconds   float64 `json:"seconds"`
	P50Millis float64 `json:"p50_rtt_ms,omitempty"`
	P99Millis float64 `json:"p99_rtt_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Mbps returns the transfer's throughput in megabits per second.
func (t transfer) Mbps() float64 {
	if t.Seconds == 0 {
		return 0
	}
	return float64(t.Bytes) * 8 / t.Seconds / 1e6
}

func dial(namespace string, source netip.Addr, address string) (net.Conn, error) {
	var conn net.Conn
	err := netns.Do(namespace, func() error {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		if source.IsValid() {
			dialer.LocalAddr = &net.TCPAddr{IP: source.AsSlice()}
		}
		var err error
		conn, err = dialer.Dial("tcp4", address)
		return err
	})
	return conn, err
}

// blast uploads as fast as it can over parallel connections for duration,
// and returns what the sink received.
func blast(namespace string, source netip.Addr, address string, duration time.Duration, connections int) transfer {
	results := make([]transfer, connections)
	var group sync.WaitGroup
	for i := range connections {
		group.Go(func() { results[i] = blastOne(namespace, source, address, duration) })
	}
	group.Wait()
	return combine(results)
}

func blastOne(namespace string, source netip.Addr, address string, duration time.Duration) transfer {
	conn, err := dial(namespace, source, address)
	if err != nil {
		return transfer{Error: err.Error()}
	}
	defer conn.Close()
	chunk := make([]byte, 64<<10)
	started := time.Now()
	for time.Since(started) < duration {
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return transfer{Error: err.Error()}
		}
		if _, err := conn.Write(chunk); err != nil {
			return transfer{Error: err.Error()}
		}
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		return transfer{Error: err.Error()}
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return transfer{Error: err.Error()}
	}
	count := make([]byte, 8)
	if _, err := io.ReadFull(conn, count); err != nil {
		return transfer{Error: "the sink didn't confirm the upload: " + err.Error()}
	}
	return transfer{Bytes: int64(binary.BigEndian.Uint64(count)), Seconds: time.Since(started).Seconds()}
}

// drain downloads as fast as it can over parallel connections for duration.
func drain(namespace string, source netip.Addr, address string, duration time.Duration, connections int) transfer {
	results := make([]transfer, connections)
	var group sync.WaitGroup
	for i := range connections {
		group.Go(func() {
			conn, err := dial(namespace, source, address)
			if err != nil {
				results[i] = transfer{Error: err.Error()}
				return
			}
			defer conn.Close()
			buffer := make([]byte, 64<<10)
			started := time.Now()
			for time.Since(started) < duration {
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					results[i] = transfer{Error: err.Error()}
					return
				}
				n, err := conn.Read(buffer)
				results[i].Bytes += int64(n)
				if err != nil {
					results[i].Error = err.Error()
					return
				}
			}
			results[i].Seconds = time.Since(started).Seconds()
		})
	}
	group.Wait()
	return combine(results)
}

// combine adds parallel transfers' bytes over the longest one's time.
func combine(results []transfer) transfer {
	var total transfer
	for _, r := range results {
		total.Bytes += r.Bytes
		total.Seconds = max(total.Seconds, r.Seconds)
		if r.Error != "" {
			total.Error = r.Error
		}
	}
	return total
}

// steady sends one 8 KiB frame every 20 ms for duration, using the upload
// protocol, and measures each frame's round trip.
func steady(namespace string, source netip.Addr, address string, duration time.Duration) transfer {
	conn, err := dial(namespace, source, address)
	if err != nil {
		return transfer{Error: err.Error()}
	}
	defer conn.Close()
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	ack := make([]byte, 1)
	var rtts []float64
	var result transfer
	started := time.Now()
	for time.Since(started) < duration {
		sent := time.Now()
		if err := conn.SetDeadline(sent.Add(5 * time.Second)); err != nil {
			return transfer{Error: err.Error()}
		}
		if _, err := conn.Write(frame); err != nil {
			return transfer{Error: err.Error()}
		}
		if _, err := io.ReadFull(conn, ack); err != nil {
			return transfer{Error: err.Error()}
		}
		rtts = append(rtts, float64(time.Since(sent).Microseconds())/1000)
		result.Bytes += int64(len(payload))
		time.Sleep(framePause)
	}
	result.Seconds = time.Since(started).Seconds()
	slices.Sort(rtts)
	result.P50Millis = rtts[len(rtts)/2]
	result.P99Millis = rtts[len(rtts)*99/100]
	// Ask for the summary so the receiver closes cleanly.
	_, _ = conn.Write(make([]byte, 4))
	return result
}

// sink counts what a heavy upload sends and reports the count once the
// sender finishes.
func sink(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return
	}
	n, err := io.Copy(io.Discard, conn)
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	count := make([]byte, 8)
	binary.BigEndian.PutUint64(count, uint64(n))
	_, _ = conn.Write(count)
}

// source streams to a heavy download until the client closes.
func source(conn net.Conn) {
	defer conn.Close()
	chunk := make([]byte, 64<<10)
	for {
		if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		if _, err := conn.Write(chunk); err != nil {
			return
		}
	}
}
