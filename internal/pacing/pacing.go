// Package pacing paces forwarded worker traffic just under the instance's
// network allowances, so AWS doesn't drop packets at random.
//
// AWS limits each instance's bandwidth in each direction and its packets per
// second. Above a limit, the hypervisor drops packets of every flow alike,
// including the lease renewals and connection copies the pair depends on.
// Pacing makes the NAT delay or drop the excess itself, from the workers
// sending the most, and never touches traffic the NAT sends itself.
//
// Two BPF programs run on every interface except loopback and the canary
// links. On ingress, the mark program records each packet's source address in
// its mark. Packets the NAT sends itself start with no mark. On egress, after
// source NAT, the pace program looks at marked packets that involve a worker:
// uploads, whose mark is the worker's address, and downloads, whose
// destination is. It gives each one a departure time from token buckets kept
// as clocks: one per worker and one shared by all traffic, each in bytes and
// in packets. sch_fq then holds the packet until that time. This is the
// earliest departure time (EDT) model of Cilium's bandwidth manager.
//
// [Run] sets the buckets' rates. A [Cap] per budget follows the instance's
// allowance counters, and [FairShare] splits the cap between the workers that
// want more than they get.
package pacing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"syscall"
	"time"
)

const (
	// workerShareRatio is the part of each cap that workers' fair shares
	// split. Keeping it below the whole cap means the shared clocks rarely
	// make a light worker wait for a heavy one.
	workerShareRatio = 0.97
	// bytesFloor and packetsFloor are the lowest allowance caps. Allowance
	// reports while forwarded traffic is below them, such as on a standby,
	// come from traffic pacing doesn't control. Every instance type natpair
	// runs on forwards far more: on AWS, a c7gn.medium forwarded 420,000
	// packets a second without exceeding its packet allowance.
	bytesFloor   = 100e6 / 8 // 100 Mbit/s
	packetsFloor = 100_000
	// statusInterval is how often a NAT that forwarded traffic logs its
	// pacing status.
	statusInterval = time.Minute
	// retryInterval is how long a NAT waits before retrying a failed load
	// or attach, so a kernel that lacks a feature doesn't flood the log.
	retryInterval = time.Minute
	// shareInterval is how often a NAT recomputes the workers' fair shares,
	// measures its CPUs and renews the limits. Until it recomputes the
	// shares, a worker that starts sending heavily can take up to the whole
	// cap on top of what the others send.
	shareInterval = 250 * time.Millisecond
	// rateWindow is how far back the forwarded rate that the allowance caps
	// compare with reaches.
	rateWindow = 100 * time.Millisecond
	// minAllowanceHold is the shortest hold after an allowance cut. Packets
	// already queued under the old cap leave over the next 20 ms horizon,
	// and AWS may drop those too.
	minAllowanceHold = 50 * time.Millisecond
)

// Config configures [Run].
type Config struct {
	// Enabled turns pacing on. Off, Run removes anything an earlier daemon
	// installed during this boot and returns.
	Enabled bool
	// Protected are the worker CIDRs. Only traffic to or from them is paced.
	Protected []netip.Prefix
	// BPFDir is where the programs are pinned, on a bpf filesystem.
	BPFDir string
	// OffFile turns pacing off while it exists, for operators who need it
	// off at once without restarting the daemon.
	OffFile string
	// Skip are interfaces never paced, besides loopback.
	Skip []string
	// StartBytes and StartPackets are the caps a NAT starts with, per
	// second. Zero starts without that cap until the instance reports
	// exceeding the allowance.
	StartBytes, StartPackets float64
	// Poll is how often the NAT reads the allowance counters.
	Poll time.Duration
}

// Counters count the packets the pace program passed or dropped.
type Counters struct {
	// Bytes and Packets count packets that left.
	Bytes, Packets uint64
	// Waited counts packets that waited more than 1 ms. A worker's count
	// also includes its dropped packets.
	Waited uint64
	// Dropped counts packets dropped because they would have waited longer
	// than the horizon.
	Dropped uint64
}

func (c *Counters) add(o Counters) {
	c.Bytes += o.Bytes
	c.Packets += o.Packets
	c.Waited += o.Waited
	c.Dropped += o.Dropped
}

// since returns the counts after previous. Counters that went backwards were
// reset, as when the kernel forgot a worker and saw it again.
func (c Counters) since(previous Counters) Counters {
	if c.Bytes < previous.Bytes || c.Packets < previous.Packets || c.Waited < previous.Waited || c.Dropped < previous.Dropped {
		return c
	}
	return Counters{Bytes: c.Bytes - previous.Bytes, Packets: c.Packets - previous.Packets, Waited: c.Waited - previous.Waited, Dropped: c.Dropped - previous.Dropped}
}

// Totals are the counters for each direction. An upload goes from a worker
// to the internet, a download from the internet to a worker.
type Totals struct {
	Upload, Download Counters
}

func (t Totals) since(previous Totals) Totals {
	return Totals{Upload: t.Upload.since(previous.Upload), Download: t.Download.since(previous.Download)}
}

func (t Totals) sum() Counters {
	sum := t.Upload
	sum.add(t.Download)
	return sum
}

// Allowances are an interface's counts of packets AWS queued or dropped
// because the instance exceeded an allowance.
type Allowances struct {
	BandwidthIn, BandwidthOut, PacketRate uint64
}

func (a Allowances) since(previous Allowances) Allowances {
	if a.BandwidthIn < previous.BandwidthIn || a.BandwidthOut < previous.BandwidthOut || a.PacketRate < previous.PacketRate {
		return Allowances{}
	}
	return Allowances{BandwidthIn: a.BandwidthIn - previous.BandwidthIn, BandwidthOut: a.BandwidthOut - previous.BandwidthOut, PacketRate: a.PacketRate - previous.PacketRate}
}

// Run paces forwarded traffic until ctx ends, and leaves the programs
// attached when it does, so traffic stays paced at the last rates while the
// daemon restarts. The kernel stops pacing on its own once the limits go
// unrenewed for limitsLifetime, so a NAT whose daemon is gone, or runs a
// release without pacing, forwards unpaced. It never returns an error and
// never blocks anything else: failures are logged and retried, and
// forwarding works without pacing. now reads the boot clock.
func Run(ctx context.Context, cfg Config, now func() time.Duration) {
	k := newKernel(cfg.BPFDir, cfg.Protected)
	if !cfg.Enabled {
		if err := k.remove(ctx); err != nil {
			slog.Warn("failed to remove pacing left from an earlier run", slog.Any("err", err))
		}
		return
	}
	defer k.close()
	l := &loop{cfg: cfg, k: k, now: now}
	ticker := time.NewTicker(cfg.Poll)
	defer ticker.Stop()
	for {
		l.step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// loop is Run's state between ticks. Every tick it reads the allowance
// counters and moves the allowance caps. Every shareInterval it also paces
// new interfaces, recomputes the workers' fair shares, moves the CPU cap and
// renews the limits.
type loop struct {
	cfg Config
	k   *kernel
	now func() time.Duration

	loaded  bool
	removed bool
	retryAt time.Duration
	// attached holds the paced interfaces by kernel index. An index outlives
	// a rename: a new owner's shared ENI first appears as eth0, and udev
	// renames it moments later, with the qdiscs and programs still on it.
	attached map[int]*attachment

	// bytes and packets follow the instance's allowances. cpu keeps the
	// forwarded packet rate below what the CPUs can carry.
	bytes, packets AllowanceCap
	cpu            CPUCap

	// window holds recent readings of the kernel's counters, for the
	// forwarded rate over the last rateWindow.
	window     []reading
	allowances map[int]Allowances
	polledAt   time.Duration

	// The previous fair share step.
	sharedAt      time.Duration
	shared        reading
	workers       map[[4]byte]Counters
	cpuTimes      []CPUTimes
	busiest       float64
	byteDemands   []Demand
	packetDemands []Demand
	limits        Limits

	// The counters at the previous status log, and the allowance counters'
	// growth since.
	statusAt       time.Duration
	status         Totals
	statusExceeded Allowances
}

// attachment is one interface pacing knows about.
type attachment struct {
	name string
	// paced is false after a failed attach, which is retried at retryAt.
	paced   bool
	retryAt time.Duration
	// warnedAt is when a failed read of its counters was last logged.
	warnedAt time.Duration
}

// reading is the kernel's counters at one time: the pace program's, and the
// paced interfaces' totals.
type reading struct {
	at     time.Duration
	totals Totals
	sent   InterfaceCounters
}

func (l *loop) step(ctx context.Context) {
	now := l.now()
	if _, err := os.Stat(l.cfg.OffFile); err == nil {
		if !l.removed && now >= l.retryAt {
			// remove releases the programs even when it fails, so the next
			// step must load them again either way.
			l.loaded = false
			if err := l.k.remove(ctx); err != nil {
				l.retryAt = now + retryInterval
				slog.Warn("failed to turn pacing off", slog.Any("err", err))
				return
			}
			l.removed = true
			slog.Warn("pacing is off because of the pacing-off request. Run `natpair pacing-on` to turn it back on.", slog.String("file", l.cfg.OffFile))
		}
		return
	}
	l.removed = false
	if !l.loaded {
		if now < l.retryAt {
			return
		}
		if err := l.k.load(); err != nil {
			l.retryAt = now + retryInterval
			slog.Warn("failed to load pacing, so forwarded traffic isn't paced", slog.Any("err", err))
			return
		}
		l.loaded = true
		// Every load starts from the configured caps, so turning pacing off
		// and on again also forgets what an earlier run learned.
		l.bytes = NewAllowanceCap(l.cfg.StartBytes, bytesFloor, max(2*l.cfg.Poll, minAllowanceHold))
		l.packets = NewAllowanceCap(l.cfg.StartPackets, packetsFloor, max(2*l.cfg.Poll, minAllowanceHold))
		l.cpu = NewCPUCap(runtime.NumCPU(), 2*shareInterval)
		l.attached, l.allowances, l.workers = map[int]*attachment{}, map[int]Allowances{}, map[[4]byte]Counters{}
		l.window, l.cpuTimes, l.byteDemands, l.packetDemands = []reading{{at: now}}, nil, nil, nil
		l.polledAt, l.statusAt, l.status, l.statusExceeded = now, now, Totals{}, Allowances{}
		l.sharedAt, l.shared = now-shareInterval, reading{at: now}
		slog.Info("pacing on", slog.Float64("cap_mbps", mbps(l.bytes.Limit)), slog.Float64("cap_kpps", l.packets.Limit/1e3), slog.Float64("cpu_cap_kpps", l.cpu.Limit/1e3))
	}

	totals, err := l.k.readTotals()
	if err != nil {
		slog.Warn("failed to read pacing counters", slog.Any("err", err))
		return
	}
	l.window = append(l.window, reading{at: now, totals: totals, sent: l.interfaceTotals()})
	for len(l.window) > 2 && l.window[1].at <= now-rateWindow {
		l.window = l.window[1:]
	}
	changed := l.poll(now)
	if now-l.sharedAt >= shareInterval {
		l.share(ctx, now, totals)
		changed = true
	}
	if changed {
		l.apply()
	}
	if now-l.statusAt >= statusInterval {
		l.logStatus(now, totals)
	}
}

// poll reads the allowance counters of every paced interface, the shared
// ENI's and the NAT's own, and moves the allowance caps. AWS counts the
// whole instance against its allowances and drops on every interface. It
// reports whether a cap changed.
func (l *loop) poll(now time.Duration) bool {
	var exceeded Allowances
	for index, a := range l.attached {
		if !a.paced {
			continue
		}
		current, found, err := l.k.allowances(a.name)
		if errors.Is(err, syscall.ENODEV) {
			// Renamed or gone since the last share step.
			l.k.forget(a.name)
			if iface, lookupErr := net.InterfaceByIndex(index); lookupErr == nil {
				a.name = iface.Name
			} else {
				delete(l.attached, index)
				delete(l.allowances, index)
			}
			continue
		}
		if err != nil {
			if now-a.warnedAt >= statusInterval || a.warnedAt == 0 {
				a.warnedAt = now
				slog.Warn("failed to read allowance counters", slog.String("interface", a.name), slog.Any("err", err))
			}
			continue
		}
		if !found {
			continue
		}
		if previous, ok := l.allowances[index]; ok {
			d := current.since(previous)
			exceeded.BandwidthIn += d.BandwidthIn
			exceeded.BandwidthOut += d.BandwidthOut
			exceeded.PacketRate += d.PacketRate
		}
		l.allowances[index] = current
	}
	l.statusExceeded.BandwidthIn += exceeded.BandwidthIn
	l.statusExceeded.BandwidthOut += exceeded.BandwidthOut
	l.statusExceeded.PacketRate += exceeded.PacketRate
	elapsed := now - l.polledAt
	l.polledAt = now
	bytesRate, packetsRate, bytesShare, packetsShare := l.rates()
	before := [2]float64{l.bytes.Limit, l.packets.Limit}
	var bytesChange, packetsChange Change
	l.bytes, bytesChange = l.bytes.Step(AllowanceObservation{Now: now, Elapsed: elapsed, Exceeded: exceeded.BandwidthIn + exceeded.BandwidthOut, Rate: bytesRate, Share: bytesShare})
	l.packets, packetsChange = l.packets.Step(AllowanceObservation{Now: now, Elapsed: elapsed, Exceeded: exceeded.PacketRate, Rate: packetsRate, Share: packetsShare})
	if bytesChange == GaveUp || packetsChange == GaveUp {
		slog.Warn("AWS kept dropping after pacing forwarded less, so pacing restored its cap and stopped cutting it",
			slog.Uint64("bw_in_allowance_exceeded", exceeded.BandwidthIn),
			slog.Uint64("bw_out_allowance_exceeded", exceeded.BandwidthOut),
			slog.Uint64("pps_allowance_exceeded", exceeded.PacketRate),
			slog.Float64("cap_mbps", mbps(l.bytes.Limit)),
			slog.Float64("cap_kpps", l.packets.Limit/1e3))
	}
	if bytesChange == CutDown || packetsChange == CutDown {
		slog.Warn("the instance exceeded its network allowance, so pacing cut its cap",
			slog.Uint64("bw_in_allowance_exceeded", exceeded.BandwidthIn),
			slog.Uint64("bw_out_allowance_exceeded", exceeded.BandwidthOut),
			slog.Uint64("pps_allowance_exceeded", exceeded.PacketRate),
			slog.Float64("forwarded_mbps", mbps(bytesRate)),
			slog.Float64("forwarded_kpps", packetsRate/1e3),
			slog.Float64("cap_mbps", mbps(l.bytes.Limit)),
			slog.Float64("cap_kpps", l.packets.Limit/1e3))
	}
	return before != [2]float64{l.bytes.Limit, l.packets.Limit}
}

// rates returns the forwarded bytes and packets per second over the window,
// and the part of what AWS counts against each allowance that forwarded
// traffic makes up. AWS counts bytes sent against the outbound bandwidth
// allowance, and packets sent and received against the packet allowance. A
// forwarded packet is received once and sent once. A single poll at a 10 ms
// interval holds a few GRO-merged packets at most, too few for a steady
// rate.
func (l *loop) rates() (bytes, packets, bytesShare, packetsShare float64) {
	first, last := l.window[0], l.window[len(l.window)-1]
	seconds := (last.at - first.at).Seconds()
	if seconds <= 0 {
		return 0, 0, 1, 1
	}
	d := last.totals.since(first.totals).sum()
	bytes, packets = float64(d.Bytes)/seconds, float64(d.Packets)/seconds
	share := func(forwarded, sent uint64) float64 {
		if sent == 0 {
			return 1
		}
		return min(1, float64(forwarded)/float64(sent))
	}
	var sentBytes, sentPackets uint64
	if last.sent.TxBytes >= first.sent.TxBytes && last.sent.TxPackets+last.sent.RxPackets >= first.sent.TxPackets+first.sent.RxPackets {
		sentBytes = last.sent.TxBytes - first.sent.TxBytes
		sentPackets = last.sent.TxPackets + last.sent.RxPackets - first.sent.TxPackets - first.sent.RxPackets
	}
	return bytes, packets, share(d.Bytes, sentBytes), share(2*d.Packets, sentPackets)
}

// interfaceTotals sums the paced interfaces' totals. A failed read gives
// zero totals, which count as nothing sent.
func (l *loop) interfaceTotals() InterfaceCounters {
	dev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return InterfaceCounters{}
	}
	counters := ParseNetDev(string(dev))
	var sum InterfaceCounters
	for _, a := range l.attached {
		c, ok := counters[a.name]
		if !a.paced || !ok {
			continue
		}
		sum.RxBytes += c.RxBytes
		sum.RxPackets += c.RxPackets
		sum.TxBytes += c.TxBytes
		sum.TxPackets += c.TxPackets
	}
	return sum
}

// share paces interfaces that appeared, measures each worker's demand and
// the busiest CPU since the previous share step, and moves the CPU cap.
func (l *loop) share(ctx context.Context, now time.Duration, totals Totals) {
	l.attach(ctx, now)
	elapsed := now - l.sharedAt
	seconds := elapsed.Seconds()
	forwarded := float64(totals.since(l.shared.totals).sum().Packets) / seconds
	l.sharedAt, l.shared = now, reading{at: now, totals: totals}

	if workers, err := l.k.readWorkers(); err != nil {
		slog.Warn("failed to read pacing workers", slog.Any("err", err))
	} else {
		l.byteDemands, l.packetDemands = l.byteDemands[:0], l.packetDemands[:0]
		for key, counters := range workers {
			d := counters.since(l.workers[key])
			if d.Packets == 0 && d.Waited == 0 {
				continue
			}
			l.byteDemands = append(l.byteDemands, Demand{Rate: float64(d.Bytes) / seconds, Waited: d.Waited > 0})
			l.packetDemands = append(l.packetDemands, Demand{Rate: float64(d.Packets) / seconds, Waited: d.Waited > 0})
		}
		l.workers = workers
	}

	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		slog.Warn("failed to read CPU times", slog.Any("err", err))
		return
	}
	cpuTimes := ParseCPUTimes(string(stat))
	previous := l.cpuTimes
	l.cpuTimes = cpuTimes
	if previous == nil {
		return
	}
	l.busiest = BusiestCPU(previous, cpuTimes)
	var change Change
	l.cpu, change = l.cpu.Step(CPUObservation{Now: now, Elapsed: elapsed, Busiest: l.busiest, Rate: forwarded})
	switch change {
	case CutDown:
		slog.Warn("a forwarding CPU is nearly full, so pacing cut the packet cap",
			slog.Float64("busiest_cpu", l.busiest),
			slog.Float64("forwarded_kpps", forwarded/1e3),
			slog.Float64("cpu_cap_kpps", l.cpu.Limit/1e3))
	case GaveUp:
		slog.Warn("a CPU stayed full after pacing forwarded less, so pacing restored the packet cap and stopped cutting it",
			slog.Float64("busiest_cpu", l.busiest),
			slog.Float64("forwarded_kpps", forwarded/1e3),
			slog.Float64("cpu_cap_kpps", l.cpu.Limit/1e3))
	}
}

// attach paces interfaces that appeared, such as the shared ENI after a
// takeover, and forgets ones that are gone.
func (l *loop) attach(ctx context.Context, now time.Duration) {
	interfaces, err := net.Interfaces()
	if err != nil {
		slog.Warn("failed to list interfaces for pacing", slog.Any("err", err))
		return
	}
	present := map[int]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || slices.Contains(l.cfg.Skip, iface.Name) {
			continue
		}
		present[iface.Index] = true
		a, seen := l.attached[iface.Index]
		if seen && a.name != iface.Name {
			l.k.forget(a.name)
			a.name = iface.Name
		}
		if seen && (a.paced || now < a.retryAt) {
			continue
		}
		if !seen {
			a = &attachment{name: iface.Name}
			l.attached[iface.Index] = a
		}
		if err := l.k.attach(ctx, iface.Name); err != nil {
			// A rename during the attach fails it. Retry at the next step
			// under the new name rather than in a minute.
			if current, lookupErr := net.InterfaceByIndex(iface.Index); lookupErr == nil && current.Name != iface.Name {
				a.name = current.Name
				continue
			}
			a.retryAt = now + retryInterval
			slog.Warn("failed to pace an interface", slog.String("interface", iface.Name), slog.Any("err", err))
			continue
		}
		a.paced = true
		slog.Info("pacing interface", slog.String("interface", iface.Name))
	}
	for index, a := range l.attached {
		if !present[index] {
			delete(l.attached, index)
			delete(l.allowances, index)
			l.k.forget(a.name)
		}
	}
}

// apply writes the caps and the workers' fair shares to the kernel. Each
// write also renews how long the kernel enforces them.
func (l *loop) apply() {
	packets := l.packetCap()
	l.limits = Limits{
		AggregateBytes:   l.bytes.Limit,
		AggregatePackets: packets,
		WorkerBytes:      FairShare(workerShareRatio*l.bytes.Limit, l.byteDemands),
		WorkerPackets:    FairShare(workerShareRatio*packets, l.packetDemands),
	}
	if err := l.k.setLimits(l.limits); err != nil {
		slog.Warn("failed to set pacing limits", slog.Any("err", err))
	}
}

// packetCap returns the lower of the allowance's and the CPUs' packet caps.
// Zero means neither caps packets.
func (l *loop) packetCap() float64 {
	switch {
	case l.packets.Limit == 0:
		return l.cpu.Limit
	case l.cpu.Limit == 0:
		return l.packets.Limit
	}
	return min(l.packets.Limit, l.cpu.Limit)
}

// logStatus logs the caps, and the traffic since the previous status. The
// worker counts and the busiest CPU are from the latest share step.
func (l *loop) logStatus(now time.Duration, totals Totals) {
	seconds := (now - l.statusAt).Seconds()
	status, exceeded := totals.since(l.status), l.statusExceeded
	l.statusAt, l.status, l.statusExceeded = now, totals, Allowances{}
	sum := status.sum()
	if sum.Packets == 0 && sum.Dropped == 0 && exceeded == (Allowances{}) {
		return
	}
	waiting := 0
	for _, d := range l.byteDemands {
		if d.Waited {
			waiting++
		}
	}
	slog.Info("pacing status",
		slog.Float64("cap_mbps", mbps(l.bytes.Limit)),
		slog.Float64("cap_kpps", l.packets.Limit/1e3),
		slog.Float64("cpu_cap_kpps", l.cpu.Limit/1e3),
		slog.Float64("ceiling_mbps", mbps(l.bytes.Ceiling)),
		slog.Float64("ceiling_kpps", l.packets.Ceiling/1e3),
		slog.Float64("cpu_ceiling_kpps", l.cpu.Ceiling/1e3),
		slog.Float64("busiest_cpu", l.busiest),
		slog.Float64("worker_share_mbps", mbps(l.limits.WorkerBytes)),
		slog.Float64("worker_share_kpps", l.limits.WorkerPackets/1e3),
		slog.Float64("upload_mbps", mbps(float64(status.Upload.Bytes)/seconds)),
		slog.Float64("download_mbps", mbps(float64(status.Download.Bytes)/seconds)),
		slog.Float64("upload_kpps", float64(status.Upload.Packets)/seconds/1e3),
		slog.Float64("download_kpps", float64(status.Download.Packets)/seconds/1e3),
		slog.Uint64("waited_packets", sum.Waited),
		slog.Uint64("dropped_packets", sum.Dropped),
		slog.Int("active_workers", len(l.byteDemands)),
		slog.Int("waiting_workers", waiting),
		slog.Uint64("bw_in_allowance_exceeded", exceeded.BandwidthIn),
		slog.Uint64("bw_out_allowance_exceeded", exceeded.BandwidthOut),
		slog.Uint64("pps_allowance_exceeded", exceeded.PacketRate))
}

// mbps converts bytes per second to megabits per second, for logs.
func mbps(bytesPerSecond float64) float64 {
	return bytesPerSecond * 8 / 1e6
}

// RequestOff turns pacing off on a running NAT until [RequestOn]. The
// request survives restarts and reboots.
func RequestOff(path string) error {
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return fmt.Errorf("failed to request pacing off: %w", err)
	}
	return nil
}

// RequestOn clears a [RequestOff].
func RequestOn(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to clear the pacing-off request: %w", err)
	}
	return nil
}
