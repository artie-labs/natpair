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
	"slices"
	"time"
)

const (
	// workerShareRatio is the part of each cap that workers' fair shares
	// split. Keeping it below the whole cap means the shared clocks rarely
	// make a light worker wait for a heavy one.
	workerShareRatio = 0.97
	// bytesFloor and packetsFloor are the lowest caps. Allowance reports
	// while forwarded traffic is below them, such as on a standby, come from
	// traffic pacing doesn't control.
	bytesFloor   = 100e6 / 8 // 100 Mbit/s
	packetsFloor = 10_000
	// statusInterval is how often a NAT that forwarded traffic logs its
	// pacing status.
	statusInterval = time.Minute
	// retryInterval is how long a NAT waits before retrying a failed load
	// or attach, so a kernel that lacks a feature doesn't flood the log.
	retryInterval = time.Minute
	// shareInterval is how often a NAT recomputes the workers' fair shares.
	// Until it does, a worker that starts sending heavily can take up to the
	// whole cap on top of what the others send.
	shareInterval = 250 * time.Millisecond
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
// release without pacing, forwards unpaced. It never returns an error and never blocks anything else:
// failures are logged and retried, and forwarding works without pacing.
// now reads the boot clock.
func Run(ctx context.Context, cfg Config, now func() time.Duration) {
	k := newKernel(cfg.BPFDir, cfg.Protected)
	if !cfg.Enabled {
		if err := k.remove(ctx); err != nil {
			slog.Warn("failed to remove pacing left from an earlier run", slog.Any("err", err))
		}
		return
	}
	defer k.close()
	l := &loop{
		cfg:     cfg,
		k:       k,
		now:     now,
		bytes:   NewCap(cfg.StartBytes, bytesFloor, 2*cfg.Poll),
		packets: NewCap(cfg.StartPackets, packetsFloor, 2*cfg.Poll),
	}
	ticker := time.NewTicker(min(cfg.Poll, shareInterval))
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

// loop is Run's state between ticks.
type loop struct {
	cfg Config
	k   *kernel
	now func() time.Duration

	loaded  bool
	removed bool
	retryAt time.Duration
	// attached maps each paced interface to when it was attached, or to
	// when to retry a failed attach, as a negative time.
	attached map[string]time.Duration

	bytes, packets Cap
	limits         Limits

	// The previous reading of the kernel's counters.
	readAt  time.Duration
	totals  Totals
	workers map[[4]byte]Counters

	// Traffic and allowance counters since the previous poll.
	polledAt   time.Duration
	polled     Counters
	allowances map[string]Allowances

	// Traffic since the previous status log.
	statusAt time.Duration
	status   Totals
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
		l.attached = map[string]time.Duration{}
		l.workers, l.allowances = map[[4]byte]Counters{}, map[string]Allowances{}
		l.readAt, l.polledAt, l.statusAt = now, now, now
		l.totals, l.polled, l.status = Totals{}, Counters{}, Totals{}
		slog.Info("pacing on", slog.Float64("cap_mbps", mbps(l.bytes.Limit)), slog.Float64("cap_kpps", l.packets.Limit/1e3))
	}
	l.attach(ctx, now)

	totals, workers, err := l.k.read()
	if err != nil {
		slog.Warn("failed to read pacing counters", slog.Any("err", err))
		return
	}
	// The first step after a load has nothing to measure rates over.
	var byteDemands, packetDemands []Demand
	if elapsed := (now - l.readAt).Seconds(); elapsed > 0 {
		delta := totals.since(l.totals)
		l.polled.add(delta.sum())
		l.status.Upload.add(delta.Upload)
		l.status.Download.add(delta.Download)
		for key, counters := range workers {
			d := counters.since(l.workers[key])
			if d.Packets == 0 && d.Waited == 0 {
				continue
			}
			byteDemands = append(byteDemands, Demand{Rate: float64(d.Bytes) / elapsed, Waited: d.Waited > 0})
			packetDemands = append(packetDemands, Demand{Rate: float64(d.Packets) / elapsed, Waited: d.Waited > 0})
		}
	}
	l.totals, l.workers, l.readAt = totals, workers, now
	if now-l.polledAt >= l.cfg.Poll {
		l.poll(now)
	}
	limits := Limits{
		AggregateBytes:   l.bytes.Limit,
		AggregatePackets: l.packets.Limit,
		WorkerBytes:      FairShare(workerShareRatio*l.bytes.Limit, byteDemands),
		WorkerPackets:    FairShare(workerShareRatio*l.packets.Limit, packetDemands),
	}
	// The limits are written every step, even unchanged, because each write
	// renews how long the kernel keeps enforcing them.
	if err := l.k.setLimits(limits); err != nil {
		slog.Warn("failed to set pacing limits", slog.Any("err", err))
	}
	l.limits = limits
	if now-l.statusAt >= statusInterval {
		l.logStatus(now, byteDemands)
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
	present := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || slices.Contains(l.cfg.Skip, iface.Name) {
			continue
		}
		present[iface.Name] = true
		at, seen := l.attached[iface.Name]
		if seen && (at >= 0 || now < -at) {
			continue
		}
		if err := l.k.attach(ctx, iface.Name); err != nil {
			l.attached[iface.Name] = -(now + retryInterval)
			slog.Warn("failed to pace an interface", slog.String("interface", iface.Name), slog.Any("err", err))
			continue
		}
		l.attached[iface.Name] = now
		slog.Info("pacing interface", slog.String("interface", iface.Name))
	}
	for name := range l.attached {
		if !present[name] {
			delete(l.attached, name)
			delete(l.allowances, name)
		}
	}
}

// poll reads the allowance counters and moves the caps.
func (l *loop) poll(now time.Duration) {
	var exceeded Allowances
	for name, at := range l.attached {
		if at < 0 {
			continue
		}
		current, found, err := l.k.allowances(name)
		if err != nil {
			slog.Warn("failed to read allowance counters", slog.String("interface", name), slog.Any("err", err))
			continue
		}
		if !found {
			continue
		}
		if previous, ok := l.allowances[name]; ok {
			d := current.since(previous)
			exceeded.BandwidthIn += d.BandwidthIn
			exceeded.BandwidthOut += d.BandwidthOut
			exceeded.PacketRate += d.PacketRate
		}
		l.allowances[name] = current
	}
	elapsed := now - l.polledAt
	seconds := elapsed.Seconds()
	bytesRate, packetsRate := float64(l.polled.Bytes)/seconds, float64(l.polled.Packets)/seconds
	l.polledAt, l.polled = now, Counters{}

	var bytesChange, packetsChange Change
	l.bytes, bytesChange = l.bytes.Step(Observation{Now: now, Elapsed: elapsed, Exceeded: exceeded.BandwidthIn + exceeded.BandwidthOut, Rate: bytesRate})
	l.packets, packetsChange = l.packets.Step(Observation{Now: now, Elapsed: elapsed, Exceeded: exceeded.PacketRate, Rate: packetsRate})
	if exceeded == (Allowances{}) {
		return
	}
	slog.Warn("the instance exceeded its network allowance",
		slog.Uint64("bw_in_allowance_exceeded", exceeded.BandwidthIn),
		slog.Uint64("bw_out_allowance_exceeded", exceeded.BandwidthOut),
		slog.Uint64("pps_allowance_exceeded", exceeded.PacketRate),
		slog.Float64("forwarded_mbps", mbps(bytesRate)),
		slog.Float64("forwarded_kpps", packetsRate/1e3),
		slog.String("bandwidth_cap", string(bytesChange)),
		slog.Float64("cap_mbps", mbps(l.bytes.Limit)),
		slog.String("packet_cap", string(packetsChange)),
		slog.Float64("cap_kpps", l.packets.Limit/1e3))
}

// logStatus logs the caps, and the traffic since the previous status. The
// worker counts are from the latest step.
func (l *loop) logStatus(now time.Duration, demands []Demand) {
	seconds := (now - l.statusAt).Seconds()
	status := l.status
	l.statusAt, l.status = now, Totals{}
	sum := status.sum()
	if sum.Packets == 0 && sum.Dropped == 0 {
		return
	}
	waiting := 0
	for _, d := range demands {
		if d.Waited {
			waiting++
		}
	}
	slog.Info("pacing status",
		slog.Float64("cap_mbps", mbps(l.bytes.Limit)),
		slog.Float64("cap_kpps", l.packets.Limit/1e3),
		slog.Float64("ceiling_mbps", mbps(l.bytes.Ceiling)),
		slog.Float64("ceiling_kpps", l.packets.Ceiling/1e3),
		slog.Float64("worker_share_mbps", mbps(l.limits.WorkerBytes)),
		slog.Float64("worker_share_kpps", l.limits.WorkerPackets/1e3),
		slog.Float64("upload_mbps", mbps(float64(status.Upload.Bytes)/seconds)),
		slog.Float64("download_mbps", mbps(float64(status.Download.Bytes)/seconds)),
		slog.Float64("upload_kpps", float64(status.Upload.Packets)/seconds/1e3),
		slog.Float64("download_kpps", float64(status.Download.Packets)/seconds/1e3),
		slog.Uint64("waited_packets", sum.Waited),
		slog.Uint64("dropped_packets", sum.Dropped),
		slog.Int("active_workers", len(demands)),
		slog.Int("waiting_workers", waiting))
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
