package guard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
)

// ensureEvery is how many readings pass between checks of where the shared
// ENI is and of the off switch: every 5 s.
const ensureEvery = 50

// receiveNice is the nice value of the shared ENI's receive threads while
// the guard limits. On a 1-vCPU NAT the receive thread shares the CPU with
// the daemon, and each health round's own work held the CPU for longer than
// the receive ring lasts: 1,024 slots at 800,000 packets a second is 1.3 ms.
// The NIC then dropped the probe's replies with the flood. On AWS, with the
// budget on, the owner's probe failed 5 to 6 times in 30 s at nice 0, once
// at -10, and never at -10 with the largest ring. The budget bounds what the
// threads do, so they can't take the whole CPU from the daemon.
const receiveNice = -10

// commandTimeout bounds each ethtool call.
const commandTimeout = 2 * time.Second

// Guard watches the shared ENI while this NAT holds it, and attaches the
// overload guard's program to it only while it sheds a flood. With any XDP
// program attached, ENA's receive path costs more: on AWS, full-rate TCP
// through a c7gn.medium cost 1,396 ns of CPU a packet against 1,220 without,
// and its throughput fell from 8.9 to 7.7 Gbps. Watching needs no program:
// the CPUs and the NIC's counters say when to attach.
type Guard struct {
	cfg     Config
	match   match
	started time.Time

	mu sync.Mutex
	// prog is loaded on the first attach and kept until Run returns.
	prog *program
	// name and index are the shared ENI the guard watches, "" while no
	// interface holds the shared address. attached is the XDP link on it,
	// nil while detached.
	name     string
	index    int
	attached link.Link
	// ringBefore is the receive ring size the guard raised from, to restore
	// on detach, or 0 if it didn't change it.
	ringBefore int
	ctrl       Controller
	// off is set while the off switch exists.
	off bool
	// ensureErr and stepErr are the last failures logged by each loop, so
	// a lasting one is logged once.
	ensureErr, stepErr string
}

// New returns a guard that does nothing until [Guard.Ensure] or [Guard.Run].
func New(cfg Config) *Guard {
	return &Guard{
		cfg: cfg,
		match: match{
			shared:       cfg.SharedAddress,
			receiverPort: cfg.ReceiverPort,
			firstPort:    cfg.FirstProbePort,
			lastPort:     cfg.LastProbePort,
			tickShift:    tickShift,
			exemptShift:  exemptShift,
		},
		started: time.Now(),
	}
}

// Ensure starts watching the interface that holds the shared address, and
// stops, detaching the program, when no interface does or while the off
// switch exists. A takeover runs it right after the shared ENI is
// configured, so a flood that follows the shared ENI is caught at once.
// Failures are logged, never returned: without the guard the NAT forwards
// as before.
func (g *Guard) Ensure(ctx context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	report(&g.ensureErr, g.ensure(ctx))
}

// Run checks where the shared ENI is every 5 s, and reads the CPUs and the
// shared ENI's counters every Interval to attach, limit and detach the
// program. It detaches the program when ctx ends.
func (g *Guard) Run(ctx context.Context) {
	// Detaching restores the ring after ctx ends, so it gets its own.
	defer g.close(context.WithoutCancel(ctx))
	g.Ensure(ctx)
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for readings := 1; ; readings++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if readings%ensureEvery == 0 {
			g.Ensure(ctx)
		}
		g.mu.Lock()
		report(&g.stepErr, g.step(ctx))
		g.mu.Unlock()
	}
}

func (g *Guard) ensure(ctx context.Context) error {
	_, err := os.Stat(g.cfg.OffPath)
	off := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to check the overload guard's off switch: %w", err)
	}
	if off != g.off {
		g.off = off
		slog.Info("overload guard switched", slog.Bool("on", !off), slog.String("off_switch", g.cfg.OffPath))
	}
	if off {
		return g.forget(ctx)
	}
	iface, err := g.sharedInterface()
	if err != nil {
		return err
	}
	if iface == nil {
		return g.forget(ctx)
	}
	if iface.Name == g.cfg.PrimaryInterface {
		return errors.Join(g.forget(ctx),
			fmt.Errorf("the primary interface %s holds the shared address %s, so the overload guard stays off it", iface.Name, g.cfg.SharedAddress))
	}
	if g.name != iface.Name || g.index != iface.Index {
		if err := g.forget(ctx); err != nil {
			return err
		}
		g.name, g.index = iface.Name, iface.Index
		slog.Info("overload guard watching", slog.String("interface", iface.Name))
		return nil
	}
	if g.attached != nil && !g.stillAttached() {
		// The kernel dropped the link, as when the interface was replaced.
		return g.detach(ctx)
	}
	if g.ctrl.Mode() == Limiting {
		// A NIC reset recreates the receive threads at nice 0.
		return g.prioritize(receiveNice)
	}
	return nil
}

// forget stops watching, detaching the program if it's attached.
func (g *Guard) forget(ctx context.Context) error {
	if g.name == "" {
		return nil
	}
	err := g.detach(ctx)
	slog.Info("overload guard stopped watching", slog.String("interface", g.name))
	g.name, g.index = "", 0
	g.ctrl.Reset()
	return err
}

// attach loads the program if needed, gives it budget and attaches it to
// the watched interface, after raising the interface's receive ring. Each
// of those restarts an ENA interface. Without the larger ring the guard
// still works, so a ring failure is only logged.
func (g *Guard) attach(ctx context.Context, budget uint64) (time.Duration, error) {
	started := time.Now()
	if g.prog == nil {
		prog, err := loadProgram(g.match)
		if err != nil {
			return 0, err
		}
		g.prog = prog
	}
	if err := g.prog.setBudget(budget); err != nil {
		return 0, err
	}
	if err := g.raiseRing(ctx, g.name); err != nil {
		slog.Warn("overload guard failed to raise the receive ring", slog.Any("err", err))
	}
	// Native mode only. The generic mode runs after the kernel builds a
	// packet buffer, which is most of what the guard saves, and it copies
	// large TCP packets into one buffer.
	attached, err := link.AttachXDP(link.XDPOptions{Program: g.prog.prog, Interface: g.index, Flags: link.XDPDriverMode})
	if err != nil {
		return 0, errors.Join(fmt.Errorf("failed to attach the overload guard to %s: %w", g.name, err), g.restoreRing(ctx))
	}
	g.attached = attached
	return time.Since(started), nil
}

// raiseRing sets the receive ring of iface to its largest size, so it holds
// packets for longer while the receive threads wait for the CPU. At 800,000
// packets a second, ENA's default of 1,024 slots lasts 1.3 ms, and on a
// c7gn.medium its maximum of 2,048 lasts 2.6 ms. It records the size to
// restore.
func (g *Guard) raiseRing(ctx context.Context, iface string) error {
	output, err := command.Run(ctx, commandTimeout, "ethtool", "-g", iface)
	if err != nil && strings.Contains(err.Error(), "Operation not supported") {
		// Its ring has no size to change, as on a veth.
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read the receive ring size of %s: %w", iface, err)
	}
	maximum, current, err := parseRings(output)
	if err != nil {
		return err
	}
	if current >= maximum {
		return nil
	}
	if _, err := command.Run(ctx, commandTimeout, "ethtool", "-G", iface, "rx", strconv.Itoa(maximum)); err != nil {
		return fmt.Errorf("failed to raise the receive ring of %s to %d: %w", iface, maximum, err)
	}
	g.ringBefore = current
	return nil
}

// ringNow returns the receive ring size of iface, or 0 if ethtool can't say.
func (g *Guard) ringNow(ctx context.Context, iface string) int {
	output, err := command.Run(ctx, commandTimeout, "ethtool", "-g", iface)
	if err != nil {
		return 0
	}
	_, current, err := parseRings(output)
	if err != nil {
		return 0
	}
	return current
}

// prioritize sets the nice value of the guarded interface's receive
// threads. It does nothing without threaded NAPI, which has no such threads.
func (g *Guard) prioritize(nice int) error {
	pids, err := receiveThreads("/proc", g.name)
	if err != nil {
		return err
	}
	var errs []error
	for _, pid := range pids {
		if err := unix.Setpriority(unix.PRIO_PROCESS, pid, nice); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("failed to set the nice value of receive thread %d to %d: %w", pid, nice, err))
		}
	}
	return errors.Join(errs...)
}

// stillAttached asks the kernel whether the link is still on g.index. The
// kernel detaches it when the interface goes away, as the shared ENI does
// on a handover, and an interface that comes back gets a new index.
func (g *Guard) stillAttached() bool {
	info, err := g.attached.Info()
	if err != nil {
		return false
	}
	xdp := info.XDP()
	return xdp != nil && int(xdp.Ifindex) == g.index
}

// detach removes the program from the watched interface, if it's on one,
// and puts the receive threads' priority and the ring back where they were.
// They are gone with the interface on a handover.
func (g *Guard) detach(ctx context.Context) error {
	if g.attached == nil {
		return nil
	}
	var errs []error
	if g.ctrl.Mode() == Limiting {
		errs = append(errs, g.prioritize(0))
	}
	if err := g.attached.Close(); err != nil {
		errs = append(errs, fmt.Errorf("failed to detach the overload guard from %s: %w", g.name, err))
	}
	g.attached = nil
	g.ctrl.Reset()
	errs = append(errs, g.restoreRing(ctx))
	return errors.Join(errs...)
}

// restoreRing puts the receive ring back to the size raiseRing raised it
// from, unless the interface is gone.
func (g *Guard) restoreRing(ctx context.Context) error {
	if g.ringBefore == 0 {
		return nil
	}
	before := g.ringBefore
	g.ringBefore = 0
	if _, err := os.Stat(filepath.Join("/sys/class/net", g.name)); err != nil {
		return nil
	}
	if _, err := command.Run(ctx, commandTimeout, "ethtool", "-G", g.name, "rx", strconv.Itoa(before)); err != nil {
		return fmt.Errorf("failed to restore the receive ring of %s to %d: %w", g.name, before, err)
	}
	return nil
}

func (g *Guard) close(ctx context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	report(&g.ensureErr, g.forget(ctx))
	if g.prog != nil {
		report(&g.ensureErr, g.prog.Close())
		g.prog = nil
	}
}

// sharedInterface returns the interface that holds the shared address, or
// nil if none does, as on a standby.
func (g *Guard) sharedInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			// It may have just gone away, as the shared ENI does on a
			// handover.
			continue
		}
		for _, addr := range addrs {
			if network, ok := addr.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(network.IP); ok && ip.Unmap() == g.cfg.SharedAddress {
					return &iface, nil
				}
			}
		}
	}
	return nil, nil
}

// step takes one reading and applies the controller's decision.
func (g *Guard) step(ctx context.Context) error {
	if g.name == "" {
		return nil
	}
	reading, err := g.read()
	if errors.Is(err, fs.ErrNotExist) {
		// The shared ENI went away between two checks, as on a handover.
		return g.forget(ctx)
	}
	if err != nil {
		return err
	}
	previous := g.ctrl.Mode()
	decision := g.ctrl.Step(reading)
	if !decision.Changed {
		return nil
	}
	switch decision.Mode {
	case Measuring:
		took, err := g.attach(ctx, decision.Budget)
		if err != nil {
			g.ctrl.Reset()
			return err
		}
		slog.Info("overload guard attached", slog.String("interface", g.name),
			slog.Float64("busiest_cpu", round(decision.Busiest)), slog.Float64("nic_drop_share", round(decision.DropShare)),
			slog.Int("rx_ring", g.ringNow(ctx, g.name)), slog.Duration("duration", took))
	case Limiting:
		if err := g.prog.setBudget(decision.Budget); err != nil {
			return errors.Join(err, g.detach(ctx))
		}
		if previous == Limiting {
			slog.Info("overload guard lowered its budget, because the NIC still drops packets", slog.String("interface", g.name),
				slog.Float64("busiest_cpu", round(decision.Busiest)), slog.Float64("nic_drop_share", round(decision.DropShare)),
				slog.Int64("budget_pps_per_cpu", int64(float64(decision.Budget)/tickSeconds)))
			return nil
		}
		slog.Warn("overload guard engaged: the CPU can't forward everything the shared ENI receives, so it drops worker packets past a budget",
			slog.String("interface", g.name),
			slog.Float64("busiest_cpu", round(decision.Busiest)),
			slog.Float64("nic_drop_share", round(decision.DropShare)),
			slog.Int64("measured_pps_per_cpu", int64(decision.Rate)),
			slog.Int64("budget_pps_per_cpu", int64(float64(decision.Budget)/tickSeconds)))
		return g.prioritize(receiveNice)
	case Unlimited:
		// The controller already forgot its mode, so detach puts the
		// priority back here.
		var priorityErr error
		if previous == Limiting {
			priorityErr = g.prioritize(0)
			slog.Info("overload guard cleared", slog.String("interface", g.name),
				slog.Float64("busiest_cpu", round(decision.Busiest)), slog.Uint64("dropped", decision.Shed))
		} else {
			slog.Info("overload guard stood down: no packets reached it while it measured", slog.String("interface", g.name))
		}
		return errors.Join(priorityErr, g.detach(ctx))
	}
	return nil
}

func (g *Guard) read() (Reading, error) {
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return Reading{}, fmt.Errorf("failed to read CPU times: %w", err)
	}
	received, err := readCounter(g.name, "rx_packets")
	if err != nil {
		return Reading{}, err
	}
	dropped, err := readCounter(g.name, "rx_over_errors")
	if err != nil {
		return Reading{}, err
	}
	reading := Reading{At: time.Since(g.started), CPUs: ParseCPUTimes(string(stat)), Received: received, Dropped: dropped}
	if g.attached != nil {
		if reading.Passed, reading.Shed, err = g.prog.counters(); err != nil {
			return Reading{}, err
		}
	}
	return reading, nil
}

func readCounter(iface, name string) (uint64, error) {
	contents, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "statistics", name))
	if err != nil {
		return 0, fmt.Errorf("failed to read %s of %s: %w", name, iface, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(contents)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse %s of %s: %w", name, iface, err)
	}
	return value, nil
}

// report logs err unless it is the failure last holds, and records it, so
// a lasting failure is logged once. A success clears last.
func report(last *string, err error) {
	if err == nil {
		*last = ""
		return
	}
	if err.Error() != *last {
		slog.Warn("overload guard failed", slog.Any("err", err))
	}
	*last = err.Error()
}

func round(share float64) float64 {
	return float64(int(share*1000+0.5)) / 1000
}
