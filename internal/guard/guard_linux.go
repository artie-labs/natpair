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
)

// ensureEvery is how many readings pass between checks of where the shared
// ENI is and of the off switch: every 5 s.
const ensureEvery = 50

// Guard keeps the overload guard attached to the shared ENI while this NAT
// holds it, and sets its budget.
type Guard struct {
	cfg     Config
	match   match
	started time.Time

	mu sync.Mutex
	// prog is loaded on the first attach and kept until Run returns.
	prog *program
	// attached is the XDP link, nil while detached, on interface name with
	// index.
	attached link.Link
	name     string
	index    int
	ctrl     Controller
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

// Ensure attaches the guard to the interface that holds the shared address,
// and detaches it when no interface does, or while the off switch exists. A
// takeover runs it right after the shared ENI is configured, before
// forwarding opens, because attaching restarts an ENA interface. Failures
// are logged, never returned: without the guard the NAT forwards as before.
func (g *Guard) Ensure() {
	g.mu.Lock()
	defer g.mu.Unlock()
	report(&g.ensureErr, g.ensure())
}

// Run checks where the shared ENI is every 5 s, and reads the CPUs and the
// shared ENI's counters every Interval to set the budget. It detaches the
// guard when ctx ends.
func (g *Guard) Run(ctx context.Context) {
	defer g.close()
	g.Ensure()
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for readings := 1; ; readings++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if readings%ensureEvery == 0 {
			g.Ensure()
		}
		g.mu.Lock()
		report(&g.stepErr, g.step())
		g.mu.Unlock()
	}
}

func (g *Guard) ensure() error {
	if _, err := os.Stat(g.cfg.OffPath); err == nil {
		return g.detach("the off switch " + g.cfg.OffPath + " exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to check the overload guard's off switch: %w", err)
	}
	iface, err := g.sharedInterface()
	if err != nil {
		return err
	}
	if iface == nil {
		return g.detach("no interface holds the shared address")
	}
	if iface.Name == g.cfg.PrimaryInterface {
		return errors.Join(g.detach("the primary interface holds the shared address"),
			fmt.Errorf("the primary interface %s holds the shared address %s, so the overload guard stays off it", iface.Name, g.cfg.SharedAddress))
	}
	if g.attached != nil && g.index == iface.Index && g.stillAttached() {
		return nil
	}
	if err := g.detach("the shared address moved to " + iface.Name); err != nil {
		return err
	}
	if g.prog == nil {
		if g.prog, err = loadProgram(g.match); err != nil {
			return err
		}
	}
	if err := g.prog.setBudget(0); err != nil {
		return err
	}
	started := time.Now()
	// Native mode only. The generic mode runs after the kernel builds a
	// packet buffer, which is most of what the guard saves, and it copies
	// large TCP packets into one buffer.
	attached, err := link.AttachXDP(link.XDPOptions{Program: g.prog.prog, Interface: iface.Index, Flags: link.XDPDriverMode})
	if err != nil {
		return fmt.Errorf("failed to attach the overload guard to %s: %w", iface.Name, err)
	}
	g.attached, g.name, g.index = attached, iface.Name, iface.Index
	g.ctrl.Reset()
	slog.Info("overload guard attached", slog.String("interface", iface.Name), slog.Duration("duration", time.Since(started)))
	return nil
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

// detach removes the guard from its interface, if it's on one.
func (g *Guard) detach(reason string) error {
	if g.attached == nil {
		return nil
	}
	err := g.attached.Close()
	g.attached = nil
	g.ctrl.Reset()
	slog.Info("overload guard detached", slog.String("interface", g.name), slog.String("reason", reason))
	if err != nil {
		return fmt.Errorf("failed to detach the overload guard from %s: %w", g.name, err)
	}
	return nil
}

func (g *Guard) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	report(&g.ensureErr, g.detach("the daemon is stopping"))
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
func (g *Guard) step() error {
	if g.attached == nil {
		return nil
	}
	reading, err := g.read()
	if errors.Is(err, fs.ErrNotExist) {
		// The shared ENI went away between two checks, as on a handover.
		return g.detach("the shared ENI is gone")
	}
	if err != nil {
		return err
	}
	previous := g.ctrl.Mode()
	decision := g.ctrl.Step(reading)
	if decision.Changed {
		if err := g.prog.setBudget(decision.Budget); err != nil {
			g.ctrl.Reset()
			return errors.Join(err, g.prog.setBudget(0))
		}
	}
	switch {
	case decision.Mode == Limiting && previous != Limiting:
		slog.Warn("overload guard engaged: the CPU can't forward everything the shared ENI receives, so it drops worker packets past a budget",
			slog.String("interface", g.name),
			slog.Float64("busiest_cpu", round(decision.Busiest)),
			slog.Float64("nic_drop_share", round(decision.DropShare)),
			slog.Int64("measured_pps_per_cpu", int64(decision.Rate)),
			slog.Int64("budget_pps_per_cpu", int64(float64(decision.Budget)/tickSeconds)))
	case decision.Mode == Unlimited && previous == Limiting:
		slog.Info("overload guard cleared", slog.String("interface", g.name),
			slog.Float64("busiest_cpu", round(decision.Busiest)), slog.Uint64("dropped", decision.Shed))
	case decision.Mode == Unlimited && previous == Measuring:
		slog.Info("overload guard stood down: no packets reached it while it measured", slog.String("interface", g.name))
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
	dropped, err := readCounter(g.name, "rx_dropped")
	if err != nil {
		return Reading{}, err
	}
	passed, shed, err := g.prog.counters()
	if err != nil {
		return Reading{}, err
	}
	return Reading{At: time.Since(g.started), CPUs: ParseCPUTimes(string(stat)), Received: received, Dropped: dropped, Passed: passed, Shed: shed}, nil
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
