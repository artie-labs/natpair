package pacing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
)

const tcTimeout = 2 * time.Second

// allowanceNames are the ENA driver's counts of packets AWS queued or dropped
// because the instance exceeded its inbound bandwidth, outbound bandwidth or
// packet rate allowance.
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html
var allowanceNames = []string{"bw_in_allowance_exceeded", "bw_out_allowance_exceeded", "pps_allowance_exceeded"}

// kernel loads the pacing programs and attaches them with tc. It pins the
// programs under dir, because tc attaches a program by its pinned path.
type kernel struct {
	dir       string
	protected []netip.Prefix
	progs     *programs
	// ethtool is a socket for reading the allowance counters, and stats
	// where each interface keeps them, so a poll is one ioctl per interface.
	ethtool int
	stats   map[string]statIndex
}

func newKernel(dir string, protected []netip.Prefix) *kernel {
	return &kernel{dir: dir, protected: protected, ethtool: -1, stats: map[string]statIndex{}}
}

func (k *kernel) markPin() string { return filepath.Join(k.dir, "mark") }
func (k *kernel) pacePin() string { return filepath.Join(k.dir, "pace") }

// load creates fresh maps, loads the programs and pins them. Interfaces still
// run the previous programs until attach replaces them.
func (k *kernel) load() error {
	progs, err := loadPrograms(k.protected)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		progs.close()
		return fmt.Errorf("failed to create the pacing BPF directory: %w", err)
	}
	for path, prog := range map[string]*ebpf.Program{k.markPin(): progs.mark, k.pacePin(): progs.pace} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			progs.close()
			return fmt.Errorf("failed to remove the old pacing program: %w", err)
		}
		if err := prog.Pin(path); err != nil {
			progs.close()
			return fmt.Errorf("failed to pin the pacing program: %w", err)
		}
	}
	k.close()
	k.progs = progs
	return nil
}

// attach paces an interface with the loaded programs.
func (k *kernel) attach(ctx context.Context, iface string) error {
	// sysfs can belong to another network namespace than the daemon's, as in
	// natpair's own tests, so the queue count comes from the kernel. mq makes
	// one class per allocated queue.
	output, err := command.Run(ctx, tcTimeout, "ip", "-d", "-j", "link", "show", "dev", iface)
	if err != nil {
		return err
	}
	var links []struct {
		TxQueues int `json:"num_tx_queues"`
	}
	if err := json.Unmarshal([]byte(output), &links); err != nil || len(links) != 1 || links[0].TxQueues < 1 {
		return fmt.Errorf("failed to count %s's transmit queues from %q", iface, output)
	}
	_, err = command.RunWithInput(ctx, tcTimeout, attachScript(iface, links[0].TxQueues, k.markPin(), k.pacePin()), "tc", "-batch", "-")
	return err
}

// remove takes pacing off every interface and unpins the programs. It only
// runs tc if this boot pinned pacing programs, so a NAT that never turned
// pacing on doesn't need tc installed.
func (k *kernel) remove(ctx context.Context) error {
	k.close()
	if _, err := os.Stat(k.dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}
	var errs []error
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// An interface can go away after the listing, such as the shared
		// ENI during a handover, and then has nothing left to remove.
		if err := detach(ctx, iface.Name); err != nil {
			if _, statErr := net.InterfaceByName(iface.Name); statErr == nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := os.RemoveAll(k.dir); err != nil {
		return fmt.Errorf("failed to unpin the pacing programs: %w", err)
	}
	return nil
}

// detach removes what attach installed on one interface.
func detach(ctx context.Context, iface string) error {
	output, err := command.Run(ctx, tcTimeout, "tc", "-j", "qdisc", "show", "dev", iface)
	if err != nil {
		return err
	}
	qdiscs, err := parseTC[qdisc](output)
	if err != nil {
		return err
	}
	var ingress, egress []filter
	for _, q := range qdiscs {
		if q.Kind != "clsact" {
			continue
		}
		for direction, target := range map[string]*[]filter{"ingress": &ingress, "egress": &egress} {
			output, err := command.Run(ctx, tcTimeout, "tc", "-j", "filter", "show", "dev", iface, direction)
			if err != nil {
				return err
			}
			if *target, err = parseTC[filter](output); err != nil {
				return err
			}
		}
	}
	script := detachScript(iface, qdiscs, ingress, egress)
	if script == "" {
		return nil
	}
	_, err = command.RunWithInput(ctx, tcTimeout, script, "tc", "-batch", "-")
	return err
}

func (k *kernel) setLimits(l Limits) error {
	return k.progs.setLimits(l)
}

// readTotals returns the counters for each direction since the programs were
// loaded.
func (k *kernel) readTotals() (Totals, error) {
	var totals Totals
	for direction, target := range map[uint32]*Counters{directionUpload: &totals.Upload, directionDownload: &totals.Download} {
		var perCPU [][4]uint64
		if err := k.progs.stats.Lookup(direction, &perCPU); err != nil {
			return Totals{}, fmt.Errorf("failed to read pacing stats: %w", err)
		}
		for _, cpu := range perCPU {
			target.add(Counters{Bytes: cpu[0], Packets: cpu[1], Waited: cpu[2], Dropped: cpu[3]})
		}
	}
	return totals, nil
}

// readWorkers returns each worker's counters since the programs were loaded.
func (k *kernel) readWorkers() (map[[4]byte]Counters, error) {
	workers := map[[4]byte]Counters{}
	keys := make([][4]byte, 1024)
	values := make([][workerSize / 8]uint64, len(keys))
	var cursor ebpf.MapBatchCursor
	for {
		n, err := k.progs.workers.BatchLookup(&cursor, keys, values, nil)
		for i := range n {
			v := values[i]
			workers[keys[i]] = Counters{Bytes: v[2], Packets: v[3], Waited: v[4], Dropped: v[5]}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return workers, nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read pacing workers: %w", err)
		}
	}
}

// allowances returns an interface's allowance counters. found is false if it
// doesn't have them, as on any interface other than an ENA one.
func (k *kernel) allowances(iface string) (Allowances, bool, error) {
	if k.ethtool < 0 {
		fd, err := ethtoolSocket()
		if err != nil {
			return Allowances{}, false, err
		}
		k.ethtool = fd
	}
	index, ok := k.stats[iface]
	if !ok {
		var err error
		if index, err = findStats(k.ethtool, iface, allowanceNames); err != nil {
			return Allowances{}, false, err
		}
		k.stats[iface] = index
	}
	if index.indexes == nil {
		return Allowances{}, false, nil
	}
	values, err := readIndexed(k.ethtool, iface, index)
	if err != nil {
		delete(k.stats, iface)
		return Allowances{}, false, err
	}
	return Allowances{BandwidthIn: values[0], BandwidthOut: values[1], PacketRate: values[2]}, true, nil
}

// forget drops what the kernel knows about an interface that went away.
func (k *kernel) forget(iface string) {
	delete(k.stats, iface)
}

// close releases this process's handles on the programs and maps. Attached
// programs keep running.
func (k *kernel) close() {
	if k.progs != nil {
		k.progs.close()
		k.progs = nil
	}
	if k.ethtool >= 0 {
		_ = unix.Close(k.ethtool)
		k.ethtool = -1
	}
}
