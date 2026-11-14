// Package napi turns on threaded NAPI for the NAT's network interfaces, so
// their receive processing runs in kernel threads that the scheduler shares
// with the daemon.
//
// Without it, a NAT forwards in softirq context. Linux 6.1 hands sustained
// softirq work to the ksoftirqd threads, which the scheduler shares with
// other tasks. Linux 6.5 and later run pending softirq work in whatever task
// re-enables bottom halves, such as the daemon during its own system calls,
// since upstream commit d15121be7485 ("Revert "softirq: Let ksoftirqd do its
// job""). On a c7gn.large on 6.18 with both CPUs full of forwarding, 96.7% of
// the daemon's CPU samples were forwarding work, and its lease renewals and
// DNS lookups timed out. With threaded NAPI (Linux 5.12 and later), each
// receive queue is polled by a kernel thread named "napi/<interface>-<id>",
// and the daemon used 0.9% of a CPU with no timeouts.
package napi

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Enable turns on threaded NAPI for every interface backed by a device, which
// on EC2 is every attached ENI, and returns how many it turned on. Interfaces
// without a device, such as lo and the probes' veths, have no hardware
// receive queues and stay as they are. It is safe to run repeatedly.
func Enable() (int, error) {
	return enable("/sys/class/net")
}

func enable(root string) (int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	enabled := 0
	var errs []error
	for _, entry := range entries {
		dir := filepath.Join(root, entry.Name())
		if _, err := os.Lstat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		switched, err := setThreaded(filepath.Join(dir, "threaded"))
		if err != nil {
			errs = append(errs, err)
		} else if switched {
			enabled++
		}
	}
	return enabled, errors.Join(errs...)
}

// setThreaded writes 1 to an interface's threaded file if it holds 0, and
// reports whether it did. Other values, such as 2 for busy polling on newer
// kernels, were set by someone else and stay. It skips an interface that
// went away, as when the shared ENI detaches, and one with no receive queues
// yet, such as an ENI that isn't up, for which the kernel refuses the write
// with EOPNOTSUPP. The next pass gets to it.
func setThreaded(path string) (bool, error) {
	current, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if strings.TrimSpace(string(current)) != "0" {
		return false, nil
	}
	err = os.WriteFile(path, []byte("1"), 0o644)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.EOPNOTSUPP) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to write 1 to %s: %w", path, err)
	}
	return true, nil
}
