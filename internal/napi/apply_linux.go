package napi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Apply turns on threaded NAPI for every interface backed by a device, which
// on EC2 is every attached ENI, and sets primary's receive threads to
// OwnNice. It returns how many settings it changed, and is safe to run
// repeatedly.
func Apply(primary string) (int, error) {
	changed := 0
	var errs []error
	// Glob fails only on a malformed pattern.
	devices, _ := filepath.Glob("/sys/class/net/*/device")
	for _, device := range devices {
		enabled, err := enable(filepath.Join(filepath.Dir(device), "threaded"))
		if err != nil {
			errs = append(errs, err)
		} else if enabled {
			changed++
		}
	}
	raised, err := raise(primary)
	return changed + raised, errors.Join(append(errs, err)...)
}

// enable writes 1 to an interface's threaded file if it holds 0. Other values,
// such as 2 for busy polling on newer kernels, were set by someone else and
// stay.
func enable(path string) (bool, error) {
	current, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if strings.TrimSpace(string(current)) != "0" {
		return false, nil
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return false, fmt.Errorf("failed to turn on threaded NAPI in %s: %w", path, err)
	}
	return true, nil
}

// raise sets primary's receive threads to OwnNice and returns how many it
// changed. The kernel creates new threads when a driver resets an interface,
// so it checks every task each time.
func raise(primary string) (int, error) {
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	var tasks []task
	for _, path := range stats {
		contents, err := os.ReadFile(path)
		if err != nil {
			// The task exited since the glob.
			continue
		}
		t, err := parseStat(string(contents))
		if err != nil {
			return 0, err
		}
		tasks = append(tasks, t)
	}
	raised := 0
	var errs []error
	for _, pid := range primaryThreads(tasks, primary) {
		if err := unix.Setpriority(unix.PRIO_PROCESS, pid, OwnNice); err != nil {
			errs = append(errs, fmt.Errorf("failed to set the nice value of receive thread %d: %w", pid, err))
			continue
		}
		raised++
	}
	return raised, errors.Join(errs...)
}
