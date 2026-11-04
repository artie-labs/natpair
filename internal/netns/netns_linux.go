package netns

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func do(name string, fn func() error) error {
	target, err := os.Open(filepath.Join("/run/netns", name))
	if err != nil {
		return fmt.Errorf("failed to open network namespace %q: %w", name, err)
	}
	defer target.Close()

	// Run on a dedicated goroutine. If restoring the original namespace fails,
	// that goroutine exits with its thread still locked, and the runtime then
	// discards the thread instead of reusing it in the wrong namespace.
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
		if err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("failed to open current network namespace: %w", err)
			return
		}
		defer original.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("failed to enter network namespace %q: %w", name, err)
			return
		}
		err = fn()
		if restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			result <- fmt.Errorf("failed to leave network namespace %q: %w", name, restoreErr)
			return
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	return <-result
}
