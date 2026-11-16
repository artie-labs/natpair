// Package command runs short-lived system tools such as iptables and ip.
package command

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Run runs name with args and returns its trimmed standard output. The command
// and any processes it starts are killed if it outlives timeout.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	return RunWithInput(ctx, timeout, "", name, args...)
}

// RunWithInput behaves like [Run] and writes input to the command's standard input.
func RunWithInput(ctx context.Context, timeout time.Duration, input, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	// Run the command in its own process group so a timeout also kills any
	// children it started, such as a probe launched through `ip netns exec`.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w: %s", name, err, lastBytes(stderr.String(), 500))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func lastBytes(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[len(value)-limit:]
	}
	return value
}

// Stream runs name with args and passes its standard output to read as it
// arrives, so a large output never has to fit in memory. The command and any
// processes it starts are killed if it outlives timeout, or if read returns
// before the output ends.
func Stream(ctx context.Context, timeout time.Duration, read func(io.Reader) error, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	readErr := read(stdout)
	if readErr != nil {
		// Stop the command, so Wait doesn't block on output nobody reads.
		cancel()
	}
	waitErr := cmd.Wait()
	switch {
	case readErr != nil:
		return fmt.Errorf("failed to read the output of %s: %w", name, readErr)
	case waitErr != nil:
		return fmt.Errorf("%s failed: %w: %s", name, waitErr, lastBytes(stderr.String(), 500))
	}
	return nil
}
