// Package command runs short-lived system tools such as iptables and ip.
package command

import (
	"bytes"
	"context"
	"fmt"
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
