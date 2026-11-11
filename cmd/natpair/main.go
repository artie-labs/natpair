// Command natpair runs a highly available pair of NAT instances.
//
// Usage:
//
//	natpair validate    --config /etc/natpair/config.json
//	natpair bootstrap   --config /etc/natpair/config.json
//	natpair run         --config /etc/natpair/config.json
//	natpair fence-close --config /etc/natpair/config.json
//	natpair maintenance
//	natpair resume
//	natpair pacing-off
//	natpair pacing-on
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// release is the release tag GoReleaser builds, such as v0.1.0. Other builds
// leave it empty.
var release string

const usage = `usage: natpair <command> [flags]

commands:
  validate     check a NAT configuration
  bootstrap    close forwarding and prepare networking at boot
  run          run health checks and ownership on a NAT
  fence-close  close worker forwarding (stop natpair.service first)
  maintenance  hand ownership from this NAT to a ready peer
  resume       make this NAT an eligible standby again
  pacing-off   stop pacing forwarded traffic, until pacing-on
  pacing-on    pace forwarded traffic again, if the configuration turns it on
`

func main() {
	// Logs go to stderr so command output, such as maintenance results, stays separate.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	commands := map[string]func(context.Context, []string) error{
		"validate":    validate,
		"bootstrap":   bootstrap,
		"run":         runNAT,
		"fence-close": fenceClose,
		"maintenance": maintenance,
		"resume":      resume,
		"pacing-off":  pacingOff,
		"pacing-on":   pacingOn,
	}
	command, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := command(ctx, os.Args[2:]); err != nil {
		slog.Error("command failed", slog.String("command", os.Args[1]), slog.Any("err", err))
		os.Exit(1)
	}
}

// configFlag parses a --config flag.
func configFlag(name string, args []string) (string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	path := flags.String("config", "", "path to the configuration file")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if *path == "" {
		return "", fmt.Errorf("--config is required")
	}
	return *path, nil
}
