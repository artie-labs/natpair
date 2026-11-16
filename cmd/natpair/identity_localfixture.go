//go:build localfixture

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/controller"
	"github.com/artie-labs/natpair/internal/handoff"
)

// The local fault campaign has no EC2. Instead of moving the shared ENI, a
// takeover points the neighbor entries for the shared addresses at this NAT.
// NATPAIR_FIXTURE_NEIGHBORS names a JSON file listing them. Each NAT holds
// the shared addresses on its own worker and outside interfaces, so with
// flow offload, a takeover offloads through the interfaces that
// NATPAIR_FIXTURE_OFFLOAD_DEVICES lists, comma-separated, where the real one
// offloads through the shared ENI. This build is only for the campaign and
// never ships.
func newHandoff(_ config.NAT, _ handoff.EC2, steps handoff.Local) func(func() error, bool) controller.Preparer {
	return func(guard func() error, verify bool) controller.Preparer {
		return fixtureIdentity{steps: steps, guard: guard, verify: verify}
	}
}

// fixtureNeighbor is a neighbor entry to point at this NAT during takeover.
// Netns is the path of the other host's network namespace.
type fixtureNeighbor struct {
	Netns     string     `json:"netns"`
	Interface string     `json:"interface"`
	Address   netip.Addr `json:"address"`
	MAC       string     `json:"mac"`
}

type fixtureIdentity struct {
	steps  handoff.Local
	guard  func() error
	verify bool
}

func (f fixtureIdentity) Prepare(ctx context.Context) error {
	contents, err := os.ReadFile(os.Getenv("NATPAIR_FIXTURE_NEIGHBORS"))
	if err != nil {
		return fmt.Errorf("failed to read fixture neighbors: %w", err)
	}
	var neighbors []fixtureNeighbor
	if err := json.Unmarshal(contents, &neighbors); err != nil {
		return fmt.Errorf("failed to parse fixture neighbors: %w", err)
	}
	if err := f.guard(); err != nil {
		return err
	}
	if err := f.steps.PrepareNetwork(ctx); err != nil {
		return err
	}
	if err := f.guard(); err != nil {
		return err
	}
	// As in the real handoff, a failed commit leaves existing connections to be
	// reset instead of stopping the takeover.
	if err := f.steps.CommitState(ctx); err != nil {
		slog.Warn("taking over without copied connections", slog.Any("err", err))
	}
	for _, neighbor := range neighbors {
		if err := f.guard(); err != nil {
			return err
		}
		if _, err := command.Run(ctx, 2*time.Second, "nsenter", "--net="+neighbor.Netns, "ip", "neigh", "replace", neighbor.Address.String(),
			"lladdr", neighbor.MAC, "nud", "permanent", "dev", neighbor.Interface); err != nil {
			return err
		}
	}
	if err := f.guard(); err != nil {
		return err
	}
	if devices := os.Getenv("NATPAIR_FIXTURE_OFFLOAD_DEVICES"); devices != "" {
		steps, ok := f.steps.(localSteps)
		if !ok {
			return fmt.Errorf("the fixture offloads only through this host's steps")
		}
		if err := steps.network.OffloadThrough(ctx, strings.Split(devices, ",")); err != nil {
			slog.Warn("failed to offload worker connections", slog.Any("err", err))
		}
	}
	if !f.verify {
		return nil
	}
	return f.steps.VerifyIdentity(ctx)
}
