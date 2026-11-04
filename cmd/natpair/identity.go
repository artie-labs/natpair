//go:build !localfixture

package main

import (
	"time"

	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/controller"
	"github.com/artie-labs/natpair/internal/handoff"
)

// sharedDeviceIndex is where the shared ENI attaches, after the primary
// interface at index 0.
const sharedDeviceIndex = 1

// newHandoff returns the EC2 takeover for each newly granted owner.
func newHandoff(cfg config.NAT, client handoff.EC2, steps handoff.Local) func(func() error, bool) controller.Preparer {
	handoffConfig := handoff.Config{
		InstanceID:  cfg.Instance.ID,
		SharedENI:   cfg.SharedENI,
		DeviceIndex: sharedDeviceIndex,
		// Leave a second for the controller to open the fence within its own limit.
		Timeout: prepareTimeout - time.Second,
	}
	return func(guard func() error, verify bool) controller.Preparer {
		return handoff.New(handoffConfig, client, steps, guard, verify)
	}
}
