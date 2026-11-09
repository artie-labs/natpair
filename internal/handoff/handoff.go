// Package handoff moves the shared ENI to this NAT during takeover, while
// worker forwarding stays closed.
//
// Worker route tables point at the shared ENI, and the shared Elastic IP is
// associated with its private IP, so moving the ENI moves both of them.
// Takeover installs local rules and the copied connections, then repeatedly
// reads the ENI and moves it one step closer to being attached here: detach
// it from another instance, attach it here, or wait for AWS to finish a
// change.
//
// Each step is chosen from what EC2 reports now, so nothing needs to be
// remembered between attempts. A late request from a previous owner usually
// fails, because the attachment it names no longer exists or the ENI is
// already attached. At worst it attaches the ENI to that owner while the ENI
// is detached. That is harmless, because the previous owner's fence already
// blocks worker traffic, and the next read finds it and moves the ENI back.
package handoff

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// pollInterval is how often the ENI is re-read while it moves. It's a
// variable only so tests can shorten it (export_test.go).
var pollInterval = 200 * time.Millisecond

const (
	// callTimeout bounds each EC2 request, so one stuck request cannot use the
	// whole takeover budget.
	callTimeout = 2 * time.Second
	// forceDetachAfter is how long a detach may stay in progress before it is
	// forced. A detach from a healthy instance took up to 11 s on AWS, and a
	// forced one needs the old NAT stopped and started, so this waits well past
	// that. A detach from an impaired instance can hang until the takeover's
	// time limit. From a stopping instance, EC2 finishes the detach only once
	// the instance has stopped, forced or not: about 20 s after a forced stop
	// on AWS.
	forceDetachAfter = 15 * time.Second
)

// EC2 is the subset of the EC2 client used for takeover.
type EC2 interface {
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
	DetachNetworkInterface(ctx context.Context, params *ec2.DetachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error)
	AttachNetworkInterface(ctx context.Context, params *ec2.AttachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error)
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// Local performs the steps on this host.
type Local interface {
	// PrepareNetwork installs SNAT and routing rules for the shared ENI.
	PrepareNetwork(ctx context.Context) error
	// DropStale deletes this NAT's own entries for connections translated to
	// the shared address, which are out of date once the other NAT has served.
	DropStale(ctx context.Context) error
	// CommitState installs connection state copied from the old NAT. If it
	// fails, the takeover continues without the copies.
	CommitState(ctx context.Context) error
	// ClaimShared stops the operating system from configuring the shared ENI.
	// It runs before each attach.
	ClaimShared(ctx context.Context, mac string) error
	// ActivateShared configures the shared ENI once it is attached here.
	ActivateShared(ctx context.Context, mac string) error
	// VerifyIdentity sends verified uploads out through the shared Elastic IP.
	VerifyIdentity(ctx context.Context) error
}

// Config identifies the shared ENI and this NAT.
type Config struct {
	InstanceID string
	SharedENI  string
	// DeviceIndex is where the shared ENI attaches on this instance.
	DeviceIndex int32
	// Timeout bounds the whole takeover.
	Timeout time.Duration
}

// Handoff performs one takeover.
type Handoff struct {
	config Config
	ec2    EC2
	local  Local
	// guard fails once this owner's lease grant has expired.
	guard    func() error
	verify   bool
	deadline time.Time
}

// New returns a handoff that must finish within config.Timeout.
//
// verify sends the final uploads through the shared Elastic IP. A last-resort
// takeover, by a NAT that could not reach the probe receiver, skips them,
// because they would fail for the same reason.
func New(config Config, client EC2, local Local, guard func() error, verify bool) *Handoff {
	return &Handoff{config: config, ec2: client, local: local, guard: guard, verify: verify, deadline: time.Now().Add(config.Timeout)}
}

// Prepare moves the shared ENI to this NAT and, unless verification is off,
// checks uploads through the shared Elastic IP.
// Forwarding for workers must stay closed until it returns successfully.
func (h *Handoff) Prepare(ctx context.Context) error {
	ctx, cancel := context.WithDeadline(ctx, h.deadline)
	defer cancel()
	started := time.Now()

	// Install rules and copied connections before the ENI arrives. Replies
	// for existing connections then match a copied entry and wait at the
	// closed fence, instead of reaching a local address with no socket and
	// being answered with a reset.
	if err := h.step(ctx, "prepare network", h.local.PrepareNetwork); err != nil {
		return err
	}
	// The shared ENI on the other NAT means it served since this NAT last did,
	// so this NAT's own entries are out of date and could block the copies.
	// While the ENI is still here, they're this NAT's live connections.
	if shared, err := h.sharedENI(ctx); err == nil && shared.Attachment != nil && aws.ToString(shared.Attachment.InstanceId) != h.config.InstanceID {
		if err := h.step(ctx, "drop out-of-date connections", h.local.DropStale); err != nil {
			if guardErr := h.guard(); guardErr != nil {
				return guardErr
			}
			slog.Warn("failed to drop out-of-date connections, so some copies may not install", slog.Any("err", err))
		}
	}
	if err := h.step(ctx, "install copied connections", h.local.CommitState); err != nil {
		if guardErr := h.guard(); guardErr != nil {
			return guardErr
		}
		// For example, conntrackd is down. Existing connections are then reset,
		// which beats leaving no NAT forwarding.
		slog.Warn("taking over without copied connections", slog.Any("err", err))
	}

	shared, err := h.attach(ctx)
	if err != nil {
		return err
	}
	if err := h.step(ctx, "activate shared ENI", func(ctx context.Context) error {
		return h.local.ActivateShared(ctx, aws.ToString(shared.MacAddress))
	}); err != nil {
		return err
	}
	// The shared canary bypasses the worker fence, so it can
	// verify the path while workers are still blocked.
	if h.verify {
		if err := h.step(ctx, "verify the shared Elastic IP", h.verifyIdentity); err != nil {
			return err
		}
	}
	slog.Info("identity prepared", slog.Duration("duration", time.Since(started)))
	return nil
}

// attach moves the shared ENI one step at a time until it is attached here.
//
// A detach that stays in progress for forceDetachAfter is forced. That is
// safe, because this NAT holds the lease and only the NAT holding the ENI gets
// worker traffic. AWS may leave the instance it was forced from still showing
// the interface, and unable to attach another at the same index, so stop and
// start that NAT before it serves again.
//
// A detach from this NAT that stays in progress for forceDetachAfter ends the
// takeover instead, so the peer can take the lease and force it. Forcing it
// from here and attaching back would leave this NAT needing a stop and start.
// Otherwise a NAT whose detach the peer had forced could take the lease back
// and wait out its whole takeover for that detach to finish.
func (h *Handoff) attach(ctx context.Context) (types.NetworkInterface, error) {
	var detachingSince time.Time
	for {
		if err := h.guard(); err != nil {
			return types.NetworkInterface{}, err
		}
		shared, err := h.sharedENI(ctx)
		if err == nil && aws.ToBool(shared.SourceDestCheck) {
			return types.NetworkInterface{}, fmt.Errorf("source/destination checking must be disabled on shared ENI %s", h.config.SharedENI)
		}
		attachment := shared.Attachment
		detaching := err == nil && attachment != nil && attachment.Status == types.AttachmentStatusDetaching
		// A failed read keeps the timer, so read errors cannot postpone a
		// forced detach.
		if err == nil && !detaching {
			detachingSince = time.Time{}
		} else if detaching && detachingSince.IsZero() {
			detachingSince = time.Now()
		}
		stuck := detaching && time.Since(detachingSince) >= forceDetachAfter
		switch {
		case err != nil:
			// Read again after the pause below.
		case attachment == nil || shared.Status == types.NetworkInterfaceStatusAvailable:
			if err = h.local.ClaimShared(ctx, aws.ToString(shared.MacAddress)); err != nil {
				break
			}
			err = h.change(ctx, "attach", func(ctx context.Context) error {
				_, err := h.ec2.AttachNetworkInterface(ctx, &ec2.AttachNetworkInterfaceInput{
					NetworkInterfaceId: aws.String(h.config.SharedENI),
					InstanceId:         aws.String(h.config.InstanceID),
					DeviceIndex:        aws.Int32(h.config.DeviceIndex),
				})
				return err
			})
		case stuck && aws.ToString(attachment.InstanceId) == h.config.InstanceID:
			return types.NetworkInterface{}, fmt.Errorf("shared ENI %s is still detaching from this instance after %s, so the peer has to force the detach", h.config.SharedENI, forceDetachAfter)
		case stuck:
			err = h.detach(ctx, attachment.AttachmentId, true)
			detachingSince = time.Now()
			h.logForcedDetach(ctx, aws.ToString(attachment.InstanceId))
		case attachment.Status != types.AttachmentStatusAttached:
			// Attaching or detaching. Wait for EC2 to finish.
		case aws.ToString(attachment.InstanceId) == h.config.InstanceID:
			return shared, nil
		default:
			err = h.detach(ctx, attachment.AttachmentId, false)
		}
		// A failed read or change may be explained by a newer state, such as
		// a late request from an earlier owner, so try again instead of giving
		// up. Errors that never clear, such as missing permissions, end the
		// takeover at its deadline.
		if err != nil {
			slog.Warn("shared ENI step failed, trying again", slog.Any("err", err))
		}
		select {
		case <-ctx.Done():
			return types.NetworkInterface{}, fmt.Errorf("shared ENI %s did not attach to this instance in time: %w", h.config.SharedENI, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// logForcedDetach says whether the instance a detach was forced from needs a
// stop and start. One that is stopping or gone starts fresh anyway, because
// EC2 doesn't finish its detach until it stops. A running instance, or one
// whose state can't be read, needs a person. On AWS, a detach from a running
// NAT that had just stepped down was still in progress after 15 s.
func (h *Handoff) logForcedDetach(ctx context.Context, instanceID string) {
	state := "unknown"
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	output, err := h.ec2.DescribeInstances(callCtx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceID}})
	if err == nil && output != nil && len(output.Reservations) == 1 && len(output.Reservations[0].Instances) == 1 && output.Reservations[0].Instances[0].State != nil {
		state = string(output.Reservations[0].Instances[0].State.Name)
	}
	switch types.InstanceStateName(state) {
	case types.InstanceStateNameStopping, types.InstanceStateNameStopped, types.InstanceStateNameShuttingDown, types.InstanceStateNameTerminated:
		slog.Info("forced the stuck shared ENI detach from an instance that is stopping or gone, so it needs no action",
			slog.String("instance", instanceID), slog.String("state", state))
	default:
		slog.Warn("forced the stuck shared ENI detach. Stop and start the NAT it was attached to before it serves again.",
			slog.String("instance", instanceID), slog.String("state", state), slog.Any("err", err))
	}
}

// detach detaches the shared ENI from another instance.
func (h *Handoff) detach(ctx context.Context, attachmentID *string, force bool) error {
	name := "detach"
	if force {
		name = "force detach"
	}
	return h.change(ctx, name, func(ctx context.Context) error {
		_, err := h.ec2.DetachNetworkInterface(ctx, &ec2.DetachNetworkInterfaceInput{AttachmentId: attachmentID, Force: aws.Bool(force)})
		return err
	})
}

// change sends one EC2 change if this owner's grant is still valid.
func (h *Handoff) change(ctx context.Context, name string, send func(context.Context) error) error {
	if err := h.guard(); err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	started := time.Now()
	if err := send(callCtx); err != nil {
		return fmt.Errorf("failed to %s shared ENI %s: %w", name, h.config.SharedENI, err)
	}
	slog.Info("shared ENI change sent", slog.String("change", name), slog.Duration("duration", time.Since(started)))
	return nil
}

func (h *Handoff) sharedENI(ctx context.Context) (types.NetworkInterface, error) {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	output, err := h.ec2.DescribeNetworkInterfaces(callCtx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{h.config.SharedENI}})
	if err != nil {
		return types.NetworkInterface{}, fmt.Errorf("failed to read shared ENI %s: %w", h.config.SharedENI, err)
	}
	if len(output.NetworkInterfaces) != 1 {
		return types.NetworkInterface{}, fmt.Errorf("expected one network interface %s, got %d", h.config.SharedENI, len(output.NetworkInterfaces))
	}
	return output.NetworkInterfaces[0], nil
}

// verifyIdentity retries the uploads until one succeeds. Right after an
// attach, EC2 can take a few seconds to deliver the shared ENI's traffic, so
// the first uploads may time out. Forwarding stays closed meanwhile, and the
// takeover's deadline and the lease guard still bound the wait.
func (h *Handoff) verifyIdentity(ctx context.Context) error {
	for {
		err := h.local.VerifyIdentity(ctx)
		if err == nil {
			return nil
		}
		if guardErr := h.guard(); guardErr != nil {
			return guardErr
		}
		slog.Warn("shared Elastic IP not working yet, trying again", slog.Any("err", err))
		select {
		case <-ctx.Done():
			return err
		case <-time.After(pollInterval):
		}
	}
}

func (h *Handoff) step(ctx context.Context, name string, fn func(context.Context) error) error {
	if err := h.guard(); err != nil {
		return err
	}
	started := time.Now()
	if err := fn(ctx); err != nil {
		return fmt.Errorf("failed to %s: %w", name, err)
	}
	slog.Info("handoff step", slog.String("step", name), slog.Duration("duration", time.Since(started)))
	return h.guard()
}
