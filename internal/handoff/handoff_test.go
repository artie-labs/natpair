package handoff_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/handoff"
	"github.com/artie-labs/natpair/internal/mocks"
)

var config = handoff.Config{InstanceID: "nat-b", SharedENI: "shared", DeviceIndex: 1, Timeout: 5 * time.Second}

// cloud is a fake EC2 account with one shared ENI, attached to NAT A at first.
type cloud struct {
	shared types.NetworkInterface
	moves  []string
	// afterDetach, if set, runs once after a detach, like a late request
	// from an earlier owner landing at that moment.
	afterDetach func()
	// impaired makes a normal detach hang in progress, as from an impaired
	// instance. Only a forced detach finishes.
	impaired bool
}

func newCloud() *cloud {
	c := &cloud{shared: types.NetworkInterface{
		SourceDestCheck: aws.Bool(false),
		MacAddress:      aws.String("02:00:00:00:00:01"),
	}}
	c.attachTo("nat-a", "old")
	return c
}

func (c *cloud) attachTo(instance, attachment string) {
	c.shared.Status = types.NetworkInterfaceStatusInUse
	c.shared.Attachment = &types.NetworkInterfaceAttachment{InstanceId: aws.String(instance), AttachmentId: aws.String(attachment), Status: types.AttachmentStatusAttached}
}

func (c *cloud) fake() *mocks.FakeEC2 {
	client := &mocks.FakeEC2{}
	client.DescribeNetworkInterfacesCalls(func(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
		// Return a copy, like a real API response.
		shared := c.shared
		if shared.Attachment != nil {
			attachment := *shared.Attachment
			shared.Attachment = &attachment
		}
		return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []types.NetworkInterface{shared}}, nil
	})
	client.DetachNetworkInterfaceCalls(func(_ context.Context, input *ec2.DetachNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error) {
		if c.shared.Attachment == nil || aws.ToString(c.shared.Attachment.AttachmentId) != aws.ToString(input.AttachmentId) {
			return nil, errors.New("InvalidAttachmentID.NotFound")
		}
		if c.impaired && !aws.ToBool(input.Force) {
			c.shared.Attachment.Status = types.AttachmentStatusDetaching
			return &ec2.DetachNetworkInterfaceOutput{}, nil
		}
		c.moves = append(c.moves, "detach")
		c.shared.Attachment, c.shared.Status = nil, types.NetworkInterfaceStatusAvailable
		if c.afterDetach != nil {
			c.afterDetach()
			c.afterDetach = nil
		}
		return &ec2.DetachNetworkInterfaceOutput{}, nil
	})
	client.AttachNetworkInterfaceCalls(func(_ context.Context, input *ec2.AttachNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error) {
		if c.shared.Attachment != nil {
			return nil, errors.New("InvalidParameterValue: interface is currently in use")
		}
		c.moves = append(c.moves, "attach")
		c.attachTo(aws.ToString(input.InstanceId), "new")
		return &ec2.AttachNetworkInterfaceOutput{AttachmentId: aws.String("new")}, nil
	})
	return client
}

func allowed() error { return nil }

func TestPrepare(t *testing.T) {
	{
		// Install copied connections first, then detach from A and attach here. A retry changes nothing.
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		client := c.fake()
		local.DropStaleCalls(func(context.Context) error {
			assert.Zero(t, local.CommitStateCallCount(), "out-of-date connections must go before the copies install")
			return nil
		})
		local.CommitStateCalls(func(context.Context) error {
			assert.Empty(t, c.moves, "copied connections must be installed before the ENI moves")
			return nil
		})
		local.ClaimSharedCalls(func(_ context.Context, mac string) error {
			assert.Equal(t, []string{"detach"}, c.moves, "the operating system must be told to leave the ENI alone before it attaches")
			assert.Equal(t, "02:00:00:00:00:01", mac)
			return nil
		})
		require.NoError(t, handoff.New(config, client, local, allowed, true).Prepare(t.Context()))
		assert.Equal(t, []string{"detach", "attach"}, c.moves)
		assert.Equal(t, 1, local.ClaimSharedCallCount())
		_, detach, _ := client.DetachNetworkInterfaceArgsForCall(0)
		assert.False(t, aws.ToBool(detach.Force))
		_, attach, _ := client.AttachNetworkInterfaceArgsForCall(0)
		assert.Equal(t, "nat-b", aws.ToString(attach.InstanceId))
		assert.Equal(t, int32(1), aws.ToInt32(attach.DeviceIndex))
		_, mac := local.ActivateSharedArgsForCall(0)
		assert.Equal(t, "02:00:00:00:00:01", mac)
		assert.Equal(t, 1, local.VerifyIdentityCallCount())
		// The ENI was on the other NAT, so this NAT's own entries were out of date.
		assert.Equal(t, 1, local.DropStaleCallCount())

		// A retry finds the ENI already here, so its connections are live.
		local.CommitStateReturns(nil)
		require.NoError(t, handoff.New(config, client, local, allowed, true).Prepare(t.Context()))
		assert.Len(t, c.moves, 2)
		assert.Equal(t, 1, local.DropStaleCallCount())
	}
	{
		// A failed commit, for example with conntrackd down, doesn't stop the takeover
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		local.CommitStateReturns(errors.New("conntrackd is not running"))
		require.NoError(t, handoff.New(config, c.fake(), local, allowed, true).Prepare(t.Context()))
		assert.Equal(t, []string{"detach", "attach"}, c.moves)
		assert.Equal(t, 1, local.VerifyIdentityCallCount())
	}
	{
		// But a lease lost during the commit still ends the takeover
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		lost := errors.New("lease lost")
		var expired bool
		local.CommitStateCalls(func(context.Context) error {
			expired = true
			return errors.New("timed out")
		})
		guard := func() error {
			if expired {
				return lost
			}
			return nil
		}
		assert.ErrorIs(t, handoff.New(config, c.fake(), local, guard, true).Prepare(t.Context()), lost)
		assert.Empty(t, c.moves)
	}
	{
		// A last-resort takeover moves the ENI but skips the final uploads, which
		// would fail for the same reason the path could not be proven
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		require.NoError(t, handoff.New(config, c.fake(), local, allowed, false).Prepare(t.Context()))
		assert.Equal(t, []string{"detach", "attach"}, c.moves)
		assert.Equal(t, 1, local.ActivateSharedCallCount())
		assert.Zero(t, local.VerifyIdentityCallCount())
	}
	{
		// Uploads that fail right after the attach, while EC2 starts delivering
		// the ENI's traffic, are retried within the takeover
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		local.VerifyIdentityReturnsOnCall(0, errors.New("i/o timeout"))
		local.VerifyIdentityReturnsOnCall(1, errors.New("i/o timeout"))
		require.NoError(t, handoff.New(config, c.fake(), local, allowed, true).Prepare(t.Context()))
		assert.Equal(t, 3, local.VerifyIdentityCallCount())
	}
	{
		// A shared path that never works fails the takeover at its deadline
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		local.VerifyIdentityReturns(errors.New("i/o timeout"))
		short := config
		short.Timeout = 150 * time.Millisecond
		err := handoff.New(short, c.fake(), local, allowed, true).Prepare(t.Context())
		assert.ErrorContains(t, err, "failed to verify the shared Elastic IP: i/o timeout")
	}
	{
		// A lease lost while retrying ends the takeover at once
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		lost := errors.New("lease lost")
		var failed bool
		local.VerifyIdentityCalls(func(context.Context) error {
			failed = true
			return errors.New("i/o timeout")
		})
		guard := func() error {
			if failed {
				return lost
			}
			return nil
		}
		assert.ErrorIs(t, handoff.New(config, c.fake(), local, guard, true).Prepare(t.Context()), lost)
		assert.Equal(t, 1, local.VerifyIdentityCallCount())
	}
	{
		// A failed claim holds back the attach until a retry succeeds
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		local.ClaimSharedReturnsOnCall(0, errors.New("networkctl failed"))
		require.NoError(t, handoff.New(config, c.fake(), local, allowed, true).Prepare(t.Context()))
		assert.Equal(t, []string{"detach", "attach"}, c.moves)
		assert.Equal(t, 2, local.ClaimSharedCallCount())
	}
	{
		// An unattached ENI is attached directly
		c := newCloud()
		c.shared.Attachment, c.shared.Status = nil, types.NetworkInterfaceStatusAvailable
		require.NoError(t, handoff.New(config, c.fake(), &mocks.FakeHandoffLocal{}, allowed, true).Prepare(t.Context()))
		assert.Equal(t, []string{"attach"}, c.moves)
	}
	{
		// A late attach from the earlier owner lands right after the detach, and the next pass corrects it
		c := newCloud()
		c.afterDetach = func() { c.attachTo("nat-a", "stale") }
		require.NoError(t, handoff.New(config, c.fake(), &mocks.FakeHandoffLocal{}, allowed, true).Prepare(t.Context()))
		assert.Equal(t, []string{"detach", "detach", "attach"}, c.moves)
		assert.Equal(t, "nat-b", aws.ToString(c.shared.Attachment.InstanceId))
	}
	{
		// A transition in progress is waited out, not interrupted
		c := newCloud()
		c.shared.Attachment.InstanceId, c.shared.Attachment.Status = aws.String("nat-b"), types.AttachmentStatusAttaching
		client := c.fake()
		describe := client.DescribeNetworkInterfacesStub
		client.DescribeNetworkInterfacesCalls(func(ctx context.Context, input *ec2.DescribeNetworkInterfacesInput, opts ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			output, err := describe(ctx, input, opts...)
			c.shared.Attachment.Status = types.AttachmentStatusAttached
			return output, err
		})
		require.NoError(t, handoff.New(config, client, &mocks.FakeHandoffLocal{}, allowed, true).Prepare(t.Context()))
		assert.Empty(t, c.moves)
		assert.Equal(t, 2, client.DescribeNetworkInterfacesCallCount())
	}
	{
		// Source/destination checking must be off for forwarding
		c := newCloud()
		c.shared.SourceDestCheck = aws.Bool(true)
		err := handoff.New(config, c.fake(), &mocks.FakeHandoffLocal{}, allowed, true).Prepare(t.Context())
		assert.ErrorContains(t, err, "source/destination checking must be disabled")
		assert.Empty(t, c.moves)
	}
	{
		// An error that never clears, such as missing permissions, ends the takeover at its deadline
		c := newCloud()
		client := c.fake()
		client.DetachNetworkInterfaceReturns(nil, errors.New("UnauthorizedOperation"))
		short := config
		short.Timeout = 150 * time.Millisecond
		err := handoff.New(short, client, &mocks.FakeHandoffLocal{}, allowed, true).Prepare(t.Context())
		assert.ErrorContains(t, err, "did not attach to this instance in time")
		assert.Greater(t, client.DetachNetworkInterfaceCallCount(), 1, "the change is retried")
	}
	{
		// A failure to drop out-of-date connections doesn't stop the takeover
		c, local := newCloud(), &mocks.FakeHandoffLocal{}
		local.DropStaleReturns(errors.New("conntrack failed"))
		require.NoError(t, handoff.New(config, c.fake(), local, allowed, true).Prepare(t.Context()))
		assert.Equal(t, 1, local.CommitStateCallCount())
		assert.Equal(t, []string{"detach", "attach"}, c.moves)
	}
	{
		// Once the lease is lost, no further change is sent
		c := newCloud()
		client := c.fake()
		lost := errors.New("lease lost")
		err := handoff.New(config, client, &mocks.FakeHandoffLocal{}, func() error { return lost }, true).Prepare(t.Context())
		assert.ErrorIs(t, err, lost)
		assert.Zero(t, client.DetachNetworkInterfaceCallCount())
		assert.Zero(t, client.AttachNetworkInterfaceCallCount())
	}
}

func TestMain(m *testing.M) {
	handoff.UseFastPolling()
	os.Exit(m.Run())
}
