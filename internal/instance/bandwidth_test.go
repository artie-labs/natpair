package instance_test

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/mocks"
)

// describe returns a fake EC2 client that describes one instance type with
// vcpus and network cards, and a default card.
func describe(vcpus, defaultCard int32, cards ...types.NetworkCardInfo) *mocks.FakeInstanceTypes {
	client := &mocks.FakeInstanceTypes{}
	client.DescribeInstanceTypesReturns(&ec2.DescribeInstanceTypesOutput{InstanceTypes: []types.InstanceTypeInfo{{
		InstanceType: types.InstanceTypeC7gnMedium,
		VCpuInfo:     &types.VCpuInfo{DefaultVCpus: aws.Int32(vcpus), DefaultCores: aws.Int32(vcpus)},
		NetworkInfo: &types.NetworkInfo{
			DefaultNetworkCardIndex: aws.Int32(defaultCard),
			NetworkPerformance:      aws.String("Up to 25 Gigabit"),
			NetworkCards:            cards,
		},
	}}}, nil)
	return client
}

func card(index int32, baselineGbps, peakGbps float64) types.NetworkCardInfo {
	return types.NetworkCardInfo{
		NetworkCardIndex:         aws.Int32(index),
		BaselineBandwidthInGbps:  aws.Float64(baselineGbps),
		PeakBandwidthInGbps:      aws.Float64(peakGbps),
		MaximumNetworkInterfaces: aws.Int32(2),
	}
}

func TestReadBandwidth(t *testing.T) {
	{
		// c7gn.medium, as EC2 describes it
		client := describe(1, 0, card(0, 3.125, 25))
		bandwidth, err := instance.ReadBandwidth(t.Context(), client, "c7gn.medium")
		require.NoError(t, err)
		assert.Equal(t, instance.Bandwidth{BaselineMbps: 3125, VCPUs: 1}, bandwidth)
		_, input, _ := client.DescribeInstanceTypesArgsForCall(0)
		assert.Equal(t, []types.InstanceType{"c7gn.medium"}, input.InstanceTypes)
	}
	{
		// With several network cards, the default card holds the primary
		// interface, whichever position EC2 lists it in
		bandwidth, err := instance.ReadBandwidth(t.Context(), describe(64, 1, card(0, 50, 50), card(1, 100, 100)), "c7gn.16xlarge")
		require.NoError(t, err)
		assert.Equal(t, instance.Bandwidth{BaselineMbps: 100000, VCPUs: 64}, bandwidth)
	}
	{
		// An instance type EC2 describes without a baseline, such as from an
		// older API, has no bandwidth instead of a zero one
		_, err := instance.ReadBandwidth(t.Context(), describe(1, 0, types.NetworkCardInfo{NetworkCardIndex: aws.Int32(0)}), "c7gn.medium")
		assert.EqualError(t, err, "EC2 didn't describe the baseline bandwidth of network card 0 of instance type c7gn.medium")
	}
	{
		_, err := instance.ReadBandwidth(t.Context(), describe(0, 0, card(0, 3.125, 25)), "c7gn.medium")
		assert.EqualError(t, err, "EC2 didn't describe the network or vCPUs of instance type c7gn.medium")
	}
	{
		client := &mocks.FakeInstanceTypes{}
		client.DescribeInstanceTypesReturns(&ec2.DescribeInstanceTypesOutput{}, nil)
		_, err := instance.ReadBandwidth(t.Context(), client, "c7gn.medium")
		assert.EqualError(t, err, "EC2 described 0 instance types for c7gn.medium, not 1")
	}
	{
		denied := errors.New("UnauthorizedOperation")
		client := &mocks.FakeInstanceTypes{}
		client.DescribeInstanceTypesReturns(nil, denied)
		_, err := instance.ReadBandwidth(t.Context(), client, "c7gn.medium")
		assert.ErrorIs(t, err, denied)
		assert.EqualError(t, err, "failed to describe instance type c7gn.medium: UnauthorizedOperation")
	}
}
