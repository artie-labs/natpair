package handoff

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
)

// stateEC2 reports one instance's state, or fails.
type stateEC2 struct {
	EC2
	state types.InstanceStateName
	err   error
}

func (s stateEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: []types.Instance{{State: &types.InstanceState{Name: s.state}}}}}}, nil
}

func TestLogForcedDetach(t *testing.T) {
	logged := func(client EC2) string {
		var buf bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
		defer slog.SetDefault(previous)
		(&Handoff{ec2: client}).logForcedDetach(t.Context(), "i-old")
		return buf.String()
	}
	{
		// An instance that is stopping starts fresh, so nobody needs to act
		out := logged(stateEC2{state: types.InstanceStateNameStopping})
		assert.Contains(t, out, "needs no action")
		assert.NotContains(t, out, "Stop and start")
	}
	{
		// A running instance needs a stop and start
		out := logged(stateEC2{state: types.InstanceStateNameRunning})
		assert.Contains(t, out, "Stop and start the NAT")
		assert.Contains(t, out, `"state":"running"`)
	}
	{
		// So does one whose state can't be read
		out := logged(stateEC2{err: errors.New("UnauthorizedOperation")})
		assert.Contains(t, out, "Stop and start the NAT")
		assert.Contains(t, out, `"state":"unknown"`)
	}
}
