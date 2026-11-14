package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/network"
)

func TestDeployExamplesAreValid(t *testing.T) {
	_, err := config.LoadNAT("../../deploy/config.example.json")
	assert.NoError(t, err)
}

func TestReportedRelease(t *testing.T) {
	previous := release
	release = "v0.1.15"
	defer func() { release = previous }()
	{
		// Bootstrap creates the directory, which /run doesn't have after a boot
		path := filepath.Join(t.TempDir(), "natpair", "release")
		require.NoError(t, writeBootedRelease(path, "v0.1.15"))
		assert.Equal(t, "v0.1.15", reportedRelease(path))
	}
	{
		// A daemon restarted into another release's binary reports none, so
		// it doesn't match any pin, including a rollback to the boot's release
		path := filepath.Join(t.TempDir(), "release")
		require.NoError(t, writeBootedRelease(path, "v0.1.14"))
		assert.Empty(t, reportedRelease(path))
	}
	{
		assert.Empty(t, reportedRelease(filepath.Join(t.TempDir(), "release")))
	}
}

// captureLogs sends the default logger's output to the returned buffer until
// the test ends.
func captureLogs(t *testing.T) *bytes.Buffer {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func TestReceiveThreadingLogsALastingFailureOnce(t *testing.T) {
	logs := captureLogs(t)
	var result func() (int, error)
	r := &receiveThreading{enable: func() (int, error) { return result() }}
	writeFails := func() (int, error) { return 0, errors.New("write failed") }
	readFails := func() (int, error) { return 1, errors.New("read failed") }
	works := func() (int, error) { return 0, nil }

	result = writeFails
	r.turnOn()
	r.turnOn()
	assert.Equal(t, 1, strings.Count(logs.String(), "write failed"))
	// A different failure is logged, and so is an interface turned on beside it
	result = readFails
	r.turnOn()
	assert.Equal(t, 1, strings.Count(logs.String(), "read failed"))
	assert.Equal(t, 1, strings.Count(logs.String(), `"interfaces":1`))
	// A pass that works resets it, so the same failure is logged again
	result = works
	r.turnOn()
	result = readFails
	r.turnOn()
	assert.Equal(t, 2, strings.Count(logs.String(), "read failed"))
}

func TestActivateSharedTurnsOnThreadedReceive(t *testing.T) {
	logs := captureLogs(t)
	cfg, err := config.LoadNAT("../../internal/config/testdata/nat.json")
	require.NoError(t, err)
	runner := &mocks.FakeRunner{}
	runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		if name == "ip" && slices.Equal(args, []string{"-j", "link"}) {
			return `[{"ifname":"lo","address":"00:00:00:00:00:00"},{"ifname":"ens5","address":"02:00:00:00:00:05"},{"ifname":"ens6","address":"02:00:00:00:00:06"}]`, nil
		}
		return "", nil
	})
	calls := 0
	commandsBefore := 0
	r := &receiveThreading{enable: func() (int, error) {
		calls++
		commandsBefore = runner.RunCallCount()
		return 0, errors.New("failed to write 1 to /sys/class/net/ens6/threaded: invalid argument")
	}}
	steps := localSteps{network: network.New(cfg, &mocks.FakeNetworkFence{}, runner), receive: r}
	{
		// A failure the 5 s loop already logged isn't logged again, and it
		// doesn't fail the takeover
		r.turnOn()
		require.NoError(t, steps.ActivateShared(t.Context(), "02:00:00:00:00:06"))
		assert.Equal(t, 2, calls)
		assert.Equal(t, 1, strings.Count(logs.String(), "failed to turn on threaded receive processing"))
		// It runs once the shared ENI is up and routed, and nothing runs after it
		assert.Equal(t, runner.RunCallCount(), commandsBefore)
		_, _, name, args := runner.RunArgsForCall(commandsBefore - 1)
		assert.Equal(t, "ip route replace default via 10.0.1.1 dev ens6 table 7001", strings.Join(append([]string{name}, args...), " "))
	}
	{
		// A failed activation returns before it
		assert.EqualError(t, steps.ActivateShared(t.Context(), "not-a-mac"), `invalid shared ENI MAC "not-a-mac"`)
		assert.Equal(t, 2, calls)
	}
}
