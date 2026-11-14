package main

import (
	"bytes"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/config"
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

func TestSpreadInterruptsLogsALastingFailureOnce(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	writeFails := func() (int, error) { return 0, errors.New("write failed") }
	readFails := func() (int, error) { return 0, errors.New("read failed") }
	works := func() (int, error) { return 0, nil }

	lastErr := spreadInterrupts("", writeFails)
	lastErr = spreadInterrupts(lastErr, writeFails)
	assert.Equal(t, 1, strings.Count(logs.String(), "write failed"))
	// A different failure is logged
	lastErr = spreadInterrupts(lastErr, readFails)
	assert.Equal(t, 1, strings.Count(logs.String(), "read failed"))
	// A pass that works resets it, so the same failure is logged again
	lastErr = spreadInterrupts(lastErr, works)
	assert.Empty(t, lastErr)
	spreadInterrupts(lastErr, writeFails)
	assert.Equal(t, 2, strings.Count(logs.String(), "write failed"))
}
