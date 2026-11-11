package main

import (
	"path/filepath"
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

func TestPacingConfig(t *testing.T) {
	{
		// Configurations without the setting leave pacing off
		assert.False(t, pacingConfig(config.NAT{}).Enabled)
	}
	{
		settings := pacingConfig(config.NAT{Pacing: &config.Pacing{Enabled: true, StartMbps: 800, StartKpps: 250}})
		assert.True(t, settings.Enabled)
		assert.Equal(t, 100e6, settings.StartBytes)
		assert.Equal(t, 250e3, settings.StartPackets)
	}
}
