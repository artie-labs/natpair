package update_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/update"
)

const archiveContent = "release archive"

type updaterFixture struct {
	updater     *update.Updater
	pinned      *mocks.FakeRecords
	runner      *mocks.FakeUpdateRunner
	report      health.Report
	owner       bool
	maintenance bool
	handover    bool
	now         time.Duration
	// commands are the commands run, as "name arg arg".
	commands []string
}

func newUpdaterFixture(t *testing.T) *updaterFixture {
	return newUpdaterFixtureFrom(t, "https://github.com/artie-labs/natpair/releases/download")
}

// newUpdaterFixtureFrom downloads releases from the https:// or s3:// prefix releases.
func newUpdaterFixtureFrom(t *testing.T, releases string) *updaterFixture {
	dir := t.TempDir()
	f := &updaterFixture{
		pinned: &mocks.FakeRecords{},
		runner: &mocks.FakeUpdateRunner{},
		report: health.Report{Release: "v0.1.0", PeerServing: true, PeerCanTakeover: true},
		now:    time.Hour,
	}
	f.runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		f.commands = append(f.commands, strings.Join(append([]string{filepath.Base(name)}, args...), " "))
		if name == "curl" || name == "aws" {
			return "", writeDownload(args)
		}
		return "", nil
	})
	f.updater = update.New(update.Config{ConfigPath: "/etc/natpair/config.json", WorkDir: dir, Releases: releases}, update.Dependencies{
		Pinned:      f.pinned,
		Runner:      f.runner,
		Health:      func() health.Report { return f.report },
		Owner:       func() bool { return f.owner },
		Maintenance: func() bool { return f.maintenance },
		HandOver:    func(want bool) { f.handover = want },
		Now:         func() time.Duration { return f.now },
	})
	return f
}

// writeDownload stands in for the release download, writing the archive where
// curl's --output or aws s3 cp's last argument points.
func writeDownload(args []string) error {
	destination := args[len(args)-1]
	for i, arg := range args {
		if arg == "--output" {
			destination = args[i+1]
		}
	}
	return os.WriteFile(destination, []byte(archiveContent), 0o644)
}

func (f *updaterFixture) pin(t *testing.T, tag, sum string) {
	value, err := json.Marshal(map[string]string{"release": tag, "sha256": sum})
	require.NoError(t, err)
	f.pinned.ReadReturns(value, nil)
}

func archiveSHA256() string {
	sum := sha256.Sum256([]byte(archiveContent))
	return hex.EncodeToString(sum[:])
}

func TestPassDownloadsFromAnS3Mirror(t *testing.T) {
	f := newUpdaterFixtureFrom(t, "s3://example-mirror/natpair")
	f.pin(t, "v0.2.0", archiveSHA256())

	require.NoError(t, f.updater.Pass(t.Context()))
	assert.Regexp(t, `^aws s3 cp --only-show-errors s3://example-mirror/natpair/v0\.2\.0/natpair_linux_arm64\.tar\.gz \S+/release\.tar\.gz$`, f.commands[0])
}

func TestPassInstallsOnTheStandby(t *testing.T) {
	f := newUpdaterFixture(t)
	f.pin(t, "v0.2.0", archiveSHA256())

	require.NoError(t, f.updater.Pass(t.Context()))
	require.Len(t, f.commands, 5)
	assert.Regexp(t, `^curl --fail --silent --show-error --location --retry 3 --output \S+/release\.tar\.gz https://github\.com/artie-labs/natpair/releases/download/v0\.2\.0/natpair_linux_arm64\.tar\.gz$`, f.commands[0])
	assert.True(t, strings.HasPrefix(f.commands[1], "tar -xzf "))
	assert.Equal(t, "natpair validate --config /etc/natpair/config.json", f.commands[2])
	assert.True(t, strings.HasPrefix(f.commands[3], "install.sh "))
	assert.True(t, strings.HasSuffix(f.commands[3], "/natpair"))
	assert.Equal(t, "systemctl reboot", f.commands[4])
}

func TestPassRejectsADownloadWithTheWrongChecksum(t *testing.T) {
	f := newUpdaterFixture(t)
	f.pin(t, "v0.2.0", strings.Repeat("0", 64))

	err := f.updater.Pass(t.Context())
	require.EqualError(t, err, "release v0.2.0: download has SHA-256 "+archiveSHA256()+", expected "+strings.Repeat("0", 64))
	assert.Len(t, f.commands, 1)
}

func TestPassRejectsAReleaseThatRejectsTheConfiguration(t *testing.T) {
	f := newUpdaterFixture(t)
	f.pin(t, "v0.2.0", archiveSHA256())
	f.runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		f.commands = append(f.commands, filepath.Base(name))
		switch filepath.Base(name) {
		case "curl":
			return "", writeDownload(args)
		case "natpair":
			return "", errors.New("unknown field")
		}
		return "", nil
	})

	require.ErrorContains(t, f.updater.Pass(t.Context()), "release v0.2.0 rejects this NAT's configuration, so replace this NAT")
	assert.Equal(t, []string{"curl", "tar", "natpair"}, f.commands)
}

func TestPassRejectsAnInvalidPin(t *testing.T) {
	ctx := t.Context()
	f := newUpdaterFixture(t)
	{
		// The tag becomes part of an S3 key.
		f.pin(t, "../v0.2.0", archiveSHA256())
		require.NoError(t, f.updater.Pass(ctx))
		assert.Empty(t, f.commands)
	}
	{
		f.pin(t, "v0.2.0", "not-a-checksum")
		require.NoError(t, f.updater.Pass(ctx))
		assert.Empty(t, f.commands)
	}
}

func TestPassWaitsAfterAFailedInstall(t *testing.T) {
	ctx := t.Context()
	f := newUpdaterFixture(t)
	f.pin(t, "v0.2.0", archiveSHA256())
	f.runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		f.commands = append(f.commands, filepath.Base(name))
		switch filepath.Base(name) {
		case "curl":
			return "", writeDownload(args)
		case "install.sh":
			return "", errors.New("install.sh failed: unknown field")
		}
		return "", nil
	})

	require.ErrorContains(t, f.updater.Pass(ctx), "failed to install release v0.2.0")
	assert.Equal(t, []string{"curl", "tar", "natpair", "install.sh"}, f.commands)
	{
		f.now += 10*time.Minute - time.Second
		require.NoError(t, f.updater.Pass(ctx))
		assert.Len(t, f.commands, 4)
	}
	{
		f.now += time.Second
		require.Error(t, f.updater.Pass(ctx))
		assert.Len(t, f.commands, 8)
	}
}

func TestPassHandsOverOnceThePeerStaysReady(t *testing.T) {
	ctx := t.Context()
	f := newUpdaterFixture(t)
	f.pin(t, "v0.2.0", archiveSHA256())
	f.owner = true
	f.report = health.Report{Release: "v0.1.0", Serving: true, PeerRelease: "v0.2.0", PeerReady: true}
	{
		require.NoError(t, f.updater.Pass(ctx))
		f.now += 90 * time.Second
		// The peer dropped out of ready, so its two minutes start again.
		f.report.PeerReady = false
		require.NoError(t, f.updater.Pass(ctx))
		f.report.PeerReady = true
		f.now += time.Second
		require.NoError(t, f.updater.Pass(ctx))
		f.now += 2*time.Minute - time.Second
		require.NoError(t, f.updater.Pass(ctx))
		assert.False(t, f.handover)
	}
	{
		f.now += time.Second
		require.NoError(t, f.updater.Pass(ctx))
		assert.True(t, f.handover)
	}
	{
		// The request is withdrawn once the peer drops out of ready.
		f.report.PeerReady = false
		require.NoError(t, f.updater.Pass(ctx))
		assert.False(t, f.handover)
	}
	assert.Empty(t, f.commands)
}

func TestPassDoesntRebootAfterTakingOverDuringTheInstall(t *testing.T) {
	f := newUpdaterFixture(t)
	f.pin(t, "v0.2.0", archiveSHA256())
	f.runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		f.commands = append(f.commands, filepath.Base(name))
		switch filepath.Base(name) {
		case "curl":
			return "", writeDownload(args)
		case "install.sh":
			// The peer failed while install.sh ran, so this NAT took over.
			f.owner = true
		}
		return "", nil
	})

	require.EqualError(t, f.updater.Pass(t.Context()), "took over while installing release v0.2.0, so not rebooting")
	assert.Equal(t, []string{"curl", "tar", "natpair", "install.sh"}, f.commands)
}
