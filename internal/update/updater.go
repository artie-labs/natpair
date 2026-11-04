package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/artie-labs/natpair/internal/health"
)

const (
	// passInterval is how often the updater reads the pinned release. A roll
	// starts within this long of an apply, which is soon enough for an
	// upgrade.
	passInterval = time.Minute
	// retryInterval is how long the updater waits after a failed install, so a
	// release that can't install isn't downloaded every pass.
	retryInterval = 10 * time.Minute

	// releaseArchive matches the Terraform module's boot script.
	releaseArchive = "natpair_linux_arm64.tar.gz"
	// installTimeout covers the download and install.sh, which runs dnf.
	installTimeout = 10 * time.Minute
	commandTimeout = time.Minute
)

var (
	tagPattern    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Records reads one record from the lease table.
type Records interface {
	Read(ctx context.Context) ([]byte, error)
}

// Runner runs system commands.
type Runner interface {
	Run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error)
}

// Config locates the files the updater uses.
type Config struct {
	// ConfigPath is this NAT's configuration, which a new release must accept.
	ConfigPath string
	// WorkDir holds downloads while they are installed.
	WorkDir string
	// Releases is the https:// or s3:// prefix that holds
	// "<tag>/natpair_linux_arm64.tar.gz".
	Releases string
}

// Dependencies connect the updater to the daemon and the system.
type Dependencies struct {
	// Pinned is the record where Terraform pins the release.
	Pinned Records
	Runner Runner
	// Health returns this NAT's latest health report.
	Health func() health.Report
	// Owner reports whether this NAT holds the lease.
	Owner func() bool
	// Maintenance reports a maintenance request made by hand.
	Maintenance func() bool
	// HandOver sets whether this NAT, the owner, hands over to its ready peer.
	HandOver func(bool)
	// Now returns elapsed time on the boot clock.
	Now func() time.Duration
}

// Updater moves this NAT to the pinned release.
type Updater struct {
	cfg  Config
	deps Dependencies

	// Only Run's goroutine uses these.
	peerReadySince time.Duration
	peerReadySeen  bool
	installFailed  time.Duration
	failedInstall  bool
}

// New returns an updater.
func New(cfg Config, deps Dependencies) *Updater {
	return &Updater{cfg: cfg, deps: deps}
}

// Run makes a pass every passInterval until ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	ticker := time.NewTicker(passInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := u.Pass(ctx); err != nil {
			slog.Warn("update pass failed", slog.Any("err", err))
		}
	}
}

// Pass reads the facts and takes the next step.
func (u *Updater) Pass(ctx context.Context) error {
	pinned, err := u.pinned(ctx)
	if err != nil {
		slog.Warn("failed to read the pinned release", slog.Any("err", err))
	}
	facts := Facts{Pinned: pinned, Report: u.deps.Health(), Owner: u.deps.Owner(), Maintenance: u.deps.Maintenance()}
	now := u.deps.Now()
	if pinned != nil && facts.Report.Serving && facts.Report.PeerRelease == pinned.Tag && facts.Report.PeerReady {
		if !u.peerReadySeen {
			u.peerReadySince, u.peerReadySeen = now, true
		}
		facts.PeerReady = now - u.peerReadySince
	} else {
		u.peerReadySeen = false
	}

	step, reason := Next(facts)
	// Log every pass while this NAT is behind, so a stalled roll keeps
	// showing in the logs once a minute. A current NAT stays quiet.
	if pinned != nil && facts.Report.Release != pinned.Tag {
		slog.Info("update", slog.String("step", step.String()), slog.String("reason", reason),
			slog.String("pinned", pinned.Tag), slog.String("running", facts.Report.Release))
	}
	// Set the handover on every pass, so the request is withdrawn as soon as
	// the owner shouldn't hand over, such as when its peer drops out of ready.
	u.deps.HandOver(step == HandOver)
	if step == Install {
		if u.failedInstall && now-u.installFailed < retryInterval {
			return nil
		}
		if err := u.install(ctx, *pinned); err != nil {
			u.installFailed, u.failedInstall = now, true
			return err
		}
		u.failedInstall = false
	}
	return nil
}

// pinned reads and checks the pinned release. The tag becomes part of the
// download URL, so anything but a plain version tag is rejected.
func (u *Updater) pinned(ctx context.Context) (*Release, error) {
	value, err := u.deps.Pinned.Read(ctx)
	if err != nil || value == nil {
		return nil, err
	}
	var release Release
	if err := json.Unmarshal(value, &release); err != nil {
		return nil, fmt.Errorf("failed to decode the pinned release %q: %w", value, err)
	}
	if !tagPattern.MatchString(release.Tag) || !sha256Pattern.MatchString(release.SHA256) {
		return nil, fmt.Errorf("invalid pinned release %q", value)
	}
	return &release, nil
}

// install downloads the pinned release, checks it, installs it with the
// release's own install.sh and reboots. Next allows it only on a
// NAT that doesn't hold the lease, where install.sh is safe.
func (u *Updater) install(ctx context.Context, release Release) error {
	dir, err := os.MkdirTemp(u.cfg.WorkDir, "natpair-update-")
	if err != nil {
		return fmt.Errorf("failed to create a download directory: %w", err)
	}
	defer os.RemoveAll(dir)
	archive := filepath.Join(dir, "release.tar.gz")
	source := fmt.Sprintf("%s/%s/%s", u.cfg.Releases, release.Tag, releaseArchive)
	download := []string{"curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3", "--output", archive, source}
	if strings.HasPrefix(source, "s3://") {
		download = []string{"aws", "s3", "cp", "--only-show-errors", source, archive}
	}
	if _, err := u.deps.Runner.Run(ctx, installTimeout, download[0], download[1:]...); err != nil {
		return fmt.Errorf("failed to download release %s from %s: %w", release.Tag, source, err)
	}
	if err := checkSHA256(archive, release.SHA256); err != nil {
		return fmt.Errorf("release %s: %w", release.Tag, err)
	}
	if _, err := u.deps.Runner.Run(ctx, commandTimeout, "tar", "-xzf", archive, "-C", dir); err != nil {
		return fmt.Errorf("failed to unpack release %s: %w", release.Tag, err)
	}
	binary := filepath.Join(dir, "natpair")
	// Check before replacing anything. Only a replacement gives the NAT a new
	// configuration, so retrying can't fix a release that rejects this one.
	if _, err := u.deps.Runner.Run(ctx, commandTimeout, binary, "validate", "--config", u.cfg.ConfigPath); err != nil {
		return fmt.Errorf("release %s rejects this NAT's configuration, so replace this NAT: %w", release.Tag, err)
	}
	if _, err := u.deps.Runner.Run(ctx, installTimeout, filepath.Join(dir, "deploy", "install.sh"), binary); err != nil {
		return fmt.Errorf("failed to install release %s: %w", release.Tag, err)
	}
	// The daemon keeps running during the install, so this NAT may have taken
	// over from a failing peer meanwhile. Rebooting it would stop egress. A
	// daemon that systemd restarts into the new binary before a reboot
	// reports no release, so a later pass as the standby installs it again
	// and reboots.
	if u.deps.Owner() {
		return fmt.Errorf("took over while installing release %s, so not rebooting", release.Tag)
	}
	slog.Info("installed the pinned release, rebooting into it", slog.String("release", release.Tag))
	if _, err := u.deps.Runner.Run(ctx, commandTimeout, "systemctl", "reboot"); err != nil {
		return fmt.Errorf("failed to reboot into release %s: %w", release.Tag, err)
	}
	return nil
}

func checkSHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open the download: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to read the download: %w", err)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != expected {
		return fmt.Errorf("download has SHA-256 %s, expected %s", actual, expected)
	}
	return nil
}
