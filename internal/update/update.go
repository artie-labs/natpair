// Package update moves a NAT pair to the release Terraform pins for it, one
// NAT at a time.
//
// Terraform writes the pinned release to the pair's lease table, and the
// daemon on each NAT checks it every minute. A NAT installs the pinned release on
// itself and reboots only while it isn't the owner and its peer serves with a
// working path, outside maintenance. The owner hands over only once its peer
// runs the pinned release and has stayed ready for [PeerReadyFor]. So a release
// that never gets ready stops at the standby, and worker egress stays on the
// owner's release. Pinning the previous release again rolls back a standby
// that still runs. One whose new release can't run at all is replaced instead:
// a new NAT installs the pinned release at first boot.
//
// A NAT keeps the configuration it got at first boot. A release that rejects
// it isn't installed, and the NAT must be replaced to get the new one.
package update

import (
	"time"

	"github.com/artie-labs/natpair/internal/health"
)

// PeerReadyFor is how long the peer must run the pinned release and stay ready
// before the owner hands over to it. A release that fails within this time
// stays on the standby.
const PeerReadyFor = 2 * time.Minute

// Release is a pinned natpair release.
type Release struct {
	Tag string `json:"release"`
	// SHA256 is the checksum of the release's natpair_linux_arm64.tar.gz.
	SHA256 string `json:"sha256"`
}

// Step is what the updater does next.
type Step int

const (
	// Wait does nothing this pass.
	Wait Step = iota
	// Install installs the pinned release on this NAT and reboots it.
	Install
	// HandOver asks this NAT, the owner, to hand over to its peer.
	HandOver
)

func (s Step) String() string {
	switch s {
	case Install:
		return "install"
	case HandOver:
		return "hand over"
	default:
		return "wait"
	}
}

// Facts is what the updater knows on one pass.
type Facts struct {
	// Pinned is the release Terraform pins for the pair, or nil if none is
	// pinned or the pin couldn't be read.
	Pinned *Release
	// Report is this NAT's latest health report. It names the release this
	// NAT runs, and whether this NAT and its peer serve.
	Report health.Report
	// Owner means this NAT holds the lease, including during a takeover,
	// before its report shows it serving.
	Owner bool
	// Maintenance means maintenance was requested on this NAT by hand.
	Maintenance bool
	// PeerReady is how long this NAT, as the owner, has seen its peer run the
	// pinned release and be ready.
	PeerReady time.Duration
}

// Next returns the next step and why.
func Next(f Facts) (Step, string) {
	switch {
	case f.Pinned == nil:
		return Wait, "no release is pinned"
	case f.Report.Release == f.Pinned.Tag:
		return Wait, "this NAT runs the pinned release"
	case f.Maintenance:
		// An engineer is working on this NAT, so leave it alone.
		return Wait, "maintenance was requested by hand"
	case f.Report.Stale:
		return Wait, "this NAT's health checks are stale"
	case !f.Owner && f.Report.PeerServing && f.Report.PeerCanTakeover:
		return Install, "this NAT is the standby, and its peer serves"
	case !f.Owner:
		// A peer that can't take over has a failing path or is in maintenance,
		// waiting to hand over to this NAT.
		return Wait, "the peer isn't serving with a working path, so this NAT stays ready to take over"
	case f.Report.PeerRelease != f.Pinned.Tag || !f.Report.PeerReady:
		return Wait, "waiting for the peer to run the pinned release and be ready"
	case f.PeerReady < PeerReadyFor:
		return Wait, "waiting for the peer to stay ready"
	default:
		return HandOver, "the peer runs the pinned release and has stayed ready"
	}
}
