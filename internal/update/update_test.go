package update_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/update"
)

func TestNext(t *testing.T) {
	pinned := &update.Release{Tag: "v0.2.0", SHA256: "aa"}
	standby := health.Report{Release: "v0.1.0", PeerRelease: "v0.1.0", PeerServing: true, PeerCanTakeover: true, PeerReady: true}
	owner := health.Report{Release: "v0.1.0", Serving: true, PeerRelease: "v0.2.0", PeerReady: true}
	{
		step, reason := update.Next(update.Facts{Report: standby})
		assert.Equal(t, update.Wait, step)
		assert.Equal(t, "no release is pinned", reason)
	}
	{
		current := owner
		current.Release = "v0.2.0"
		step, reason := update.Next(update.Facts{Pinned: pinned, Owner: true, Report: current, PeerReady: time.Hour})
		assert.Equal(t, update.Wait, step)
		assert.Equal(t, "this NAT runs the pinned release", reason)
	}
	{
		step, reason := update.Next(update.Facts{Pinned: pinned, Report: standby, Maintenance: true})
		assert.Equal(t, update.Wait, step)
		assert.Equal(t, "maintenance was requested by hand", reason)
	}
	{
		stale := standby
		stale.Stale = true
		step, _ := update.Next(update.Facts{Pinned: pinned, Report: stale})
		assert.Equal(t, update.Wait, step)
	}
	{
		step, _ := update.Next(update.Facts{Pinned: pinned, Report: standby})
		assert.Equal(t, update.Install, step)
	}
	{
		// A NAT taking over doesn't serve yet, and its report may still show
		// the peer serving, but it owns the lease.
		step, reason := update.Next(update.Facts{Pinned: pinned, Report: standby, Owner: true})
		assert.Equal(t, update.Wait, step)
		assert.Equal(t, "waiting for the peer to run the pinned release and be ready", reason)
	}
	{
		// With no serving peer, the standby is all that's left to take over.
		lone := standby
		lone.PeerServing = false
		step, reason := update.Next(update.Facts{Pinned: pinned, Report: lone})
		assert.Equal(t, update.Wait, step)
		assert.Equal(t, "the peer isn't serving with a working path, so this NAT stays ready to take over", reason)
	}
	{
		// An owner in maintenance, or with a failing path, can't take over and
		// may need this NAT at any moment.
		needed := standby
		needed.PeerCanTakeover = false
		step, _ := update.Next(update.Facts{Pinned: pinned, Report: needed})
		assert.Equal(t, update.Wait, step)
	}
	{
		behind := owner
		behind.PeerRelease = "v0.1.0"
		step, _ := update.Next(update.Facts{Pinned: pinned, Owner: true, Report: behind, PeerReady: time.Hour})
		assert.Equal(t, update.Wait, step)
	}
	{
		notReady := owner
		notReady.PeerReady = false
		step, _ := update.Next(update.Facts{Pinned: pinned, Owner: true, Report: notReady, PeerReady: time.Hour})
		assert.Equal(t, update.Wait, step)
	}
	{
		step, reason := update.Next(update.Facts{Pinned: pinned, Owner: true, Report: owner, PeerReady: 2*time.Minute - time.Second})
		assert.Equal(t, update.Wait, step)
		assert.Equal(t, "waiting for the peer to stay ready", reason)
	}
	{
		step, _ := update.Next(update.Facts{Pinned: pinned, Owner: true, Report: owner, PeerReady: 2 * time.Minute})
		assert.Equal(t, update.HandOver, step)
	}
}
