//go:build linux && privileged

package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/network"
)

func run(t *testing.T, name string, args ...string) string {
	output, err := command.Run(t.Context(), 2*time.Second, name, args...)
	require.NoError(t, err)
	return output
}

// peerPath returns the interface and source address the kernel picks for
// traffic this host sends to 10.94.6.11, as conntrackd's copies to the peer.
func peerPath(t *testing.T) (string, string) {
	var routes []struct {
		Dev     string `json:"dev"`
		PrefSrc string `json:"prefsrc"`
	}
	require.NoError(t, json.Unmarshal([]byte(run(t, "ip", "-j", "route", "get", "10.94.6.11")), &routes))
	require.Len(t, routes, 1)
	return routes[0].Dev, routes[0].PrefSrc
}

func TestKeepPeerRouteRestoresRoute(t *testing.T) {
	// Two links in one subnet, as a NAT's own interface and the shared ENI.
	for _, link := range []struct{ name, address string }{{"own-route", "10.94.6.10/24"}, {"shared-route", "10.94.6.100/24"}} {
		run(t, "ip", "link", "add", link.name, "type", "dummy")
		t.Cleanup(func() {
			// t.Context is cancelled before cleanup runs.
			_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", link.name)
			assert.NoError(t, err)
		})
		run(t, "ip", "addr", "add", link.address, "dev", link.name)
		run(t, "ip", "link", "set", link.name, "up")
	}
	// The shared address's subnet route wins, as on AWS once the shared ENI
	// is attached.
	run(t, "ip", "route", "replace", "10.94.6.0/24", "dev", "shared-route", "src", "10.94.6.100")
	cfg, err := config.LoadNAT("../../internal/config/testdata/nat.json")
	require.NoError(t, err)
	cfg.PeerIP = netip.MustParseAddr("10.94.6.11")
	cfg.Instance = instance.Facts{ID: "i-test", PrivateIP: netip.MustParseAddr("10.94.6.10"), Interface: "own-route"}
	run(t, "ip", "route", "replace", "10.94.6.11/32", "dev", "own-route", "src", "10.94.6.10")

	// check runs keepPeerRoute until its first check has finished. The channel
	// is unbuffered, so the second tick is taken only once the first check is
	// done. The second check may run after cancel, which the assertions don't
	// depend on.
	check := func() {
		ctx, cancel := context.WithCancel(t.Context())
		ticks := make(chan time.Time)
		done := make(chan struct{})
		go func() {
			keepPeerRoute(ctx, network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{}), ticks)
			close(done)
		}()
		ticks <- time.Now()
		ticks <- time.Now()
		cancel()
		<-done
	}
	{
		// Something deletes the route, and the copies would leave through the
		// shared link. The next check puts the route back.
		run(t, "ip", "route", "del", "10.94.6.11/32")
		dev, src := peerPath(t)
		require.Equal(t, "shared-route", dev)
		require.Equal(t, "10.94.6.100", src)
		check()
		dev, src = peerPath(t)
		assert.Equal(t, "own-route", dev)
		assert.Equal(t, "10.94.6.10", src)
	}
	{
		// Something points the route at the shared link instead
		run(t, "ip", "route", "replace", "10.94.6.11/32", "dev", "shared-route", "src", "10.94.6.100")
		dev, _ := peerPath(t)
		require.Equal(t, "shared-route", dev)
		check()
		dev, src := peerPath(t)
		assert.Equal(t, "own-route", dev)
		assert.Equal(t, "10.94.6.10", src)
	}
}
