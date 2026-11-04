//go:build linux && privileged

package network_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/command"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/network"
)

func run(t *testing.T, name string, args ...string) string {
	output, err := command.Run(t.Context(), 2*time.Second, name, args...)
	require.NoError(t, err)
	return output
}

func TestSharedPath(t *testing.T) {
	cfg := testConfig(t)
	cfg.SharedAddress = netip.MustParsePrefix("10.94.2.100/24")

	run(t, "ip", "link", "add", "shared-test", "type", "dummy")
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "link", "del", "shared-test")
		assert.NoError(t, err)
	})
	var links []struct {
		Address string `json:"address"`
	}
	require.NoError(t, json.Unmarshal([]byte(run(t, "ip", "-j", "link", "show", "shared-test")), &links))
	mac := links[0].Address

	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	require.NoError(t, n.ActivateShared(t.Context(), mac))
	assert.Contains(t, run(t, "ip", "-4", "addr", "show", "dev", "shared-test"), "10.94.2.100/24")
	assert.Contains(t, run(t, "ip", "route", "show", "table", "7001"), "default via 10.94.2.1 dev shared-test")
}

func TestSharedRules(t *testing.T) {
	cfg := testConfig(t)
	n := network.New(cfg, &mocks.FakeNetworkFence{}, network.SystemRunner{})
	// Running twice must not fail on rules that already exist.
	for range 2 {
		require.NoError(t, n.PrepareNetwork(t.Context()))
	}
	rules := run(t, "ip", "rule", "show", "table", "7001")
	assert.Contains(t, rules, "from 10.0.16.0/20 lookup 7001")
	assert.Contains(t, rules, "from 198.18.0.6 lookup 7001")
}
