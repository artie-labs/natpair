//go:build linux && privileged

package netns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/command"
)

func interfaceNames(t *testing.T) []string {
	interfaces, err := net.Interfaces()
	require.NoError(t, err)
	var names []string
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names
}

func TestDo(t *testing.T) {
	const name = "natpair-test"
	_, err := command.Run(t.Context(), 2*time.Second, "ip", "netns", "add", name)
	require.NoError(t, err)
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		_, err := command.Run(context.WithoutCancel(t.Context()), 2*time.Second, "ip", "netns", "delete", name)
		assert.NoError(t, err)
	})
	outside := interfaceNames(t)

	var inside []string
	require.NoError(t, Do(name, func() error {
		inside = interfaceNames(t)
		return nil
	}))
	// New namespaces can also hold kernel fallback tunnel devices, so check
	// for the host's interface instead of an exact list.
	require.Contains(t, outside, "eth0")
	assert.Contains(t, inside, "lo")
	assert.NotContains(t, inside, "eth0")
	assert.Equal(t, outside, interfaceNames(t))

	assert.ErrorContains(t, Do("missing-namespace", func() error { return nil }), `failed to open network namespace "missing-namespace"`)
}
