//go:build linux && privileged

package ports

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/command"
)

// TestCheckReadsTheKernelTable counts real entries, inserted the way SNAT
// leaves them, through `conntrack -L` in the test container's own table.
func TestCheckReadsTheKernelTable(t *testing.T) {
	shared := netip.MustParseAddr("10.98.1.100")
	watcher := New(shared, 100, func() bool { return true }, func() time.Duration { return 0 })
	{
		// No translated connections: conntrack lists nothing, which isn't a failure
		watcher.check(t.Context())
		assert.Zero(t, watcher.Used())
	}
	for i := range 72 {
		port := fmt.Sprint(20000 + i)
		_, err := command.Run(t.Context(), 5*time.Second, "conntrack", "-I", "-p", "tcp",
			"-s", "10.98.16.5", "-d", "203.0.113.77", "--sport", port, "--dport", "5432",
			"-r", "203.0.113.77", "-q", shared.String(), "--reply-port-src", "5432", "--reply-port-dst", port,
			"--state", "ESTABLISHED", "-u", "SEEN_REPLY,ASSURED", "-t", "120")
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_, _ = command.Run(t.Context(), 5*time.Second, "conntrack", "-D", "--reply-dst", shared.String())
	})
	watcher.check(t.Context())
	assert.InDelta(t, 0.72, watcher.Used(), 1e-9)
}
