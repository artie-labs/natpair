package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/mocks"
	"github.com/artie-labs/natpair/internal/network"
)

const (
	showPeerRoute    = "ip -j route show 10.0.1.11/32"
	replacePeerRoute = "ip route replace 10.0.1.11/32 dev ens5 src 10.0.1.10"
)

// runKeepPeerRoute runs keepPeerRoute for one tick at each of the times,
// answering `ip -j route show` with the routes in order. It returns the
// commands run and the warnings logged.
func runKeepPeerRoute(t *testing.T, routes []string, times []time.Time) ([]string, []string) {
	cfg, err := config.LoadNAT("../../internal/config/testdata/nat.json")
	require.NoError(t, err)
	cfg.Instance = instance.Facts{ID: "i-test", PrivateIP: netip.MustParseAddr("10.0.1.10"), Interface: "ens5"}

	var commands []string
	runner := &mocks.FakeRunner{}
	runner.RunCalls(func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		line := strings.Join(append([]string{name}, args...), " ")
		commands = append(commands, line)
		if line != showPeerRoute {
			return "", nil
		}
		route := routes[0]
		routes = routes[1:]
		if route == "error" {
			return "", errors.New("ip failed")
		}
		return route, nil
	})

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})))
	defer slog.SetDefault(previous)

	ctx, cancel := context.WithCancel(t.Context())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		keepPeerRoute(ctx, network.New(cfg, &mocks.FakeNetworkFence{}, runner), ticks)
		close(done)
	}()
	for _, at := range times {
		ticks <- at
	}
	// The channel is unbuffered, so the loop has finished every check but the
	// last. Cancel and wait for it to finish that one too.
	cancel()
	<-done
	return commands, strings.FieldsFunc(logs.String(), func(r rune) bool { return r == '\n' })
}

func TestKeepPeerRoute(t *testing.T) {
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	correct := `[{"dst":"10.0.1.11","dev":"ens5","scope":"link","prefsrc":"10.0.1.10","flags":[]}]`
	{
		// A correct route is left alone, and nothing is logged
		commands, warnings := runKeepPeerRoute(t, []string{correct}, []time.Time{start})
		assert.Equal(t, []string{showPeerRoute}, commands)
		assert.Empty(t, warnings)
	}
	{
		// A missing route is put back and logged
		commands, warnings := runKeepPeerRoute(t, []string{"[]"}, []time.Time{start})
		assert.Equal(t, []string{showPeerRoute, replacePeerRoute}, commands)
		assert.Equal(t, []string{`level=WARN msg="the route to the peer was missing or wrong and has been restored" checks=1`}, warnings)
	}
	{
		// A route through the shared ENI, or from the shared address, is put back
		for _, wrong := range []string{
			`[{"dst":"10.0.1.11","dev":"ens6","scope":"link","prefsrc":"10.0.1.10","flags":[]}]`,
			`[{"dst":"10.0.1.11","dev":"ens5","scope":"link","prefsrc":"10.0.1.100","flags":[]}]`,
		} {
			commands, warnings := runKeepPeerRoute(t, []string{wrong}, []time.Time{start})
			assert.Equal(t, []string{showPeerRoute, replacePeerRoute}, commands)
			assert.Len(t, warnings, 1)
		}
	}
	{
		// While something keeps removing the route, the warning repeats at most
		// once a minute and counts the checks that found it gone. A correct
		// route in between ends the run, so the next removal warns at once.
		commands, warnings := runKeepPeerRoute(t,
			[]string{"[]", "[]", "[]", "[]", correct, "[]"},
			[]time.Time{start, start.Add(5 * time.Second), start.Add(55 * time.Second), start.Add(time.Minute), start.Add(65 * time.Second), start.Add(70 * time.Second)})
		assert.Len(t, commands, 11)
		assert.Equal(t, []string{
			`level=WARN msg="the route to the peer was missing or wrong and has been restored" checks=1`,
			`level=WARN msg="the route to the peer was missing or wrong and has been restored" checks=3`,
			`level=WARN msg="the route to the peer was missing or wrong and has been restored" checks=1`,
		}, warnings)
	}
	{
		// A failed check is logged, and the route is left as it is
		commands, warnings := runKeepPeerRoute(t, []string{"error"}, []time.Time{start})
		assert.Equal(t, []string{showPeerRoute}, commands)
		assert.Equal(t, []string{`level=WARN msg="failed to check or restore the route to the peer" err="ip failed" checks=1`}, warnings)
	}
}
