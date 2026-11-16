package ports

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entries returns `conntrack -L` lines for count TCP connections from
// workers to addr:port, translated to the shared address 10.0.1.100.
func entries(addr string, port, count int) string {
	var lines strings.Builder
	for i := range count {
		fmt.Fprintf(&lines, "tcp      6 431999 ESTABLISHED src=10.0.16.%d dst=%s sport=%d dport=%d src=%s dst=10.0.1.100 sport=%d dport=%d [ASSURED] mark=0 use=1\n",
			i%250+1, addr, 1024+i, port, addr, port, 1024+i)
	}
	return lines.String()
}

func TestCount(t *testing.T) {
	database := Destination{Protocol: "tcp", Addr: netip.MustParseAddr("203.0.113.9"), Port: 5432}
	resolver := Destination{Protocol: "udp", Addr: netip.MustParseAddr("198.51.100.53"), Port: 53}
	output := entries("203.0.113.9", 5432, 3) +
		"udp      17 29 src=10.0.16.5 dst=198.51.100.53 sport=40001 dport=53 [UNREPLIED] src=198.51.100.53 dst=10.0.1.100 sport=53 dport=40001 mark=0 use=1\n" +
		// The reply direction's dst and dport don't count.
		"tcp      6 117 TIME_WAIT src=10.0.16.6 dst=203.0.113.9 sport=40002 dport=5432 src=203.0.113.9 dst=10.0.1.100 sport=5432 dport=40002 [ASSURED] mark=0 use=1\n" +
		// ICMP has no ports to run out of.
		"icmp     1 29 src=10.0.16.5 dst=203.0.113.9 type=8 code=0 id=7 src=203.0.113.9 dst=10.0.1.100 type=0 code=0 id=7 mark=0 use=1\n"
	{
		counts, err := count(strings.NewReader(output), maxDestinations)
		require.NoError(t, err)
		assert.Equal(t, map[Destination]int{database: 4, resolver: 1}, counts)
	}
	{
		// Past the limit, the busiest destination is still found, and its
		// count is low by at most entries/(limit+1)
		var many strings.Builder
		for i := range 300 {
			fmt.Fprintf(&many, "tcp      6 431999 ESTABLISHED src=10.0.16.5 dst=198.51.100.%d sport=%d dport=443 src=x\n", i%250, 2000+i)
		}
		mixed := many.String() + entries("203.0.113.9", 5432, 1000) + many.String()
		counts, err := count(strings.NewReader(mixed), 10)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(counts), 10)
		assert.GreaterOrEqual(t, counts[database], 1000-1600/11)
		assert.LessOrEqual(t, counts[database], 1000)
	}
}

func TestCheck(t *testing.T) {
	database := "tcp 203.0.113.9:5432"
	type fixture struct {
		watcher *Watcher
		logs    *bytes.Buffer
		now     time.Duration
		table   string
		serving bool
		lists   int
	}
	newFixture := func(t *testing.T) *fixture {
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
		t.Cleanup(func() { slog.SetDefault(previous) })
		f := &fixture{logs: &logs, serving: true}
		f.watcher = New(netip.MustParseAddr("10.0.1.100"), 1000, func() bool { return f.serving }, func() time.Duration { return f.now })
		f.watcher.list = func(_ context.Context, read func(io.Reader) error) error {
			f.lists++
			return read(strings.NewReader(f.table))
		}
		return f
	}
	warnings := func(f *fixture) int {
		return strings.Count(f.logs.String(), "use most of the shared address's ports")
	}
	{
		// 699 of 1,000 ports is under 70%: no warning
		f := newFixture(t)
		f.table = entries("203.0.113.9", 5432, 699) + entries("198.51.100.1", 443, 10)
		f.watcher.check(t.Context())
		assert.Zero(t, warnings(f))
		assert.InDelta(t, 0.699, f.watcher.Used(), 1e-9)
	}
	{
		// At 70%, the busiest destination is named with its count, once per
		// 10 minutes, and a line follows when it drops back under
		f := newFixture(t)
		f.table = entries("203.0.113.9", 5432, 700)
		f.watcher.check(t.Context())
		assert.Equal(t, 1, warnings(f))
		assert.Contains(t, f.logs.String(), `"destination":"`+database+`","connections":700,"ports":1000,"percent":70`)
		assert.InDelta(t, 0.7, f.watcher.Used(), 1e-9)
		f.now += warnInterval - time.Second
		f.watcher.check(t.Context())
		assert.Equal(t, 1, warnings(f))
		f.now += time.Second
		f.watcher.check(t.Context())
		assert.Equal(t, 2, warnings(f))
		f.table = entries("203.0.113.9", 5432, 500)
		f.watcher.check(t.Context())
		assert.Equal(t, 1, strings.Count(f.logs.String(), "back under 70%"))
		f.watcher.check(t.Context())
		assert.Equal(t, 1, strings.Count(f.logs.String(), "back under 70%"))
		// Past 70% again, it warns at once
		f.table = entries("203.0.113.9", 5432, 800)
		f.watcher.check(t.Context())
		assert.Equal(t, 3, warnings(f))
	}
	{
		// A standby doesn't count: its old translations stay until conntrackd
		// flushes them
		f := newFixture(t)
		f.table = entries("203.0.113.9", 5432, 900)
		f.watcher.check(t.Context())
		f.serving = false
		f.watcher.check(t.Context())
		assert.Equal(t, 1, f.lists)
		assert.Zero(t, f.watcher.Used())
	}
	{
		// A failed read keeps the last count and is logged
		f := newFixture(t)
		f.table = entries("203.0.113.9", 5432, 800)
		f.watcher.check(t.Context())
		f.watcher.list = func(context.Context, func(io.Reader) error) error { return fmt.Errorf("conntrack failed") }
		f.watcher.check(t.Context())
		assert.Contains(t, f.logs.String(), `"err":"conntrack failed"`)
		assert.InDelta(t, 0.8, f.watcher.Used(), 1e-9)
	}
}

// BenchmarkCount reads 500,000 entries to 500 destinations.
func BenchmarkCount(b *testing.B) {
	var table bytes.Buffer
	for i := range 500_000 {
		fmt.Fprintf(&table, "tcp      6 431999 ESTABLISHED src=10.0.%d.%d dst=198.51.100.%d sport=%d dport=%d src=198.51.100.%d dst=10.0.1.100 sport=443 dport=%d [ASSURED] mark=0 use=1\n",
			i>>8&255, i&255, i%250, 1024+i%60000, 443+i%4, i%250, 1024+i%60000)
	}
	for b.Loop() {
		counts, err := count(bytes.NewReader(table.Bytes()), maxDestinations)
		require.NoError(b, err)
		require.Len(b, counts, 500)
	}
}
