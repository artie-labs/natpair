// Package ports watches how many of the shared address's ports worker
// connections use for each destination.
//
// Every worker connection leaves from the shared address. The kernel tells
// connections apart by protocol and by both addresses and ports, so to one
// destination address, port and protocol, such as one database's 5432/tcp,
// the shared address can hold only as many connections at a time as it has
// source ports. Past that, new connections to that destination fail while
// connections elsewhere still work. Closed TCP connections hold their port
// for the time they stay in the connection table.
package ports

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/artie-labs/natpair/internal/command"
)

const (
	// Interval is how often the watcher counts. A count reads the kernel's
	// whole connection table.
	Interval = time.Minute
	// warnPercent is the share of a destination's ports, in percent, past
	// which the watcher warns.
	warnPercent = 70
	// clearPercent is the share a destination must drop under before the
	// watcher says it's back under. The gap keeps a destination hovering
	// around warnPercent from logging a pair of lines at every count.
	clearPercent = 60
	// warnInterval is the shortest time between warnings about one
	// destination.
	warnInterval = 10 * time.Minute
	// maxDestinations caps how many destinations a count keeps, a few
	// hundred KB.
	// Past it, the count keeps the busiest: any destination with more than
	// 1/(maxDestinations+1) of the connections is still found, and its count
	// may be low by at most that many. At 524,288 connections that is 127,
	// against the 42,000 or more a warning needs.
	maxDestinations = 4096
	// listTimeout bounds one read of the connection table.
	listTimeout = 2 * time.Minute
)

// Destination is where worker connections go: a protocol, an address and a
// port.
type Destination struct {
	Protocol string
	Addr     netip.Addr
	Port     uint16
}

func (d Destination) String() string {
	return fmt.Sprintf("%s %s", d.Protocol, netip.AddrPortFrom(d.Addr, d.Port))
}

// Watcher counts, every Interval while this NAT serves, the connections
// translated to the shared address for each destination.
type Watcher struct {
	// ports is how many source ports the shared address offers each
	// destination.
	ports   int
	serving func() bool
	now     func() time.Duration
	// list streams the kernel's entries for connections translated to the
	// shared address, one a line, in the format of `conntrack -L`.
	list func(ctx context.Context, read func(io.Reader) error) error

	// over holds the destinations past warnPercent that haven't dropped
	// under clearPercent since. warned holds when each destination was last
	// warned about, for warnInterval.
	over   map[Destination]bool
	warned map[Destination]time.Duration

	mu sync.Mutex
	// used is the busiest destination's share of its ports, from 0 to 1, at
	// the latest count.
	used float64
}

// New returns a watcher of connections translated to shared, which offers
// ports source ports to each destination. now returns elapsed time on the
// boot clock.
func New(shared netip.Addr, ports int, serving func() bool, now func() time.Duration) *Watcher {
	return &Watcher{
		ports:   ports,
		serving: serving,
		now:     now,
		list: func(ctx context.Context, read func(io.Reader) error) error {
			return command.Stream(ctx, listTimeout, read, "conntrack", "-L", "--reply-dst", shared.String())
		},
		over:   map[Destination]bool{},
		warned: map[Destination]time.Duration{},
	}
}

// Used returns the busiest destination's share of its ports at the latest
// count, from 0 to 1. It is 0 while this NAT doesn't serve, including before
// the first count after it stops.
func (w *Watcher) Used() float64 {
	if !w.serving() {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.used
}

// Run counts now and every Interval until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		w.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// check counts once, and warns about each destination past warnPercent of
// its ports. A standby holds no current translations: after it steps down,
// its old ones stay until conntrackd flushes them.
func (w *Watcher) check(ctx context.Context) {
	if !w.serving() {
		// The next owner counts these connections now. This NAT starts afresh
		// if it serves again.
		w.setUsed(0)
		clear(w.over)
		return
	}
	var counts map[Destination]int
	err := w.list(ctx, func(r io.Reader) error {
		var err error
		counts, err = count(r, maxDestinations)
		return err
	})
	if err != nil {
		slog.Warn("failed to count the shared address's ports in use", slog.Any("err", err))
		return
	}
	busiest := 0
	for _, connections := range counts {
		busiest = max(busiest, connections)
	}
	w.setUsed(float64(busiest) / float64(w.ports))

	now := w.now()
	maps.DeleteFunc(w.warned, func(_ Destination, at time.Duration) bool { return now-at >= warnInterval })
	for destination, connections := range counts {
		if connections*100 < w.ports*warnPercent {
			continue
		}
		w.over[destination] = true
		if _, ok := w.warned[destination]; ok {
			continue
		}
		w.warned[destination] = now
		slog.Warn("worker connections to one destination use most of the shared address's ports for it, "+
			"so new connections to it will fail once all are used. Spread them across more destinations, "+
			"reuse connections, or give the workers more source addresses.",
			slog.String("destination", destination.String()), slog.Int("connections", connections),
			slog.Int("ports", w.ports), slog.Int("percent", connections*100/w.ports))
	}
	for destination := range w.over {
		if counts[destination]*100 < w.ports*clearPercent {
			delete(w.over, destination)
			slog.Info(fmt.Sprintf("worker connections to a destination are back under %d%% of the shared address's ports", clearPercent),
				slog.String("destination", destination.String()), slog.Int("connections", counts[destination]),
				slog.Int("ports", w.ports))
		}
	}
}

func (w *Watcher) setUsed(used float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.used = used
}

// count reads `conntrack -L` lines from r and counts the TCP and UDP entries
// for each original destination. It keeps at most limit destinations, using
// the Misra-Gries algorithm: a destination that doesn't fit lowers every
// count by one, and counts that reach 0 make room. Under the limit, the
// counts are exact.
func count(r io.Reader, limit int) (map[Destination]int, error) {
	counts := map[Destination]int{}
	lines := bufio.NewScanner(r)
	lines.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for lines.Scan() {
		destination, ok := parseDestination(lines.Bytes())
		if !ok {
			continue
		}
		if _, ok := counts[destination]; ok || len(counts) < limit {
			counts[destination]++
			continue
		}
		for other, connections := range counts {
			if connections == 1 {
				delete(counts, other)
			} else {
				counts[other] = connections - 1
			}
		}
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

var (
	dstKey   = []byte(" dst=")
	dportKey = []byte(" dport=")
)

// parseDestination returns the original destination of a TCP or UDP entry
// line, such as
//
//	tcp      6 431999 ESTABLISHED src=10.0.16.5 dst=203.0.113.9 sport=40000 dport=443 src=203.0.113.9 dst=10.0.1.100 ...
//
// The first dst= and dport= are the original direction's.
func parseDestination(line []byte) (Destination, bool) {
	var protocol string
	switch {
	case bytes.HasPrefix(line, []byte("tcp ")):
		protocol = "tcp"
	case bytes.HasPrefix(line, []byte("udp ")):
		protocol = "udp"
	default:
		return Destination{}, false
	}
	addr, ok := field(line, dstKey)
	if !ok {
		return Destination{}, false
	}
	port, ok := field(line, dportKey)
	if !ok {
		return Destination{}, false
	}
	parsedAddr, err := netip.ParseAddr(string(addr))
	if err != nil {
		return Destination{}, false
	}
	parsedPort, err := strconv.ParseUint(string(port), 10, 16)
	if err != nil {
		return Destination{}, false
	}
	return Destination{Protocol: protocol, Addr: parsedAddr, Port: uint16(parsedPort)}, true
}

// field returns the value after the first key in line, up to the next space.
func field(line, key []byte) ([]byte, bool) {
	start := bytes.Index(line, key)
	if start < 0 {
		return nil, false
	}
	value := line[start+len(key):]
	if end := bytes.IndexByte(value, ' '); end >= 0 {
		value = value[:end]
	}
	return value, len(value) > 0
}
