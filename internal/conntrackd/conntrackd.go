// Package conntrackd runs conntrackd commands and parses their output.
//
// The kernel's connection table (conntrack) records each connection and its
// address translation. conntrackd copies these entries from the active NAT to
// the standby, using its FTFW mode, which resends updates that get lost. The
// standby keeps the copies in conntrackd's memory (its "external cache"), not
// in the kernel, until takeover. Commit then installs them into the kernel, so
// existing connections keep their address translation.
package conntrackd

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/artie-labs/natpair/internal/command"
)

// takeoverStepTimeout bounds each conntrackd command in TakeOver.
const takeoverStepTimeout = 10 * time.Second

// configTemplate is conntrackd's configuration. A restarted conntrackd starts
// with no copies, and idle connections send no updates that would copy them
// again, so StartupResync asks the peer for its whole table. Amazon Linux's
// conntrackd 1.4.6 accepts "on" but not "yes" here.
//
// Only forwarded connections are copied. The NAT's own connections, such as
// SSH, SSM and its AWS API calls, use its own address or the shared address.
// The filter matches a connection's original addresses, so worker traffic,
// which is translated to the shared address only in its reply direction, is
// still copied.
const configTemplate = `Sync {
    Mode FTFW {
        StartupResync on
    }
    UDP {
        IPv4_address %[1]s
        IPv4_Destination_Address %[2]s
        Port 3780
        Interface %[3]s
        Checksum on
    }
}
General {
    HashSize %[6]d
    HashLimit %[7]d
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    LogFile %[4]s/conntrackd.log
    LockFile %[4]s/conntrackd.lock
    UNIX {
        Path %[4]s/conntrackd.ctl
    }
    Filter From Userspace {
        Protocol Accept {
            TCP
        }
        Address Ignore {
            IPv4_address 127.0.0.1
            IPv6_address ::1
            IPv4_address %[1]s
            IPv4_address %[5]s
        }
    }
}
`

// WriteConfig writes conntrackd's configuration to path. It replicates over
// iface from local to peer, ignores connections to or from local and shared,
// copies at most maxConnections, and keeps its log, lock file and control
// socket in dir. The kernel's connection table is sized to the same limit,
// because connections past it couldn't be copied.
func WriteConfig(path string, local, peer, shared netip.Addr, iface, dir string, maxConnections int) error {
	contents := fmt.Sprintf(configTemplate, local, peer, iface, dir, shared, maxConnections/4, maxConnections)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(contents), 0o644); err != nil {
		return fmt.Errorf("failed to write conntrackd configuration: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("failed to write conntrackd configuration: %w", err)
	}
	return nil
}

// Client runs conntrackd with the configuration bootstrap wrote.
type Client struct {
	ConfigPath string
}

// Stats returns `conntrackd -s` output: cache and replication counters.
func (c Client) Stats(ctx context.Context) (string, error) {
	return c.run(ctx, 2*time.Second, "-s")
}

// InternalCache returns `conntrackd -i` output: this NAT's own entries.
func (c Client) InternalCache(ctx context.Context) (string, error) {
	return c.run(ctx, 2*time.Second, "-i")
}

// ExternalCache returns `conntrackd -e` output: entries copied from the peer.
func (c Client) ExternalCache(ctx context.Context) (string, error) {
	return c.run(ctx, 2*time.Second, "-e")
}

// RequestResync asks the peer to send its whole connection table again.
func (c Client) RequestResync(ctx context.Context) error {
	_, err := c.run(ctx, 2*time.Second, "-n")
	return err
}

// TakeOver installs the copied connections when this NAT becomes the owner,
// following conntrackd's own primary-backup script. It commits the copies into
// the kernel table, flushes both caches, reloads its own cache from the kernel
// table, and sends it all to the peer. Without the last steps, the peer holds
// no copies of the committed connections until a health round finds its copy
// incomplete and asks for them, so ownership moving straight back could lose
// them.
//
// Each step may take takeoverStepTimeout. Committing a full table can take
// seconds: on AWS, 114,000 entries took 0.9 s on a
// t4g.micro. A commit cut off by a short timeout keeps running inside
// conntrackd, and every later command waits behind it.
func (c Client) TakeOver(ctx context.Context) error {
	for _, flag := range []string{"-c", "-f", "-R", "-B"} {
		if _, err := c.run(ctx, takeoverStepTimeout, flag); err != nil {
			return err
		}
	}
	return nil
}

// ScheduleFlush schedules a flush of this NAT's forwarded connections after
// conntrackd's PurgeTimeout, as StepDown does. A takeover before then cancels
// it.
func (c Client) ScheduleFlush(ctx context.Context) error {
	_, err := c.run(ctx, 2*time.Second, "-t")
	return err
}

// StepDown runs when this NAT stops being the owner. It schedules a flush of
// its forwarded connections after conntrackd's PurgeTimeout, 60 s by default,
// by which time the shared ENI has moved, so stale entries cannot clash with
// copies it commits on a later takeover. A takeover before then cancels the
// flush. It also replaces its copies with the new owner's whole table. Copies
// it gathered while serving can be entries the peer has since flushed, and
// conntrackd doesn't send removals for its own flush, so a later takeover
// would commit them as dead connections.
func (c Client) StepDown(ctx context.Context) error {
	for _, args := range [][]string{{"-t"}, {"-f", "external"}, {"-n"}} {
		if _, err := c.run(ctx, 2*time.Second, args...); err != nil {
			return err
		}
	}
	return nil
}

func (c Client) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	return command.Run(ctx, timeout, "conntrackd", append([]string{"-C", c.ConfigPath}, args...)...)
}

// Tuple is the original direction of a TCP connection.
type Tuple struct {
	Src     netip.Addr `json:"src"`
	Dst     netip.Addr `json:"dst"`
	SrcPort uint16     `json:"sport"`
	DstPort uint16     `json:"dport"`
}

// tuplePattern matches the first src/dst/sport/dport group on an entry line,
// which is the connection's original direction.
var tuplePattern = regexp.MustCompile(`src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)`)

// agePattern matches how long conntrackd has held an entry.
var agePattern = regexp.MustCompile(`\[active since (\d+)s\]`)

// CachedTuples parses `conntrackd -e` output into the set of original tuples.
func CachedTuples(output string) map[Tuple]bool {
	tuples := map[Tuple]bool{}
	for line := range strings.SplitSeq(output, "\n") {
		if tuple, ok := parseTuple(line); ok {
			tuples[tuple] = true
		}
	}
	return tuples
}

// OldestTuples parses `conntrackd -i` output and returns the original tuples
// of the count entries conntrackd has held longest, oldest first.
func OldestTuples(output string, count int) []Tuple {
	type entry struct {
		tuple Tuple
		age   int
	}
	var entries []entry
	for line := range strings.SplitSeq(output, "\n") {
		tuple, ok := parseTuple(line)
		match := agePattern.FindStringSubmatch(line)
		if !ok || match == nil {
			continue
		}
		age, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		entries = append(entries, entry{tuple: tuple, age: age})
	}
	slices.SortStableFunc(entries, func(a, b entry) int { return b.age - a.age })
	var oldest []Tuple
	for _, e := range entries[:min(count, len(entries))] {
		oldest = append(oldest, e.tuple)
	}
	return oldest
}

func parseTuple(line string) (Tuple, bool) {
	match := tuplePattern.FindStringSubmatch(line)
	if match == nil {
		return Tuple{}, false
	}
	src, srcErr := netip.ParseAddr(match[1])
	dst, dstErr := netip.ParseAddr(match[2])
	srcPort, srcPortErr := strconv.ParseUint(match[3], 10, 16)
	dstPort, dstPortErr := strconv.ParseUint(match[4], 10, 16)
	if srcErr != nil || dstErr != nil || srcPortErr != nil || dstPortErr != nil {
		return Tuple{}, false
	}
	return Tuple{Src: src, Dst: dst, SrcPort: uint16(srcPort), DstPort: uint16(dstPort)}, true
}

// cacheSizePattern matches the entry count that follows each cache's heading
// in `conntrackd -s` output.
var cacheSizePattern = regexp.MustCompile(`cache (internal|external):\s*current active connections:\s*(\d+)`)

// CacheSizes parses `conntrackd -s` output into the number of connections
// this NAT tracks (the internal cache) and the number copied from the peer
// (the external cache). ok is false unless both counts are present.
func CacheSizes(output string) (tracked, copied int, ok bool) {
	found := 0
	for _, match := range cacheSizePattern.FindAllStringSubmatch(output, -1) {
		value, err := strconv.Atoi(match[2])
		if err != nil {
			return 0, 0, false
		}
		if match[1] == "internal" {
			tracked = value
		} else {
			copied = value
		}
		found++
	}
	return tracked, copied, found == 2
}
