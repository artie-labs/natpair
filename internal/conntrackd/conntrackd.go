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
	"bufio"
	"bytes"
	"cmp"
	"container/heap"
	"context"
	"fmt"
	"io"
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
//
// Sizes that follow the connection limit, from [WriteConfig]:
//   - HashSize, the buckets in each of conntrackd's two caches, is one per
//     connection, as in the kernel's table (see network's
//     sizeConnectionTable). Each bucket costs 16 bytes in each cache, 16 MB
//     for both at 524,288.
//   - ResendQueueSize is how many sent updates conntrackd keeps until the
//     peer acknowledges them, so it can resend those the peer reports lost.
//     With the default of 131,072, less than one full copy, conntrackd
//     discarded the start of a large copy before the peer asked for its lost
//     parts again. The queue holds references to cache entries, not copies.
//   - SndSocketBuffer and RcvSocketBuffer are the copies' socket buffers,
//     and NetlinkBufferSize is the kernel event socket's (see
//     socketBytesPerConnection). conntrackd reads no kernel events while it
//     sends a full copy, and an event lost to a full buffer leaves the
//     peer's copy out of date until conntrackd resyncs with the kernel 30 s
//     later. NetlinkBufferSizeMaxGrowth lets conntrackd double that buffer
//     once if it fills.
const configTemplate = `Sync {
    Mode FTFW {
        StartupResync on
        ResendQueueSize %[6]d
    }
    UDP {
        IPv4_address %[1]s
        IPv4_Destination_Address %[2]s
        Port 3780
        Interface %[3]s
        Checksum on
        SndSocketBuffer %[7]d
        RcvSocketBuffer %[7]d
    }
}
General {
    HashSize %[6]d
    HashLimit %[6]d
    NetlinkBufferSize %[7]d
    NetlinkBufferSizeMaxGrowth %[8]d
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

// socketBytesPerConnection sizes conntrackd's socket buffers per connection
// in the table. A full copy to the peer, which conntrackd sends when the peer
// restarts or asks for it, is about 100 bytes a connection on the wire (26 MB
// for 262,144 on AWS), sent in 1 to 3 s. With Linux's default buffer of
// about 208 KB, the receiving NAT dropped most of that burst, and after the
// resends its copy still lacked 13 to 31% of the table. The kernel doubles
// the size conntrackd asks for to cover its own bookkeeping, so 64 bytes a
// connection lets the buffer hold about the whole copy: 32 MB at 524,288.
// conntrackd sets its buffers with SO_RCVBUFFORCE and SO_SNDBUFFORCE, which
// root may use past net.core.rmem_max and wmem_max, so those limits for every
// other socket on the host stay as they are. A buffer uses memory only while
// data waits in it.
const socketBytesPerConnection = 64

// WriteConfig writes conntrackd's configuration to path. It replicates over
// iface from local to peer, ignores connections to or from local and shared,
// copies at most maxConnections, and keeps its log, lock file and control
// socket in dir. The kernel's connection table is sized to the same limit,
// because connections past it couldn't be copied.
func WriteConfig(path string, local, peer, shared netip.Addr, iface, dir string, maxConnections int) error {
	socketBuffer := maxConnections * socketBytesPerConnection
	contents := fmt.Sprintf(configTemplate, local, peer, iface, dir, shared, maxConnections, socketBuffer, 2*socketBuffer)
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

// scanTimeout bounds a pass over one of conntrackd's caches. conntrackd
// writes the cache from a forked process, so its own work doesn't wait for
// the pass. On AWS, it wrote 1,990,000 entries in 7.3 s.
const scanTimeout = 2 * time.Minute

// Oldest reads `conntrackd -i`, this NAT's own entries, and returns the
// original tuples of the count established connections conntrackd has held
// longest, oldest first. It keeps only count entries while it reads, so its
// memory doesn't grow with the table.
func (c Client) Oldest(ctx context.Context, count int) ([]Tuple, error) {
	var oldest []Tuple
	err := c.scan(ctx, "-i", func(r io.Reader) error {
		var err error
		oldest, err = readOldest(r, count)
		return err
	})
	return oldest, err
}

// Copied reads `conntrackd -e`, the entries copied from the peer, and
// returns which of wanted it holds. It keeps only wanted while it reads.
func (c Client) Copied(ctx context.Context, wanted []Tuple) (map[Tuple]bool, error) {
	var found map[Tuple]bool
	err := c.scan(ctx, "-e", func(r io.Reader) error {
		var err error
		found, err = readCopied(r, wanted)
		return err
	})
	return found, err
}

func (c Client) scan(ctx context.Context, cache string, read func(io.Reader) error) error {
	return command.Stream(ctx, scanTimeout, read, "conntrackd", "-C", c.ConfigPath, cache)
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

// text is how the tuple starts in conntrackd's output.
func (t Tuple) text() string {
	return fmt.Sprintf("src=%s dst=%s sport=%d dport=%d", t.Src, t.Dst, t.SrcPort, t.DstPort)
}

// newLines returns a scanner over conntrackd's output, one entry a line. An
// entry is about 250 bytes, so a line past maxLine means the output isn't
// what natpair expects.
func newLines(r io.Reader) *bufio.Scanner {
	const maxLine = 64 * 1024
	lines := bufio.NewScanner(r)
	lines.Buffer(make([]byte, 0, maxLine), maxLine)
	return lines
}

// readOldest returns the original tuples of the count established entries
// with the longest age in r, oldest first. Lines look like
//
//	tcp      6 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=10 dport=443 src=... [ASSURED] mark=0 [active since 1184s]
//
// Only established connections count. Entries in other states, such as the
// TIME_WAIT that follows every closed connection, leave the table within
// minutes, and a peer checking for one that just left would find its copy
// gone too. Of entries with the same age, the first one read wins.
func readOldest(r io.Reader, count int) ([]Tuple, error) {
	if count <= 0 {
		return nil, nil
	}
	held := make(oldestHeap, 0, count)
	lines := newLines(r)
	for read := 0; lines.Scan(); read++ {
		line := lines.Bytes()
		start := bytes.Index(line, srcKey)
		if start < 0 || !bytes.Contains(line[:start], established) {
			continue
		}
		age, ok := parseAge(line)
		if !ok {
			continue
		}
		// The heap's top is the youngest it holds. A younger or equal entry
		// can't replace it, so most lines are skipped before their tuple is
		// parsed.
		if len(held) == count && age <= held[0].age {
			continue
		}
		tuple, ok := parseTuple(line[start:])
		if !ok {
			continue
		}
		entry := heldEntry{tuple: tuple, age: age, order: read}
		if len(held) < count {
			heap.Push(&held, entry)
		} else {
			held[0] = entry
			heap.Fix(&held, 0)
		}
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(held, func(a, b heldEntry) int {
		if a.age != b.age {
			return cmp.Compare(b.age, a.age)
		}
		return cmp.Compare(a.order, b.order)
	})
	oldest := make([]Tuple, len(held))
	for i, entry := range held {
		oldest[i] = entry.tuple
	}
	return oldest, nil
}

// readCopied returns which of wanted appear in r as an entry's original
// tuple.
func readCopied(r io.Reader, wanted []Tuple) (map[Tuple]bool, error) {
	byText := make(map[string]Tuple, len(wanted))
	for _, tuple := range wanted {
		byText[tuple.text()] = tuple
	}
	found := make(map[Tuple]bool, len(wanted))
	lines := newLines(r)
	for lines.Scan() {
		if len(found) == len(byText) {
			// Read to the end anyway, since conntrackd waits until its output
			// is read.
			continue
		}
		text, ok := tupleText(lines.Bytes())
		if !ok {
			continue
		}
		// Converting the bytes inside the index expression doesn't copy them.
		if tuple, ok := byText[string(text)]; ok {
			found[tuple] = true
		}
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	return found, nil
}

var (
	srcKey      = []byte("src=")
	established = []byte(" ESTABLISHED ")
	ageKey      = []byte("[active since ")
)

// tupleText returns the line's first src, dst, sport and dport fields, the
// connection's original direction, as they appear in the line.
func tupleText(line []byte) ([]byte, bool) {
	start := bytes.Index(line, srcKey)
	if start < 0 {
		return nil, false
	}
	rest := line[start:]
	end := 0
	for _, key := range []string{"src=", "dst=", "sport=", "dport="} {
		if !bytes.HasPrefix(rest[end:], []byte(key)) {
			return nil, false
		}
		space := bytes.IndexByte(rest[end:], ' ')
		if space < 0 {
			space = len(rest) - end
		}
		end += space + 1
	}
	return rest[:end-1], true
}

// parseTuple parses the first src, dst, sport and dport fields of line.
func parseTuple(line []byte) (Tuple, bool) {
	text, ok := tupleText(line)
	if !ok {
		return Tuple{}, false
	}
	fields := strings.Fields(string(text))
	src, srcErr := netip.ParseAddr(strings.TrimPrefix(fields[0], "src="))
	dst, dstErr := netip.ParseAddr(strings.TrimPrefix(fields[1], "dst="))
	srcPort, srcPortErr := strconv.ParseUint(strings.TrimPrefix(fields[2], "sport="), 10, 16)
	dstPort, dstPortErr := strconv.ParseUint(strings.TrimPrefix(fields[3], "dport="), 10, 16)
	if srcErr != nil || dstErr != nil || srcPortErr != nil || dstPortErr != nil {
		return Tuple{}, false
	}
	return Tuple{Src: src, Dst: dst, SrcPort: uint16(srcPort), DstPort: uint16(dstPort)}, true
}

// parseAge parses how long conntrackd has held an entry, in seconds, from
// "[active since 1184s]".
func parseAge(line []byte) (int, bool) {
	start := bytes.Index(line, ageKey)
	if start < 0 {
		return 0, false
	}
	digits := line[start+len(ageKey):]
	end := bytes.IndexByte(digits, 's')
	if end <= 0 {
		return 0, false
	}
	age, err := strconv.Atoi(string(digits[:end]))
	return age, err == nil
}

// heldEntry is an entry readOldest holds: its tuple, its age and its line
// number.
type heldEntry struct {
	tuple Tuple
	age   int
	order int
}

// oldestHeap is a min-heap by age, then by line number reversed, so its top
// is the entry readOldest would drop first.
type oldestHeap []heldEntry

func (h oldestHeap) Len() int { return len(h) }
func (h oldestHeap) Less(i, j int) bool {
	if h[i].age != h[j].age {
		return h[i].age < h[j].age
	}
	return h[i].order > h[j].order
}
func (h oldestHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *oldestHeap) Push(x any)   { *h = append(*h, x.(heldEntry)) }
func (h *oldestHeap) Pop() any {
	old := *h
	entry := old[len(old)-1]
	*h = old[:len(old)-1]
	return entry
}

// statsPattern matches each cache's heading in `conntrackd -s` output, its
// entry count and how many entries it has added.
var statsPattern = regexp.MustCompile(`cache (internal|external):\s*current active connections:\s*(\d+)\s*connections created:\s*(\d+)`)

// Stats are counters from `conntrackd -s`.
type Stats struct {
	// Tracked is the number of connections this NAT tracks, its internal
	// cache.
	Tracked int
	// Copied is the number of connections copied from the peer, its external
	// cache.
	Copied int
	// CopiesAdded counts the copies conntrackd added since it started. It grows
	// as the peer opens connections, and starts over when conntrackd restarts.
	CopiesAdded int
}

// ParseStats parses `conntrackd -s` output. ok is false unless both caches'
// counters are present.
func ParseStats(output string) (Stats, bool) {
	var stats Stats
	found := 0
	for _, match := range statsPattern.FindAllStringSubmatch(output, -1) {
		count, countErr := strconv.Atoi(match[2])
		added, addedErr := strconv.Atoi(match[3])
		if countErr != nil || addedErr != nil {
			return Stats{}, false
		}
		if match[1] == "internal" {
			stats.Tracked = count
		} else {
			stats.Copied, stats.CopiesAdded = count, added
		}
		found++
	}
	return stats, found == 2
}
