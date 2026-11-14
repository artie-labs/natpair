// Package health checks whether this NAT can forward traffic and whether its
// peer is ready to take over.
//
// While serving, the monitor checks every ServingInterval that verified
// uploads out through the shared Elastic IP and the shared ENI succeed. While
// standing by, it checks every StandbyInterval that uploads out through this
// NAT's own public IP succeed. It then confirms that conntrackd copied the
// peer's recent probe connections and its oldest connections. Each NAT posts
// its report to the pair's DynamoDB board after every round, so each can tell
// whether the other is ready.
package health

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/artie-labs/natpair/internal/conntrackd"
	"github.com/artie-labs/natpair/internal/network"
	"github.com/artie-labs/natpair/internal/probe"
)

// Probe timing. Every interval and window below is a multiple of
// BaseInterval, so changing BaseInterval changes them all consistently.
const (
	// BaseInterval is how often the active NAT checks the path workers use.
	// It sets how quickly a broken path is noticed: about two intervals.
	BaseInterval = time.Second
	// ServingInterval is the round interval while serving, and while standing
	// by for a failing peer.
	ServingInterval = BaseInterval
	// StandbyInterval is the round interval while standing by. A standby only
	// has to show that it is ready, so it probes less often.
	StandbyInterval = 5 * BaseInterval

	// staleRounds is how many of its own rounds a report stays valid. An older
	// report means the monitor is stuck.
	staleRounds = 3
	// flowRounds is how many rounds a probe connection is advertised to the
	// peer as evidence for replication.
	flowRounds = 3
	// replicationRounds is how many rounds one confirmed copy keeps this NAT ready.
	replicationRounds = 3
	// requiredSuccesses is the number of consecutive healthy rounds before
	// this NAT counts as able to forward.
	requiredSuccesses = 2
	// oldestCount is how many of its longest-held connections a NAT publishes.
	// The peer's copy counts as complete only when it holds all of them. A
	// restarted conntrackd starts empty, and idle connections send no updates
	// that would copy them again, so only a full copy brings them over. A count
	// can't show that: on AWS, churn pushed a restarted standby's copy past 90%
	// of the owner's count while it held none of 209 idle connections.
	oldestCount = 16
	// oldestInterval is how often a NAT reads its oldest connections again.
	// Reading them dumps conntrackd's whole cache.
	oldestInterval = StandbyInterval
	// incompleteRounds is how many rounds in a row a copy must miss the peer's
	// oldest connections before this NAT asks for a full copy. One round can
	// miss a connection that closed after the peer's report.
	incompleteRounds = 2
	// resyncInterval is the shortest time between requests for a full copy, so
	// a large copy still on its way isn't requested again.
	resyncInterval = 30 * BaseInterval
	// logInterval is how often a round is logged while its result doesn't
	// change. Alerts that fire when a pair logs no ready standby round for 10
	// minutes rely on it staying well below that.
	logInterval = 60 * BaseInterval
	// nearlyFullPercent is how full the kernel's connection table must be,
	// in percent, before this NAT warns, and before dropped packets count as
	// the table being full.
	nearlyFullPercent = 90
	// tableWarnInterval is the shortest time between repeats of each warning
	// about the connection table, and about the handshake check.
	tableWarnInterval = 60 * BaseInterval
	// handshakeAttempts is how many TCP handshakes an owner whose upload
	// timed out tries at once, to tell a congested path from a dead one. On
	// AWS, forwarding more small UDP packets than the CPU could process lost
	// 64 to 87% of pings through the NAT. At 87%, all 40 fail in 0.4% of
	// rounds. A step-down needs two such rounds in a row, which at about
	// 1.5 s a round come about once a day. Each failed attempt keeps an
	// entry in the connection table for up to 2 minutes, a few thousand
	// entries while an overload lasts.
	handshakeAttempts = 40
)

// StaleAfter returns how old a report from rounds of the given interval may
// be before it is treated as stale.
func StaleAfter(interval time.Duration) time.Duration {
	return staleRounds * interval
}

// Report is the result of one health round. The peer reads it through
// [Reports].
type Report struct {
	// PathHealthy is true when this round's upload passed.
	PathHealthy         bool `json:"path_healthy"`
	ConsecutiveFailures int  `json:"consecutive_failures"`
	// TrackedConnections is the number of connections conntrackd tracks on
	// this NAT, which the peer should hold copies of.
	TrackedConnections int `json:"tracked_connections"`
	// Oldest are the connections conntrackd has held longest on this NAT. The
	// peer must hold copies of all of them before it counts as ready.
	Oldest []conntrackd.Tuple `json:"oldest"`
	// CanForward means this NAT's path passed requiredSuccesses consecutive rounds.
	CanForward bool `json:"can_forward"`
	// CanForwardUnverified means this NAT has not proven its path, for example
	// because the probe receiver is unreachable. It may still take a free lease
	// as a last resort, because an unproven NAT beats no NAT forwarding.
	CanForwardUnverified bool `json:"can_forward_unverified"`
	// Ready means this NAT can forward, holds recently copied connections,
	// and is not in maintenance or cooldown. A copy counts when it holds at
	// least one of the peer's recent probe connections and all of the peer's
	// oldest connections, and it stays recent for replicationRounds.
	Ready bool `json:"ready"`
	// ProvenWhilePeerFailing means this round proved this NAT's path while the
	// peer was failing its own checks. That shows the peer's failure is its
	// own, not one both NATs share, such as a probe receiver outage.
	ProvenWhilePeerFailing bool `json:"proven_while_peer_failing"`
	// PeerConfirmedFailure means the peer proved its path while this NAT was
	// failing, so the failure is this NAT's. An owner steps down only then.
	PeerConfirmedFailure bool `json:"peer_confirmed_failure"`
	// Congested means this NAT is serving and its upload timed out, but
	// some of its handshakes through the shared Elastic IP completed while
	// others were lost. The path works but drops packets, as when more
	// traffic arrives than the NAT can forward, so the round doesn't count as
	// a path failure.
	Congested bool `json:"congested"`
	// CanTakeover means this NAT can forward and is not in maintenance or cooldown.
	CanTakeover     bool `json:"can_takeover"`
	PeerReady       bool `json:"peer_ready"`
	PeerCanTakeover bool `json:"peer_can_takeover"`
	// Release is the natpair release this NAT runs, or "" if unknown.
	Release string `json:"release,omitempty"`
	// Serving means this NAT's forwarding was open when the round started.
	Serving bool `json:"serving"`
	// PeerRelease and PeerServing come from the peer's fresh report. They are
	// empty and false without one. The updater reads them to decide when this
	// NAT may update itself or hand over.
	PeerRelease string `json:"peer_release,omitempty"`
	PeerServing bool   `json:"peer_serving"`
	// Flows are recent probe connections that the peer should find among its
	// copied connections.
	Flows []probe.Flow `json:"flows"`
	Stale bool         `json:"stale"`
}

// Config lists what the monitor checks.
type Config struct {
	// Probe goes out through this NAT's own public IP while standing by.
	Probe probe.Target
	// ServingProbe goes out through the shared Elastic IP while serving.
	ServingProbe probe.Target
	// Release is the release this NAT runs, or "" if unknown, reported to the
	// peer.
	Release string
}

// Prober checks a path.
type Prober interface {
	// Upload sends one verified upload.
	Upload(ctx context.Context, target probe.Target) (probe.Flow, error)
	// Handshakes opens attempts TCP connections to target's receiver at once
	// and returns how many connected.
	Handshakes(ctx context.Context, target probe.Target, attempts int) (int, error)
}

// Conntrack reads conntrackd's counters and copied connections.
type Conntrack interface {
	Stats(ctx context.Context) (string, error)
	InternalCache(ctx context.Context) (string, error)
	ExternalCache(ctx context.Context) (string, error)
	// RequestResync asks the peer to send its whole connection table again.
	RequestResync(ctx context.Context) error
}

// ConnectionTable reads the kernel's connection table.
type ConnectionTable interface {
	ReadConnectionTable(ctx context.Context) (network.ConnectionTable, error)
}

// Reports exchanges reports with the peer NAT.
type Reports interface {
	Publish(ctx context.Context, report any, interval time.Duration) error
	// Read returns the peer's report, or nil if the peer posts no fresh
	// reports.
	Read(ctx context.Context) (*Report, error)
}

// Dependencies connect the monitor to the system and the controller.
type Dependencies struct {
	Prober    Prober
	Conntrack Conntrack
	Table     ConnectionTable
	Reports   Reports
	// Serving reports whether this NAT currently forwards worker traffic.
	Serving func() bool
	// Inhibited reports maintenance, or the cooldown after stepping down or a
	// failed takeover.
	Inhibited func() bool
	// Now returns elapsed time on the boot clock.
	Now func() time.Duration
}

type timedFlow struct {
	flow probe.Flow
	at   time.Duration
}

// roundState is the part of a round's result that is logged as soon as it
// changes.
type roundState struct {
	healthy, ready, serving, peerReady bool
}

// Monitor runs health rounds and keeps the latest report.
type Monitor struct {
	config Config
	deps   Dependencies

	// State carried between rounds. Round and interval use it without a lock,
	// so only one goroutine may call them.
	failures        int
	successes       int
	flows           []timedFlow
	lastReplication time.Duration
	replicated      bool
	oldest          []conntrackd.Tuple
	oldestAt        time.Duration
	readOldest      bool
	incomplete      int
	lastResync      time.Duration
	resynced        bool
	// peerFailing means the peer's latest report showed failed rounds. A
	// standby then checks its own path at the serving interval, so the owner
	// learns quickly whether the failure is its own.
	peerFailing bool
	// table is the connection table's reading after the previous round's
	// upload, if tableRead.
	table     network.ConnectionTable
	tableRead bool
	// These limit how often each warning about the connection table repeats.
	tableUnread, nearlyFull, full, fullProbe warning
	// These limit how often each warning about the handshake check repeats.
	unchecked, congestedProbe warning
	// logged is the state of the last logged round, logged at loggedAt.
	logged    roundState
	loggedAt  time.Duration
	hasLogged bool

	mu             sync.Mutex
	latest         Report
	latestAt       time.Duration
	latestInterval time.Duration
	hasRound       bool
}

// New returns a monitor.
func New(config Config, deps Dependencies) *Monitor {
	return &Monitor{config: config, deps: deps}
}

// Run performs health rounds until ctx is cancelled: every ServingInterval
// while serving and every StandbyInterval otherwise. It checks every
// BaseInterval whether a round is due, so a NAT that starts serving switches
// to fast rounds without waiting out a standby interval.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(BaseInterval)
	defer ticker.Stop()
	var last time.Duration
	for first := true; ; first = false {
		serving := m.deps.Serving()
		due := first || m.deps.Now()-last >= m.interval(serving)
		// A standby looks at the peer every tick, so it starts confirming a
		// failing owner's problem at once instead of at its next round.
		if !due && !serving {
			due = m.peerReportFailing(ctx)
		}
		if due {
			last = m.deps.Now()
			m.Round(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Monitor) interval(serving bool) time.Duration {
	if serving || m.peerFailing {
		return ServingInterval
	}
	return StandbyInterval
}

// peerReportFailing reads the peer's report and reports whether it shows
// failed rounds.
func (m *Monitor) peerReportFailing(ctx context.Context) bool {
	peer, err := m.deps.Reports.Read(ctx)
	return err == nil && peer != nil && !peer.Stale && peer.ConsecutiveFailures > 0
}

// Latest returns the newest report. A report older than StaleAfter of its
// round interval is returned as stale, with every capability cleared.
func (m *Monitor) Latest() Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	report := m.latest
	if !m.hasRound || m.deps.Now()-m.latestAt > StaleAfter(m.latestInterval) {
		report.Stale = true
		report.Ready, report.CanForward, report.CanForwardUnverified, report.CanTakeover, report.PathHealthy = false, false, false, false, false
		report.Flows, report.Oldest = nil, nil
	}
	return report
}

// Round runs one health round and stores its report.
func (m *Monitor) Round(ctx context.Context) Report {
	started := m.deps.Now()
	serving := m.deps.Serving()
	// Read the peer first, so this round knows whether the peer is failing.
	peer, readErr := m.deps.Reports.Read(ctx)
	if readErr != nil {
		slog.Warn("failed to read the peer's report", slog.Any("err", readErr))
	}
	peerOK := readErr == nil && peer != nil && !peer.Stale
	if !peerOK {
		peer = &Report{}
	}
	m.peerFailing = peerOK && peer.ConsecutiveFailures > 0
	roundInterval := m.interval(serving)

	// While serving, the shared identity is the path workers use, so it
	// replaces the own-identity probe.
	target := m.config.Probe
	if serving {
		target = m.config.ServingProbe
	}
	flow, probeErr := m.deps.Prober.Upload(ctx, target)
	healthy := probeErr == nil
	now := m.deps.Now()
	// Read after the upload, so the drops since the last reading include the
	// upload's packets.
	tableFull := m.readTable(ctx, now)
	// Lost packets fail an upload only by running it out of time, since TCP
	// resends them. Any other failure, such as a reply showing the wrong
	// source address, came back over the path, so it counts without a check.
	// A standby's load doesn't move with the shared ENI, so its failures
	// count too.
	completed, checked := 0, false
	if serving && !tableFull && errors.Is(probeErr, probe.ErrTimeout) {
		completed, checked = m.handshakes(ctx, target, now)
	}
	congested := checked && completed > 0 && completed < handshakeAttempts

	switch {
	case healthy:
		m.failures, m.successes = 0, m.successes+1
	case tableFull:
		// A full table drops the upload's new connection, as it drops new
		// worker connections. The peer would load the same copied table on
		// taking over, and fail the same way, so this round proves nothing
		// about the path and counts neither way. On AWS, an owner whose table
		// filled stepped down, and so did the NAT that took over from it.
		if m.fullProbe.due(now) {
			slog.Warn("the health probe failed because this NAT's connection table is full, so it doesn't count as a path failure",
				slog.Any("probe_error", probeErr), slog.Int("connections", m.table.Connections), slog.Int("max_connections", m.table.Max))
		}
	case congested:
		// The upload leaves through the shared Elastic IP and is translated
		// like worker traffic, so when forwarding loses packets it loses
		// the upload's too, and the upload runs out of time. The handshakes
		// that completed prove the path delivers both ways, and the peer
		// would get the same traffic on taking over. On AWS, an owner
		// forwarding more UDP than its CPU could process stepped down, the
		// new owner did too seconds later, and the pair moved 2 to 4 times
		// a minute, each move pausing forwarding for about 10 s. So this
		// round ends any run of failures, but doesn't count as a success.
		m.failures = 0
		if m.congestedProbe.due(now) {
			slog.Warn("the health probe failed, but the path is alive, so forwarding is congested and it doesn't count as a path failure",
				slog.Any("probe_error", probeErr), slog.Int("handshakes", completed), slog.Int("attempts", handshakeAttempts))
		}
	default:
		m.failures, m.successes = m.failures+1, 0
	}
	var flows []timedFlow
	for _, flow := range m.flows {
		if now-flow.at < flowRounds*roundInterval {
			flows = append(flows, flow)
		}
	}
	if probeErr == nil {
		flows = append(flows, timedFlow{flow: flow, at: now})
	}
	m.flows = flows

	var tracked, copied int
	if stats, err := m.deps.Conntrack.Stats(ctx); err == nil {
		tracked, copied, _ = conntrackd.CacheSizes(stats)
	} else {
		slog.Warn("conntrackd is not answering, so connections are not being copied", slog.Any("err", err))
	}
	if !m.readOldest || now-m.oldestAt >= oldestInterval {
		m.oldest, m.oldestAt, m.readOldest = nil, now, true
		if cache, err := m.deps.Conntrack.InternalCache(ctx); err == nil {
			m.oldest = conntrackd.OldestTuples(cache, oldestCount)
		}
	}

	verified := false
	oldestCopied := 0
	if peerOK {
		// A running control socket alone does not prove state was copied.
		if cache, err := m.deps.Conntrack.ExternalCache(ctx); err == nil {
			copies := conntrackd.CachedTuples(cache)
			for _, tuple := range peer.Oldest {
				if copies[tuple] {
					oldestCopied++
				}
			}
			complete := oldestCopied == len(peer.Oldest)
			if complete || serving {
				m.incomplete = 0
			} else {
				m.incomplete++
			}
			// A standby with an incomplete copy asks for a full one, for example
			// after its conntrackd restarted while the peer was down, so its
			// startup request went unanswered. An owner doesn't ask: right after a
			// takeover, the full copy would hold the former owner's old entries,
			// and the former owner's scheduled flush removes them without telling
			// the owner. On AWS, 80,000 of these copies stayed and inflated the
			// copied count after the next handover.
			if m.incomplete >= incompleteRounds && (!m.resynced || now-m.lastResync >= resyncInterval) {
				slog.Warn("copied connections are incomplete, requesting a full copy from the peer",
					slog.Int("peer_oldest", len(peer.Oldest)), slog.Int("peer_oldest_copied", oldestCopied))
				m.lastResync, m.resynced = now, true
				if err := m.deps.Conntrack.RequestResync(ctx); err != nil {
					slog.Warn("failed to request a full copy", slog.Any("err", err))
				}
			}
			verified = complete && copiedPeerFlows(copies, peer.Flows)
		}
	}
	if verified {
		m.replicated, m.lastReplication = true, now
	}
	recent := m.replicated && now-m.lastReplication <= replicationRounds*roundInterval

	inhibited := m.deps.Inhibited()
	// conntrackd isn't required to forward. A NAT without it takes over without
	// copied connections, which beats leaving no NAT forwarding. Ready, which
	// planned maintenance needs, still requires recent copies.
	canForward := m.successes >= requiredSuccesses
	ready := canForward && recent && !inhibited
	report := Report{
		PathHealthy:            healthy,
		ConsecutiveFailures:    m.failures,
		TrackedConnections:     tracked,
		Oldest:                 m.oldest,
		CanForward:             canForward,
		CanForwardUnverified:   !canForward,
		Ready:                  ready,
		CanTakeover:            !inhibited && canForward,
		PeerReady:              peerOK && peer.Ready,
		PeerCanTakeover:        peerOK && peer.CanTakeover,
		ProvenWhilePeerFailing: m.peerFailing && healthy,
		PeerConfirmedFailure:   peerOK && peer.ProvenWhilePeerFailing,
		Release:                m.config.Release,
		Congested:              congested,
		Serving:                serving,
		PeerRelease:            peer.Release,
		PeerServing:            peerOK && peer.Serving,
	}
	for _, flow := range m.flows {
		report.Flows = append(report.Flows, flow.flow)
	}

	m.mu.Lock()
	m.latest, m.latestAt, m.latestInterval, m.hasRound = report, now, roundInterval, true
	m.mu.Unlock()

	if err := m.deps.Reports.Publish(ctx, report, roundInterval); err != nil {
		slog.Warn("failed to publish this round's report", slog.Any("err", err))
	}

	// The owner runs a round every second or two. Logging each one would make
	// up almost all of natpair's logs, about 36,000 lines a day per owner.
	// Failed rounds and changes are logged at once, and otherwise one round
	// each logInterval.
	state := roundState{healthy: healthy, ready: ready, serving: serving, peerReady: report.PeerReady}
	if !healthy || !m.hasLogged || state != m.logged || now-m.loggedAt >= logInterval {
		m.logged, m.loggedAt, m.hasLogged = state, now, true
		attrs := []any{
			slog.Bool("healthy", healthy), slog.Bool("copied", verified), slog.Bool("ready", ready),
			slog.Bool("peer_ready", report.PeerReady), slog.Duration("duration", m.deps.Now()-started),
			slog.Bool("serving", serving), slog.Any("probe_error", probeErr), slog.Bool("table_full", tableFull),
			slog.Bool("congested", congested),
			slog.Int("tracked_connections", tracked), slog.Int("copied_connections", copied),
			slog.Int("peer_tracked_connections", peer.TrackedConnections),
			slog.Int("peer_oldest", len(peer.Oldest)), slog.Int("peer_oldest_copied", oldestCopied),
			slog.String("release", m.config.Release),
		}
		if checked {
			attrs = append(attrs, slog.Int("handshakes", completed))
		}
		slog.Info("health round", attrs...)
	}
	return report
}

// readTable reads the kernel's connection table, warns while it is nearly
// full or full, and reports whether it was full since the previous reading.
//
// Full means the kernel dropped packets it couldn't track since the previous
// reading, while the table was at least nearlyFullPercent full. The drop
// counter is the direct evidence: the kernel counts each packet it drops
// because a new connection has no room for an entry, which is how a full
// table breaks a probe. The size alone can't tell. A table at its limit can
// still take a new connection by evicting one that is closing, and then
// nothing is dropped. The size check rules out the counter's rarer causes,
// such as two packets racing to insert the same entry.
func (m *Monitor) readTable(ctx context.Context, now time.Duration) bool {
	table, err := m.deps.Table.ReadConnectionTable(ctx)
	previous, hadPrevious := m.table, m.tableRead
	m.table, m.tableRead = table, err == nil
	if err != nil {
		if m.tableUnread.due(now) {
			slog.Warn("failed to read the connection table, so a full table can't be told from a path failure", slog.Any("err", err))
		}
		return false
	}
	nearlyFull := table.Max > 0 && table.Connections*100 >= table.Max*nearlyFullPercent
	full := nearlyFull && hadPrevious && table.Drops > previous.Drops
	switch {
	case full:
		if m.full.due(now) {
			slog.Warn("the connection table is full, so the kernel drops new connections. Raise max_connections and replace the NATs.",
				slog.Int("connections", table.Connections), slog.Int("max_connections", table.Max), slog.Uint64("dropped", table.Drops-previous.Drops))
		}
	case nearlyFull:
		if m.nearlyFull.due(now) {
			slog.Warn("the connection table is nearly full, so new connections may be dropped. Raise max_connections and replace the NATs.",
				slog.Int("connections", table.Connections), slog.Int("max_connections", table.Max))
		}
	}
	return full
}

// handshakes tries handshakeAttempts TCP handshakes through target's path,
// after an upload that timed out, and returns how many completed. It reports
// false if it couldn't try, such as when the receiver's address is unknown.
//
// Some but not all completing means the path delivers but loses packets.
// None completing means it's dead. All completing means small packets get
// through without loss, so the upload failed for another reason, such as a
// path that drops full-size packets, and the failure counts. A handshake
// can't be forged from off the path, because the answer must acknowledge
// the random sequence number the kernel chose for the SYN, and a flood can
// only make handshakes fail.
func (m *Monitor) handshakes(ctx context.Context, target probe.Target, now time.Duration) (int, bool) {
	completed, err := m.deps.Prober.Handshakes(ctx, target, handshakeAttempts)
	if err != nil {
		if m.unchecked.due(now) {
			slog.Warn("failed to check whether the path is alive, so the failed probe counts", slog.Any("err", err))
		}
		return 0, false
	}
	return completed, true
}

// warning limits a repeated warning to one each tableWarnInterval.
type warning struct {
	at     time.Duration
	logged bool
}

// due reports whether the warning may be logged now, and if so, records it.
func (w *warning) due(now time.Duration) bool {
	if w.logged && now-w.at < tableWarnInterval {
		return false
	}
	w.at, w.logged = now, true
	return true
}

// copiedPeerFlows reports whether the copied connections include at least
// one of the peer's recent probe connections.
func copiedPeerFlows(cache map[conntrackd.Tuple]bool, flows []probe.Flow) bool {
	for _, flow := range flows {
		if cache[conntrackd.Tuple{Src: flow.Src, Dst: flow.Dst, SrcPort: flow.SrcPort, DstPort: flow.DstPort}] {
			return true
		}
	}
	return false
}
