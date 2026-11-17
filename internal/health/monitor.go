// Package health checks whether this NAT can forward traffic and whether its
// peer is ready to take over.
//
// While serving, the monitor checks every ServingInterval that verified
// uploads out through the shared Elastic IP and the shared ENI succeed. While
// standing by, it checks every StandbyInterval that uploads out through this
// NAT's own public IP succeed. It then confirms that conntrackd keeps adding
// copies of the peer's new connections, holds copies of the peer's oldest
// connections, and holds about as many copies as the peer tracks
// connections. Each NAT posts its report to the pair's DynamoDB board after
// every round, so each can tell whether the other is ready.
package health

import (
	"context"
	"log/slog"
	"maps"
	"slices"
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
	// peer. Earlier releases check that they copied one of them.
	flowRounds = 3
	// replicationRounds is how many rounds one confirmed copy keeps this NAT ready.
	replicationRounds = 3
	// requiredSuccesses is the number of consecutive healthy rounds before
	// this NAT counts as able to forward.
	requiredSuccesses = 2
	// failureGapRounds is how many rounds in a row that count neither way,
	// such as with a full connection table, end a run of failed rounds. Without
	// it, one failure, hours of full table, then one more failure would count
	// as two in a row and make the owner step down.
	failureGapRounds = 3
	// oldestCount is how many of its longest-held connections a NAT publishes.
	// The peer's copy counts as complete only when it holds all of them. A
	// restarted conntrackd starts empty, and idle connections send no updates
	// that would copy them again, so only a full copy brings them over. A count
	// can't show that: on AWS, churn pushed a restarted standby's copy past 90%
	// of the owner's count while it held none of 209 idle connections.
	oldestCount = 16
	// copiedPercent is how much of the owner's table, in percent, a standby's
	// copy must hold before the standby counts as ready. The oldest
	// connections and probe connections are a sample, which the start of a
	// full copy usually carries. On AWS, standbys whose full copy lost 13 to
	// 31% of the table passed that sample and reported ready, and the next
	// takeover reset the connections they lacked. The owner's count comes
	// from its latest report, up to a second or two old, so the margin covers
	// the table shrinking that much in between, and copies on their way.
	copiedPercent = 95
	// copiedSlack is how many connections a standby's copy may lack whatever
	// the share. In a small table, a few connections opened or closed since
	// the owner's report are more than 5% of it. A full copy loses
	// connections only when its burst overflows the standby's buffers, which
	// takes tens of thousands of them, so the slack never hides that.
	copiedSlack = 100
	// copyWindow is how long after conntrackd last added a copy of one of
	// the peer's connections this NAT still counts as being copied to. Each
	// of the peer's health rounds opens a probe connection, at least one
	// every StandbyInterval.
	copyWindow = replicationRounds * StandbyInterval
	// oldestInterval is how often a NAT reads its oldest connections again.
	// Reading them has conntrackd write its whole cache, which took 3.3 s at
	// 819,541 connections on AWS.
	oldestInterval = 60 * BaseInterval
	// copiesInterval is the shortest time between passes over this NAT's
	// copies, which also have conntrackd write its whole cache. A pass runs
	// only while some of the peer's oldest connections aren't confirmed.
	copiesInterval = 3 * StandbyInterval
	// confirmFor is how long a pass's finding that a copy holds one of the
	// peer's oldest connections lasts before a new pass checks it again, in
	// case the copy was emptied without this NAT noticing.
	confirmFor = 5 * 60 * BaseInterval
	// missingFor is how long one of the peer's oldest connections may stay
	// missing from this NAT's copy before it asks for a full copy. A
	// connection that closed stays in the peer's reports until the peer reads
	// its oldest connections again, up to oldestInterval later.
	missingFor = oldestInterval + 2*StandbyInterval
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
	// about the connection table.
	tableWarnInterval = 60 * BaseInterval
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
	PathHealthy bool `json:"path_healthy"`
	// TableFull means this round's upload failed because this NAT's
	// connection table was full, so the failure says nothing about the path.
	// The round counts neither as failed nor as healthy. Only this NAT reads
	// it, so it isn't sent to the peer.
	TableFull           bool `json:"-"`
	ConsecutiveFailures int  `json:"consecutive_failures"`
	// TrackedConnections is the number of connections conntrackd tracks on
	// this NAT, which the peer should hold copies of.
	TrackedConnections int `json:"tracked_connections"`
	// TrackedUnknown means this NAT couldn't read both of conntrackd's
	// counts this round, so TrackedConnections isn't a count to compare a
	// copy against. Releases before it never set it.
	TrackedUnknown bool `json:"tracked_unknown,omitempty"`
	// Oldest are the established connections conntrackd has held longest on
	// this NAT, read every oldestInterval. The peer must hold copies of all of
	// them before it counts as ready.
	Oldest []conntrackd.Tuple `json:"oldest"`
	// CanForward means this NAT's path passed requiredSuccesses consecutive rounds.
	CanForward bool `json:"can_forward"`
	// CanForwardUnverified means this NAT has not proven its path, for example
	// because the probe receiver is unreachable. It may still take a free lease
	// as a last resort, because an unproven NAT beats no NAT forwarding.
	CanForwardUnverified bool `json:"can_forward_unverified"`
	// Ready means this NAT can forward, holds recently copied connections,
	// and is not in maintenance or cooldown. A copy counts when conntrackd
	// added a copy within copyWindow, it holds all of the peer's oldest
	// connections, and, while standing by, at least copiedPercent of the
	// peer's TrackedConnections or all but copiedSlack of them. It stays
	// recent for replicationRounds.
	Ready bool `json:"ready"`
	// ProvenWhilePeerFailing means this round proved this NAT's path while the
	// peer was failing its own checks. That shows the peer's failure is its
	// own, not one both NATs share, such as a probe receiver outage.
	ProvenWhilePeerFailing bool `json:"proven_while_peer_failing"`
	// PeerConfirmedFailure means the peer proved its path while this NAT was
	// failing, so the failure is this NAT's. An owner steps down only then.
	PeerConfirmedFailure bool `json:"peer_confirmed_failure"`
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
	// Flows are recent probe connections. Earlier releases check that they
	// hold a copy of one of the peer's.
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

// Prober sends one verified upload.
type Prober interface {
	Upload(ctx context.Context, target probe.Target) (probe.Flow, error)
}

// Conntrack reads conntrackd's counters and copied connections.
type Conntrack interface {
	Stats(ctx context.Context) (string, error)
	// Oldest returns the count established connections this NAT has tracked
	// longest, oldest first.
	Oldest(ctx context.Context, count int) ([]conntrackd.Tuple, error)
	// Copied returns which of wanted this NAT holds copies of.
	Copied(ctx context.Context, wanted []conntrackd.Tuple) (map[conntrackd.Tuple]bool, error)
	// RequestResync asks the peer to send its whole connection table again.
	RequestResync(ctx context.Context) error
	// Flushes counts the times natpair has had conntrackd flush its caches,
	// as a takeover and a step-down do.
	Flushes() uint64
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
	healthy, tableFull, ready, serving, peerReady bool
}

// Monitor runs health rounds and keeps the latest report.
type Monitor struct {
	config Config
	deps   Dependencies

	// State carried between rounds. Round and interval use it without a lock,
	// so only one goroutine may call them.
	failures  int
	successes int
	// uncounted is how many rounds counted neither way since the last failed
	// round.
	uncounted       int
	flows           []timedFlow
	lastReplication time.Duration
	replicated      bool
	// shortSince is when this NAT's copy started holding too few of the
	// peer's connections, if shortRun.
	shortSince time.Duration
	shortRun   bool
	lastResync time.Duration
	resynced   bool
	// copiesAdded is conntrackd's latest count of copies it added, read at
	// addedReadAt, if addedRead. addedAt is when that count last changed, if
	// addedMoved.
	copiesAdded int
	addedReadAt time.Duration
	addedAt     time.Duration
	addedRead   bool
	addedMoved  bool
	// flushes is Conntrack.Flushes at the previous round, if servedBefore.
	flushes uint64
	// wasServing is whether the previous round served, if servedBefore.
	wasServing   bool
	servedBefore bool
	scans        scanner
	// peerFailing means the peer's latest report showed failed rounds. A
	// standby then checks its own path at the serving interval, so the owner
	// learns quickly whether the failure is its own.
	peerFailing bool
	// table is the last good reading of the connection table, if tableRead.
	// A failed reading keeps it, so the next good one still has drops to
	// compare with. The drop counter only grows, so the comparison holds.
	table     network.ConnectionTable
	tableRead bool
	// These limit how often each warning about the connection table repeats.
	tableUnread, nearlyFull, full, fullProbe warning
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
	return &Monitor{config: config, deps: deps, scans: scanner{conntrack: deps.Conntrack}}
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

	// countedFailure is whether this round counts as failed.
	countedFailure := false
	switch {
	case healthy:
		m.failures, m.successes = 0, m.successes+1
	case tableFull:
		// A full table drops the upload's new connection, as it drops new
		// worker connections. The peer loads copies of this NAT's TCP
		// connections on taking over, so when TCP fills the table, as on AWS,
		// it would fail the same way. This round proves nothing about the
		// path and counts neither way. On AWS, an owner whose table
		// filled stepped down, and so did the NAT that took over from it.
		m.uncounted++
		if m.uncounted >= failureGapRounds {
			m.failures = 0
		}
		if m.fullProbe.due(now) {
			slog.Warn("the health probe failed because this NAT's connection table is full, so it doesn't count as a path failure",
				slog.Any("probe_error", probeErr), slog.Int("connections", m.table.Connections), slog.Int("max_connections", m.table.Max))
		}
	default:
		m.failures, m.successes, m.uncounted = m.failures+1, 0, 0
		countedFailure = true
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

	var stats conntrackd.Stats
	counted := false
	if output, err := m.deps.Conntrack.Stats(ctx); err == nil {
		stats, counted = conntrackd.ParseStats(output)
	} else {
		slog.Warn("conntrackd is not answering, so connections are not being copied", slog.Any("err", err))
	}
	tracked, copied := stats.Tracked, stats.Copied
	m.noteCopies(now, serving, stats, counted)
	if peerOK {
		m.scans.start(ctx, now, peer.Oldest)
	} else {
		m.scans.start(ctx, now, nil)
	}
	oldest, oldestCopied, oldestLost := m.scans.results(peer.Oldest, peerOK, now)

	verified := false
	// A running control socket alone does not prove state was copied.
	if peerOK && counted {
		// Only a standby's copy is what a takeover would install. The
		// owner's copy is of the standby's table, and the NAT that just
		// stepped down still counts its old table until its flush 60 s
		// later. The owner's count must have been read too: an owner whose
		// conntrackd didn't answer reports 0, which any copy would cover.
		// Releases before TrackedUnknown don't say so, and their 0 is
		// trusted as before.
		covers := copied*100 >= peer.TrackedConnections*copiedPercent ||
			peer.TrackedConnections-copied <= copiedSlack
		shortfall := !serving && !peer.TrackedUnknown && !covers
		enough := serving || (!peer.TrackedUnknown && covers)
		complete := oldestCopied == len(peer.Oldest) && enough
		// A copy measured short isn't ready, even within
		// replicationRounds of the last good one, such as just after this
		// NAT's conntrackd restarted empty. An unknown count only fails this
		// round's check. What passes found about the peer's oldest
		// connections still counts: a copy that lost part of a burst keeps
		// the entries it got, and noteCopies forgets them when the copy is
		// emptied.
		if shortfall {
			m.replicated = false
		}
		// Only measured rounds start or end the time a copy has been short.
		switch {
		case shortfall:
			if !m.shortRun {
				m.shortSince, m.shortRun = now, true
			}
		case enough:
			m.shortRun = false
		}
		// A standby with an incomplete copy asks for a full one, for example
		// after its conntrackd restarted while the peer was down, so its
		// startup request went unanswered. An owner doesn't ask: right after a
		// takeover, the full copy would hold the former owner's old entries,
		// and the former owner's scheduled flush removes them without telling
		// the owner. On AWS, 80,000 of these copies stayed and inflated the
		// copied count after the next handover. A full copy of a large table
		// takes seconds to arrive, such as conntrackd's own request when it
		// starts, so a short copy asks again only once it has stayed short
		// for resyncInterval.
		incomplete := (m.shortRun && now-m.shortSince >= resyncInterval) || oldestLost
		if !serving && incomplete && (!m.resynced || now-m.lastResync >= resyncInterval) {
			slog.Warn("copied connections are incomplete, requesting a full copy from the peer",
				slog.Int("peer_oldest", len(peer.Oldest)), slog.Int("peer_oldest_copied", oldestCopied),
				slog.Int("copied_connections", copied), slog.Int("peer_tracked_connections", peer.TrackedConnections))
			m.lastResync, m.resynced = now, true
			if err := m.deps.Conntrack.RequestResync(ctx); err != nil {
				slog.Warn("failed to request a full copy", slog.Any("err", err))
			}
		}
		arriving := m.addedMoved && now-m.addedAt <= copyWindow
		verified = complete && arriving
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
		TableFull:              !healthy && tableFull,
		ConsecutiveFailures:    m.failures,
		TrackedConnections:     tracked,
		TrackedUnknown:         !counted,
		Oldest:                 oldest,
		CanForward:             canForward,
		CanForwardUnverified:   !canForward,
		Ready:                  ready,
		CanTakeover:            !inhibited && canForward,
		PeerReady:              peerOK && peer.Ready,
		PeerCanTakeover:        peerOK && peer.CanTakeover,
		ProvenWhilePeerFailing: m.peerFailing && healthy,
		PeerConfirmedFailure:   peerOK && peer.ProvenWhilePeerFailing,
		Release:                m.config.Release,
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
	state := roundState{healthy: healthy, tableFull: report.TableFull, ready: ready, serving: serving, peerReady: report.PeerReady}
	// Each round that counts as failed is logged. Others, including failed
	// rounds that don't count, such as with a full table, which can last
	// hours, are logged when something changes and once a minute.
	if countedFailure || !m.hasLogged || state != m.logged || now-m.loggedAt >= logInterval {
		m.logged, m.loggedAt, m.hasLogged = state, now, true
		slog.Info("health round",
			slog.Bool("healthy", healthy), slog.Bool("copied", verified), slog.Bool("ready", ready),
			slog.Bool("peer_ready", report.PeerReady), slog.Duration("duration", m.deps.Now()-started),
			slog.Bool("serving", serving), slog.Any("probe_error", probeErr), slog.Bool("table_full", tableFull),
			slog.Int("tracked_connections", tracked), slog.Int("copied_connections", copied),
			slog.Int("peer_tracked_connections", peer.TrackedConnections),
			slog.Int("peer_oldest", len(peer.Oldest)), slog.Int("peer_oldest_copied", oldestCopied),
			slog.String("release", m.config.Release))
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
	if err != nil {
		if m.tableUnread.due(now) {
			slog.Warn("failed to read the connection table, so a full table can't be told from a path failure", slog.Any("err", err))
		}
		return false
	}
	previous, hadPrevious := m.table, m.tableRead
	m.table, m.tableRead = table, true
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

// noteCopies records when conntrackd last added a copy, and forgets which of
// the peer's oldest connections this NAT's copy held when the copy may have
// been emptied since: conntrackd restarted, which starts its count over, or
// natpair had conntrackd flush its caches, as a takeover and a step-down do.
// A takeover that fails after the flush leaves this NAT standing by, so only
// the count of flushes shows it. The count of copies is 32 bits, so it also
// starts over after about 4 billion copies, which costs one extra pass.
// This NAT isn't ready again until it has checked the new copy.
func (m *Monitor) noteCopies(now time.Duration, serving bool, stats conntrackd.Stats, counted bool) {
	flushes := m.deps.Conntrack.Flushes()
	emptied := m.servedBefore && (serving != m.wasServing || flushes != m.flushes)
	m.flushes = flushes
	if counted {
		if m.addedRead && stats.CopiesAdded != m.copiesAdded {
			emptied = emptied || stats.CopiesAdded < m.copiesAdded
			// A count that moved since a read longer than copyWindow ago may
			// have moved before copies stopped arriving.
			if now-m.addedReadAt <= copyWindow {
				m.addedAt, m.addedMoved = now, true
			}
		}
		m.copiesAdded, m.addedReadAt, m.addedRead = stats.CopiesAdded, now, true
	}
	if emptied {
		m.scans.forget()
		m.replicated = false
	}
	// The oldest connections read in the other role belong to the wrong
	// table: a standby's are its own few connections, not the ones it now
	// forwards. Read them again at once, so the peer doesn't check against
	// them for up to oldestInterval.
	if m.servedBefore && serving != m.wasServing {
		m.scans.rereadOldest()
	}
	m.wasServing, m.servedBefore = serving, true
}

// scanner reads conntrackd's caches outside the health rounds, one pass at
// a time. A pass has conntrackd write a whole cache, which takes seconds for
// a large table, and a round waiting for it would make its report late. Each
// pass keeps only the few connections it looks for, so natpair's memory
// doesn't grow with the table. Round starts the passes that are due and uses
// what the finished ones found.
type scanner struct {
	conntrack Conntrack
	// done lets tests wait for a pass to finish.
	done sync.WaitGroup

	mu      sync.Mutex
	running bool
	// oldest are this NAT's oldest connections, read by the latest pass,
	// which started at oldestAt, if oldestRead.
	oldest     []conntrackd.Tuple
	oldestAt   time.Duration
	oldestRead bool
	// copiesAt is when the latest pass over this NAT's copies started, if
	// copiesRead.
	copiesAt   time.Duration
	copiesRead bool
	// confirmed holds the peer's oldest connections that a pass found among
	// this NAT's copies, with when that pass started. missing holds those a
	// pass didn't find, with when the first pass that missed them started.
	confirmed map[conntrackd.Tuple]time.Duration
	missing   map[conntrackd.Tuple]time.Duration
	// generation counts calls to forget, so a pass that started before one
	// doesn't record what it found.
	generation int
}

// start begins a pass if one is due and none is running. A pass reads this
// NAT's oldest connections every oldestInterval, and looks for peerOldest
// among its copies while any of them aren't confirmed.
func (s *scanner) start(ctx context.Context, now time.Duration, peerOldest []conntrackd.Tuple) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	readOldest := !s.oldestRead || now-s.oldestAt >= oldestInterval
	var wanted []conntrackd.Tuple
	if !s.copiesRead || now-s.copiesAt >= copiesInterval {
		for _, tuple := range peerOldest {
			at, ok := s.confirmed[tuple]
			if !ok || now-at >= confirmFor {
				wanted = slices.Clone(peerOldest)
				break
			}
		}
	}
	if !readOldest && wanted == nil {
		return
	}
	if readOldest {
		s.oldestAt, s.oldestRead = now, true
	}
	if wanted != nil {
		s.copiesAt, s.copiesRead = now, true
	}
	s.running = true
	generation := s.generation
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		if readOldest {
			// A failed pass publishes no list. What it read may cover only
			// part of the table, and the previous list may hold a connection
			// that closed since. The peer would miss its copy for longer than
			// missingFor and ask for full copies until the next pass.
			oldest, err := s.conntrack.Oldest(ctx, oldestCount)
			if err != nil {
				slog.Warn("failed to read this NAT's oldest connections from conntrackd", slog.Any("err", err))
				oldest = nil
			}
			s.mu.Lock()
			s.oldest = oldest
			s.mu.Unlock()
		}
		var found map[conntrackd.Tuple]bool
		var err error
		if wanted != nil {
			found, err = s.conntrack.Copied(ctx, wanted)
			if err != nil {
				slog.Warn("failed to read the copied connections from conntrackd", slog.Any("err", err))
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		if wanted == nil || err != nil || generation != s.generation {
			return
		}
		if s.confirmed == nil {
			s.confirmed, s.missing = map[conntrackd.Tuple]time.Duration{}, map[conntrackd.Tuple]time.Duration{}
		}
		for _, tuple := range wanted {
			if found[tuple] {
				s.confirmed[tuple] = now
				delete(s.missing, tuple)
				continue
			}
			delete(s.confirmed, tuple)
			if _, ok := s.missing[tuple]; !ok {
				s.missing[tuple] = now
			}
		}
	}()
}

// results returns this NAT's oldest connections, how many of peerOldest the
// finished passes found among its copies within 2 confirmFor, and whether any
// of peerOldest has been missing for missingFor. With a current peer report,
// it forgets connections that are no longer among peerOldest. Without one,
// it keeps them, so a failed read of the board doesn't throw away what
// passes found.
func (s *scanner) results(peerOldest []conntrackd.Tuple, current bool, now time.Duration) ([]conntrackd.Tuple, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current {
		for _, findings := range []map[conntrackd.Tuple]time.Duration{s.confirmed, s.missing} {
			maps.DeleteFunc(findings, func(tuple conntrackd.Tuple, _ time.Duration) bool {
				return !slices.Contains(peerOldest, tuple)
			})
		}
	}
	copied, lost := 0, false
	for _, tuple := range peerOldest {
		// A pass checks again after confirmFor. If passes keep failing, the
		// finding stops counting after twice that.
		if at, ok := s.confirmed[tuple]; ok && now-at < 2*confirmFor {
			copied++
		}
		if since, ok := s.missing[tuple]; ok && now-since >= missingFor {
			lost = true
		}
	}
	return s.oldest, copied, lost
}

// rereadOldest makes the next pass read this NAT's oldest connections.
func (s *scanner) rereadOldest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oldestRead = false
}

// forget drops what passes found about this NAT's copies, including a pass
// still running, so the next pass checks them again. That pass still waits
// for copiesInterval, so a copy that stays short isn't read every round.
func (s *scanner) forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.confirmed, s.missing = nil, nil
	s.generation++
}
