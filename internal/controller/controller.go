// Package controller decides when this NAT is the owner: the NAT that holds
// the shared ENI and forwards worker traffic.
//
// Only the lease decides who the owner is. Health checks decide when a
// standby may take the lease and when an owner steps down. A standby whose
// path is proven takes a free lease right away. As a last resort, when no
// probe receiver is reachable, a standby with an unproven path takes it after
// waiting a little longer, so a NAT with a proven path wins when there is one.
// An owner steps down only for a peer whose path is proven. An owner opens the
// fence only after its takeover succeeds, and keeps it open by renewing the
// lease.
//
// While the lease store is unreachable, a serving owner keeps its fence open
// and keeps retrying. Only the NAT holding the shared ENI gets worker
// traffic, and a standby can move the ENI only after taking the lease. If
// DynamoDB is down for both NATs, neither can take it, so the owner forwarding
// on is safe. If only the owner lost DynamoDB, the standby takes the lease and
// moves the ENI, which cuts the owner off, and the owner closes once it sees
// the lease is gone. A takeover in progress keeps going only while its grant
// lasts, so it stops before the peer could take the lease back.
//
// Any other failure ends this NAT's ownership session: the fence closes, and
// only then is the lease released, so the peer can take over right away
// instead of waiting out this NAT's deadline. If this NAT's own path failed,
// or its takeover failed while the peer can take over, a cooldown also stops
// it from trying to become the owner again right away. A NAT that recovers
// never takes ownership back from a healthy peer.
package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/lease"
)

// The run loop's intervals. They're variables only so tests can shorten them
// (export_test.go).
var (
	renewInterval   = 500 * time.Millisecond
	acquireInterval = 500 * time.Millisecond
	loopInterval    = 50 * time.Millisecond
	// lastResortDelay is how much longer a NAT with an unproven path waits
	// before contending, so a NAT with a proven path takes the lease first.
	lastResortDelay = 2 * health.BaseInterval
	// restartDelay separates ownership sessions.
	restartDelay = time.Second
)

const (
	// cooldown keeps a NAT that just stepped down, or failed a takeover, from
	// contending, so a flapping path cannot bounce ownership back and forth.
	cooldown = 12 * time.Second
	// contendWarnInterval is the shortest time between warnings about failed
	// attempts to take ownership. A NAT that can't reach the lease store fails
	// every attempt, twice a second: on AWS, 67 warnings in 37 s.
	contendWarnInterval = time.Minute

	maintenanceFile = "maintenance"
)

var (
	errMaintenance = errors.New("maintenance requested")
	errHandover    = errors.New("handover requested")
	errDemoted     = errors.New("stepped down after corroborated path failure")
	errTakeover    = errors.New("takeover failed")
)

// Fence opens and closes worker forwarding.
type Fence interface {
	Install(ctx context.Context) error
	Arm(deadline time.Duration) error
	Close() error
}

// Health returns the latest health report.
type Health interface {
	Latest() health.Report
}

// Preparer performs one takeover.
type Preparer interface {
	Prepare(ctx context.Context) error
}

// Config sets ownership behavior.
type Config struct {
	Node     string
	StateDir string
	// PrepareTimeout bounds a takeover.
	PrepareTimeout time.Duration
}

// Dependencies connect the controller to the system.
type Dependencies struct {
	Fence  Fence
	Health Health
	Store  lease.Store
	// NewHandoff returns the takeover for a newly granted owner. guard fails
	// once that owner's grant expires or the session ends. verify is false for
	// a last-resort takeover, which skips the final uploads through the shared
	// Elastic IP because no probe receiver is reachable.
	NewHandoff func(guard func() error, verify bool) Preparer
	// StepDown runs after this NAT stops being the owner and its fence is
	// closed. It clears the connection state the NAT no longer serves.
	StepDown func(ctx context.Context) error
	// Now returns elapsed time on the boot clock.
	Now func() time.Duration
}

// Controller runs ownership sessions.
type Controller struct {
	cfg     Config
	deps    Dependencies
	serving atomic.Bool
	// owner is set from the moment this NAT acquires the lease until it
	// releases it, including the takeover before forwarding opens.
	owner atomic.Bool
	// cooldownUntil is a boot-clock time in nanoseconds.
	cooldownUntil atomic.Int64
	// handover asks the owner to hand ownership to a ready peer. Each acquired
	// lease clears it. See [Controller.SetHandover].
	handover atomic.Bool
}

// New returns a controller.
func New(cfg Config, deps Dependencies) *Controller {
	return &Controller{cfg: cfg, deps: deps}
}

// Serving reports whether this NAT forwards worker traffic.
func (c *Controller) Serving() bool {
	return c.serving.Load()
}

// Owner reports whether this NAT holds the lease, from acquiring it, through
// the takeover, until it releases it. Unlike [Controller.Serving], it is
// already true while the takeover runs.
func (c *Controller) Owner() bool {
	return c.owner.Load()
}

// Inhibited reports maintenance, or the cooldown after stepping down or a
// failed takeover. An inhibited NAT does not offer or accept ownership.
func (c *Controller) Inhibited() bool {
	return c.maintenanceRequested() || c.coolingDown()
}

// ShouldDemote reports whether an owner should step down: its path failed two
// rounds in a row, and the peer proved its own path while this owner was
// failing and can take over. A failure both NATs share, such as a probe
// receiver outage, never demotes, because the peer cannot prove its path
// either. A stale report never demotes, because the monitor itself may be the
// problem.
func ShouldDemote(report health.Report) bool {
	return !report.Stale && report.ConsecutiveFailures >= 2 && report.PeerCanTakeover && report.PeerConfirmedFailure
}

// Run closes forwarding, then runs ownership sessions until ctx is cancelled.
// It returns an error only if forwarding cannot be closed.
func (c *Controller) Run(ctx context.Context) error {
	if err := c.deps.Fence.Install(ctx); err != nil {
		return err
	}
	for {
		l, err := c.session(ctx)
		closeErr := c.deps.Fence.Close()
		// Cool down only when this NAT's own path failed, or its takeover
		// failed while the peer can take over instead. When a session ends for
		// another reason, such as one lost renewal, a cooldown would only
		// delay recovery. So would one after a failed takeover with no peer to
		// take over: a standby's takeover can run out of time just as the EC2
		// API comes back, and the 12 s cooldown would then delay its next attempt.
		// The cooldown starts before the release and before this NAT reports
		// that it stopped serving, so the peer never sees it as both idle and
		// ready to take over.
		if errors.Is(err, errDemoted) || (errors.Is(err, errTakeover) && c.deps.Health.Latest().PeerCanTakeover) {
			c.startCooldown()
		}
		// Release only once forwarding is closed, because the peer may start
		// forwarding as soon as the release lands. It also runs on shutdown,
		// so stopping the service hands over quickly.
		if closeErr == nil && l != nil {
			owned := l.Current() != nil
			if err := l.Release(context.WithoutCancel(ctx)); err != nil {
				slog.Warn("failed to release ownership, so the peer waits the full takeover interval", slog.Any("err", err))
			}
			if owned {
				if err := c.deps.StepDown(context.WithoutCancel(ctx)); err != nil {
					slog.Warn("failed to clear the connection state this NAT no longer serves", slog.Any("err", err))
				}
			}
		}
		c.serving.Store(false)
		c.owner.Store(false)
		if closeErr != nil {
			// The process exits so systemd reinstalls the fence on restart.
			return fmt.Errorf("failed to close forwarding: %w", closeErr)
		}
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("ownership session ended", slog.Any("reason", err))
		if !sleep(ctx, restartDelay) {
			return nil
		}
	}
}

// session runs one ownership session and returns its lease for release.
func (c *Controller) session(ctx context.Context) (*lease.Lease, error) {
	owner := c.cfg.Node + "/" + rand.Text()
	l := lease.New(c.deps.Store, owner, c.deps.Now)
	return l, c.contendAndServe(ctx, l)
}

// contendAndServe waits for the lease, takes over, and forwards until something
// ends the session.
func (c *Controller) contendAndServe(ctx context.Context, l *lease.Lease) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	var takeover chan error
	defer func() {
		// Fail the running takeover's lease checks before cancelling it, so it
		// cannot start another AWS change on the way out.
		l.Abandon()
		cancel()
		if takeover != nil {
			<-takeover
		}
	}()

	var stageStarted, nextRenewal, nextAcquire, lastResortSince time.Duration
	// lastResortWaiting means this NAT can only contend as a last resort and
	// has been waiting out lastResortDelay since lastResortSince.
	var lastResortWaiting, verified bool
	// contendFailures counts failed attempts to take ownership since the last
	// warning about them.
	var contendFailing bool
	var contendFailures int
	var contendWarnedAt time.Duration
	// prepared means the takeover finished, and forwarding opens at the next
	// successful renewal.
	var prepared bool
	// storeDown means a serving owner's renewals cannot reach the lease
	// store, so it keeps the fence open without a current grant.
	var storeDown bool
	for {
		report := c.deps.Health.Latest()
		now := c.deps.Now()
		if l.Current() == nil {
			verified = report.Ready || report.CanForward
			eligible := verified
			if !verified && report.CanForwardUnverified {
				if !lastResortWaiting {
					lastResortWaiting, lastResortSince = true, now
				}
				eligible = now-lastResortSince >= lastResortDelay
			} else {
				lastResortWaiting = false
			}
			if eligible && !c.Inhibited() && now >= nextAcquire {
				nextAcquire = now + acquireInterval
				acquired, err := l.Acquire(sessionCtx)
				if errors.Is(err, lease.ErrLost) {
					return err
				}
				// A contender holds nothing, so it retries on the next tick.
				if err == nil {
					contendFailing, contendFailures = false, 0
				} else {
					contendFailures++
					if !contendFailing || now-contendWarnedAt >= contendWarnInterval {
						slog.Warn("failed to contend for ownership", slog.Any("err", err), slog.Int("attempts", contendFailures))
						contendFailing, contendWarnedAt, contendFailures = true, now, 0
					}
				}
				if acquired != nil {
					c.owner.Store(true)
					// A request made before this session belongs to an earlier
					// one, so it must not hand this one over.
					c.handover.Store(false)
					slog.Info("ownership acquired", slog.Int64("epoch", acquired.Record.Epoch), slog.Bool("copied_state_ready", report.Ready), slog.Bool("path_proven", verified))
					stageStarted, nextRenewal = c.deps.Now(), c.deps.Now()+renewInterval
					preparer := c.deps.NewHandoff(func() error {
						_, err := l.Valid()
						return err
					}, verified)
					takeover = make(chan error, 1)
					go func() { takeover <- preparer.Prepare(sessionCtx) }()
				}
			}
		} else {
			// Maintenance and a handover request hand over only to a peer that
			// passes its forwarding and copied-connection checks.
			if !report.Stale && report.PeerReady {
				if c.maintenanceRequested() {
					return errMaintenance
				}
				if c.handover.Load() {
					return errHandover
				}
			}
			if !storeDown {
				if _, err := l.Valid(); err != nil {
					return err
				}
			}
			if ShouldDemote(report) {
				return errDemoted
			}
			if now >= nextRenewal {
				renewed, err := l.Renew(sessionCtx)
				switch {
				case err == nil:
					if storeDown {
						slog.Info("lease store reachable again")
						storeDown = false
					}
					if c.serving.Load() {
						if err := c.deps.Fence.Arm(renewed.Deadline); err != nil {
							return err
						}
					}
				case errors.Is(err, lease.ErrUnavailable) && c.serving.Load():
					if !storeDown {
						slog.Warn("lease store unreachable, forwarding on while the shared ENI stays here", slog.Any("err", err))
						storeDown = true
					}
					if err := c.deps.Fence.Arm(now + lease.Hold); err != nil {
						return err
					}
				case errors.Is(err, lease.ErrUnavailable):
					// A takeover keeps going while its grant lasts: the check
					// above ends it once the grant expires, and the takeover checks
					// the grant before each AWS change. On AWS, single renewals
					// timed out while conntrackd installed 27,000 to 124,000
					// copies, and ending the takeover then cost about 8 s each.
					slog.Warn("lease renewal failed during takeover, continuing while the grant lasts", slog.Any("err", err))
				default:
					return err
				}
				nextRenewal = c.deps.Now() + renewInterval
			}
			if !c.serving.Load() {
				if now-stageStarted > c.cfg.PrepareTimeout {
					return fmt.Errorf("%w: exceeded %s", errTakeover, c.cfg.PrepareTimeout)
				}
				select {
				case err := <-takeover:
					takeover = nil
					if err != nil {
						return fmt.Errorf("%w: %w", errTakeover, err)
					}
					// A last-resort takeover cannot prove its path, so only a
					// stuck monitor stops it.
					if report.Stale || (verified && !report.PathHealthy) {
						return fmt.Errorf("%w: forwarding path failed during takeover", errTakeover)
					}
					prepared = true
				default:
				}
				if prepared {
					// Forwarding opens with a fresh grant. If the store is
					// unreachable, try again on the next tick while the grant lasts.
					renewed, err := l.Renew(sessionCtx)
					switch {
					case errors.Is(err, lease.ErrUnavailable):
					case err != nil:
						return err
					default:
						if err := c.deps.Fence.Arm(renewed.Deadline); err != nil {
							return err
						}
						c.serving.Store(true)
						slog.Info("forwarding open", slog.Duration("takeover", c.deps.Now()-stageStarted))
					}
				}
			}
		}
		if !sleep(ctx, loopInterval) {
			return ctx.Err()
		}
	}
}

func (c *Controller) startCooldown() {
	c.cooldownUntil.Store(int64(c.deps.Now() + cooldown))
}

func (c *Controller) coolingDown() bool {
	return int64(c.deps.Now()) < c.cooldownUntil.Load()
}

func (c *Controller) maintenanceRequested() bool {
	_, err := os.Stat(filepath.Join(c.cfg.StateDir, maintenanceFile))
	return err == nil
}

// MaintenanceRequested reports whether this NAT has a maintenance request in
// place.
func (c *Controller) MaintenanceRequested() bool {
	return c.maintenanceRequested()
}

// SetHandover sets whether this NAT, while it owns the lease, hands ownership
// to its peer once the peer passes its forwarding and copied-connection
// checks. The caller withdraws a request it no longer wants. Unlike
// maintenance, the request lives in memory and the next acquired lease clears
// it, so it never outlives a restart and never hands over a later session.
func (c *Controller) SetHandover(want bool) {
	c.handover.Store(want)
}

// RequestMaintenance takes the NAT in stateDir out of rotation. An owner hands
// ownership to its peer once the peer passes its forwarding and
// copied-connection checks, and a standby stops offering to take over. The
// request persists until [Resume].
func RequestMaintenance(stateDir string) error {
	if err := os.WriteFile(filepath.Join(stateDir, maintenanceFile), nil, 0o600); err != nil {
		return fmt.Errorf("failed to request maintenance: %w", err)
	}
	return nil
}

// Resume clears a maintenance request. The NAT becomes an eligible standby
// once its checks pass. It never takes ownership back from a healthy peer.
func Resume(stateDir string) error {
	if err := os.Remove(filepath.Join(stateDir, maintenanceFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to clear maintenance: %w", err)
	}
	return nil
}

// sleep waits for d and reports false if ctx was cancelled first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
