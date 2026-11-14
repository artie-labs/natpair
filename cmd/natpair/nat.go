package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"golang.org/x/sync/errgroup"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/config"
	"github.com/artie-labs/natpair/internal/conntrackd"
	"github.com/artie-labs/natpair/internal/controller"
	"github.com/artie-labs/natpair/internal/dynamo"
	"github.com/artie-labs/natpair/internal/fence"
	"github.com/artie-labs/natpair/internal/health"
	"github.com/artie-labs/natpair/internal/instance"
	"github.com/artie-labs/natpair/internal/irq"
	"github.com/artie-labs/natpair/internal/network"
	"github.com/artie-labs/natpair/internal/probe"
	"github.com/artie-labs/natpair/internal/update"
)

// prepareTimeout bounds a takeover. It leaves ample margin for the EC2 calls,
// which handoff bounds with callTimeout.
const prepareTimeout = 30 * time.Second

func loadNAT(name string, args []string) (config.NAT, error) {
	path, err := configFlag(name, args)
	if err != nil {
		return config.NAT{}, err
	}
	return config.LoadNAT(path)
}

// discover fills in this instance's facts from the instance metadata service
// and returns the AWS configuration for the NAT's own calls.
func discover(ctx context.Context, cfg *config.NAT) (aws.Config, error) {
	metadataConfig, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS configuration: %w", err)
	}
	if cfg.Instance, err = instance.Discover(ctx, metadataConfig); err != nil {
		return aws.Config{}, err
	}
	// Retries are off: a retried conditional write or EC2 change could apply
	// after a newer owner's change.
	awsConfig, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Instance.Region), awsconfig.WithRetryMaxAttempts(1))
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS configuration: %w", err)
	}
	return awsConfig, nil
}

func newFence(cfg config.NAT) (*fence.Fence, error) {
	return fence.New(config.BPFDir, cfg.ProtectedCIDRs)
}

func validate(_ context.Context, args []string) error {
	if _, err := loadNAT("validate", args); err != nil {
		return err
	}
	fmt.Println("Configuration is valid.")
	return nil
}

func bootstrap(ctx context.Context, args []string) error {
	cfg, err := loadNAT("bootstrap", args)
	if err != nil {
		return err
	}
	if _, err := discover(ctx, &cfg); err != nil {
		return err
	}
	// conntrackd starts after bootstrap and reads this file.
	if err := conntrackd.WriteConfig(config.ConntrackdConfigPath, cfg.Instance.PrivateIP, cfg.PeerIP, cfg.SharedAddress.Addr(), cfg.Instance.Interface, config.StateDir, cfg.ConnectionLimit()); err != nil {
		return err
	}
	f, err := newFence(cfg)
	if err != nil {
		return err
	}
	if err := network.New(cfg, f, network.SystemRunner{}).Bootstrap(ctx); err != nil {
		return err
	}
	spreadInterrupts("", irq.Spread)
	return writeBootedRelease(config.BootedReleasePath, release)
}

// writeBootedRelease records the release whose bootstrap prepared this boot.
func writeBootedRelease(path, release string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create the booted release's directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(release), 0o644); err != nil {
		return fmt.Errorf("failed to record the booted release: %w", err)
	}
	return nil
}

// reportedRelease returns the release this NAT reports: its own, if its
// bootstrap prepared this boot, and "" otherwise. They differ when systemd
// restarts the daemon into a binary the updater installed without rebooting,
// after this NAT took over during the install. That binary runs without its
// own bootstrap, and the boot's release no longer runs either, so the NAT
// reports none. The updater then reinstalls and reboots it whatever is
// pinned, and the peer doesn't hand over to it.
func reportedRelease(path string) string {
	contents, err := os.ReadFile(path)
	if err != nil {
		slog.Warn("failed to read the booted release, so this NAT reports none", slog.Any("err", err))
		return ""
	}
	if booted := string(contents); booted != release {
		slog.Warn("this boot was prepared by another release, so this NAT reports none until it reboots",
			slog.String("booted", booted), slog.String("running", release))
		return ""
	}
	return release
}

// fenceClose reinstalls the fence, which closes forwarding. systemd runs it
// after the daemon stops for any reason. While the daemon runs, its next
// renewal reopens forwarding, so stop the service first to keep it closed.
//
// It also schedules the flush that StepDown schedules. A daemon killed while
// it owned the pair never steps down, so the kernel table keeps its old
// connections. If ownership moves back later, they can clash with the copies
// the commit installs, and those connections are reset.
func fenceClose(ctx context.Context, args []string) error {
	cfg, err := loadNAT("fence-close", args)
	if err != nil {
		return err
	}
	f, err := newFence(cfg)
	if err != nil {
		return err
	}
	if err := f.Install(ctx); err != nil {
		return err
	}
	if err := (conntrackd.Client{ConfigPath: config.ConntrackdConfigPath}).ScheduleFlush(ctx); err != nil {
		slog.Warn("failed to schedule a flush of this NAT's old connections", slog.Any("err", err))
	}
	return nil
}

func maintenance(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("maintenance takes no arguments")
	}
	if err := controller.RequestMaintenance(config.StateDir); err != nil {
		return err
	}
	fmt.Println("Maintenance requested. An active NAT hands over once its peer passes its checks. Check that the peer serves and traffic works through it before replacing this NAT.")
	return nil
}

func resume(_ context.Context, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("resume takes no arguments")
	}
	if err := controller.Resume(config.StateDir); err != nil {
		return err
	}
	fmt.Println("Maintenance cleared. This NAT becomes an eligible standby once its checks pass.")
	return nil
}

func runNAT(ctx context.Context, args []string) error {
	configPath, err := configFlag("run", args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadNAT(configPath)
	if err != nil {
		return err
	}
	awsConfig, err := discover(ctx, &cfg)
	if err != nil {
		return err
	}
	db := dynamodb.NewFromConfig(awsConfig)
	ownership := dynamo.NewRecord(db, cfg.LeaseTable, cfg.LeaseRecordID("ownership"))
	reports := health.NewNATExchange(dynamo.NewBoard(db, cfg.LeaseTable, cfg.LeaseRecordID(config.BoardRecord)), cfg.Instance.ID, bootclock.Now)

	f, err := newFence(cfg)
	if err != nil {
		return err
	}
	net := network.New(cfg, f, network.SystemRunner{})
	conntrack := conntrackd.Client{ConfigPath: config.ConntrackdConfigPath}
	// The instance role signs uploads to a receiver that requires IAM
	// authentication.
	prober := &probe.Client{Credentials: awsConfig.Credentials}
	steps := localSteps{network: net, conntrack: conntrack, prober: prober, target: cfg.SharedProbe()}

	var ctrl *controller.Controller
	monitor := health.New(health.Config{
		Probe:        cfg.OwnProbe(),
		ServingProbe: cfg.SharedProbe(),
		Release:      reportedRelease(config.BootedReleasePath),
	}, health.Dependencies{
		Prober:    prober,
		Conntrack: conntrack,
		Reports:   reports,
		Serving:   func() bool { return ctrl.Serving() },
		Inhibited: func() bool { return ctrl.Inhibited() },
		Now:       bootclock.Now,
	})
	ctrl = controller.New(controller.Config{
		Node:           cfg.Instance.ID,
		StateDir:       config.StateDir,
		PrepareTimeout: prepareTimeout,
	}, controller.Dependencies{
		Fence:      f,
		Health:     monitor,
		Store:      ownership,
		NewHandoff: newHandoff(cfg, ec2.NewFromConfig(awsConfig), steps),
		StepDown:   conntrack.StepDown,
		Now:        bootclock.Now,
	})

	updater := update.New(update.Config{ConfigPath: configPath, WorkDir: "/var/tmp", Releases: cfg.Releases()}, update.Dependencies{
		Pinned:      dynamo.NewRecord(db, cfg.LeaseTable, cfg.LeaseRecordID(config.ReleaseRecord)),
		Runner:      network.SystemRunner{},
		Health:      monitor.Latest,
		Owner:       ctrl.Owner,
		Maintenance: ctrl.MaintenanceRequested,
		HandOver:    ctrl.SetHandover,
		Now:         bootclock.Now,
	})

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		monitor.Run(ctx)
		return nil
	})
	group.Go(func() error {
		return ctrl.Run(ctx)
	})
	group.Go(func() error {
		keepForwardingEnabled(ctx, net)
		return nil
	})
	group.Go(func() error {
		keepInterruptsSpread(ctx)
		return nil
	})
	group.Go(func() error {
		updater.Run(ctx)
		return nil
	})
	return group.Wait()
}

// keepForwardingEnabled restores IPv4 forwarding within 0.5 s if it was turned
// off, for example by `sysctl --system`. While it's off, the owner's health
// rounds fail, and two failed rounds in a row make it step down.
func keepForwardingEnabled(ctx context.Context, n *network.Network) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		restored, err := n.EnsureForwarding(ctx)
		switch {
		case err != nil:
			slog.Warn("failed to check IPv4 forwarding", slog.Any("err", err))
		case restored:
			slog.Warn("IPv4 forwarding was off and has been turned back on")
		}
	}
}

// keepInterruptsSpread spreads the ENA queue interrupts every 5 s. That
// catches the shared ENI's interrupts within 5 s of a takeover, without
// touching the takeover itself, and undoes anything else that moved them.
func keepInterruptsSpread(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		lastErr = spreadInterrupts(lastErr, irq.Spread)
	}
}

// spreadInterrupts runs spread, normally [irq.Spread], which puts queue n of
// each ENI on CPU n. A failure only costs forwarding capacity, so it is
// logged, and only when it differs from lastErr, the previous pass's failure,
// so a lasting one isn't logged every 5 s. It returns this pass's failure, or
// "" if there was none.
func spreadInterrupts(lastErr string, spread func() (int, error)) string {
	moved, err := spread()
	if moved > 0 {
		slog.Info("spread network queue interrupts across the CPUs", slog.Int("moved", moved))
	}
	if err == nil {
		return ""
	}
	if err.Error() != lastErr {
		slog.Warn("failed to spread the network queues' interrupts across the CPUs", slog.Any("err", err))
	}
	return err.Error()
}

// localSteps performs the takeover steps on this host.
type localSteps struct {
	network   *network.Network
	conntrack conntrackd.Client
	prober    *probe.Client
	target    probe.Target
}

func (s localSteps) PrepareNetwork(ctx context.Context) error {
	return s.network.PrepareNetwork(ctx)
}

func (s localSteps) DropStale(ctx context.Context) error {
	return s.network.DropStale(ctx)
}

func (s localSteps) CommitState(ctx context.Context) error {
	return s.conntrack.TakeOver(ctx)
}

func (s localSteps) ClaimShared(ctx context.Context, mac string) error {
	return s.network.ClaimShared(ctx, mac)
}

func (s localSteps) ActivateShared(ctx context.Context, mac string) error {
	return s.network.ActivateShared(ctx, mac)
}

func (s localSteps) VerifyIdentity(ctx context.Context) error {
	if _, err := s.prober.Upload(ctx, s.target); err != nil {
		return fmt.Errorf("upload through the shared Elastic IP failed: %w", err)
	}
	return nil
}
