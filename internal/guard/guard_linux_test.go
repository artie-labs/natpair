//go:build linux && privileged

package guard

import (
	"bytes"
	"context"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
)

func ip(t *testing.T, args ...string) string {
	output, err := command.Run(t.Context(), 5*time.Second, "ip", args...)
	require.NoError(t, err)
	return output
}

func attached(t *testing.T) bool {
	return regexp.MustCompile(`prog/xdp id \d+`).MatchString(ip(t, "-d", "link", "show", "gs0"))
}

// pings sends count pings from the peer namespace to the shared address and
// returns how many were answered.
func pings(t *testing.T, count int) int {
	// ping exits with an error when replies are missing, so its output is
	// read whatever the exit status.
	output, _ := exec.CommandContext(t.Context(), "ip", "netns", "exec", "guard-peer", "ping", "-c", strconv.Itoa(count), "-i", "0.01", "-W", "1", "10.99.0.1").CombinedOutput()
	match := regexp.MustCompile(`(\d+) received`).FindSubmatch(output)
	require.NotNil(t, match, output)
	received, err := strconv.Atoi(string(match[1]))
	require.NoError(t, err)
	return received
}

// TestGuard attaches the guard to a veth that holds the shared address, as
// the shared ENI does on an owner, and sends it pings from a namespace.
func TestGuard(t *testing.T) {
	ip(t, "netns", "add", "guard-peer")
	ip(t, "link", "add", "gs0", "type", "veth", "peer", "name", "gp0")
	t.Cleanup(func() {
		// t.Context is cancelled before cleanup runs.
		ctx := context.WithoutCancel(t.Context())
		_, err := command.Run(ctx, 5*time.Second, "ip", "link", "del", "gs0")
		assert.NoError(t, err)
		_, err = command.Run(ctx, 5*time.Second, "ip", "netns", "del", "guard-peer")
		assert.NoError(t, err)
	})
	ip(t, "link", "set", "gp0", "netns", "guard-peer")
	ip(t, "-n", "guard-peer", "addr", "add", "10.99.0.2/24", "dev", "gp0")
	ip(t, "-n", "guard-peer", "link", "set", "gp0", "up")
	ip(t, "link", "set", "gs0", "up")

	off := filepath.Join(t.TempDir(), "overload-guard-off")
	g := New(Config{SharedAddress: netip.MustParseAddr("10.99.0.1"), PrimaryInterface: "guard-primary", ReceiverPort: 443, FirstProbePort: 61000, LastProbePort: 65535, OffPath: off})
	// An 18-minute budget window, so the pings below all fall in one
	g.match.tickShift, g.match.exemptShift = 40, 44
	t.Cleanup(func() { g.close(context.WithoutCancel(t.Context())) })

	// No interface holds the shared address yet, as on a standby
	require.NoError(t, g.ensure(t.Context()))
	assert.Empty(t, g.name)

	ip(t, "addr", "add", "10.99.0.1/24", "dev", "gs0")
	require.NoError(t, g.ensure(t.Context()))
	assert.Equal(t, "gs0", g.name)
	// Watching attaches nothing: ENA's receive path costs more with any
	// program attached
	assert.False(t, attached(t))

	// Engaging attaches it with a budget, here 1 per CPU in an 18-minute
	// window, so at most one ping per CPU passes. ARP isn't IPv4, so the
	// neighbor lookups still work.
	_, err := g.attach(t.Context(), 1)
	require.NoError(t, err)
	assert.True(t, attached(t))
	ip(t, "-n", "guard-peer", "neigh", "flush", "all")
	assert.LessOrEqual(t, pings(t, 20), runtime.NumCPU())
	require.NoError(t, g.prog.setBudget(math.MaxUint64))
	assert.Equal(t, 5, pings(t, 5), "measuring passes everything")
	t.Run("receive threads", func(t *testing.T) {
		// While limiting, the shared interface's threaded NAPI receive
		// threads run at nice -10, and go back to 0 after
		require.NoError(t, os.WriteFile("/sys/class/net/gs0/threaded", []byte("1"), 0o644))
		pids, err := receiveThreads("/proc", "gs0")
		require.NoError(t, err)
		if len(pids) == 0 {
			// Kernel threads belong to the host's PID namespace, so a
			// container such as make test-privileged's doesn't see them.
			// The NAT's daemon runs on the host.
			t.Skip("no receive threads visible in this PID namespace")
		}
		threads, err := prioritize("gs0", receiveNice)
		require.NoError(t, err)
		assert.Equal(t, len(pids), threads)
		for _, pid := range pids {
			nice, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
			require.NoError(t, err)
			// The raw value is 20 - nice
			assert.Equal(t, 30, nice)
		}
		_, err = prioritize("gs0", 0)
		require.NoError(t, err)
		for _, pid := range pids {
			nice, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
			require.NoError(t, err)
			assert.Equal(t, 20, nice)
		}
	})
	require.NoError(t, g.detach(t.Context()))
	assert.False(t, attached(t))
	assert.Equal(t, 5, pings(t, 5))
	{
		// The off switch stops the watching and detaches the program, and
		// removing it starts watching again
		_, err := g.attach(t.Context(), 1)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(off, nil, 0o600))
		require.NoError(t, g.ensure(t.Context()))
		assert.False(t, attached(t))
		assert.Empty(t, g.name)
		require.NoError(t, os.Remove(off))
		require.NoError(t, g.ensure(t.Context()))
		assert.Equal(t, "gs0", g.name)
	}
	{
		// It never watches the primary interface, even if that holds the
		// shared address
		g.cfg.PrimaryInterface = "gs0"
		assert.EqualError(t, g.ensure(t.Context()), "the primary interface gs0 holds the shared address 10.99.0.1, so the overload guard stays off it")
		assert.Empty(t, g.name)
		g.cfg.PrimaryInterface = "guard-primary"
		require.NoError(t, g.ensure(t.Context()))
	}
	{
		// The shared ENI goes away while the program is on it, as on a
		// handover: the next reading stops watching
		_, err := g.attach(t.Context(), 1)
		require.NoError(t, err)
		ip(t, "link", "del", "gs0")
		require.NoError(t, g.step(t.Context()))
		assert.Nil(t, g.attached)
		assert.Empty(t, g.name)
		// A new one comes back with the shared address
		ip(t, "link", "add", "gs0", "type", "veth", "peer", "name", "gp0")
		ip(t, "link", "set", "gp0", "netns", "guard-peer")
		ip(t, "addr", "add", "10.99.0.1/24", "dev", "gs0")
		ip(t, "link", "set", "gs0", "up")
		require.NoError(t, g.ensure(t.Context()))
		assert.Equal(t, "gs0", g.name)
	}
	{
		// A handover takes the shared address away
		_, err := g.attach(t.Context(), 1)
		require.NoError(t, err)
		ip(t, "addr", "del", "10.99.0.1/24", "dev", "gs0")
		require.NoError(t, g.ensure(t.Context()))
		assert.False(t, attached(t))
		assert.Empty(t, g.name)
	}
}

// simulated is a netdevsim interface that holds the shared address, with
// threaded NAPI on. netdevsim has a receive ring the guard can raise and
// takes native XDP, like ENA. It returns the interface's name. netdevsim
// creates the interface in the test's network namespace. On a host whose
// network manager takes over new interfaces, such as systemd-networkd
// removing addresses it didn't set, run the tests in a fresh one:
// ip netns add test && ip netns exec test ./guard.test.
func simulated(t *testing.T, id string) string {
	if _, err := os.Stat("/sys/bus/netdevsim/new_device"); err != nil {
		t.Skip("netdevsim isn't loaded. Run modprobe netdevsim to run this test")
	}
	require.NoError(t, os.WriteFile("/sys/bus/netdevsim/new_device", []byte(id+" 1"), 0o200))
	t.Cleanup(func() {
		assert.NoError(t, os.WriteFile("/sys/bus/netdevsim/del_device", []byte(id), 0o200))
	})
	if _, err := exec.LookPath("udevadm"); err == nil {
		// udev may rename the new interface. Wait until it has.
		_, err := command.Run(t.Context(), 10*time.Second, "udevadm", "settle")
		require.NoError(t, err)
	}
	entries, err := os.ReadDir("/sys/bus/netdevsim/devices/netdevsim" + id + "/net")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	name := entries[0].Name()
	ip(t, "addr", "add", "10.98.0.1/24", "dev", name)
	ip(t, "link", "set", name, "up")
	require.NoError(t, os.WriteFile("/sys/class/net/"+name+"/threaded", []byte("1"), 0o644))
	return name
}

// simulatedConfig returns the guard's configuration for the interface that
// simulated creates, with its files in a new directory.
func simulatedConfig(t *testing.T) Config {
	dir := t.TempDir()
	return Config{SharedAddress: netip.MustParseAddr("10.98.0.1"), PrimaryInterface: "guard-primary", ReceiverPort: 443, FirstProbePort: 61000, LastProbePort: 65535, OffPath: filepath.Join(dir, "off"), RingPath: filepath.Join(dir, "ring")}
}

// ringSize returns the current receive ring size of iface.
func ringSize(t *testing.T, iface string) int {
	output, err := command.Run(t.Context(), 5*time.Second, "ethtool", "-g", iface)
	require.NoError(t, err)
	_, current, err := parseRings(output)
	require.NoError(t, err)
	return current
}

// ringChanges puts an ethtool first on PATH that records each change it is
// asked to make, then runs the real one, and returns a function that reads
// the changes so far.
func ringChanges(t *testing.T) func() []string {
	real, err := exec.LookPath("ethtool")
	require.NoError(t, err)
	dir := t.TempDir()
	log := filepath.Join(dir, "changes")
	script := "#!/bin/sh\n[ \"$1\" = -G ] && echo \"$*\" >> " + log + "\nexec " + real + " \"$@\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ethtool"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		contents, err := os.ReadFile(log)
		if os.IsNotExist(err) {
			return nil
		}
		require.NoError(t, err)
		return strings.Split(strings.TrimSpace(string(contents)), "\n")
	}
}

// assertNices checks that iface's one receive thread runs at nice. Kernel
// threads belong to the host's PID namespace, so where this one doesn't show
// them, as in a container, it only logs, and the rest of the test still
// runs.
func assertNices(t *testing.T, iface string, nice int) {
	pids, err := receiveThreads("/proc", iface)
	require.NoError(t, err)
	if len(pids) == 0 {
		t.Log("no receive threads visible in this PID namespace, so their nice values go unchecked")
		return
	}
	var nices []int
	for _, pid := range pids {
		raw, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
		require.NoError(t, err)
		// The raw value is 20 - nice
		nices = append(nices, 20-raw)
	}
	assert.Equal(t, []int{nice}, nices)
}

// TestGuardSheds drives the guard through a flood with the controller tests'
// simulated readings, on a driver with a receive ring and receive threads
// whose names are longer than 15 characters.
func TestGuardSheds(t *testing.T) {
	name := simulated(t, "7317")
	g := New(simulatedConfig(t))
	t.Cleanup(func() { g.close(context.WithoutCancel(t.Context())) })
	require.NoError(t, g.ensure(t.Context()))
	require.Equal(t, name, g.name)
	// netdevsim's ring starts at 512 of at most 4,096
	require.Equal(t, 512, ringSize(t, name))

	var n nat
	feed := func(l load, count int) {
		for range count {
			require.NoError(t, g.apply(t.Context(), n.next(l)))
		}
	}
	feed(flood, 10)
	assert.Nil(t, g.attached)
	// The flood engages it: the program goes on and the ring to its largest
	feed(flood, 1)
	require.NotNil(t, g.attached)
	assert.Equal(t, 4096, ringSize(t, name))
	// It measures, then limits with a budget of 471 a tick, and the receive
	// threads run at nice -10
	feed(flood, 1)
	feed(load{busyTicks: 10, received: 60_000, dropped: 40_000, passed: [2]uint64{50_000, 10_000}}, 1)
	require.Equal(t, Limiting, g.ctrl.Mode())
	var budgets []uint64
	require.NoError(t, g.prog.budgets.Lookup(uint32(0), &budgets))
	assert.Equal(t, uint64(471), budgets[0])
	assertNices(t, name, -10)

	// Once it sheds under 5% for a second and the NIC hasn't dropped for
	// 1.5 s, it clears: the program comes off and the ring and the threads
	// go back
	feed(load{busyTicks: 5, received: 40_000, passed: [2]uint64{39_990, 0}, shed: [2]uint64{10, 0}}, 15)
	assert.Equal(t, Unlimited, g.ctrl.Mode())
	assert.Nil(t, g.attached)
	assert.False(t, regexp.MustCompile(`prog/xdp id \d+`).MatchString(ip(t, "-d", "link", "show", name)))
	assert.Equal(t, 512, ringSize(t, name))
	assertNices(t, name, 0)
	// Flooded again at once, it engages after a second of readings since it
	// cleared, as the controller decided
	feed(flood, 9)
	assert.Nil(t, g.attached)
	feed(flood, 1)
	assert.NotNil(t, g.attached)
}

// TestGuardRefusedLeavesTheRing has the driver refuse the program, as ENA
// does above its largest XDP MTU, at every overload. Each ring change
// restarts an ENA interface, so a refused attach must not change the ring.
func TestGuardRefusedLeavesTheRing(t *testing.T) {
	changes := ringChanges(t)
	name := simulated(t, "7318")
	// netdevsim refuses XDP above an MTU of 4,000
	ip(t, "link", "set", name, "mtu", "9000")
	g := New(simulatedConfig(t))
	t.Cleanup(func() { g.close(context.WithoutCancel(t.Context())) })
	require.NoError(t, g.ensure(t.Context()))
	var logs bytes.Buffer
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	var n nat
	for range 2 {
		for range 10 {
			require.NoError(t, g.apply(t.Context(), n.next(flood)))
		}
		require.NoError(t, g.apply(t.Context(), n.next(flood)))
		assert.Nil(t, g.attached)
		assert.Equal(t, Unlimited, g.ctrl.Mode())
	}
	assert.Empty(t, changes())
	assert.Equal(t, 512, ringSize(t, name))
	// The refusal lasts, so it is logged once
	failures := regexp.MustCompile(`msg="overload guard failed" err="failed to attach the overload guard to `+name+`: .*invalid argument"`).FindAllString(logs.String(), -1)
	assert.Len(t, failures, 1, logs.String())
}

// crashWhileLimiting has a guard engage on the netdevsim interface name and
// then die without cleaning up, as a killed daemon does. The kernel takes the
// program off with the dead daemon's link, but the receive ring stays at its
// largest and the receive threads at nice -10.
func crashWhileLimiting(t *testing.T, cfg Config, name string) {
	g := New(cfg)
	require.NoError(t, g.ensure(t.Context()))
	require.Equal(t, name, g.name)
	var n nat
	for range 12 {
		require.NoError(t, g.apply(t.Context(), n.next(flood)))
	}
	require.NoError(t, g.apply(t.Context(), n.next(load{busyTicks: 10, received: 60_000, dropped: 40_000, passed: [2]uint64{50_000, 10_000}})))
	require.Equal(t, Limiting, g.ctrl.Mode())
	require.NoError(t, g.attached.Close())
	require.NoError(t, g.prog.Close())
	require.Equal(t, 4096, ringSize(t, name))
}

// startGuard starts a guard and stops it at its first wait, after it starts
// watching.
func startGuard(t *testing.T, cfg Config) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	New(cfg).Run(ctx)
}

// TestGuardRecoversAfterACrash starts a guard after one was killed while it
// limited. It puts the ring and the receive threads back even with the off
// switch on, which is what an operator would set after the guard misbehaved.
func TestGuardRecoversAfterACrash(t *testing.T) {
	name := simulated(t, "7319")
	cfg := simulatedConfig(t)
	crashWhileLimiting(t, cfg, name)
	assertNices(t, name, -10)
	assert.FileExists(t, cfg.RingPath)
	require.NoError(t, os.WriteFile(cfg.OffPath, nil, 0o600))

	startGuard(t, cfg)
	assert.Equal(t, 512, ringSize(t, name))
	assertNices(t, name, 0)
	assert.NoFileExists(t, cfg.RingPath)
}

// TestGuardRecoversOnlyItsOwnRing starts a guard after a crash where the
// ring it raised is no longer there to restore. It leaves the ring alone and
// forgets the record.
func TestGuardRecoversOnlyItsOwnRing(t *testing.T) {
	name := simulated(t, "7320")
	cfg := simulatedConfig(t)
	{
		// Another ENI now holds the shared address with a large ring, as
		// when the shared ENI moved: a new MAC stands for a different ENI
		crashWhileLimiting(t, cfg, name)
		ip(t, "link", "set", name, "address", "02:00:00:00:73:20")
		startGuard(t, cfg)
		assert.Equal(t, 4096, ringSize(t, name))
		assert.NoFileExists(t, cfg.RingPath)
	}
	{
		// The ring is no longer at the size the guard set, as when the
		// shared ENI moved to the other NAT and back, or someone else changed
		// it
		_, err := command.Run(t.Context(), 5*time.Second, "ethtool", "-G", name, "rx", "512")
		require.NoError(t, err)
		crashWhileLimiting(t, cfg, name)
		_, err = command.Run(t.Context(), 5*time.Second, "ethtool", "-G", name, "rx", "1024")
		require.NoError(t, err)
		startGuard(t, cfg)
		assert.Equal(t, 1024, ringSize(t, name))
		assert.NoFileExists(t, cfg.RingPath)
	}
}
