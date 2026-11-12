//go:build linux && privileged

package pacing

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/artie-labs/natpair/internal/command"
)

func TestLoopFollowsRenamedInterfaces(t *testing.T) {
	if output, err := command.Run(t.Context(), 2*time.Second, "tc", "qdisc", "add", "dev", "lo", "root", "fq"); err != nil {
		t.Skipf("this kernel lacks sch_fq, which pacing needs: %v %s", err, output)
	}
	tc(t, "qdisc", "del", "dev", "lo", "root")
	dir := t.TempDir()
	require.NoError(t, unix.Mount("bpf", dir, "bpf", 0, ""))
	t.Cleanup(func() { assert.NoError(t, unix.Unmount(dir, 0)) })
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	l := &loop{cfg: Config{Poll: 10 * time.Millisecond}, k: newKernel(filepath.Join(dir, "pacing"), testProtected)}
	require.NoError(t, l.k.load())
	defer l.k.close()
	l.attached, l.allowances, l.window = map[int]*attachment{}, map[int]Allowances{}, []reading{{}}

	// A new owner's shared ENI first appears as eth0 and is renamed after.
	_, err := command.Run(t.Context(), 2*time.Second, "ip", "link", "add", "prn0", "type", "veth", "peer", "name", "prn1")
	require.NoError(t, err)
	iface, err := net.InterfaceByName("prn0")
	require.NoError(t, err)
	l.attach(t.Context(), time.Second)
	require.Contains(t, l.attached, iface.Index)
	assert.True(t, l.attached[iface.Index].paced)
	_, err = command.Run(t.Context(), 2*time.Second, "ip", "link", "set", "prn0", "name", "prn9")
	require.NoError(t, err)
	// The test's context ends before its cleanups run. The link may be gone.
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() { _, _ = command.Run(ctx, 2*time.Second, "ip", "link", "del", "prn9") })

	l.poll(2 * time.Second)
	l.attach(t.Context(), 2*time.Second)
	require.Contains(t, l.attached, iface.Index)
	assert.Equal(t, "prn9", l.attached[iface.Index].name)
	assert.True(t, l.attached[iface.Index].paced)
	// The programs stayed on the device through the rename, so it needs no
	// second attach.
	assert.Contains(t, tc(t, "filter", "show", "dev", "prn9", "egress"), "natpair_pace")
	// Other tests in the same network namespace come and go, so only this
	// test's links count.
	assert.NotRegexp(t, `failed[^\n]*"prn`, logs.String())
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte(`"msg":"pacing interface","interface":"prn0"`)))
	assert.NotContains(t, logs.String(), `"interface":"prn9"`)

	// A detached ENI is forgotten without errors.
	_, err = command.Run(t.Context(), 2*time.Second, "ip", "link", "del", "prn9")
	require.NoError(t, err)
	l.poll(3 * time.Second)
	l.attach(t.Context(), 3*time.Second)
	assert.NotContains(t, l.attached, iface.Index)
	assert.NotRegexp(t, `failed[^\n]*"prn`, logs.String())
}
