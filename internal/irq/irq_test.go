package irq

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// interrupts is /proc/interrupts on a two-CPU NAT holding the shared ENI.
const interrupts = `           CPU0       CPU1
 10:     208744     195873     GICv3  27 Level     arch_timer
 58:          0          0   ITS-MSI 524288 Edge      ena-mgmnt@pci:0000:00:05.0
 59:   18376402        117   ITS-MSI 524289 Edge      ens5-Tx-Rx-0
 60:        305   20117385   ITS-MSI 524290 Edge      ens5-Tx-Rx-1
 62:          0          0   ITS-MSI 1048576 Edge      ena-mgmnt@pci:0000:00:06.0
 63:   94123412          0   ITS-MSI 1048577 Edge      ens6-Tx-Rx-0
 64:   88003121          0   ITS-MSI 1048578 Edge      ens6-Tx-Rx-1
IPI0:      41223      39876       Rescheduling interrupts
ERR:          0
`

func TestPlan(t *testing.T) {
	{
		// Each interface's queue n goes to CPU n. The management interrupts
		// and the timer stay where they are.
		assert.Equal(t, []placement{{59, 0}, {60, 1}, {63, 0}, {64, 1}}, plan(interrupts))
	}
	{
		// More queues than CPUs wrap around
		const oneCPU = `           CPU0
 59:   18376402   ITS-MSI 524289 Edge      ens5-Tx-Rx-0
 60:        305   ITS-MSI 524290 Edge      ens5-Tx-Rx-1
`
		assert.Equal(t, []placement{{59, 0}, {60, 0}}, plan(oneCPU))
	}
	{
		// The CPUs are the header's, so an offline CPU 1 is skipped
		const offlineCPU = `           CPU0       CPU2
 59:   18376402        117   ITS-MSI 524289 Edge      ens5-Tx-Rx-0
 60:        305   20117385   ITS-MSI 524290 Edge      ens5-Tx-Rx-1
`
		assert.Equal(t, []placement{{59, 0}, {60, 2}}, plan(offlineCPU))
	}
	{
		assert.Empty(t, plan("           CPU0\n 10:  5  GICv3  27 Level  arch_timer\n"))
	}
}

func TestSpread(t *testing.T) {
	// /proc/interrupts on a two-CPU amd64 NAT, with both of ens5's queues on
	// CPU 0. Interrupt 29 is gone from /proc/irq, as when the shared ENI
	// detaches between the two reads.
	const amd64Interrupts = `            CPU0       CPU1
  24:          0          0  PCI-MSI-0000:00:05.0   0-edge      ena-mgmnt@pci:0000:00:05.0
  25:    1830467          0  PCI-MSI-0000:00:05.0   1-edge      ens5-Tx-Rx-0
  26:    1702931          0  PCI-MSI-0000:00:05.0   2-edge      ens5-Tx-Rx-1
  29:         12          0  PCI-MSI-0000:00:06.0   1-edge      ens6-Tx-Rx-0
`
	proc := t.TempDir()
	writeFile(t, filepath.Join(proc, "interrupts"), amd64Interrupts)
	for irq, cpus := range map[string]string{"24": "0-1", "25": "0", "26": "0"} {
		writeFile(t, filepath.Join(proc, "irq", irq, "smp_affinity_list"), cpus+"\n")
	}

	moved, err := spread(proc)
	assert.Equal(t, 1, moved)
	assert.NoError(t, err)
	assert.Equal(t, "0-1\n", readFile(t, filepath.Join(proc, "irq", "24", "smp_affinity_list")))
	assert.Equal(t, "0\n", readFile(t, filepath.Join(proc, "irq", "25", "smp_affinity_list")))
	assert.Equal(t, "1", readFile(t, filepath.Join(proc, "irq", "26", "smp_affinity_list")))
	{
		// A second pass finds them in place and writes nothing
		moved, err := spread(proc)
		assert.Zero(t, moved)
		assert.NoError(t, err)
	}
	{
		// A failed read is reported, and the other interrupts still move
		proc := t.TempDir()
		writeFile(t, filepath.Join(proc, "interrupts"), amd64Interrupts)
		require.NoError(t, os.MkdirAll(filepath.Join(proc, "irq", "25", "smp_affinity_list"), 0o755))
		writeFile(t, filepath.Join(proc, "irq", "26", "smp_affinity_list"), "0\n")
		moved, err := spread(proc)
		assert.Equal(t, 1, moved)
		assert.ErrorContains(t, err, "failed to read interrupt 25's CPUs")
		assert.Equal(t, "1", readFile(t, filepath.Join(proc, "irq", "26", "smp_affinity_list")))
	}
	{
		// A non-ENA host, where irqbalance is off and nothing would place
		// the queues
		proc := t.TempDir()
		writeFile(t, filepath.Join(proc, "interrupts"), "           CPU0\n 10:  5  GICv3  27 Level  arch_timer\n")
		_, err := spread(proc)
		assert.EqualError(t, err, "found no ENA queue interrupts in /proc/interrupts")
	}
	{
		_, err := spread(t.TempDir())
		assert.ErrorIs(t, err, fs.ErrNotExist)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(contents)
}
