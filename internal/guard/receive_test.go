package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enaRings is `ethtool -g ens6` on a c7gn.medium.
const enaRings = `Ring parameters for ens6:
Pre-set maximums:
RX:		2048
RX Mini:	n/a
RX Jumbo:	n/a
TX:		512
Current hardware settings:
RX:		1024
RX Mini:	n/a
RX Jumbo:	n/a
TX:		512
`

func TestParseRings(t *testing.T) {
	maximum, current, err := parseRings(enaRings)
	require.NoError(t, err)
	assert.Equal(t, [2]int{2048, 1024}, [2]int{maximum, current})
	{
		// A device without ring settings
		_, _, err := parseRings("Ring parameters for lo:\nnetlink error: Operation not supported\n")
		assert.EqualError(t, err, "ethtool reported no receive ring size")
	}
	{
		_, _, err := parseRings("Pre-set maximums:\nRX:\t\tlots\n")
		assert.EqualError(t, err, `failed to parse the receive ring size "RX:\t\tlots": strconv.Atoi: parsing "lots": invalid syntax`)
	}
}

// addProcess adds a process to a fake /proc with the given name and flags.
func addProcess(t *testing.T, root, pid, comm, flags string) {
	dir := filepath.Join(root, pid)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	stat := pid + " (" + comm + ") S 2 0 0 0 -1 " + flags + " 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644))
}

func TestReceiveThreads(t *testing.T) {
	root := t.TempDir()
	// Kernel threads carry PF_KTHREAD, 0x00200000, among other flags
	addProcess(t, root, "44694", "napi/ens6-0", "2129984")
	addProcess(t, root, "44695", "napi/ens6-8193", "2129984")
	// The primary interface's receive thread
	addProcess(t, root, "4673", "napi/ens5-4097", "2129984")
	// An ordinary process can name itself like a receive thread
	addProcess(t, root, "900", "napi/ens6-1", "4194560")
	// A name with spaces and parentheses
	addProcess(t, root, "901", "a) (b", "2129984")
	require.NoError(t, os.Mkdir(filepath.Join(root, "self"), 0o755))
	// A process that exited before its stat was read
	require.NoError(t, os.Mkdir(filepath.Join(root, "902"), 0o755))

	pids, err := receiveThreads(root, "ens6")
	require.NoError(t, err)
	assert.ElementsMatch(t, []int{44694, 44695}, pids)
	{
		pids, err := receiveThreads(root, "ens7")
		require.NoError(t, err)
		assert.Empty(t, pids)
	}
}

func TestParseStat(t *testing.T) {
	comm, flags, ok := parseStat("901 (a) (b) S 2 0 0 0 -1 2129984 0 0\n")
	assert.True(t, ok)
	assert.Equal(t, "a) (b", comm)
	assert.Equal(t, uint64(2129984), flags)
	{
		_, _, ok := parseStat("901 (cut")
		assert.False(t, ok)
	}
}
