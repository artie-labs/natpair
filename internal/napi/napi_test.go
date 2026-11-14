package napi

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addInterface adds an interface to a fake /sys/class/net. A device-backed
// one gets a device link, as an ENI has. threaded is the threaded file's
// contents, or "" for none.
func addInterface(t *testing.T, root, name string, device bool, threaded string) {
	dir := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	if device {
		require.NoError(t, os.Symlink("../../../devices/pci0000:00/0000:00:05.0", filepath.Join(dir, "device")))
	}
	if threaded != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "threaded"), []byte(threaded), 0o644))
	}
}

func readThreaded(t *testing.T, root, name string) string {
	contents, err := os.ReadFile(filepath.Join(root, name, "threaded"))
	require.NoError(t, err)
	return string(contents)
}

// allListed stands in for the kernel's interface list when every interface in
// the fake /sys/class/net still exists.
func allListed(string) bool { return true }

func TestEnable(t *testing.T) {
	// A NAT that owns the shared ENI (ens6), with lo, Docker's bridge and a
	// probe veth beside its ENIs.
	root := t.TempDir()
	addInterface(t, root, "ens5", true, "0\n")
	addInterface(t, root, "ens6", true, "0\n")
	addInterface(t, root, "lo", false, "0\n")
	addInterface(t, root, "docker0", false, "0\n")
	addInterface(t, root, "nat-can0", false, "0\n")
	// 2 is busy polling on newer kernels, which someone else chose
	addInterface(t, root, "ens7", true, "2\n")
	// An ENI whose threaded file is gone, as when it detaches mid-pass, or a
	// kernel without threaded NAPI
	addInterface(t, root, "ens8", true, "")

	enabled, err := enable(root, allListed)
	assert.NoError(t, err)
	assert.Equal(t, 2, enabled)
	assert.Equal(t, "1", readThreaded(t, root, "ens5"))
	assert.Equal(t, "1", readThreaded(t, root, "ens6"))
	// Interfaces without a device have no hardware receive queues
	assert.Equal(t, "0\n", readThreaded(t, root, "lo"))
	assert.Equal(t, "0\n", readThreaded(t, root, "docker0"))
	assert.Equal(t, "0\n", readThreaded(t, root, "nat-can0"))
	assert.Equal(t, "2\n", readThreaded(t, root, "ens7"))
	{
		// A second pass finds them on and writes nothing
		enabled, err := enable(root, allListed)
		assert.NoError(t, err)
		assert.Zero(t, enabled)
	}
}

func TestEnableKeepsGoingAfterAFailure(t *testing.T) {
	// A threaded path that can't be read, here a directory, fails that
	// interface but not the others
	root := t.TempDir()
	addInterface(t, root, "ens5", true, "")
	require.NoError(t, os.Mkdir(filepath.Join(root, "ens5", "threaded"), 0o755))
	addInterface(t, root, "ens6", true, "0\n")

	enabled, err := enable(root, allListed)
	assert.ErrorIs(t, err, syscall.EISDIR)
	path := filepath.Join(root, "ens5", "threaded")
	assert.EqualError(t, err, "failed to read "+path+": read "+path+": is a directory")
	assert.Equal(t, 1, enabled)
	assert.Equal(t, "1", readThreaded(t, root, "ens6"))
}

func TestEnableSkipsAnInterfaceBeingRemoved(t *testing.T) {
	// While the kernel removes a device, such as the old owner's shared ENI
	// after a takeover, the device is no longer listed but its sysfs files
	// are still there and fail. Here the failure is a read of a directory.
	root := t.TempDir()
	addInterface(t, root, "ens5", true, "0\n")
	addInterface(t, root, "ens6", true, "")
	require.NoError(t, os.Mkdir(filepath.Join(root, "ens6", "threaded"), 0o755))
	var checked []string
	listed := func(name string) bool {
		checked = append(checked, name)
		return name != "ens6"
	}

	enabled, err := enable(root, listed)
	assert.NoError(t, err)
	assert.Equal(t, 1, enabled)
	assert.Equal(t, "1", readThreaded(t, root, "ens5"))
	// Only a failed interface is looked up
	assert.Equal(t, []string{"ens6"}, checked)
}
