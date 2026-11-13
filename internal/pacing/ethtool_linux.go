package pacing

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ethtool commands and sizes, from include/uapi/linux/ethtool.h. Driver
// statistics such as ENA's allowance counters are only available through
// this ioctl, not through ethtool's netlink interface.
const (
	ethtoolGetStringSetInfo = 0x37
	ethtoolGetStrings       = 0x1b
	ethtoolGetStats         = 0x1d
	ethtoolStatsSet         = 1
	ethtoolStringLength     = 32
)

// ethtoolRequest is struct ifreq with its ifr_data member, padded to the
// kernel's 40 bytes.
type ethtoolRequest struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [16]byte
}

// ethtoolSpare is how many more statistics than counted the buffers hold.
// Kernels before 6.10 or so ignore the count a request passes and write as
// many as the driver has at the time, which can grow between calls, such as
// when the queue count changes. Newer kernels write nothing if the counts
// differ.
const ethtoolSpare = 256

// statIndex says where some named statistics are among an interface's
// driver statistics.
type statIndex struct {
	// count is how many statistics the driver had when they were looked up.
	count int
	// indexes are the positions of the names, or nil if the interface
	// doesn't report all of them, as on any interface other than an ENA one.
	indexes []int
}

// findStats finds the driver statistics with the given names.
func findStats(fd int, iface string, names []string) (statIndex, error) {
	// struct ethtool_sset_info: cmd, reserved, sset_mask, then one u32 count
	// per set in the mask.
	info := make([]byte, 20)
	binary.NativeEndian.PutUint32(info[0:], ethtoolGetStringSetInfo)
	binary.NativeEndian.PutUint64(info[8:], 1<<ethtoolStatsSet)
	if err := ethtool(fd, iface, info); err != nil {
		return statIndex{}, fmt.Errorf("failed to count %s's statistics: %w", iface, err)
	}
	if binary.NativeEndian.Uint64(info[8:])&(1<<ethtoolStatsSet) == 0 {
		return statIndex{}, nil
	}
	count := int(binary.NativeEndian.Uint32(info[16:]))

	// struct ethtool_gstrings: cmd, string_set, len, then the names.
	strs := make([]byte, 12+(count+ethtoolSpare)*ethtoolStringLength)
	binary.NativeEndian.PutUint32(strs[0:], ethtoolGetStrings)
	binary.NativeEndian.PutUint32(strs[4:], ethtoolStatsSet)
	binary.NativeEndian.PutUint32(strs[8:], uint32(count))
	if err := ethtool(fd, iface, strs); err != nil {
		return statIndex{}, fmt.Errorf("failed to read %s's statistic names: %w", iface, err)
	}
	if written := int(binary.NativeEndian.Uint32(strs[8:])); written != count {
		return statIndex{}, fmt.Errorf("%s's statistics changed while being read", iface)
	}
	index := statIndex{count: count, indexes: make([]int, len(names))}
	for i := range index.indexes {
		index.indexes[i] = -1
	}
	for i := range count {
		name := unix.ByteSliceToString(strs[12+i*ethtoolStringLength : 12+(i+1)*ethtoolStringLength])
		for j, wanted := range names {
			if name == wanted {
				index.indexes[j] = i
			}
		}
	}
	if slices.Contains(index.indexes, -1) {
		index.indexes = nil
	}
	return index, nil
}

// readIndexed reads the statistics index points at. It fails if the driver's
// statistics changed since findStats, so the caller finds them again.
func readIndexed(fd int, iface string, index statIndex) ([]uint64, error) {
	// struct ethtool_stats: cmd, n_stats, then the u64 values.
	stats := make([]byte, 8+(index.count+ethtoolSpare)*8)
	binary.NativeEndian.PutUint32(stats[0:], ethtoolGetStats)
	binary.NativeEndian.PutUint32(stats[4:], uint32(index.count))
	if err := ethtool(fd, iface, stats); err != nil {
		return nil, fmt.Errorf("failed to read %s's statistics: %w", iface, err)
	}
	if written := int(binary.NativeEndian.Uint32(stats[4:])); written != index.count {
		return nil, fmt.Errorf("%s's statistics changed while being read", iface)
	}
	values := make([]uint64, len(index.indexes))
	for j, i := range index.indexes {
		values[j] = binary.NativeEndian.Uint64(stats[8+i*8:])
	}
	return values, nil
}

func ethtoolSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to open a socket for ethtool: %w", err)
	}
	return fd, nil
}

// ethtool runs one SIOCETHTOOL request, whose command and results are in
// data. KeepAlive holds data until the kernel has written it.
func ethtool(fd int, iface string, data []byte) error {
	var request ethtoolRequest
	copy(request.name[:unix.IFNAMSIZ-1], iface)
	request.data = unsafe.Pointer(&data[0])
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&request)))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}
