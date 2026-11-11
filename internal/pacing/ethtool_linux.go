package pacing

import (
	"encoding/binary"
	"fmt"
	"runtime"
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

// readStats returns the driver statistics with the given names, in order.
// found is false if the interface doesn't report all of them, as on any
// interface other than an ENA one.
func readStats(iface string, names []string) (values []uint64, found bool, err error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open a socket for ethtool: %w", err)
	}
	defer unix.Close(fd)

	// struct ethtool_sset_info: cmd, reserved, sset_mask, then one u32 count
	// per set in the mask.
	info := make([]byte, 20)
	binary.NativeEndian.PutUint32(info[0:], ethtoolGetStringSetInfo)
	binary.NativeEndian.PutUint64(info[8:], 1<<ethtoolStatsSet)
	if err := ethtool(fd, iface, info); err != nil {
		return nil, false, fmt.Errorf("failed to count %s's statistics: %w", iface, err)
	}
	if binary.NativeEndian.Uint64(info[8:])&(1<<ethtoolStatsSet) == 0 {
		return nil, false, nil
	}
	count := int(binary.NativeEndian.Uint32(info[16:]))

	// struct ethtool_gstrings: cmd, string_set, len, then the names.
	strs := make([]byte, 12+(count+ethtoolSpare)*ethtoolStringLength)
	binary.NativeEndian.PutUint32(strs[0:], ethtoolGetStrings)
	binary.NativeEndian.PutUint32(strs[4:], ethtoolStatsSet)
	binary.NativeEndian.PutUint32(strs[8:], uint32(count))
	if err := ethtool(fd, iface, strs); err != nil {
		return nil, false, fmt.Errorf("failed to read %s's statistic names: %w", iface, err)
	}
	if written := int(binary.NativeEndian.Uint32(strs[8:])); written != count {
		return nil, false, fmt.Errorf("%s's statistics changed while being read", iface)
	}
	indexes := make([]int, len(names))
	for i := range indexes {
		indexes[i] = -1
	}
	for i := range count {
		raw := strs[12+i*ethtoolStringLength : 12+(i+1)*ethtoolStringLength]
		name := unix.ByteSliceToString(raw)
		for j, wanted := range names {
			if name == wanted {
				indexes[j] = i
			}
		}
	}
	for _, index := range indexes {
		if index < 0 {
			return nil, false, nil
		}
	}

	// struct ethtool_stats: cmd, n_stats, then the u64 values.
	stats := make([]byte, 8+(count+ethtoolSpare)*8)
	binary.NativeEndian.PutUint32(stats[0:], ethtoolGetStats)
	binary.NativeEndian.PutUint32(stats[4:], uint32(count))
	if err := ethtool(fd, iface, stats); err != nil {
		return nil, false, fmt.Errorf("failed to read %s's statistics: %w", iface, err)
	}
	if written := int(binary.NativeEndian.Uint32(stats[4:])); written != count {
		return nil, false, fmt.Errorf("%s's statistics changed while being read", iface)
	}
	values = make([]uint64, len(names))
	for j, index := range indexes {
		values[j] = binary.NativeEndian.Uint64(stats[8+index*8:])
	}
	return values, true, nil
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
