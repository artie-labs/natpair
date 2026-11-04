// Package bootclock reads elapsed time since boot.
//
// Ownership deadlines use CLOCK_BOOTTIME because it never jumps when the wall
// clock changes, and the kernel forwarding guard reads the same clock through
// bpf_ktime_get_boot_ns. Userspace and kernel therefore agree on when a grant
// expires.
package bootclock

import "time"

// Now returns the time elapsed since boot.
func Now() time.Duration {
	return now()
}
