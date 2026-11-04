package bootclock

import (
	"time"

	"golang.org/x/sys/unix"
)

func now() time.Duration {
	var spec unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &spec); err != nil {
		// CLOCK_BOOTTIME exists on every Linux kernel this binary supports.
		panic("CLOCK_BOOTTIME is unavailable: " + err.Error())
	}
	return time.Duration(spec.Nano())
}
