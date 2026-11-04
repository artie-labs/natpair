//go:build !linux

package bootclock

import "time"

// The NAT only runs on Linux. Other platforms count from process start so unit
// tests can run on developer machines.
var started = time.Now()

func now() time.Duration {
	return time.Since(started)
}
