//go:build !linux

package irq

import "errors"

// Spread is only supported on Linux.
func Spread() (int, error) {
	return 0, errors.New("spreading interrupts requires Linux")
}
