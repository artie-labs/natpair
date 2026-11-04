//go:build !linux

package fence

import (
	"context"
	"errors"
	"time"
)

var errUnsupported = errors.New("the forwarding fence requires Linux")

// Install is only supported on Linux.
func (f *Fence) Install(context.Context) error {
	return errUnsupported
}

// Arm is only supported on Linux.
func (f *Fence) Arm(time.Duration) error {
	return errUnsupported
}

// Close is only supported on Linux.
func (f *Fence) Close() error {
	return errUnsupported
}
