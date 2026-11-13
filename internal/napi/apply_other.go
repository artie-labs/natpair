//go:build !linux

package napi

import "errors"

// Apply is only supported on Linux.
func Apply(string) (int, error) {
	return 0, errors.New("threaded NAPI requires Linux")
}
