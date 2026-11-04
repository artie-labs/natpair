//go:build !linux

package netns

import "errors"

func do(string, func() error) error {
	return errors.New("network namespaces require Linux")
}
