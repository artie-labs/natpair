//go:build !linux

package guard

import "context"

// Guard does nothing off Linux, which has no XDP.
type Guard struct{}

// New returns a guard that does nothing.
func New(Config) *Guard {
	return &Guard{}
}

// Ensure does nothing off Linux.
func (*Guard) Ensure() {}

// Run waits for ctx to end.
func (*Guard) Run(ctx context.Context) {
	<-ctx.Done()
}
