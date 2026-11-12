package network

import "context"

// UntrackOwnTraffic exposes untrackOwnTraffic to the privileged tests.
func (n *Network) UntrackOwnTraffic(ctx context.Context) error {
	return n.untrackOwnTraffic(ctx)
}
