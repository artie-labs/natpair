package network

import "context"

// UntrackOwnTraffic exposes untrackOwnTraffic to the privileged tests.
func (n *Network) UntrackOwnTraffic(ctx context.Context) error {
	return n.untrackOwnTraffic(ctx)
}

// ProtectHost exposes protectHost to the privileged tests.
func (n *Network) ProtectHost(ctx context.Context) error {
	return n.protectHost(ctx)
}
