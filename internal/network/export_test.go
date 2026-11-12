package network

import "context"

// RoutePeer exposes routePeer to the privileged tests.
func (n *Network) RoutePeer(ctx context.Context) error {
	return n.routePeer(ctx)
}

// UntrackOwnTraffic exposes untrackOwnTraffic to the privileged tests.
func (n *Network) UntrackOwnTraffic(ctx context.Context) error {
	return n.untrackOwnTraffic(ctx)
}
