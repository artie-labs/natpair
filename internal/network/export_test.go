package network

import "context"

// RoutePeer exposes routePeer to the privileged tests.
func (n *Network) RoutePeer(ctx context.Context) error {
	return n.routePeer(ctx)
}

// InstallFirewall exposes installFirewall to the privileged tests.
func (n *Network) InstallFirewall(ctx context.Context) error {
	return n.installFirewall(ctx)
}
