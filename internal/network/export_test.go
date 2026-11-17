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

// ProtectHost exposes protectHost to the privileged tests.
func (n *Network) ProtectHost(ctx context.Context) error {
	return n.protectHost(ctx)
}

// UseLoadFiles points ReadLoad at stat and sysNet instead of /proc/stat and
// /sys/class/net, until the returned function restores them.
func UseLoadFiles(stat, sysNet string) func() {
	previousStat, previousNet := procStat, sysClassNet
	procStat, sysClassNet = stat, sysNet
	return func() { procStat, sysClassNet = previousStat, previousNet }
}
