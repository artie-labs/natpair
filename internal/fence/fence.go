// Package fence stops this NAT from forwarding worker traffic once its lease
// grant expires, even if the controller process is killed or frozen.
//
// Every forwarded packet to or from a protected worker CIDR jumps to the
// NATPAIR chain. That chain runs a small BPF program that compares the
// boot clock with one absolute deadline stored in a pinned BPF map. Packets
// pass only before the deadline. The controller writes each grant's deadline,
// so a delayed write can only restore an already expired deadline, never
// extend it.
package fence

import (
	"fmt"
	"net/netip"
	"path/filepath"
)

// Fence manages the forwarding guard for the protected worker CIDRs.
type Fence struct {
	dir         string
	mapPath     string
	programPath string
	protected   []netip.Prefix
}

// New returns a fence that pins its BPF objects under bpfDir, which must be on
// a mounted bpf filesystem.
func New(bpfDir string, protected []netip.Prefix) (*Fence, error) {
	if len(protected) == 0 {
		return nil, fmt.Errorf("protected worker CIDRs are required")
	}
	return &Fence{
		dir:         bpfDir,
		mapPath:     filepath.Join(bpfDir, "deadline"),
		programPath: filepath.Join(bpfDir, "check"),
		protected:   protected,
	}, nil
}
