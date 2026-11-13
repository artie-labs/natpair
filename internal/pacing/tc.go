package pacing

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// What natpair installs on an interface, and how it finds its own again.
const (
	// rootHandle marks natpair's root qdisc. Removal deletes only a root
	// qdisc with this handle.
	rootHandle = "7a01:"
	// filterPref is the priority of natpair's tc filters. Removal deletes
	// only filters with this priority.
	filterPref = 7001
	// fqLimit and fqFlowLimit are the most packets each sch_fq holds, in
	// total and per flow. Forwarded packets have no socket, so sch_fq hashes
	// them into at most 1,024 flows. The pacer's horizon is what bounds the
	// queue, so these only need to stay out of its way. sch_fq's defaults,
	// 10,000 and 100, would drop a fast worker's packets after the pacer
	// already counted them. The total is higher still, because several heavy
	// workers can each queue 20 ms before the fair shares adjust, and a full
	// sch_fq would also drop packets the NAT sends itself.
	fqLimit     = 100000
	fqFlowLimit = 10000
)

// attachScript returns `tc -batch` input that paces an interface with
// txQueues transmit queues. A multiqueue interface gets mq with one sch_fq per
// queue, so CPUs sending on different queues never share a qdisc lock. The
// clsact qdisc runs the mark program on packets arriving and the pace program
// on packets leaving. Every command replaces, so running it again is safe.
func attachScript(iface string, txQueues int, markPin, pacePin string) string {
	fq := fmt.Sprintf("fq limit %d flow_limit %d", fqLimit, fqFlowLimit)
	var lines []string
	if txQueues > 1 {
		lines = append(lines, fmt.Sprintf("qdisc replace dev %s root handle %s mq", iface, rootHandle))
		for queue := 1; queue <= txQueues; queue++ {
			lines = append(lines, fmt.Sprintf("qdisc replace dev %s parent %s%x %s", iface, rootHandle, queue, fq))
		}
	} else {
		lines = append(lines, fmt.Sprintf("qdisc replace dev %s root handle %s %s", iface, rootHandle, fq))
	}
	lines = append(lines,
		fmt.Sprintf("qdisc replace dev %s clsact", iface),
		fmt.Sprintf("filter replace dev %s ingress protocol all pref %d handle 1 bpf direct-action object-pinned %s", iface, filterPref, markPin),
		fmt.Sprintf("filter replace dev %s egress protocol all pref %d handle 1 bpf direct-action object-pinned %s", iface, filterPref, pacePin),
	)
	return strings.Join(lines, "\n") + "\n"
}

// qdisc is one entry of `tc -j qdisc show`.
type qdisc struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Root   bool   `json:"root"`
}

// filter is one entry of `tc -j filter show`.
type filter struct {
	Pref int `json:"pref"`
}

// detachScript returns `tc -batch` input that removes what attachScript
// installed, given the interface's qdiscs and its ingress and egress filters,
// or "" if nothing of natpair's is there. It leaves other qdiscs and filters
// alone, and keeps the clsact qdisc while other filters use it.
func detachScript(iface string, qdiscs []qdisc, ingress, egress []filter) string {
	ours := func(f filter) bool { return f.Pref == filterPref }
	var lines []string
	for _, side := range []struct {
		direction string
		filters   []filter
	}{{"ingress", ingress}, {"egress", egress}} {
		if slices.ContainsFunc(side.filters, ours) {
			lines = append(lines, fmt.Sprintf("filter del dev %s %s pref %d", iface, side.direction, filterPref))
		}
	}
	others := slices.ContainsFunc(ingress, func(f filter) bool { return !ours(f) }) ||
		slices.ContainsFunc(egress, func(f filter) bool { return !ours(f) })
	if len(lines) > 0 && !others && slices.ContainsFunc(qdiscs, func(q qdisc) bool { return q.Kind == "clsact" }) {
		lines = append(lines, fmt.Sprintf("qdisc del dev %s clsact", iface))
	}
	if slices.ContainsFunc(qdiscs, func(q qdisc) bool { return q.Root && q.Handle == rootHandle }) {
		lines = append(lines, fmt.Sprintf("qdisc del dev %s root", iface))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// parseTC parses the JSON that `tc -j ... show` prints. tc prints nothing
// instead of an empty list for some empty results.
func parseTC[T any](output string) ([]T, error) {
	var entries []T
	if strings.TrimSpace(output) == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return nil, fmt.Errorf("failed to parse tc output: %w", err)
	}
	return entries, nil
}
