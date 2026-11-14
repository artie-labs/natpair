// Package irq spreads the ENA driver's queue interrupts across the CPUs.
//
// A NAT forwards almost entirely in softirq context, on the CPU that took
// each queue's interrupt. irqbalance can put every queue of an interface on
// one CPU, and then a two-CPU NAT forwards with one: on AWS, a c7gn.large
// forwarded 9.6 Gbps with its shared ENI's two interrupts on one CPU, and
// 14.7 Gbps once they were spread.
package irq

import (
	"regexp"
	"strconv"
	"strings"
)

// queuePattern matches the name ENA gives each queue's interrupt in
// /proc/interrupts, such as "ens5-Tx-Rx-1".
var queuePattern = regexp.MustCompile(`-Tx-Rx-(\d+)$`)

// Placement is the CPU one queue interrupt should run on.
type Placement struct {
	IRQ int
	CPU int
}

// Plan returns where each ENA queue interrupt in interrupts, the contents of
// /proc/interrupts, should run: queue n on CPU n modulo cpus.
func Plan(interrupts string, cpus int) []Placement {
	var placements []Placement
	for _, line := range strings.Split(interrupts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		match := queuePattern.FindStringSubmatch(fields[len(fields)-1])
		irq, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if match == nil || err != nil || cpus < 1 {
			continue
		}
		queue, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		placements = append(placements, Placement{IRQ: irq, CPU: queue % cpus})
	}
	return placements
}
