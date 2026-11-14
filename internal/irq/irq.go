// Package irq spreads the ENA driver's queue interrupts across the CPUs.
//
// A NAT forwards almost entirely in softirq context, on the CPU that took
// each queue's interrupt. irqbalance can put every queue of an interface on
// one CPU, and then a two-CPU NAT forwards with one: on AWS, a c7gn.large
// forwarded 9.6 Gbps with its shared ENI's two interrupts on one CPU, and
// about 18 Gbps once they were spread.
package irq

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// queuePattern matches the name ENA gives each queue's interrupt in
// /proc/interrupts, such as "ens5-Tx-Rx-1".
var queuePattern = regexp.MustCompile(`-Tx-Rx-(\d+)$`)

// Spread moves each ENA queue interrupt to its CPU from [plan], writing only
// those that are elsewhere. It returns how many it moved. Finding no queue
// interrupts is an error, since irqbalance is off and nothing else places
// them. An interrupt that goes away while Spread runs, as when the shared ENI
// detaches, is skipped.
func Spread() (int, error) {
	return spread("/proc")
}

func spread(proc string) (int, error) {
	interrupts, err := os.ReadFile(filepath.Join(proc, "interrupts"))
	if err != nil {
		return 0, fmt.Errorf("failed to read interrupts: %w", err)
	}
	placements := plan(string(interrupts))
	if len(placements) == 0 {
		return 0, errors.New("found no ENA queue interrupts in /proc/interrupts")
	}
	moved := 0
	var errs []error
	for _, p := range placements {
		path := filepath.Join(proc, "irq", strconv.Itoa(p.irq), "smp_affinity_list")
		current, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read interrupt %d's CPUs: %w", p.irq, err))
			continue
		}
		cpu := strconv.Itoa(p.cpu)
		if strings.TrimSpace(string(current)) == cpu {
			continue
		}
		err = os.WriteFile(path, []byte(cpu), 0o644)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to move interrupt %d to CPU %s: %w", p.irq, cpu, err))
			continue
		}
		moved++
	}
	return moved, errors.Join(errs...)
}

// placement is the CPU one queue interrupt should run on.
type placement struct {
	irq int
	cpu int
}

// plan returns where each ENA queue interrupt in interrupts, the contents of
// /proc/interrupts, should run: queue n on the nth online CPU, wrapping
// around. The header line names the online CPUs, such as "CPU0 CPU1".
func plan(interrupts string) []placement {
	header, rows, _ := strings.Cut(interrupts, "\n")
	var cpus []int
	for _, field := range strings.Fields(header) {
		if cpu, err := strconv.Atoi(strings.TrimPrefix(field, "CPU")); err == nil {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) == 0 {
		return nil
	}
	var placements []placement
	for _, line := range strings.Split(rows, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		match := queuePattern.FindStringSubmatch(fields[len(fields)-1])
		if match == nil {
			continue
		}
		irq, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			continue
		}
		queue, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		placements = append(placements, placement{irq: irq, cpu: cpus[queue%len(cpus)]})
	}
	return placements
}
