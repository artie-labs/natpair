package irq

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Spread moves each ENA queue interrupt to its CPU from [Plan], writing only
// those that are elsewhere. It returns how many it moved.
func Spread() (int, error) {
	interrupts, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return 0, fmt.Errorf("failed to read interrupts: %w", err)
	}
	moved := 0
	var errs []error
	for _, p := range Plan(string(interrupts), runtime.NumCPU()) {
		path := fmt.Sprintf("/proc/irq/%d/smp_affinity_list", p.IRQ)
		current, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to read interrupt %d's CPUs: %w", p.IRQ, err))
			continue
		}
		cpu := strconv.Itoa(p.CPU)
		if strings.TrimSpace(string(current)) == cpu {
			continue
		}
		if err := os.WriteFile(path, []byte(cpu), 0o644); err != nil {
			errs = append(errs, fmt.Errorf("failed to move interrupt %d to CPU %s: %w", p.IRQ, cpu, err))
			continue
		}
		moved++
	}
	return moved, errors.Join(errs...)
}
