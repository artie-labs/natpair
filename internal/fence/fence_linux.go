package fence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/artie-labs/natpair/internal/bootclock"
	"github.com/artie-labs/natpair/internal/command"
)

const chain = "NATPAIR"

var deadlineMapSpec = ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}

// Install closes forwarding for protected CIDRs, loads the BPF guard with a
// zero deadline, and then routes protected traffic through it. Forwarding
// stays closed until [Fence.Arm] writes a future deadline. Installing again
// is safe and closes forwarding.
func (f *Fence) Install(ctx context.Context) error {
	current, err := command.Run(ctx, 2*time.Second, "iptables", "-w", "1", "-S", "FORWARD")
	if err != nil {
		return err
	}
	var existing []string
	for line := range strings.SplitSeq(current, "\n") {
		if strings.HasPrefix(line, "-A FORWARD ") && !strings.Contains(line, "-j "+chain) {
			existing = append(existing, line)
		}
	}
	if _, err := command.RunWithInput(ctx, 2*time.Second, f.closedRules(existing), "iptables-restore", "--noflush", "-w", "1"); err != nil {
		return err
	}
	if err := f.loadGuard(); err != nil {
		return err
	}
	_, err = command.RunWithInput(ctx, 2*time.Second, f.guardRules(), "iptables-restore", "--noflush", "-w", "1")
	return err
}

// Arm allows forwarding until deadline, measured on the boot clock.
func (f *Fence) Arm(deadline time.Duration) error {
	if deadline <= bootclock.Now() {
		return fmt.Errorf("an expired grant cannot open forwarding")
	}
	return f.writeDeadline(uint64(deadline))
}

// Close stops forwarding immediately.
func (f *Fence) Close() error {
	return f.writeDeadline(0)
}

func (f *Fence) loadGuard() error {
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return fmt.Errorf("failed to create BPF directory: %w", err)
	}
	deadlines, err := ebpf.LoadPinnedMap(f.mapPath, nil)
	if errors.Is(err, os.ErrNotExist) {
		deadlines, err = ebpf.NewMap(&deadlineMapSpec)
		if err != nil {
			return fmt.Errorf("failed to create deadline map: %w", err)
		}
		if err := deadlines.Pin(f.mapPath); err != nil {
			return errors.Join(fmt.Errorf("failed to pin deadline map: %w", err), deadlines.Close())
		}
	} else if err != nil {
		return fmt.Errorf("failed to open deadline map: %w", err)
	}
	defer deadlines.Close()
	if err := checkDeadlineMap(deadlines); err != nil {
		return err
	}
	if err := deadlines.Put(uint32(0), uint64(0)); err != nil {
		return fmt.Errorf("failed to reset deadline: %w", err)
	}

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: guardInstructions(deadlines.FD()),
	})
	if err != nil {
		return fmt.Errorf("failed to load forwarding guard: %w", err)
	}
	defer program.Close()
	// Forwarding is already closed, so replacing the pin cannot open a gap.
	// Replacing it also drops any program code from an older version.
	if err := os.Remove(f.programPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove old forwarding guard: %w", err)
	}
	if err := program.Pin(f.programPath); err != nil {
		return fmt.Errorf("failed to pin forwarding guard: %w", err)
	}
	return nil
}

// guardInstructions returns a socket filter that matches (returns 1) while
// the boot clock is before the deadline in map key 0, and otherwise returns 0.
func guardInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		// key = 0, stored on the stack
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "reject"),
		// R6 = deadline in nanoseconds
		asm.LoadMem(asm.R6, asm.R0, 0, asm.DWord),
		asm.FnKtimeGetBootNs.Call(),
		asm.JGE.Reg(asm.R0, asm.R6, "reject"),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("reject"),
		asm.Return(),
	}
}

func (f *Fence) writeDeadline(nanoseconds uint64) error {
	deadlines, err := ebpf.LoadPinnedMap(f.mapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to open deadline map: %w", err)
	}
	defer deadlines.Close()
	if err := checkDeadlineMap(deadlines); err != nil {
		return err
	}
	if err := deadlines.Put(uint32(0), nanoseconds); err != nil {
		return fmt.Errorf("failed to write deadline: %w", err)
	}
	return nil
}

func checkDeadlineMap(deadlines *ebpf.Map) error {
	if deadlines.Type() != deadlineMapSpec.Type || deadlines.KeySize() != deadlineMapSpec.KeySize ||
		deadlines.ValueSize() != deadlineMapSpec.ValueSize || deadlines.MaxEntries() != deadlineMapSpec.MaxEntries {
		return fmt.Errorf("unexpected deadline map format at the pinned path")
	}
	return nil
}

// closedRules returns an iptables-restore input that closes forwarding for
// protected CIDRs. The guard jumps go first, ahead of any accept rule,
// including those for established connections. Other forwarding rules on this
// dedicated NAT are kept, and old guard jumps are removed so repeated installs
// do not stack them.
func (f *Fence) closedRules(existing []string) string {
	rules := "*filter\n:FORWARD DROP [0:0]\n:" + chain + " - [0:0]\n-F " + chain + "\n-A " + chain + " -j DROP\n-F FORWARD\n"
	for _, prefix := range f.protected {
		for _, direction := range []string{"-s", "-d"} {
			rules += fmt.Sprintf("-A FORWARD %s %s -j %s\n", direction, prefix, chain)
		}
	}
	for _, line := range existing {
		rules += line + "\n"
	}
	return rules + "COMMIT\n"
}

// guardRules returns an iptables-restore input that lets protected traffic
// through only while the pinned BPF program matches.
func (f *Fence) guardRules() string {
	return "*filter\n-F " + chain + "\n" +
		"-A " + chain + " -m bpf --object-pinned " + f.programPath + " -j RETURN\n" +
		"-A " + chain + " -j DROP\nCOMMIT\n"
}
