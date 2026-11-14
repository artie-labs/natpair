package guard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// XDP return codes, from include/uapi/linux/bpf.h.
const (
	xdpDrop = 1
	xdpPass = 2
)

// The window for probe replies past the budget. Like the budget's tick, it
// is a power of two of nanoseconds.
const (
	// exemptShift sets the window for probe replies past the budget: 2^24
	// ns, about 16.8 ms.
	exemptShift = 24
	// exemptCap is how many probe replies each CPU passes past the budget in
	// one exempt window, about 7,600 a second. A probe round takes about 15
	// replies and a handshake check 40, often in the same few milliseconds.
	// Forged replies past the cap are dropped like other packets, so they
	// can't take more than about 1.5% of a CPU.
	exemptCap = 128
)

// cpuState is the program's per-CPU state, which only the program writes.
// The field order is the layout the instructions use.
type cpuState struct {
	// Tick is the budget's current window, and Count the packets seen in it.
	Tick, Count uint64
	// ExemptWindow is the current window for probe replies past the budget,
	// and ExemptCount the ones passed in it.
	ExemptWindow, ExemptCount uint64
	// Passed and Shed count the packets passed and dropped while the
	// program had a budget.
	Passed, Shed uint64
}

// Offsets of cpuState's fields.
const (
	offTick         = 0
	offCount        = 8
	offExemptWindow = 16
	offExemptCount  = 24
	offPassed       = 32
	offShed         = 40
)

// match is what the program lets through past its budget: TCP to the shared
// address from the receiver's port to the shared canary's ports.
type match struct {
	shared                 netip.Addr
	receiverPort           uint16
	firstPort, lastPort    uint16
	tickShift, exemptShift int
}

// program is the loaded XDP program and its maps. The daemon writes budgets
// and the program writes states, so neither overwrites the other's values.
type program struct {
	budgets *ebpf.Map
	states  *ebpf.Map
	prog    *ebpf.Program
	cpus    int
}

func loadProgram(m match) (*program, error) {
	if !m.shared.Is4() {
		return nil, fmt.Errorf("the overload guard needs an IPv4 shared address, got %s", m.shared)
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("failed to count CPUs: %w", err)
	}
	budgets, err := ebpf.NewMap(&ebpf.MapSpec{Name: "guard_budget", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return nil, fmt.Errorf("failed to create the overload guard's budget map: %w", err)
	}
	states, err := ebpf.NewMap(&ebpf.MapSpec{Name: "guard_state", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 48, MaxEntries: 1})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to create the overload guard's state map: %w", err), budgets.Close())
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "natpair_guard",
		Type:         ebpf.XDP,
		License:      "GPL",
		Instructions: instructions(budgets.FD(), states.FD(), m),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to load the overload guard: %w", err), budgets.Close(), states.Close())
	}
	return &program{budgets: budgets, states: states, prog: prog, cpus: cpus}, nil
}

func (p *program) Close() error {
	return errors.Join(p.prog.Close(), p.budgets.Close(), p.states.Close())
}

// setBudget gives every CPU the same budget of packets per tick. 0 means no
// limit.
func (p *program) setBudget(budget uint64) error {
	values := make([]uint64, p.cpus)
	for i := range values {
		values[i] = budget
	}
	if err := p.budgets.Put(uint32(0), values); err != nil {
		return fmt.Errorf("failed to set the overload guard's budget: %w", err)
	}
	return nil
}

// counters returns each CPU's passed and dropped packet counts.
func (p *program) counters() (passed, shed []uint64, err error) {
	var states []cpuState
	if err := p.states.Lookup(uint32(0), &states); err != nil {
		return nil, nil, fmt.Errorf("failed to read the overload guard's counters: %w", err)
	}
	for _, s := range states {
		passed = append(passed, s.Passed)
		shed = append(shed, s.Shed)
	}
	return passed, shed, nil
}

// instructions returns the XDP program.
//
// Fast path, budget 0: one per-CPU map lookup and two comparisons, then
// XDP_PASS. With a budget, it counts the packet in the CPU's current tick
// and passes it while the count is within the budget. Past the budget it
// passes anything that isn't IPv4, and up to exemptCap probe replies per
// exempt window, and drops the rest.
func instructions(budgetsFD, statesFD int, m match) asm.Instructions {
	shared := m.shared.As4()
	// The program loads the address from the packet in the host's byte order.
	sharedWord := binary.NativeEndian.Uint32(shared[:])
	return slices.Concat(asm.Instructions{
		// R6 = the xdp_md context, kept across calls.
		asm.Mov.Reg(asm.R6, asm.R1),
		// key = 0, stored on the stack.
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, budgetsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		// R7 = budget, 0 for no limit.
		asm.LoadMem(asm.R7, asm.R0, 0, asm.DWord),
		asm.JEq.Imm(asm.R7, 0, "pass"),

		// R8 = this CPU's state.
		asm.LoadMapPtr(asm.R1, statesFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.Mov.Reg(asm.R8, asm.R0),
		// R9 = now, R0 = the current tick. A new tick starts a new count.
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R9, asm.R0),
		asm.RSh.Imm(asm.R0, int32(m.tickShift)),
		asm.LoadMem(asm.R1, asm.R8, offTick, asm.DWord),
		asm.JEq.Reg(asm.R1, asm.R0, "count"),
		asm.StoreMem(asm.R8, offTick, asm.R0, asm.DWord),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R8, offCount, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R8, offCount, asm.DWord).WithSymbol("count"),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, offCount, asm.R1, asm.DWord),
		asm.JLE.Reg(asm.R1, asm.R7, "passed"),

		// Past the budget. R2 = data, R3 = data_end.
		asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
		// Too short for an Ethernet header, so not IPv4: the kernel decides.
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, 14),
		asm.JGT.Reg(asm.R4, asm.R3, "passed"),
		// EtherType 0x0800 is IPv4. Anything else, such as ARP, passes.
		asm.LoadMem(asm.R1, asm.R2, 12, asm.Byte),
		asm.JNE.Imm(asm.R1, 0x08, "passed"),
		asm.LoadMem(asm.R1, asm.R2, 13, asm.Byte),
		asm.JNE.Imm(asm.R1, 0x00, "passed"),
		// A 20-byte IPv4 header, TCP, to the shared address.
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, 14+20),
		asm.JGT.Reg(asm.R4, asm.R3, "drop"),
		asm.LoadMem(asm.R1, asm.R2, 14+9, asm.Byte),
		asm.JNE.Imm(asm.R1, 6, "drop"),
		asm.LoadMem(asm.R1, asm.R2, 14+16, asm.Word),
		asm.JNE.Imm32(asm.R1, int32(sharedWord), "drop"),
		// A fragment after the first has no TCP header.
		asm.LoadMem(asm.R1, asm.R2, 14+6, asm.Byte),
		asm.And.Imm(asm.R1, 0x1f),
		asm.JNE.Imm(asm.R1, 0, "drop"),
		asm.LoadMem(asm.R1, asm.R2, 14+7, asm.Byte),
		asm.JNE.Imm(asm.R1, 0, "drop"),
		// R2 = data + the IPv4 header's length, 20 to 60 bytes.
		asm.LoadMem(asm.R1, asm.R2, 14, asm.Byte),
		asm.And.Imm(asm.R1, 0x0f),
		asm.JLT.Imm(asm.R1, 5, "drop"),
		asm.LSh.Imm(asm.R1, 2),
		asm.Add.Reg(asm.R2, asm.R1),
		// The TCP ports.
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, 14+4),
		asm.JGT.Reg(asm.R4, asm.R3, "drop"),
	}, loadPort(asm.R2, 14), asm.Instructions{
		asm.JNE.Imm(asm.R1, int32(m.receiverPort), "drop"),
	}, loadPort(asm.R2, 16), asm.Instructions{
		asm.JLT.Imm(asm.R1, int32(m.firstPort), "drop"),
		asm.JGT.Imm(asm.R1, int32(m.lastPort), "drop"),

		// A probe reply: pass it if this CPU's exempt window has room.
		asm.RSh.Imm(asm.R9, int32(m.exemptShift)),
		asm.LoadMem(asm.R1, asm.R8, offExemptWindow, asm.DWord),
		asm.JEq.Reg(asm.R1, asm.R9, "exempt"),
		asm.StoreMem(asm.R8, offExemptWindow, asm.R9, asm.DWord),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R8, offExemptCount, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R8, offExemptCount, asm.DWord).WithSymbol("exempt"),
		asm.JGE.Imm(asm.R1, exemptCap, "drop"),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, offExemptCount, asm.R1, asm.DWord),

		asm.LoadMem(asm.R1, asm.R8, offPassed, asm.DWord).WithSymbol("passed"),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, offPassed, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, xdpPass),
		asm.Return(),

		asm.LoadMem(asm.R1, asm.R8, offShed, asm.DWord).WithSymbol("drop"),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, offShed, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, xdpDrop),
		asm.Return(),

		asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("pass"),
		asm.Return(),
	})
}

// loadPort loads the big-endian 16-bit port at base+offset into R1. It uses
// R5.
func loadPort(base asm.Register, offset int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, base, offset, asm.Byte),
		asm.LSh.Imm(asm.R1, 8),
		asm.LoadMem(asm.R5, base, offset+1, asm.Byte),
		asm.Or.Reg(asm.R1, asm.R5),
	}
}
