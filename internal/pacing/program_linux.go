package pacing

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Offsets of the struct __sk_buff fields the programs use, from
// include/uapi/linux/bpf.h. They are part of the kernel's stable API.
const (
	skbLen      = 0
	skbMark     = 8
	skbProtocol = 16
	skbData     = 76
	skbDataEnd  = 80
	skbTstamp   = 152
	skbWireLen  = 160
	skbGSOSegs  = 164
)

// Offsets into an Ethernet frame carrying IPv4. tc programs see the frame
// from its Ethernet header on both ingress and egress.
const (
	ipSourceOffset      = 14 + 12
	ipDestinationOffset = 14 + 16
	ipHeaderEnd         = 14 + 20
)

// Return codes of a direct-action tc program.
const (
	tcActionOK   = 0
	tcActionShot = 2
)

// Layout of the limits map's one value: the four costs [Limits.costs]
// returns, then the monotonic time in nanoseconds until which they apply.
const (
	limitAggregateByte   = 0
	limitAggregatePacket = 8
	limitWorkerByte      = 16
	limitWorkerPacket    = 24
	limitExpiry          = 32
	limitsSize           = 40
)

// Layout of the clocks map's one value: the aggregate's departure clocks, in
// nanoseconds on the monotonic clock.
const (
	clockBytes   = 0
	clockPackets = 8
	clocksSize   = 16
)

// Layout of a worker's value: its departure clocks and its counters.
const (
	workerClockBytes   = 0
	workerClockPackets = 8
	workerBytes        = 16
	workerPackets      = 24
	workerWaited       = 32
	workerDropped      = 40
	workerSize         = 48
)

// Layout of a direction's value in the per-CPU stats map.
const (
	statBytes   = 0
	statPackets = 8
	statWaited  = 16
	statDropped = 24
	statSize    = 32
)

// Directions index the stats map.
const (
	directionUpload   = 0
	directionDownload = 1
)

// Pacing timing. A packet that would have to wait longer than horizon is
// dropped instead, which tells the sender to slow down and bounds how much
// the qdiscs hold: horizon times the cap. Bursts let a worker, or all
// traffic, send that much time's worth at once after being idle, so a light
// worker's short bursts don't wait. The aggregate's burst is small, because
// AWS counts short bursts above the allowance too.
const (
	horizon        = 20_000_000 // 20 ms, in nanoseconds
	workerBurst    = 2_000_000  // 2 ms
	aggregateBurst = 250_000    // 0.25 ms
	// longWait is how long a packet must wait to count as waiting. The fair
	// shares treat a worker whose packets waited as wanting more. Shorter
	// waits are a burst being smoothed out: an 8 KiB write arrives as six
	// packets at once and overruns the shared clock's burst by microseconds.
	longWait = 1_000_000 // 1 ms
)

// limitsLifetime is how long the kernel enforces limits after the daemon last
// wrote them. The daemon writes them four times a second, and a restart
// takes a few seconds.
const limitsLifetime = 10 * time.Second

// maxWorkers is how many workers the pacer tracks at once. The least recently
// seen worker is forgotten first. A VPC CIDR holds at most 65,536 addresses.
const maxWorkers = 65536

var (
	limitsSpec = ebpf.MapSpec{Name: "natpair_limits", Type: ebpf.Array, KeySize: 4, ValueSize: limitsSize, MaxEntries: 1}
	clocksSpec = ebpf.MapSpec{Name: "natpair_clocks", Type: ebpf.Array, KeySize: 4, ValueSize: clocksSize, MaxEntries: 1}
	// workersSpec keys each worker by its IPv4 address as it appears in the
	// packet, in network byte order.
	workersSpec = ebpf.MapSpec{Name: "natpair_workers", Type: ebpf.LRUHash, KeySize: 4, ValueSize: workerSize, MaxEntries: maxWorkers}
	statsSpec   = ebpf.MapSpec{Name: "natpair_stats", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: statSize, MaxEntries: 2}
)

// ipv4Protocol is ETH_P_IP as __sk_buff.protocol holds it: in network byte
// order, read as a native integer.
var ipv4Protocol = int32(binary.NativeEndian.Uint16([]byte{0x08, 0x00}))

// markInstructions returns the ingress program. It copies an IPv4 packet's
// source address into the packet's mark, unless something already marked
// it. A forwarded packet keeps its mark until it leaves, after source NAT has
// replaced its source address, so the egress program can still tell which
// worker sent it. Packets the NAT itself sends start with no mark, which is
// how the egress program tells them apart and leaves them alone.
func markInstructions() asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, skbMark, asm.Word),
		asm.JNE.Imm(asm.R2, 0, "out"),
		asm.LoadMem(asm.R2, asm.R1, skbProtocol, asm.Word),
		asm.JNE.Imm(asm.R2, ipv4Protocol, "out"),
		asm.LoadMem(asm.R2, asm.R1, skbData, asm.Word),
		asm.LoadMem(asm.R3, asm.R1, skbDataEnd, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, ipHeaderEnd),
		asm.JGT.Reg(asm.R4, asm.R3, "out"),
		asm.LoadMem(asm.R4, asm.R2, ipSourceOffset, asm.Word),
		asm.StoreMem(asm.R1, skbMark, asm.R4, asm.Word),
		asm.Mov.Imm(asm.R0, tcActionOK).WithSymbol("out"),
		asm.Return(),
	}
}

// Stack slots of the egress program, as offsets from the frame pointer.
const (
	slotKey       = -8
	slotDepart    = -16
	slotCostWB    = -24 // worker, bytes
	slotCostWP    = -32 // worker, packets
	slotCostAB    = -40 // aggregate, bytes
	slotCostAP    = -48 // aggregate, packets
	slotDirection = -56
	slotSegments  = -64
	slotWaited    = -72
	slotZero      = -72 - workerSize
)

// paceInstructions returns the egress program. It paces packets that arrived
// marked, so were forwarded, and involve a protected worker: an upload whose
// mark is a worker's address, or a download to a worker. It gives each
// packet a departure time from the worker's own clocks, and from the
// aggregate's if the worker's didn't delay it, and sch_fq holds the packet
// until then. It leaves every other packet alone.
//
// Each clock is a token bucket in departure-time form. A packet reserves its
// cost on the clock with an atomic add, so CPUs never lose each other's
// reservations, and leaves no earlier than the start of its reservation. A
// clock that fell more than its burst behind now restarts from there. A
// packet that would leave later than horizon from now is dropped, and its
// reservations are given back.
//
// The limits map holds each clock's cost per byte and per packet. Zero means
// that clock doesn't limit.
func paceInstructions(protected []netip.Prefix, limits, clocks, workers, stats *ebpf.Map) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R2, asm.R6, skbMark, asm.Word),
		asm.JEq.Imm(asm.R2, 0, "pass"),
		asm.LoadMem(asm.R3, asm.R6, skbProtocol, asm.Word),
		asm.JNE.Imm(asm.R3, ipv4Protocol, "pass"),
		// An upload: the mark is the worker that sent it.
		asm.StoreImm(asm.RFP, slotDirection, directionUpload, asm.Word),
		asm.Mov.Reg(asm.R7, asm.R2),
	}
	ins = append(ins, matchProtected(asm.R7, protected, "keyed")...)
	ins = append(ins,
		// A download: the destination is the worker that receives it.
		asm.StoreImm(asm.RFP, slotDirection, directionDownload, asm.Word),
		asm.LoadMem(asm.R2, asm.R6, skbData, asm.Word),
		asm.LoadMem(asm.R3, asm.R6, skbDataEnd, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, ipHeaderEnd),
		asm.JGT.Reg(asm.R4, asm.R3, "pass"),
		asm.LoadMem(asm.R7, asm.R2, ipDestinationOffset, asm.Word),
	)
	ins = append(ins, matchProtected(asm.R7, protected, "keyed")...)
	ins = append(ins,
		asm.Ja.Label("pass"),

		asm.StoreMem(asm.RFP, slotKey, asm.R7, asm.Word).WithSymbol("keyed"),
		// R8 = bytes on the wire, which counts every segment's headers of a
		// GRO-merged packet. Programs run by BPF_PROG_TEST_RUN may leave it 0.
		asm.LoadMem(asm.R8, asm.R6, skbWireLen, asm.Word),
		asm.JNE.Imm(asm.R8, 0, "sized"),
		asm.LoadMem(asm.R8, asm.R6, skbLen, asm.Word),
		// Packets: a GRO-merged packet leaves as gso_segs packets.
		asm.LoadMem(asm.R1, asm.R6, skbGSOSegs, asm.Word).WithSymbol("sized"),
		asm.JNE.Imm(asm.R1, 0, "counted"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreMem(asm.RFP, slotSegments, asm.R1, asm.DWord).WithSymbol("counted"),
		// The library has no 64-bit store of an immediate, so stores of zero
		// go through a register.
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.RFP, slotWaited, asm.R1, asm.DWord),
		// R9 = now. sch_fq compares departure times with this clock.
		asm.FnKtimeGetNs.Call(),
		asm.Mov.Reg(asm.R9, asm.R0),
		// Limits nobody renewed, because no daemon manages pacing any more,
		// no longer apply.
		asm.LoadMapValue(asm.R1, limits.FD(), 0),
		asm.LoadMem(asm.R1, asm.R1, limitExpiry, asm.DWord),
		asm.JGT.Reg(asm.R9, asm.R1, "pass"),

		// R7 = the worker's value, created on first sight.
		asm.LoadMapPtr(asm.R1, workers.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, slotKey),
		asm.FnMapLookupElem.Call(),
		asm.JNE.Imm(asm.R0, 0, "found"),
	)
	ins = append(ins, asm.Mov.Imm(asm.R1, 0))
	for offset := int16(0); offset < workerSize; offset += 8 {
		ins = append(ins, asm.StoreMem(asm.RFP, slotZero+offset, asm.R1, asm.DWord))
	}
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, workers.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, slotKey),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, slotZero),
		asm.Mov.Imm(asm.R4, int32(ebpf.UpdateNoExist)),
		asm.FnMapUpdateElem.Call(),
		asm.LoadMapPtr(asm.R1, workers.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, slotKey),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.Mov.Reg(asm.R7, asm.R0).WithSymbol("found"),

		// Each clock's cost for this packet.
		asm.LoadMapValue(asm.R5, limits.FD(), 0),
	)
	ins = append(ins, byteCost(limitWorkerByte, slotCostWB)...)
	ins = append(ins, packetCost(limitWorkerPacket, slotCostWP)...)
	ins = append(ins, byteCost(limitAggregateByte, slotCostAB)...)
	ins = append(ins, packetCost(limitAggregatePacket, slotCostAP)...)
	ins = append(ins, asm.StoreMem(asm.RFP, slotDepart, asm.R9, asm.DWord))
	ins = append(ins, reserve(asm.R7, workerClockBytes, slotCostWB, workerBurst, "wb")...)
	ins = append(ins, reserve(asm.R7, workerClockPackets, slotCostWP, workerBurst, "wp")...)
	ins = append(ins, beyondHorizon("drop_worker")...)
	ins = append(ins,
		// A packet its worker's clock delays skips the shared clocks, so a
		// worker's own queue never makes other workers wait. Its clock
		// already holds it to its share, and the daemon keeps the shares'
		// sum under the cap.
		asm.LoadMem(asm.R1, asm.RFP, slotDepart, asm.DWord),
		asm.JGT.Reg(asm.R1, asm.R9, "accept"),
		asm.LoadMapValue(asm.R4, clocks.FD(), 0),
	)
	ins = append(ins, reserve(asm.R4, clockBytes, slotCostAB, aggregateBurst, "ab")...)
	ins = append(ins, reserve(asm.R4, clockPackets, slotCostAP, aggregateBurst, "ap")...)
	ins = append(ins, beyondHorizon("drop_all")...)
	ins = append(ins,
		// Accepted. A packet that must wait gets its departure time.
		asm.LoadMem(asm.R1, asm.RFP, slotDepart, asm.DWord).WithSymbol("accept"),
		asm.JLE.Reg(asm.R1, asm.R9, "accounted"),
		asm.StoreMem(asm.R6, skbTstamp, asm.R1, asm.DWord),
		asm.Sub.Reg(asm.R1, asm.R9),
		asm.JLE.Imm(asm.R1, longWait, "accounted"),
		asm.LoadMem(asm.R1, asm.RFP, slotSegments, asm.DWord),
		asm.StoreMem(asm.RFP, slotWaited, asm.R1, asm.DWord),
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, workerWaited),
		asm.AddAtomic.Mem(asm.R7, asm.R8, asm.DWord, workerBytes).WithSymbol("accounted"),
		asm.LoadMem(asm.R1, asm.RFP, slotSegments, asm.DWord),
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, workerPackets),
	)
	ins = append(ins, lookupStats(stats, "pass")...)
	ins = append(ins, addStat(statBytes, asm.R8)...)
	ins = append(ins, asm.LoadMem(asm.R1, asm.RFP, slotSegments, asm.DWord))
	ins = append(ins, addStat(statPackets, asm.R1)...)
	ins = append(ins, asm.LoadMem(asm.R1, asm.RFP, slotWaited, asm.DWord))
	ins = append(ins, addStat(statWaited, asm.R1)...)
	ins = append(ins, asm.Ja.Label("pass"))

	// Dropped: give back the reservations, so the clocks only count packets
	// that leave. Otherwise a worker sending faster than its share would push
	// its clock ever further ahead and lose every packet.
	ins = append(ins, asm.LoadMapValue(asm.R4, clocks.FD(), 0).WithSymbol("drop_all"))
	ins = append(ins, release(asm.R4, clockBytes, slotCostAB)...)
	ins = append(ins, release(asm.R4, clockPackets, slotCostAP)...)
	ins = append(ins, asm.Mov.Imm(asm.R1, 0).WithSymbol("drop_worker"))
	ins = append(ins, release(asm.R7, workerClockBytes, slotCostWB)...)
	ins = append(ins, release(asm.R7, workerClockPackets, slotCostWP)...)
	ins = append(ins,
		asm.LoadMem(asm.R1, asm.RFP, slotSegments, asm.DWord),
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, workerWaited),
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, workerDropped),
	)
	ins = append(ins, lookupStats(stats, "shot")...)
	ins = append(ins, asm.LoadMem(asm.R1, asm.RFP, slotSegments, asm.DWord))
	ins = append(ins, addStat(statDropped, asm.R1)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, tcActionShot).WithSymbol("shot"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, tcActionOK).WithSymbol("pass"),
		asm.Return(),
	)
	return ins
}

// matchProtected jumps to label if the IPv4 address in reg, in network byte
// order, is in one of the prefixes. It compares with 32-bit operations, so a
// mask with its top bit set isn't sign-extended.
func matchProtected(reg asm.Register, prefixes []netip.Prefix, label string) asm.Instructions {
	var ins asm.Instructions
	for _, prefix := range prefixes {
		network := prefix.Masked().Addr().As4()
		var maskBytes [4]byte
		for bit := range prefix.Bits() {
			maskBytes[bit/8] |= 0x80 >> (bit % 8)
		}
		ins = append(ins,
			asm.Mov.Reg32(asm.R1, reg),
			asm.And.Imm32(asm.R1, int32(binary.NativeEndian.Uint32(maskBytes[:]))),
			asm.JEq.Imm32(asm.R1, int32(binary.NativeEndian.Uint32(network[:])), label),
		)
	}
	return ins
}

// byteCost stores the packet's cost on one clock, from its per-byte cost in
// the limits value R5 and its size in R8.
func byteCost(limit, slot int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.R5, limit, asm.DWord),
		asm.Mul.Reg(asm.R1, asm.R8),
		asm.RSh.Imm(asm.R1, byteCostShift),
		asm.StoreMem(asm.RFP, slot, asm.R1, asm.DWord),
	}
}

// packetCost stores the packet's cost on one clock, from its per-packet cost
// in the limits value R5 and its segment count.
func packetCost(limit, slot int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.R5, limit, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, slotSegments, asm.DWord),
		asm.Mul.Reg(asm.R1, asm.R2),
		asm.StoreMem(asm.RFP, slot, asm.R1, asm.DWord),
	}
}

// reserve adds the cost in slot to the clock at ptr+offset and moves the
// departure time to the start of the reservation if that is later. R9 holds
// now. It uses R1 to R3.
func reserve(ptr asm.Register, offset, slot int16, burst int32, label string) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.RFP, slot, asm.DWord),
		asm.JEq.Imm(asm.R1, 0, label+"_done"),
		asm.Mov.Reg(asm.R2, asm.R1),
		// R2 = the clock before this packet's reservation
		fetchAdd(ptr, asm.R2, offset),
		asm.Mov.Reg(asm.R3, asm.R2),
		asm.Add.Imm(asm.R3, burst),
		asm.JGE.Reg(asm.R3, asm.R9, label+"_busy"),
		// Idle for longer than the burst: restart the clock at now - burst,
		// plus this packet's cost. Another CPU's reservation in between is
		// lost, which only happens while traffic is light.
		asm.Mov.Reg(asm.R3, asm.R9),
		asm.Sub.Imm(asm.R3, burst),
		asm.Add.Reg(asm.R3, asm.R1),
		asm.StoreMem(ptr, offset, asm.R3, asm.DWord),
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.JGE.Reg(asm.R2, asm.R9, label+"_late").WithSymbol(label + "_busy"),
		asm.Mov.Reg(asm.R2, asm.R9),
		asm.LoadMem(asm.R3, asm.RFP, slotDepart, asm.DWord).WithSymbol(label + "_late"),
		asm.JGE.Reg(asm.R3, asm.R2, label+"_done"),
		asm.StoreMem(asm.RFP, slotDepart, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R1, 0).WithSymbol(label + "_done"),
	}
}

// fetchAdd returns `src = atomic_fetch_add((u64 *)(dst + offset), src)`.
// cilium/ebpf v0.22 writes an atomic instruction's immediate from Constant
// before it fills Constant in, so its FetchAdd comes out as a plain add that
// leaves src unchanged. Setting Constant here writes the right immediate.
func fetchAdd(dst, src asm.Register, offset int16) asm.Instruction {
	ins := asm.FetchAdd.Mem(dst, src, asm.DWord, offset)
	ins.Constant = int64(asm.FetchAdd >> 8)
	return ins
}

// release gives back the cost in slot to the clock at ptr+offset.
func release(ptr asm.Register, offset, slot int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R2, asm.RFP, slot, asm.DWord),
		asm.Mov.Imm(asm.R1, 0),
		asm.Sub.Reg(asm.R1, asm.R2),
		asm.AddAtomic.Mem(ptr, asm.R1, asm.DWord, offset),
	}
}

// beyondHorizon jumps to label if the departure time is more than horizon
// after now.
func beyondHorizon(label string) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R1, asm.RFP, slotDepart, asm.DWord),
		asm.Sub.Reg(asm.R1, asm.R9),
		asm.JGT.Imm(asm.R1, horizon, label),
	}
}

// lookupStats sets R0 to this CPU's stats for the packet's direction, or
// jumps to label if the lookup fails.
func lookupStats(stats *ebpf.Map, label string) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R1, stats.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, slotDirection),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, label),
	}
}

// addStat adds reg to one of the per-CPU counters at R0. Only this CPU
// writes them, so the add needn't be atomic.
func addStat(offset int16, reg asm.Register) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R2, asm.R0, offset, asm.DWord),
		asm.Add.Reg(asm.R2, reg),
		asm.StoreMem(asm.R0, offset, asm.R2, asm.DWord),
	}
}

// programs holds the loaded maps and programs.
type programs struct {
	limits, clocks, workers, stats *ebpf.Map
	mark, pace                     *ebpf.Program
}

// loadPrograms creates fresh maps and loads both programs.
func loadPrograms(protected []netip.Prefix) (*programs, error) {
	p := &programs{}
	var err error
	for _, m := range []struct {
		target **ebpf.Map
		spec   *ebpf.MapSpec
	}{{&p.limits, &limitsSpec}, {&p.clocks, &clocksSpec}, {&p.workers, &workersSpec}, {&p.stats, &statsSpec}} {
		if *m.target, err = ebpf.NewMap(m.spec); err != nil {
			p.close()
			return nil, fmt.Errorf("failed to create pacing map %s: %w", m.spec.Name, err)
		}
	}
	if p.mark, err = ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "natpair_mark", Type: ebpf.SchedCLS, License: "GPL", Instructions: markInstructions(),
	}); err != nil {
		p.close()
		return nil, fmt.Errorf("failed to load the pacing mark program: %w", err)
	}
	if p.pace, err = ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "natpair_pace", Type: ebpf.SchedCLS, License: "GPL",
		Instructions: paceInstructions(protected, p.limits, p.clocks, p.workers, p.stats),
	}); err != nil {
		p.close()
		return nil, fmt.Errorf("failed to load the pacing program: %w", err)
	}
	return p, nil
}

func (p *programs) close() {
	for _, m := range []*ebpf.Map{p.limits, p.clocks, p.workers, p.stats} {
		if m != nil {
			_ = m.Close()
		}
	}
	for _, prog := range []*ebpf.Program{p.mark, p.pace} {
		if prog != nil {
			_ = prog.Close()
		}
	}
}

// setLimits writes the limits the programs enforce until limitsLifetime from
// now. Programs read them per packet, so a change applies to the next packet.
func (p *programs) setLimits(l Limits) error {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return fmt.Errorf("failed to read the monotonic clock: %w", err)
	}
	costs := l.costs()
	value := [5]uint64{costs[0], costs[1], costs[2], costs[3], uint64(now.Nano() + limitsLifetime.Nanoseconds())}
	if err := p.limits.Put(uint32(0), value); err != nil {
		return fmt.Errorf("failed to write pacing limits: %w", err)
	}
	return nil
}
