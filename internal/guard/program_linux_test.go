//go:build linux && privileged

package guard

import (
	"encoding/binary"
	"math"
	"net/netip"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var sharedAddress = netip.MustParseAddr("10.0.1.100")

// testMatch is production's match with windows of 2^40 ns (18 minutes) for
// the budget and 2^44 ns (5 hours) for probe replies, so a test never
// crosses into a new window between two packets.
var testMatch = match{shared: sharedAddress, receiverPort: 443, firstPort: 61000, lastPort: 65535, tickShift: 40, exemptShift: 44}

// pinCPU keeps the test on one CPU, whose per-CPU state the program uses.
func pinCPU(t testing.TB) {
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	var set unix.CPUSet
	set.Set(0)
	require.NoError(t, unix.SchedSetaffinity(0, &set))
}

func mustLoad(t testing.TB, m match) *program {
	p, err := loadProgram(m)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, p.Close()) })
	return p
}

// packet is an Ethernet frame with an IPv4 header, unless etherType says
// otherwise, and 4 bytes of ports.
type packet struct {
	etherType        uint16
	ihl              int
	protocol         byte
	fragment         uint16
	dst              netip.Addr
	srcPort, dstPort uint16
}

// probeReply is a reply from the receiver to the shared canary's lowest
// port.
var probeReply = packet{etherType: 0x0800, ihl: 5, protocol: 6, dst: sharedAddress, srcPort: 443, dstPort: 61000}

func (p packet) bytes() []byte {
	frame := make([]byte, 14, 128)
	binary.BigEndian.PutUint16(frame[12:], p.etherType)
	if p.etherType != 0x0800 {
		return append(frame, make([]byte, 46)...)
	}
	// A header length below 5 still gets the 20-byte header, so only the
	// length field is wrong.
	header := make([]byte, max(p.ihl, 5)*4)
	header[0] = 0x40 | byte(p.ihl)
	binary.BigEndian.PutUint16(header[2:], uint16(len(header)+20))
	binary.BigEndian.PutUint16(header[6:], p.fragment)
	header[8] = 64
	header[9] = p.protocol
	copy(header[12:], netip.MustParseAddr("192.0.2.1").AsSlice())
	copy(header[16:], p.dst.AsSlice())
	ports := make([]byte, 20)
	binary.BigEndian.PutUint16(ports[0:], p.srcPort)
	binary.BigEndian.PutUint16(ports[2:], p.dstPort)
	return append(append(frame, header...), ports...)
}

func run(t testing.TB, p *program, data []byte) uint32 {
	result, err := p.prog.Run(&ebpf.RunOptions{Data: data})
	require.NoError(t, err)
	return result
}

func totals(t testing.TB, p *program) (passed, shed uint64) {
	passedPerCPU, shedPerCPU, err := p.counters()
	require.NoError(t, err)
	for i := range passedPerCPU {
		passed += passedPerCPU[i]
		shed += shedPerCPU[i]
	}
	return passed, shed
}

func TestProgram(t *testing.T) {
	pinCPU(t)
	worker := packet{etherType: 0x0800, ihl: 5, protocol: 17, dst: netip.MustParseAddr("203.0.113.7"), srcPort: 40000, dstPort: 53}.bytes()
	{
		// Budget 0 passes everything without counting
		p := mustLoad(t, testMatch)
		for range 3 {
			assert.Equal(t, uint32(xdpPass), run(t, p, worker))
		}
		passed, shed := totals(t, p)
		assert.Zero(t, passed+shed)
	}
	{
		// Within the budget everything passes, and past it worker packets drop
		p := mustLoad(t, testMatch)
		require.NoError(t, p.setBudget(2))
		assert.Equal(t, uint32(xdpPass), run(t, p, worker))
		assert.Equal(t, uint32(xdpPass), run(t, p, worker))
		assert.Equal(t, uint32(xdpDrop), run(t, p, worker))
		passed, shed := totals(t, p)
		assert.Equal(t, [2]uint64{2, 1}, [2]uint64{passed, shed})
		// Taking the budget off passes everything again
		require.NoError(t, p.setBudget(0))
		assert.Equal(t, uint32(xdpPass), run(t, p, worker))
	}
	{
		// While measuring nothing drops, and everything is counted
		p := mustLoad(t, testMatch)
		require.NoError(t, p.setBudget(math.MaxUint64))
		for range 5 {
			assert.Equal(t, uint32(xdpPass), run(t, p, worker))
		}
		passed, shed := totals(t, p)
		assert.Equal(t, [2]uint64{5, 0}, [2]uint64{passed, shed})
	}
}

func TestProgramPastTheBudget(t *testing.T) {
	pinCPU(t)
	p := mustLoad(t, testMatch)
	require.NoError(t, p.setBudget(1))
	// Use up the budget
	require.Equal(t, uint32(xdpPass), run(t, p, probeReply.bytes()))

	passes := map[string]packet{
		"ARP":                 {etherType: 0x0806},
		"IPv6":                {etherType: 0x86dd},
		"probe reply":         probeReply,
		"highest probe port":  {etherType: 0x0800, ihl: 5, protocol: 6, dst: sharedAddress, srcPort: 443, dstPort: 65535},
		"IPv4 options":        {etherType: 0x0800, ihl: 6, protocol: 6, dst: sharedAddress, srcPort: 443, dstPort: 61000},
		"first fragment (MF)": {etherType: 0x0800, ihl: 5, protocol: 6, fragment: 0x2000, dst: sharedAddress, srcPort: 443, dstPort: 61000},
	}
	for name, pkt := range passes {
		assert.Equal(t, uint32(xdpPass), run(t, p, pkt.bytes()), name)
	}
	drops := map[string]packet{
		"below the probe ports": {etherType: 0x0800, ihl: 5, protocol: 6, dst: sharedAddress, srcPort: 443, dstPort: 60999},
		"another source port":   {etherType: 0x0800, ihl: 5, protocol: 6, dst: sharedAddress, srcPort: 444, dstPort: 61000},
		"another address":       {etherType: 0x0800, ihl: 5, protocol: 6, dst: netip.MustParseAddr("10.0.1.101"), srcPort: 443, dstPort: 61000},
		"UDP":                   {etherType: 0x0800, ihl: 5, protocol: 17, dst: sharedAddress, srcPort: 443, dstPort: 61000},
		"later fragment":        {etherType: 0x0800, ihl: 5, protocol: 6, fragment: 0x0001, dst: sharedAddress, srcPort: 443, dstPort: 61000},
		"header length below 5": {etherType: 0x0800, ihl: 4, protocol: 6, dst: sharedAddress, srcPort: 443, dstPort: 61000},
	}
	for name, pkt := range drops {
		assert.Equal(t, uint32(xdpDrop), run(t, p, pkt.bytes()), name)
	}
	{
		// An IPv4 frame cut short inside its header
		assert.Equal(t, uint32(xdpDrop), run(t, p, probeReply.bytes()[:30]))
	}
}

func TestProgramCapsProbeReplies(t *testing.T) {
	pinCPU(t)
	p := mustLoad(t, testMatch)
	require.NoError(t, p.setBudget(1))
	reply := probeReply.bytes()
	require.Equal(t, uint32(xdpPass), run(t, p, reply))
	// Forged replies past the budget pass only up to the cap
	for range exemptCap {
		require.Equal(t, uint32(xdpPass), run(t, p, reply))
	}
	assert.Equal(t, uint32(xdpDrop), run(t, p, reply))
	// ARP still passes once the cap is spent
	assert.Equal(t, uint32(xdpPass), run(t, p, packet{etherType: 0x0806}.bytes()))
	passed, shed := totals(t, p)
	assert.Equal(t, [2]uint64{1 + exemptCap + 1, 1}, [2]uint64{passed, shed})
}

func TestLoadProgramRejectsIPv6(t *testing.T) {
	_, err := loadProgram(match{shared: netip.MustParseAddr("2001:db8::1")})
	assert.EqualError(t, err, "the overload guard needs an IPv4 shared address, got 2001:db8::1")
}

// BenchmarkProgram measures the program per packet with BPF_PROG_TEST_RUN,
// against a program that only returns XDP_PASS. Run it as root with
// go test -tags privileged -run '^$' -bench Program ./internal/guard
func BenchmarkProgram(b *testing.B) {
	pinCPU(b)
	worker := packet{etherType: 0x0800, ihl: 5, protocol: 17, dst: netip.MustParseAddr("203.0.113.7"), srcPort: 40000, dstPort: 53}.bytes()
	measure := func(b *testing.B, prog *ebpf.Program, data []byte) {
		const repeat = 10_000_000
		var total float64
		for b.Loop() {
			_, perRun, err := prog.Benchmark(data, repeat, nil)
			require.NoError(b, err)
			total += float64(perRun.Nanoseconds())
		}
		b.ReportMetric(total/float64(b.N), "ns/packet")
	}
	b.Run("pass only", func(b *testing.B) {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.XDP, License: "GPL", Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, xdpPass), asm.Return(),
		}})
		require.NoError(b, err)
		defer prog.Close()
		measure(b, prog, worker)
	})
	b.Run("budget 0", func(b *testing.B) {
		p := mustLoad(b, match{shared: sharedAddress, receiverPort: 443, firstPort: 61000, lastPort: 65535, tickShift: tickShift, exemptShift: exemptShift})
		measure(b, p.prog, worker)
	})
	b.Run("within budget", func(b *testing.B) {
		p := mustLoad(b, testMatch)
		require.NoError(b, p.setBudget(math.MaxUint64))
		measure(b, p.prog, worker)
	})
	b.Run("past budget, dropped", func(b *testing.B) {
		p := mustLoad(b, testMatch)
		require.NoError(b, p.setBudget(1))
		measure(b, p.prog, worker)
	})
	b.Run("past budget, probe reply", func(b *testing.B) {
		// Past the cap, so this is the longest path that drops
		p := mustLoad(b, testMatch)
		require.NoError(b, p.setBudget(1))
		measure(b, p.prog, probeReply.bytes())
	})
}
