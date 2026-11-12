//go:build linux && privileged

package pacing

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// skbContext is struct __sk_buff, which BPF_PROG_TEST_RUN takes as the
// program's context and returns after the run. The kernel rejects nonzero
// fields a test may not set, and returns ENOSPC if the struct is shorter than
// its own.
type skbContext struct {
	Len, PktType, Mark, QueueMapping, Protocol, VlanPresent, VlanTCI, VlanProto uint32
	Priority, IngressIfindex, Ifindex, TCIndex                                  uint32
	CB                                                                          [5]uint32
	Hash, TCClassid, Data, DataEnd, NapiID, Family, RemoteIP4, LocalIP4         uint32
	RemoteIP6, LocalIP6                                                         [4]uint32
	RemotePort, LocalPort, DataMeta                                             uint32
	FlowKeys, Tstamp                                                            uint64
	WireLen, GSOSegs                                                            uint32
	Sk                                                                          uint64
	GSOSize, TstampType                                                         uint32
	Hwtstamp                                                                    uint64
}

var (
	testProtected = []netip.Prefix{netip.MustParsePrefix("10.94.0.0/16"), netip.MustParsePrefix("172.31.128.0/17")}
	worker        = netip.MustParseAddr("10.94.1.10")
	otherWorker   = netip.MustParseAddr("172.31.200.7")
	server        = netip.MustParseAddr("203.0.113.9")
	sharedAddress = netip.MustParseAddr("10.94.2.100")
)

// frame returns a 100-byte Ethernet frame holding an IPv4 packet.
func frame(source, destination netip.Addr) []byte {
	data := make([]byte, 100)
	binary.BigEndian.PutUint16(data[12:], unix.ETH_P_IP)
	data[14] = 0x45
	binary.BigEndian.PutUint16(data[16:], 86)
	data[22] = 64
	data[23] = unix.IPPROTO_TCP
	source4, destination4 := source.As4(), destination.As4()
	copy(data[26:], source4[:])
	copy(data[30:], destination4[:])
	return data
}

// mark returns an address as the mark program writes it.
func mark(addr netip.Addr) uint32 {
	a := addr.As4()
	return binary.NativeEndian.Uint32(a[:])
}

func monotonic(t *testing.T) uint64 {
	var now unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))
	return uint64(now.Nano())
}

func run(t *testing.T, program *ebpf.Program, data []byte, in skbContext) (uint32, skbContext) {
	var out skbContext
	result, err := program.Run(&ebpf.RunOptions{Data: data, Context: in, ContextOut: &out})
	require.NoError(t, err)
	return result, out
}

func load(t *testing.T) *programs {
	p, err := loadPrograms(testProtected)
	require.NoError(t, err)
	t.Cleanup(p.close)
	return p
}

func TestMarkProgram(t *testing.T) {
	p := load(t)
	{
		result, out := run(t, p.mark, frame(worker, server), skbContext{})
		assert.Equal(t, uint32(tcActionOK), result)
		assert.Equal(t, mark(worker), out.Mark)
	}
	{
		// A mark set by something else stays
		_, out := run(t, p.mark, frame(worker, server), skbContext{Mark: 7})
		assert.Equal(t, uint32(7), out.Mark)
	}
	{
		// Frames other than IPv4, such as ARP, stay unmarked
		data := frame(worker, server)
		binary.BigEndian.PutUint16(data[12:], unix.ETH_P_ARP)
		_, out := run(t, p.mark, data, skbContext{})
		assert.Zero(t, out.Mark)
	}
}

func TestPaceClassifies(t *testing.T) {
	p := load(t)
	// One packet costs 1 ms on every clock, so any paced packet after the
	// bursts would wait.
	require.NoError(t, p.setLimits(Limits{AggregatePackets: 1000, WorkerPackets: 1000}))
	workerCounters := func(addr netip.Addr) (counters [6]uint64, ok bool) {
		return counters, p.workers.Lookup(addr.As4(), &counters) == nil
	}
	{
		// Packets the NAT sends itself arrive unmarked and are left alone
		result, out := run(t, p.pace, frame(sharedAddress, server), skbContext{})
		assert.Equal(t, uint32(tcActionOK), result)
		assert.Zero(t, out.Tstamp)
		var key [4]byte
		assert.ErrorIs(t, p.workers.NextKey(nil, &key), ebpf.ErrKeyNotExist)
	}
	{
		// An upload leaves with the shared address as its source, and is
		// counted for the worker in its mark
		result, _ := run(t, p.pace, frame(sharedAddress, server), skbContext{Mark: mark(worker), WireLen: 1000, GSOSegs: 3})
		assert.Equal(t, uint32(tcActionOK), result)
		counters, ok := workerCounters(worker)
		require.True(t, ok)
		assert.Equal(t, uint64(1000), counters[2], "bytes")
		assert.Equal(t, uint64(3), counters[3], "packets")
	}
	{
		// A download is counted for the worker it goes to
		run(t, p.pace, frame(server, otherWorker), skbContext{Mark: mark(server)})
		counters, ok := workerCounters(otherWorker)
		require.True(t, ok)
		assert.Equal(t, uint64(100), counters[2], "bytes")
		assert.Equal(t, uint64(1), counters[3], "packets")
	}
	{
		// Forwarded traffic that involves no worker isn't paced
		run(t, p.pace, frame(server, netip.MustParseAddr("198.18.0.6")), skbContext{Mark: mark(server)})
		_, ok := workerCounters(netip.MustParseAddr("198.18.0.6"))
		assert.False(t, ok)
	}
	var stats [][4]uint64
	require.NoError(t, p.stats.Lookup(uint32(directionUpload), &stats))
	var upload [4]uint64
	for _, cpu := range stats {
		for i := range cpu {
			upload[i] += cpu[i]
		}
	}
	assert.Equal(t, [4]uint64{1000, 3, 0, 0}, upload)
}

func TestPaceDepartures(t *testing.T) {
	p := load(t)
	// Each packet costs 1 ms on the worker's clock. Its 2 ms burst lets the
	// first packets leave at once, then each waits 1 ms longer than the one
	// before, until a wait would pass the 20 ms horizon.
	require.NoError(t, p.setLimits(Limits{WorkerPackets: 1000}))
	upload := skbContext{Mark: mark(worker)}
	var departures []uint64
	var dropped int
	for range 30 {
		before := monotonic(t)
		result, out := run(t, p.pace, frame(sharedAddress, server), upload)
		if result == tcActionShot {
			dropped++
			continue
		}
		if out.Tstamp != 0 {
			// No packet is held past the horizon
			assert.LessOrEqual(t, time.Duration(out.Tstamp-before), 20*time.Millisecond)
			departures = append(departures, out.Tstamp)
		}
	}
	// Measured against the packets' own departure times, not the test's
	// clock, these hold however slowly the test runs: each delayed packet
	// leaves exactly 1 ms after the one before, and some are dropped.
	require.NotEmpty(t, departures)
	for i := 1; i < len(departures); i++ {
		assert.Equal(t, uint64(time.Millisecond), departures[i]-departures[i-1], "packet %d", i)
	}
	assert.Positive(t, dropped)
	lastDeparture := departures[len(departures)-1]
	{
		// Dropped packets give their reservations back. The clock ends 1 ms
		// after the last accepted packet's departure, not later.
		var counters [6]uint64
		require.NoError(t, p.workers.Lookup(worker.As4(), &counters))
		assert.Equal(t, lastDeparture+uint64(time.Millisecond), counters[1])
		assert.Equal(t, uint64(dropped), counters[5], "dropped")
	}
	{
		// Another worker has its own clock, so it doesn't wait
		result, out := run(t, p.pace, frame(server, otherWorker), skbContext{Mark: mark(server)})
		assert.Equal(t, uint32(tcActionOK), result)
		assert.Zero(t, out.Tstamp)
	}
	{
		// A larger limit applies to the next packet
		require.NoError(t, p.setLimits(Limits{}))
		result, out := run(t, p.pace, frame(sharedAddress, server), upload)
		assert.Equal(t, uint32(tcActionOK), result)
		assert.Zero(t, out.Tstamp)
	}
}

func TestPaceStopsWhenLimitsExpire(t *testing.T) {
	p := load(t)
	// Limits a daemon last wrote 1 ms ago and that ran out since, as when no
	// daemon manages pacing any more.
	costs := Limits{WorkerPackets: 1}.costs()
	expired := [5]uint64{costs[0], costs[1], costs[2], costs[3], monotonic(t) - 1}
	require.NoError(t, p.limits.Put(uint32(0), expired))
	for range 3 {
		result, out := run(t, p.pace, frame(sharedAddress, server), skbContext{Mark: mark(worker)})
		assert.Equal(t, uint32(tcActionOK), result)
		assert.Zero(t, out.Tstamp)
	}
}

func TestPaceAggregate(t *testing.T) {
	p := load(t)
	// 1 MB/s shared by all workers: a 1,000-byte packet costs 1 ms. A
	// GRO-merged packet costs its bytes on the wire.
	require.NoError(t, p.setLimits(Limits{AggregateBytes: 1e6}))
	before := monotonic(t)
	run(t, p.pace, frame(sharedAddress, server), skbContext{Mark: mark(worker), WireLen: 5000})
	_, out := run(t, p.pace, frame(server, otherWorker), skbContext{Mark: mark(server), WireLen: 1000})
	// The first packet started the clock 0.25 ms in the past.
	assert.InDelta(t, 4750*time.Microsecond, time.Duration(out.Tstamp-before), float64(300*time.Microsecond))
}

func TestPaceCountsLongWaits(t *testing.T) {
	p := load(t)
	// A packet costs 0.4 ms on the shared clock, whose burst is 0.25 ms.
	require.NoError(t, p.setLimits(Limits{AggregatePackets: 2500}))
	light := skbContext{Mark: mark(worker)}
	var waited int
	for range 4 {
		if _, out := run(t, p.pace, frame(sharedAddress, server), light); out.Tstamp != 0 {
			waited++
		}
	}
	// A burst that overruns the shared clock by under 1 ms is smoothed, but
	// doesn't count as waiting, so it doesn't lower the worker's fair share.
	assert.Equal(t, 3, waited)
	var counters [6]uint64
	require.NoError(t, p.workers.Lookup(worker.As4(), &counters))
	assert.Zero(t, counters[4], "waited")
	{
		// The next three wait 1.35, 1.75 and 2.15 ms, so they count
		for range 3 {
			run(t, p.pace, frame(sharedAddress, server), light)
		}
		require.NoError(t, p.workers.Lookup(worker.As4(), &counters))
		assert.Equal(t, uint64(3), counters[4], "waited")
	}
}

func TestPaceHeavyWorkerDoesNotHoldUpOthers(t *testing.T) {
	p := load(t)
	// A packet costs 1 ms on the shared clock and on each worker's clock.
	require.NoError(t, p.setLimits(Limits{AggregatePackets: 1000, WorkerPackets: 1000}))
	heavy := skbContext{Mark: mark(worker)}
	for range 10 {
		run(t, p.pace, frame(sharedAddress, server), heavy)
	}
	// The heavy worker's first 3 packets fit its 2 ms burst and left on
	// time, so they took 3 ms on the shared clock, minus its 0.25 ms burst.
	// The 7 its own clock delayed don't hold up another worker.
	before := monotonic(t)
	_, out := run(t, p.pace, frame(server, otherWorker), skbContext{Mark: mark(server)})
	assert.InDelta(t, 2750*time.Microsecond, time.Duration(out.Tstamp-before), float64(500*time.Microsecond))
}

// BenchmarkPace measures the egress program's cost per packet for a paced
// upload that doesn't wait, which runs every step. Run it with
// `go test -tags privileged -run '^$' -bench Pace ./internal/pacing/`.
func BenchmarkPace(b *testing.B) {
	p, err := loadPrograms(testProtected)
	require.NoError(b, err)
	defer p.close()
	// Limits far above the benchmark's rate keep every packet on time.
	require.NoError(b, p.setLimits(Limits{AggregateBytes: 1e15, AggregatePackets: 1e12, WorkerBytes: 1e15, WorkerPackets: 1e12}))
	for _, bench := range []struct {
		name string
		mark netip.Addr
	}{{"paced", worker}, {"unmarked", netip.Addr{}}} {
		b.Run(bench.name, func(b *testing.B) {
			in := skbContext{WireLen: 1500}
			if bench.mark.IsValid() {
				in.Mark = mark(bench.mark)
			}
			data := frame(sharedAddress, server)
			b.ResetTimer()
			started := time.Now()
			_, err := p.pace.Run(&ebpf.RunOptions{Data: data, Context: in, Repeat: uint32(b.N)})
			require.NoError(b, err)
			b.ReportMetric(float64(time.Since(started).Nanoseconds())/float64(b.N), "ns/packet")
		})
	}
}

func TestPaceWorkerStateIsBounded(t *testing.T) {
	p := load(t)
	require.NoError(t, p.setLimits(Limits{WorkerPackets: 1}))
	// More distinct workers than the map holds: the least recently seen are
	// forgotten, so memory stays bounded.
	for i := range maxWorkers + 5000 {
		addr := netip.AddrFrom4([4]byte{10, 94, byte(i >> 8), byte(i)})
		if i >= 65536 {
			addr = netip.AddrFrom4([4]byte{172, 31, 128 + byte((i-65536)>>8), byte(i - 65536)})
		}
		run(t, p.pace, frame(sharedAddress, server), skbContext{Mark: mark(addr)})
	}
	var key [4]byte
	var value [6]uint64
	count := 0
	for iter := p.workers.Iterate(); iter.Next(&key, &value); {
		count++
	}
	assert.LessOrEqual(t, count, maxWorkers)
}

func TestPaceKeysOnlyTheReceivingWorker(t *testing.T) {
	p := load(t)
	require.NoError(t, p.setLimits(Limits{WorkerPackets: 1000}))
	// A download from the internet whose source claims to be another worker
	// is charged to the worker it goes to. Its source address never picks
	// whose state it uses.
	run(t, p.pace, frame(otherWorker, worker), skbContext{Mark: mark(server)})
	var counters [6]uint64
	assert.NoError(t, p.workers.Lookup(worker.As4(), &counters))
	assert.ErrorIs(t, p.workers.Lookup(otherWorker.As4(), &counters), ebpf.ErrKeyNotExist)
}
