package pacing

import "math"

// Limits are the rates the kernel enforces, in bytes or packets per second.
// Zero means no limit.
type Limits struct {
	// AggregateBytes and AggregatePackets cap all paced traffic together:
	// uploads and downloads, on every interface.
	AggregateBytes, AggregatePackets float64
	// WorkerBytes and WorkerPackets cap each worker.
	WorkerBytes, WorkerPackets float64
}

// byteCostShift is how many fractional bits a cost per byte has. A
// multiply and a shift then price a packet without dividing.
const byteCostShift = 16

// costs returns the limits as the kernel stores them, in the order of the
// limits map's value: nanoseconds per byte in fixed point with byteCostShift
// fractional bits, and nanoseconds per packet.
func (l Limits) costs() [4]uint64 {
	return [4]uint64{
		cost(l.AggregateBytes, 1<<byteCostShift),
		cost(l.AggregatePackets, 1),
		cost(l.WorkerBytes, 1<<byteCostShift),
		cost(l.WorkerPackets, 1),
	}
}

// cost returns how many nanoseconds, times scale, one unit takes at rate
// units per second. It rounds up, so the kernel never paces faster than the
// rate. Zero rate means no limit, so zero cost.
func cost(rate, scale float64) uint64 {
	if rate <= 0 {
		return 0
	}
	return uint64(math.Ceil(1e9 * scale / rate))
}
