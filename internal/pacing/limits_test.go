package pacing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLimitsCosts(t *testing.T) {
	{
		// 1 Gbit/s is 0.008 ns a bit, 8 ns a byte, and 8 * 65,536 in fixed
		// point. 1 Mpps is 1,000 ns a packet.
		assert.Equal(t, [4]uint64{524288, 1000, 524288, 1000}, Limits{AggregateBytes: 125e6, AggregatePackets: 1e6, WorkerBytes: 125e6, WorkerPackets: 1e6}.costs())
	}
	{
		// Costs round up, so the kernel never paces faster than the rate. At
		// 3 Mpps a packet takes 333.3 ns.
		assert.Equal(t, uint64(334), Limits{AggregatePackets: 3e6}.costs()[1])
	}
	{
		// No limit costs nothing, which the programs skip
		assert.Equal(t, [4]uint64{}, Limits{}.costs())
	}
}
