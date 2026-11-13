package napi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A receive thread of the primary interface, at the default nice value of 0.
const primaryStat = "812 (napi/ens5-8193) S 2 0 0 0 -1 2129984 0 0 0 0 0 31 0 0 20 0 1 0 512 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0"

func TestParseStat(t *testing.T) {
	{
		parsed, err := parseStat(primaryStat)
		assert.NoError(t, err)
		assert.Equal(t, task{pid: 812, name: "napi/ens5-8193", kernel: true, nice: 0}, parsed)
	}
	{
		// A user process at nice -10, whose name holds a space and a ")".
		parsed, err := parseStat("4321 (my (app) x) S 1 4321 4321 0 -1 4194560 120 0 0 0 7 3 0 0 30 -10 9 0 900 1000000 300 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0")
		assert.NoError(t, err)
		assert.Equal(t, task{pid: 4321, name: "my (app) x", kernel: false, nice: -10}, parsed)
	}
	{
		_, err := parseStat("812 napi/ens5-8193 S 2")
		assert.EqualError(t, err, `failed to find the name in "812 napi/ens5-8193 S 2"`)
	}
	{
		_, err := parseStat("812 (napi/ens5-8193) S 2 0 0 0 -1 2129984")
		assert.EqualError(t, err, `too few fields in "812 (napi/ens5-8193) S 2 0 0 0 -1 2129984"`)
	}
}

func TestPrimaryThreads(t *testing.T) {
	tasks := []task{
		{pid: 812, name: "napi/ens5-8193", kernel: true},
		{pid: 813, name: "napi/ens5-8194", kernel: true, nice: OwnNice},
		// The shared ENI's threads keep their priority, under the name the
		// interface had when they started, before udev renamed it.
		{pid: 900, name: "napi/eth0-8195", kernel: true},
		{pid: 901, name: "napi/ens6-8196", kernel: true},
		// A longer interface name that starts with the primary's.
		{pid: 902, name: "napi/ens50-8197", kernel: true},
		// A user process named like a receive thread.
		{pid: 4321, name: "napi/ens5-1", kernel: false},
		{pid: 16, name: "ksoftirqd/0", kernel: true},
	}
	assert.Equal(t, []int{812}, primaryThreads(tasks, "ens5"))
	assert.Empty(t, primaryThreads(tasks, "ens7"))
}
