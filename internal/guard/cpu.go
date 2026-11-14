package guard

import (
	"strconv"
	"strings"
)

// CPUTimes is one CPU's time counters from /proc/stat, in clock ticks.
type CPUTimes struct {
	// Busy is time spent on anything but idling or waiting for I/O,
	// including the softirq and receive thread time forwarding runs in.
	Busy uint64
	// Total is all time.
	Total uint64
}

// ParseCPUTimes returns each CPU's counters from the contents of /proc/stat,
// in the order the file lists them. It skips the line that sums all CPUs.
func ParseCPUTimes(stat string) []CPUTimes {
	var cpus []CPUTimes
	for line := range strings.SplitSeq(stat, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] == "cpu" || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		var times CPUTimes
		// user nice system idle iowait irq softirq steal, then guest times,
		// which user and nice already include.
		for i, field := range fields[1:min(len(fields), 9)] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				break
			}
			times.Total += value
			if i != 3 && i != 4 {
				times.Busy += value
			}
		}
		cpus = append(cpus, times)
	}
	return cpus
}

// BusiestCPU returns the largest share of time any one CPU was busy between
// two readings, from 0 to 1. One full CPU starves the NAT's own work that
// runs there, such as its path probes, whatever the other CPUs do. It
// returns 0 if the readings don't match, as when a CPU went offline.
func BusiestCPU(before, after []CPUTimes) float64 {
	if len(before) != len(after) {
		return 0
	}
	var busiest float64
	for i := range after {
		if after[i].Total <= before[i].Total || after[i].Busy < before[i].Busy {
			continue
		}
		share := float64(after[i].Busy-before[i].Busy) / float64(after[i].Total-before[i].Total)
		busiest = max(busiest, min(share, 1))
	}
	return busiest
}
