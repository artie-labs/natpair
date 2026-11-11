package pacing

import "slices"

// Demand is one worker's use of a budget during one interval.
type Demand struct {
	// Rate is what the worker sent or received, in units per second.
	Rate float64
	// Waited is true if any of the worker's packets waited more than 1 ms,
	// so the worker may want more than Rate.
	Waited bool
}

// FairShare returns the most any one worker may use of capacity, in units
// per second, so that under contention each active worker gets a fair share.
// Zero capacity means no cap, and FairShare returns zero: no limit.
//
// It splits capacity max-min fairly. Workers that never waited keep what they
// used. Workers that waited want more than they got, so they split the rest
// equally. A worker that never waited but used more than that equal split is
// held to it too. While no worker waits, any one worker may use the whole
// capacity, so below the cap nothing waits.
//
// For example, with capacity 100 and workers that used 5 without waiting and
// 70 and 25 while waiting, the two waiting workers split 95, so each may use
// 47.5.
func FairShare(capacity float64, demands []Demand) float64 {
	if capacity <= 0 {
		return 0
	}
	waiting := 0
	var kept []float64
	for _, d := range demands {
		if d.Waited {
			waiting++
		} else {
			kept = append(kept, d.Rate)
		}
	}
	if waiting == 0 {
		return capacity
	}
	// Move the largest workers that kept what they used into the split while
	// they used more than it. Rates that were measured above a cap that has
	// since been cut can leave nothing to keep, and then all workers split
	// the capacity equally.
	slices.Sort(kept)
	remaining := capacity
	for _, rate := range kept {
		remaining -= rate
	}
	for len(kept) > 0 {
		largest := kept[len(kept)-1]
		if largest <= remaining/float64(waiting) {
			break
		}
		kept = kept[:len(kept)-1]
		remaining += largest
		waiting++
	}
	return remaining / float64(waiting)
}
