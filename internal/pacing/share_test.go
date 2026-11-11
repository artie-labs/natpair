package pacing

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFairShare(t *testing.T) {
	{
		// No cap means no per-worker limit
		assert.Zero(t, FairShare(0, []Demand{{Rate: 50, Waited: true}}))
	}
	{
		// Below the cap nothing waits, so any one worker may use all of it
		assert.Equal(t, 100.0, FairShare(100, []Demand{{Rate: 60}, {Rate: 30}}))
		assert.Equal(t, 100.0, FairShare(100, nil))
	}
	{
		// Waiting workers split what the others leave
		assert.Equal(t, 47.5, FairShare(100, []Demand{{Rate: 5}, {Rate: 70, Waited: true}, {Rate: 25, Waited: true}}))
	}
	{
		// One heavy worker gets all that light ones leave
		assert.Equal(t, 88.0, FairShare(100, []Demand{{Rate: 99, Waited: true}, {Rate: 2}, {Rate: 4}, {Rate: 6}}))
	}
	{
		// A worker that didn't wait but used more than the split is held to it
		assert.Equal(t, 45.0, FairShare(100, []Demand{{Rate: 10}, {Rate: 60}, {Rate: 30, Waited: true}}))
	}
	{
		// Rates measured above a cap that was since cut leave nothing to keep,
		// so every worker gets an equal split
		assert.Equal(t, 20.0, FairShare(60, []Demand{{Rate: 40}, {Rate: 50}, {Rate: 30, Waited: true}}))
	}
}
