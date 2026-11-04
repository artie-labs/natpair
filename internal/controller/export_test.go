package controller

import "time"

// UseFastTiming shortens the run loop's intervals about 25 times, so tests
// of the loop don't wait out production intervals in real time.
func UseFastTiming() {
	renewInterval, acquireInterval, loopInterval = 20*time.Millisecond, 20*time.Millisecond, 5*time.Millisecond
	lastResortDelay, restartDelay = 100*time.Millisecond, 40*time.Millisecond
}

// LastResortDelay is the current last-resort delay, shortened by UseFastTiming.
func LastResortDelay() time.Duration {
	return lastResortDelay
}
