package handoff

import "time"

// UseFastPolling re-reads the ENI every 10 ms, so tests don't wait out
// production polls in real time.
func UseFastPolling() {
	pollInterval = 10 * time.Millisecond
}
