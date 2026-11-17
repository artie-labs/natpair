package health

// WaitForScans waits until the monitor's running pass over conntrackd's
// caches, if any, finishes.
func WaitForScans(m *Monitor) {
	m.scans.done.Wait()
}
