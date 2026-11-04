// Package netns runs code inside a named network namespace.
package netns

// Do runs fn with its network namespace set to name, as created by
// `ip netns add`. Sockets opened inside fn stay in that namespace after Do
// returns. An empty name runs fn in the current namespace.
//
// Only code that runs on fn's goroutine is inside the namespace. Do not start
// goroutines inside fn, and pass literal IP addresses to dialers so name
// resolution does not run on another thread.
func Do(name string, fn func() error) error {
	if name == "" {
		return fn()
	}
	return do(name, fn)
}
