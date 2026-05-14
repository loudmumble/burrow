//go:build !linux

package cmd

// isDebuggerAttached returns false on non-Linux platforms.
// Windows: could check IsDebuggerPresent() but requires cgo or syscall.
func isDebuggerAttached() bool {
	return false
}
