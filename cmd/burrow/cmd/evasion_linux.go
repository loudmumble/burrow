//go:build linux

package cmd

import (
	"os"
	"strings"
)

// isDebuggerAttached checks /proc/self/status for TracerPid != 0.
func isDebuggerAttached() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			return pid != "0"
		}
	}
	return false
}
