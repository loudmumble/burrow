//go:build !linux

package sys

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// MemExec on non-Linux platforms falls back to writing to a temp file,
// executing it, and cleaning up. Not truly fileless but functional.
func MemExec(binary []byte, args []string) error {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf(".burrow-%d.tmp", os.Getpid()))

	if err := os.WriteFile(tmpFile, binary, 0700); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}

	argv := append([]string{tmpFile}, args...)
	execErr := syscall.Exec(tmpFile, argv, os.Environ())
	if execErr != nil {
		os.Remove(tmpFile)
		return execErr
	}
	return nil
}
