//go:build linux

package sys

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// memfdCreate creates an anonymous in-memory file descriptor using the
// memfd_create syscall. The file exists only in RAM — no disk artifact.
func memfdCreate(name string) (int, error) {
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return -1, err
	}
	fd, _, errno := syscall.Syscall(
		319, // SYS_memfd_create
		uintptr(unsafe.Pointer(nameBytes)),
		0, // flags
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("memfd_create: %v", errno)
	}
	return int(fd), nil
}

// MemExec writes a binary to an anonymous memfd and executes it with the
// given arguments. On success, this replaces the current process (execve).
// On failure, it returns an error and the caller should fall back to disk.
func MemExec(binary []byte, args []string) error {
	fd, err := memfdCreate("")
	if err != nil {
		return fmt.Errorf("memfd_create: %w", err)
	}

	f := os.NewFile(uintptr(fd), "memfd")
	if _, err := f.Write(binary); err != nil {
		f.Close()
		return fmt.Errorf("write to memfd: %w", err)
	}
	// Don't close — we exec from it.

	exePath := fmt.Sprintf("/proc/self/fd/%d", fd)

	// Build argv: [exePath, args...]
	argv := append([]string{exePath}, args...)

	// execve replaces this process entirely.
	return syscall.Exec(exePath, argv, os.Environ())
}
