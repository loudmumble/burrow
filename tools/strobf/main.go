// strobf — Custom string obfuscation preprocessor for Go sources.
//
// Parses Go source files, finds string literals, encrypts them with a
// per-build random key using a custom cipher (XOR + positional add + rotate),
// and outputs modified source + a decoder file.
//
// Usage:
//
//	strobf -input cmd/stager/main.go -outdir cmd/stager/_build
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const keySize = 32

// stringEntry tracks a string literal found in the source.
type stringEntry struct {
	offset  int    // byte offset of literal start in source
	endOff  int    // byte offset of literal end in source
	value   string // unquoted string value
	varName string // generated replacement variable name
}

// offsetRange represents a byte offset range [start, end).
type offsetRange struct {
	start, end int
}

func main() {
	inputFile := flag.String("input", "", "Go source file to obfuscate")
	outDir := flag.String("outdir", "", "Output directory for obfuscated files")
	flag.Parse()

	if *inputFile == "" || *outDir == "" {
		log.Fatal("usage: strobf -input <file.go> -outdir <dir>")
	}

	// Read source as raw bytes for text-based replacement.
	srcBytes, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("read %s: %v", *inputFile, err)
	}
	src := string(srcBytes)

	// Parse the Go source.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, *inputFile, srcBytes, parser.ParseComments)
	if err != nil {
		log.Fatalf("parse %s: %v", *inputFile, err)
	}

	pkgName := f.Name.Name

	// Generate a random 32-byte key.
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("crypto/rand: %v", err)
	}

	// Collect positions to skip: imports, const decls, struct tags, case clauses.
	importRanges := collectImportPositions(fset, f)
	constRanges := collectConstPositions(fset, f)
	tagRanges := collectStructTagPositions(fset, f)
	caseRanges := collectCaseClausePositions(fset, f)

	// Find all string literals to obfuscate.
	var entries []stringEntry
	varCounter := 0

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}

		litPos := fset.Position(lit.Pos())
		litEnd := fset.Position(lit.End())
		off := litPos.Offset
		endOff := litEnd.Offset

		// Skip if inside import, const, struct tag, or case clause.
		if inRanges(off, importRanges) || inRanges(off, constRanges) || inRanges(off, tagRanges) || inRanges(off, caseRanges) {
			return true
		}

		// Unquote the string value.
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}

		// Skip empty or single-char strings.
		if len(val) <= 1 {
			return true
		}

		// Generate unique variable name with random hex.
		randBytes := make([]byte, 2)
		rand.Read(randBytes)
		varName := fmt.Sprintf("_b%s%d", hex.EncodeToString(randBytes), varCounter)
		varCounter++

		entries = append(entries, stringEntry{
			offset:  off,
			endOff:  endOff,
			value:   val,
			varName: varName,
		})

		return true
	})

	// Sort by offset in REVERSE order (end to start) for safe text replacement.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].offset > entries[j].offset
	})

	// Replace string literals in source text, working backwards.
	modified := src
	for _, e := range entries {
		modified = modified[:e.offset] + e.varName + modified[e.endOff:]
	}

	// Create output directory.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("mkdir %s: %v", *outDir, err)
	}

	// Write modified source.
	outFile := filepath.Join(*outDir, filepath.Base(*inputFile))
	if err := os.WriteFile(outFile, []byte(modified), 0644); err != nil {
		log.Fatalf("write %s: %v", outFile, err)
	}

	// Re-sort entries by forward order for consistent decoder output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].offset < entries[j].offset
	})

	// Generate and write zstrdec.go (not _strdec.go — underscore prefix ignored by go build).
	decSrc := generateDecoderFile(pkgName, key, entries)
	decFile := filepath.Join(*outDir, "zstrdec.go")
	if err := os.WriteFile(decFile, []byte(decSrc), 0644); err != nil {
		log.Fatalf("write %s: %v", decFile, err)
	}

	fmt.Printf("strobf: obfuscated %d strings in %s -> %s\n", len(entries), *inputFile, *outDir)
}

func collectImportPositions(fset *token.FileSet, f *ast.File) []offsetRange {
	var ranges []offsetRange
	ast.Inspect(f, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			return true
		}
		start := fset.Position(gd.Pos()).Offset
		end := fset.Position(gd.End()).Offset
		ranges = append(ranges, offsetRange{start, end})
		return false
	})
	return ranges
}

func collectConstPositions(fset *token.FileSet, f *ast.File) []offsetRange {
	var ranges []offsetRange
	ast.Inspect(f, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		start := fset.Position(gd.Pos()).Offset
		end := fset.Position(gd.End()).Offset
		ranges = append(ranges, offsetRange{start, end})
		return false
	})
	return ranges
}

func collectStructTagPositions(fset *token.FileSet, f *ast.File) []offsetRange {
	var ranges []offsetRange
	ast.Inspect(f, func(n ast.Node) bool {
		field, ok := n.(*ast.Field)
		if !ok || field.Tag == nil {
			return true
		}
		start := fset.Position(field.Tag.Pos()).Offset
		end := fset.Position(field.Tag.End()).Offset
		ranges = append(ranges, offsetRange{start, end})
		return true
	})
	return ranges
}

func collectCaseClausePositions(fset *token.FileSet, f *ast.File) []offsetRange {
	var ranges []offsetRange
	ast.Inspect(f, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expr := range cc.List {
			start := fset.Position(expr.Pos()).Offset
			end := fset.Position(expr.End()).Offset
			ranges = append(ranges, offsetRange{start, end})
		}
		return true
	})
	return ranges
}

func inRanges(offset int, ranges []offsetRange) bool {
	for _, r := range ranges {
		if offset >= r.start && offset < r.end {
			return true
		}
	}
	return false
}

// Cipher functions.

func rotateLeft8(b byte, n byte) byte {
	n &= 0x07
	return (b << n) | (b >> (8 - n))
}

func encode(plain []byte, key []byte) []byte {
	out := make([]byte, len(plain))
	for i, b := range plain {
		step1 := b ^ key[i%keySize]
		step2 := byte((int(step1) + (i*7 + 13)) & 0xFF)
		step3 := rotateLeft8(step2, key[(i+1)%keySize]&0x07)
		out[i] = step3
	}
	return out
}

func generateDecoderFile(pkg string, key []byte, entries []stringEntry) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("package %s\n\n", pkg))

	// Key as byte array.
	b.WriteString("var _k = [32]byte{")
	for i, k := range key {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(fmt.Sprintf("0x%02x", k))
	}
	b.WriteString("}\n\n")

	// Decoder function: rotateRight8 + subtract + XOR.
	b.WriteString("func _d(e []byte) string {\n")
	b.WriteString("\td := make([]byte, len(e))\n")
	b.WriteString("\tfor i, b := range e {\n")
	b.WriteString("\t\tr := _k[(i+1)%32] & 0x07\n")
	b.WriteString("\t\ts1 := (b >> r) | (b << (8 - r))\n")
	b.WriteString("\t\ts2 := byte((int(s1) - (i*7 + 13)) & 0xFF)\n")
	b.WriteString("\t\ts3 := s2 ^ _k[i%32]\n")
	b.WriteString("\t\td[i] = s3\n")
	b.WriteString("\t}\n")
	b.WriteString("\treturn string(d)\n")
	b.WriteString("}\n\n")

	// Variable declarations (package-level).
	b.WriteString("var (\n")
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("\t%s string\n", e.varName))
	}
	b.WriteString(")\n\n")

	// init() function to decode all strings at startup.
	b.WriteString("func init() {\n")
	for _, e := range entries {
		encrypted := encode([]byte(e.value), key)
		b.WriteString(fmt.Sprintf("\t%s = _d([]byte{", e.varName))
		for i, eb := range encrypted {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(fmt.Sprintf("0x%02x", eb))
		}
		b.WriteString("})\n")
	}
	b.WriteString("}\n")

	return b.String()
}
