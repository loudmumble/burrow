package replay

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordAndPlayback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.brpl")

	// Record.
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	rec.Record(DirOutbound, []byte("hello"))
	rec.Record(DirInbound, []byte("world"))
	rec.Record(DirOutbound, []byte("!"))
	rec.Close()

	// Playback.
	p, err := NewPlayer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	frames, err := p.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3", len(frames))
	}
	if string(frames[0].Data) != "hello" {
		t.Errorf("frame[0] = %q, want %q", frames[0].Data, "hello")
	}
	if frames[0].Direction != DirOutbound {
		t.Errorf("frame[0].Direction = %d, want DirOutbound", frames[0].Direction)
	}
	if string(frames[1].Data) != "world" {
		t.Errorf("frame[1] = %q, want %q", frames[1].Data, "world")
	}
	if frames[1].Direction != DirInbound {
		t.Errorf("frame[1].Direction = %d, want DirInbound", frames[1].Direction)
	}
}

func TestInvalidMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.brpl")
	os.WriteFile(path, []byte("BAAD"), 0644)

	_, err := NewPlayer(path)
	if err == nil {
		t.Error("should reject invalid magic")
	}
}

func TestEmptyReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.brpl")
	rec, _ := NewRecorder(path)
	rec.Close()

	p, err := NewPlayer(path)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	_, err = p.Next()
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}
