package doh

import (
	"testing"
)

func TestChunkString(t *testing.T) {
	tests := []struct {
		input string
		size  int
		want  int
	}{
		{"", 10, 0},
		{"abc", 10, 1},
		{"abcdef", 3, 2},
		{"abcdefg", 3, 3},
		{"a", 1, 1},
	}
	for _, tt := range tests {
		chunks := chunkString(tt.input, tt.size)
		if len(chunks) != tt.want {
			t.Errorf("chunkString(%q, %d) = %d chunks, want %d", tt.input, tt.size, len(chunks), tt.want)
		}
		// Verify roundtrip.
		joined := ""
		for _, c := range chunks {
			joined += c
		}
		if joined != tt.input {
			t.Errorf("roundtrip: got %q, want %q", joined, tt.input)
		}
	}
}

func TestTransportName(t *testing.T) {
	tr := New()
	if tr.Name() != "doh" {
		t.Errorf("name = %q, want %q", tr.Name(), "doh")
	}
}

func TestListenNotSupported(t *testing.T) {
	tr := New()
	if err := tr.Listen(nil, "127.0.0.1:0", nil); err == nil {
		t.Error("Listen should return error for DoH")
	}
}

func TestAcceptNotSupported(t *testing.T) {
	tr := New()
	if _, err := tr.Accept(); err == nil {
		t.Error("Accept should return error for DoH")
	}
}
