package transport

import (
	"testing"
	"time"
)

func TestBackoff(t *testing.T) {
	base := time.Second

	d0 := Backoff(base, 0)
	if d0 < 900*time.Millisecond || d0 > 1100*time.Millisecond {
		t.Errorf("attempt 0 delay = %v, want ~1s", d0)
	}

	d3 := Backoff(base, 3)
	if d3 < 7*time.Second || d3 > 9*time.Second {
		t.Errorf("attempt 3 delay = %v, want ~8s", d3)
	}

	d100 := Backoff(base, 100)
	if d100 > 33*time.Second {
		t.Errorf("attempt 100 delay = %v, should be capped at ~30s", d100)
	}
}

func TestRegistry(t *testing.T) {
	if Registry == nil {
		t.Fatal("Registry is nil")
	}
}
