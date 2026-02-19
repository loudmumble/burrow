package netstack

import (
	"context"
	"log"
	"os"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatalf("New(default opts) error = %v", err)
	}
	defer s.Close()

	if s.ns == nil {
		t.Fatal("stack is nil")
	}
	if s.ep == nil {
		t.Fatal("endpoint is nil")
	}
	if s.cancel == nil {
		t.Fatal("cancel func is nil")
	}
}

func TestNewDefaults(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer s.Close()

	if s.mtu != 1500 {
		t.Errorf("default MTU = %d, want 1500", s.mtu)
	}
	if s.logger == nil {
		t.Fatal("default logger is nil")
	}
}

func TestNewCustomOpts(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	s, err := New(Opts{
		MTU:         9000,
		TCPBufSize:  32768,
		MaxInFlight: 2048,
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("New(custom opts) error = %v", err)
	}
	defer s.Close()

	if s.mtu != 9000 {
		t.Errorf("custom MTU = %d, want 9000", s.mtu)
	}
	if s.logger != logger {
		t.Error("custom logger not set")
	}
}

func TestInjectPacketEmpty(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Empty packet should be silently dropped, no panic.
	s.InjectPacket(nil)
	s.InjectPacket([]byte{})
}

func TestInjectPacketIPv4(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Minimal IPv4 header (20 bytes) with version nibble = 4.
	// This is not a valid TCP/UDP packet, but InjectPacket should
	// not panic on it — the stack silently drops unrecognized traffic.
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[2] = 0x00
	pkt[3] = 0x14 // total length = 20
	pkt[9] = 6    // protocol = TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	s.InjectPacket(pkt)
}

func TestInjectPacketIPv6(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Minimal IPv6 header (40 bytes) with version nibble = 6.
	pkt := make([]byte, 40)
	pkt[0] = 0x60 // version=6

	s.InjectPacket(pkt)
}

func TestInjectMalformed(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		name string
		data []byte
	}{
		{"single byte", []byte{0xFF}},
		{"garbage 5 bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}},
		{"version 0", []byte{0x00, 0x00, 0x00, 0x00}},
		{"version 15", []byte{0xF0, 0x00, 0x00, 0x00}},
		{"truncated ipv4", []byte{0x45, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must not panic on any malformed input.
			s.InjectPacket(tt.data)
		})
	}
}

func TestReadPacketCancelled(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = s.ReadPacket(ctx)
	if err == nil {
		t.Fatal("ReadPacket with cancelled context should return error")
	}
	if err != context.Canceled {
		t.Errorf("ReadPacket error = %v, want context.Canceled", err)
	}
}

func TestReadPacketTimeout(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = s.ReadPacket(ctx)
	if err == nil {
		t.Fatal("ReadPacket should return error after timeout")
	}
}

func TestClose(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloseAfterInject(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}

	// Inject some packets then close. Should not leak or panic.
	for i := 0; i < 10; i++ {
		pkt := make([]byte, 20)
		pkt[0] = 0x45
		pkt[2] = 0x00
		pkt[3] = 0x14
		pkt[9] = 17 // UDP
		copy(pkt[12:16], []byte{10, 0, 0, 1})
		copy(pkt[16:20], []byte{10, 0, byte(i), 1})
		s.InjectPacket(pkt)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() after inject error = %v", err)
	}
}

func TestMultipleStacks(t *testing.T) {
	// Creating multiple independent stacks should work.
	stacks := make([]*Stack, 3)
	for i := range stacks {
		s, err := New(Opts{MTU: uint32(1500 + i*100)})
		if err != nil {
			t.Fatalf("New() stack %d error = %v", i, err)
		}
		stacks[i] = s
	}

	// Verify each has its own MTU.
	for i, s := range stacks {
		expected := uint32(1500 + i*100)
		if s.mtu != expected {
			t.Errorf("stack[%d] MTU = %d, want %d", i, s.mtu, expected)
		}
	}

	for _, s := range stacks {
		s.Close()
	}
}

func TestInjectDoesNotBlockOnFullQueue(t *testing.T) {
	s, err := New(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Inject more packets than the channel buffer (512). The stack should
	// process or drop them without blocking the caller indefinitely.
	done := make(chan struct{})
	go func() {
		pkt := make([]byte, 20)
		pkt[0] = 0x45
		pkt[2] = 0x00
		pkt[3] = 0x14
		pkt[9] = 6 // TCP
		copy(pkt[12:16], []byte{10, 0, 0, 1})
		copy(pkt[16:20], []byte{10, 0, 0, 2})

		for i := 0; i < 1024; i++ {
			s.InjectPacket(pkt)
		}
		close(done)
	}()

	select {
	case <-done:
		// OK, didn't block.
	case <-time.After(5 * time.Second):
		t.Fatal("InjectPacket blocked on full queue for >5s")
	}
}
