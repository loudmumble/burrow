package udp

import (
	"context"
	"net"
	"testing"
	"time"
)

// startUDPEchoServer binds a UDP socket that echoes every datagram back.
func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], src)
		}
	}()
	return conn.LocalAddr().String()
}

func TestNewForwarder(t *testing.T) {
	fwd := NewForwarder("127.0.0.1:9000", "127.0.0.1:9001")

	if fwd.ListenAddr != "127.0.0.1:9000" {
		t.Fatalf("ListenAddr = %q, want 127.0.0.1:9000", fwd.ListenAddr)
	}
	if fwd.RemoteAddr != "127.0.0.1:9001" {
		t.Fatalf("RemoteAddr = %q, want 127.0.0.1:9001", fwd.RemoteAddr)
	}
	if fwd.Status != StatusPending {
		t.Fatalf("Status = %v, want pending", fwd.Status)
	}
	if fwd.Timeout != 60*time.Second {
		t.Fatalf("Timeout = %v, want 60s", fwd.Timeout)
	}
	if fwd.clients == nil {
		t.Fatal("clients map not initialized")
	}
}

func TestUDPForwardRoundTrip(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	fwd := NewForwarder("127.0.0.1:0", echoAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fwd.StartWithContext(ctx); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Stop()

	listenAddr := fwd.Addr()
	if listenAddr == "" {
		t.Fatal("forwarder has no listen address")
	}

	// Send datagram through forwarder.
	raddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer clientConn.Close()

	msg := []byte("udp forward test")
	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf[:n], msg)
	}
}

func TestUDPMultipleClients(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	fwd := NewForwarder("127.0.0.1:0", echoAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fwd.StartWithContext(ctx); err != nil {
		t.Fatalf("start forwarder: %v", err)
	}
	defer fwd.Stop()

	raddr, _ := net.ResolveUDPAddr("udp", fwd.Addr())

	// Create two independent clients (different local ports).
	c1, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	c2, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	msg1 := []byte("client-one")
	msg2 := []byte("client-two")

	c1.Write(msg1)
	c2.Write(msg2)

	buf := make([]byte, 64)

	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c1.Read(buf)
	if err != nil {
		t.Fatalf("c1 read: %v", err)
	}
	if string(buf[:n]) != string(msg1) {
		t.Fatalf("c1 echo = %q, want %q", buf[:n], msg1)
	}

	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = c2.Read(buf)
	if err != nil {
		t.Fatalf("c2 read: %v", err)
	}
	if string(buf[:n]) != string(msg2) {
		t.Fatalf("c2 echo = %q, want %q", buf[:n], msg2)
	}

	// Verify two distinct client entries.
	fwd.mu.Lock()
	numClients := len(fwd.clients)
	fwd.mu.Unlock()
	if numClients != 2 {
		t.Fatalf("client count = %d, want 2", numClients)
	}
}

func TestUDPIdleTimeout(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	// Very short timeout so reaper cleans up quickly.
	fwd := NewForwarderWithTimeout("127.0.0.1:0", echoAddr, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fwd.StartWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	defer fwd.Stop()

	raddr, _ := net.ResolveUDPAddr("udp", fwd.Addr())
	c, _ := net.DialUDP("udp", nil, raddr)
	defer c.Close()

	c.Write([]byte("timeout test"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	c.Read(buf)

	// Verify client was registered.
	fwd.mu.Lock()
	if len(fwd.clients) == 0 {
		fwd.mu.Unlock()
		t.Fatal("expected client entry after send")
	}
	fwd.mu.Unlock()

	// Manually trigger reap after waiting past the timeout.
	time.Sleep(100 * time.Millisecond)
	fwd.reapIdle()

	fwd.mu.Lock()
	remaining := len(fwd.clients)
	fwd.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("client count after reap = %d, want 0", remaining)
	}
}

func TestUDPBytesTransferred(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	fwd := NewForwarder("127.0.0.1:0", echoAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd.StartWithContext(ctx)
	defer fwd.Stop()

	raddr, _ := net.ResolveUDPAddr("udp", fwd.Addr())
	c, _ := net.DialUDP("udp", nil, raddr)
	defer c.Close()

	msg := []byte("bytes test")
	c.Write(msg)

	buf := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	c.Read(buf)

	// Small delay for counters to settle.
	time.Sleep(50 * time.Millisecond)

	bIn, bOut := fwd.BytesTransferred()
	if bIn == 0 {
		t.Fatal("bytesIn should be > 0")
	}
	if bOut == 0 {
		t.Fatal("bytesOut should be > 0")
	}
}

func TestUDPContextCancel(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	fwd := NewForwarder("127.0.0.1:0", echoAddr)
	ctx, cancel := context.WithCancel(context.Background())

	if err := fwd.StartWithContext(ctx); err != nil {
		t.Fatal(err)
	}

	addr := fwd.Addr()
	if addr == "" {
		t.Fatal("forwarder has no address")
	}

	if fwd.Status != StatusActive {
		t.Fatalf("status = %v, want active", fwd.Status)
	}

	// Send one datagram to create a client goroutine.
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	c, _ := net.DialUDP("udp", nil, raddr)
	c.Write([]byte("cancel test"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	c.Read(buf)
	c.Close()

	// Cancel context — all goroutines should wind down.
	cancel()
	fwd.Stop()

	// After Stop, the listening conn should be closed.
	// Attempting to send should not reach the forwarder.
	c2, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("dial after stop: %v", err)
	}
	defer c2.Close()

	c2.Write([]byte("after stop"))
	c2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = c2.Read(buf)
	if err == nil {
		t.Fatal("should not receive response after stop")
	}
}
