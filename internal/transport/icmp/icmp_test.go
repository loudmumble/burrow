package icmp

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
)

// Compile-time interface compliance checks.
var _ transport.Transport = (*ICMPTransport)(nil)
var _ net.Conn = (*icmpConn)(nil)

func TestRegistered(t *testing.T) {
	ctor, ok := transport.Registry["icmp"]
	if !ok {
		t.Fatal("icmp transport not registered in transport.Registry")
	}
	tr := ctor()
	if tr.Name() != "icmp" {
		t.Fatalf("Name() = %q, want %q", tr.Name(), "icmp")
	}
}

func TestName(t *testing.T) {
	tr := NewICMPTransport(true)
	if tr.Name() != "icmp" {
		t.Fatalf("Name() = %q, want %q", tr.Name(), "icmp")
	}
}

func TestListenClose(t *testing.T) {
	tr := NewICMPTransport(true)
	err := tr.Listen(context.Background(), "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := tr.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty after Listen")
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Double close should be safe.
	if err := tr.Close(); err != nil {
		t.Fatalf("Double Close: %v", err)
	}
}

func TestBidirectionalSmallData(t *testing.T) {
	srv := NewICMPTransport(true)
	if err := srv.Listen(context.Background(), "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	addr := srv.Addr()

	// Dial a client.
	client := NewICMPTransport(true)
	clientConn, err := client.Dial(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Accept on server side.
	acceptDone := make(chan struct{})
	var serverConn net.Conn
	var acceptErr error
	go func() {
		defer close(acceptDone)
		conn, err := srv.Accept()
		if err != nil {
			acceptErr = err
			return
		}
		serverConn = conn
	}()

	// Client writes upstream data — triggers session creation.
	upstream := []byte("hello server")
	n, err := clientConn.Write(upstream)
	if err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if n != len(upstream) {
		t.Fatalf("client Write: wrote %d, want %d", n, len(upstream))
	}

	// Wait for accept.
	select {
	case <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	}
	if acceptErr != nil {
		t.Fatalf("Accept: %v", acceptErr)
	}
	defer serverConn.Close()

	// Server reads upstream data.
	buf := make([]byte, 256)
	n, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if string(buf[:n]) != string(upstream) {
		t.Fatalf("server Read: got %q, want %q", buf[:n], upstream)
	}

	// Server writes downstream data.
	downstream := []byte("hello client")
	n, err = serverConn.Write(downstream)
	if err != nil {
		t.Fatalf("server Write: %v", err)
	}
	if n != len(downstream) {
		t.Fatalf("server Write: wrote %d, want %d", n, len(downstream))
	}

	// Client reads downstream data.
	readDone := make(chan []byte, 1)
	go func() {
		b := make([]byte, 256)
		nn, _ := clientConn.Read(b)
		readDone <- b[:nn]
	}()

	select {
	case got := <-readDone:
		if string(got) != string(downstream) {
			t.Fatalf("client Read: got %q, want %q", got, downstream)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client Read timed out waiting for downstream data")
	}
}

func TestLargerTransfer(t *testing.T) {
	srv := NewICMPTransport(true)
	if err := srv.Listen(context.Background(), "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	client := NewICMPTransport(true)
	clientConn, err := client.Dial(context.Background(), srv.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Accept server connection.
	var serverConn net.Conn
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, _ := srv.Accept()
		serverConn = conn
	}()

	// Generate data larger than maxPayload (1400 bytes) to force multi-packet.
	bigData := make([]byte, 5000)
	for i := range bigData {
		bigData[i] = byte(i % 256)
	}

	// Client writes big data (will be chunked across multiple ICMP packets).
	n, err := clientConn.Write(bigData)
	if err != nil {
		t.Fatalf("client Write big data: %v", err)
	}
	if n != len(bigData) {
		t.Fatalf("client Write: wrote %d, want %d", n, len(bigData))
	}

	select {
	case <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	}
	defer serverConn.Close()

	// Server reads all the data.
	var received []byte
	deadline := time.After(5 * time.Second)
	for len(received) < len(bigData) {
		buf := make([]byte, 4096)
		readCh := make(chan int, 1)
		go func() {
			nn, _ := serverConn.Read(buf)
			readCh <- nn
		}()
		select {
		case nn := <-readCh:
			received = append(received, buf[:nn]...)
		case <-deadline:
			t.Fatalf("server Read timed out: received %d/%d bytes", len(received), len(bigData))
		}
	}

	if !bytes.Equal(received, bigData) {
		t.Fatalf("data mismatch: got %d bytes, want %d bytes", len(received), len(bigData))
	}
}
