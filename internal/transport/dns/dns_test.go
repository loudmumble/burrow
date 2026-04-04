package dns

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
)

// Compile-time interface compliance check.
var _ transport.Transport = (*DNSTransport)(nil)

// Compile-time net.Conn compliance check.
var _ io.ReadWriteCloser = (*dnsConn)(nil)

func TestRegistered(t *testing.T) {
	ctor, ok := transport.Registry["dns"]
	if !ok {
		t.Fatal("dns transport not registered in transport.Registry")
	}
	tr := ctor()
	if tr.Name() != "dns" {
		t.Fatalf("Name() = %q, want %q", tr.Name(), "dns")
	}
}

func TestName(t *testing.T) {
	tr := NewDNSTransport()
	if tr.Name() != "dns" {
		t.Fatalf("Name() = %q, want %q", tr.Name(), "dns")
	}
}

func TestListenClose(t *testing.T) {
	tr := NewDNSTransport()
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

	// Double close should be safe
	if err := tr.Close(); err != nil {
		t.Fatalf("Double Close: %v", err)
	}
}

func TestBidirectionalSmallData(t *testing.T) {
	srv := NewDNSTransport()
	if err := srv.Listen(context.Background(), "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	addr := srv.Addr()

	// Dial a client
	client := NewDNSTransport()
	clientConn, err := client.Dial(context.Background(), addr, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Accept on server side
	acceptDone := make(chan struct{})
	var serverConn interface{ io.ReadWriteCloser }
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

	// Client writes upstream data - this triggers session creation
	upstream := []byte("hello server")
	n, err := clientConn.Write(upstream)
	if err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if n != len(upstream) {
		t.Fatalf("client Write: wrote %d, want %d", n, len(upstream))
	}

	// Wait for accept
	select {
	case <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timed out")
	}
	if acceptErr != nil {
		t.Fatalf("Accept: %v", acceptErr)
	}
	defer serverConn.Close()

	// Server reads upstream data
	buf := make([]byte, 256)
	n, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if string(buf[:n]) != string(upstream) {
		t.Fatalf("server Read: got %q, want %q", buf[:n], upstream)
	}

	// Server writes downstream data
	downstream := []byte("hello client")
	n, err = serverConn.Write(downstream)
	if err != nil {
		t.Fatalf("server Write: %v", err)
	}
	if n != len(downstream) {
		t.Fatalf("server Write: wrote %d, want %d", n, len(downstream))
	}

	// Client reads downstream data (may need polling cycle)
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

func TestChunking(t *testing.T) {
	srv := NewDNSTransport()
	if err := srv.Listen(context.Background(), "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	client := NewDNSTransport()
	clientConn, err := client.Dial(context.Background(), srv.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	// Accept server connection
	var serverConn io.ReadWriteCloser
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, _ := srv.Accept()
		serverConn = conn
	}()

	// Generate data larger than maxPayloadPerQuery (110 bytes)
	bigData := make([]byte, 500)
	for i := range bigData {
		bigData[i] = byte(i % 256)
	}

	// Client writes big data (will be chunked across multiple queries)
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

	// Server reads all the data
	var received []byte
	deadline := time.After(5 * time.Second)
	for len(received) < len(bigData) {
		buf := make([]byte, 1024)
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
		t.Fatalf("server received data mismatch: got %d bytes, want %d bytes", len(received), len(bigData))
	}
}

func TestConcurrentSessions(t *testing.T) {
	srv := NewDNSTransport()
	if err := srv.Listen(context.Background(), "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	const numClients = 3
	addr := srv.Addr()

	// Start accepting in background
	serverConns := make(chan io.ReadWriteCloser, numClients)
	go func() {
		for i := 0; i < numClients; i++ {
			conn, err := srv.Accept()
			if err != nil {
				return
			}
			serverConns <- conn
		}
	}()

	// Dial multiple clients and send unique data
	var wg sync.WaitGroup
	clientResults := make([]error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client := NewDNSTransport()
			conn, err := client.Dial(context.Background(), addr, nil)
			if err != nil {
				clientResults[idx] = err
				return
			}
			defer conn.Close()

			msg := []byte("msg-from-client-" + string(rune('A'+idx)))
			if _, err := conn.Write(msg); err != nil {
				clientResults[idx] = err
			}
		}(i)
	}

	wg.Wait()

	for i, err := range clientResults {
		if err != nil {
			t.Fatalf("client %d error: %v", i, err)
		}
	}

	// Collect server-side connections and verify we got data from each
	deadline := time.After(5 * time.Second)
	received := 0
	for received < numClients {
		select {
		case conn := <-serverConns:
			buf := make([]byte, 256)
			readCh := make(chan int, 1)
			go func() {
				nn, _ := conn.Read(buf)
				readCh <- nn
			}()
			select {
			case nn := <-readCh:
				if nn == 0 {
					t.Error("server read 0 bytes from session")
				}
				received++
				conn.Close()
			case <-deadline:
				t.Fatalf("timed out reading from server conn, got %d/%d", received, numClients)
			}
		case <-deadline:
			t.Fatalf("timed out accepting connections, got %d/%d", received, numClients)
		}
	}
}

func TestBuildQueryName(t *testing.T) {
	// Test with data
	data := []byte("hello")
	name := buildQueryName(data, 0, "abc12345")
	if !strings.HasSuffix(name, ".abc12345.t.tun.") {
		t.Fatalf("query name missing session/zone suffix: %s", name)
	}

	// Test poll (no data)
	poll := buildQueryName(nil, 1, "abc12345")
	if !strings.HasPrefix(poll, "p.") {
		t.Fatalf("poll query should start with 'p.': %s", poll)
	}
}

func TestSplitTXT(t *testing.T) {
	// Empty string
	chunks := splitTXT("")
	if len(chunks) != 1 || chunks[0] != "" {
		t.Fatalf("splitTXT empty: got %v", chunks)
	}

	// Short string
	chunks = splitTXT("hello")
	if len(chunks) != 1 || chunks[0] != "hello" {
		t.Fatalf("splitTXT short: got %v", chunks)
	}

	// Long string (> 255)
	long := strings.Repeat("a", 300)
	chunks = splitTXT(long)
	if len(chunks) != 2 {
		t.Fatalf("splitTXT 300 chars: got %d chunks, want 2", len(chunks))
	}
	if len(chunks[0]) != 255 {
		t.Fatalf("first chunk len = %d, want 255", len(chunks[0]))
	}
	if len(chunks[1]) != 45 {
		t.Fatalf("second chunk len = %d, want 45", len(chunks[1]))
	}
}

func TestExtractTXTPayload(t *testing.T) {
	// nil message
	if got := extractTXTPayload(nil); got != nil {
		t.Fatalf("expected nil for nil msg, got %v", got)
	}
}

func TestDNSAddrInterface(t *testing.T) {
	addr := &dnsAddr{session: "test123"}
	if addr.Network() != "dns" {
		t.Fatalf("Network() = %q, want %q", addr.Network(), "dns")
	}
	if addr.String() != "dns://test123" {
		t.Fatalf("String() = %q, want %q", addr.String(), "dns://test123")
	}
}

func TestConnCloseIdempotent(t *testing.T) {
	srv := NewDNSTransport()
	if err := srv.Listen(context.Background(), "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	conn, err := srv.Dial(context.Background(), srv.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Write to trigger session
	conn.Write([]byte("x"))

	// Close multiple times should not panic
	conn.Close()
	conn.Close()
	conn.Close()
}
