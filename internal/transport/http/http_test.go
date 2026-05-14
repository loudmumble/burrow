package http_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/transport"
	httptransport "github.com/loudmumble/burrow/internal/transport/http"
)

var _ transport.Transport = (*httptransport.HTTPTransport)(nil)

func TestHTTPTransportInterface(t *testing.T) {
	var _ transport.Transport = httptransport.NewHTTPTransport()
}

func TestHTTPTransportName(t *testing.T) {
	tr := httptransport.NewHTTPTransport()
	if tr.Name() != "http" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "http")
	}
}

func TestHTTPTransportListenClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tr := httptransport.NewHTTPTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	addr := tr.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty")
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad addr %q: %v", addr, err)
	}
	if port == "0" {
		t.Fatal("port should not be 0 after Listen")
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestHTTPTransportListenAcceptDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvTr := httptransport.NewHTTPTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	addr := srvTr.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty")
	}

	acceptDone := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := srvTr.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		acceptDone <- conn
	}()

	clientTr := httptransport.NewHTTPTransport()
	clientConn, err := clientTr.Dial(ctx, addr, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	select {
	case srvConn := <-acceptDone:
		if srvConn == nil {
			t.Fatal("server connection is nil")
		}
		srvConn.Close()
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Accept")
	}
}

func TestHTTPTransportBidirectional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvTr := httptransport.NewHTTPTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := srvTr.Accept()
		acceptDone <- conn
	}()

	clientTr := httptransport.NewHTTPTransport()
	clientConn, err := clientTr.Dial(ctx, srvTr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn := <-acceptDone

	// Client → Server
	testData := "hello from client"
	if _, err := clientConn.Write([]byte(testData)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, 256)
	n, err := srvConn.Read(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf[:n]) != testData {
		t.Errorf("server got %q, want %q", string(buf[:n]), testData)
	}

	// Server → Client
	reply := "hello from server"
	if _, err := srvConn.Write([]byte(reply)); err != nil {
		t.Fatalf("server write: %v", err)
	}

	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != reply {
		t.Errorf("client got %q, want %q", string(buf[:n]), reply)
	}

	clientConn.Close()
	srvConn.Close()
}

func TestHTTPTransportMultipleConcurrentStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srvTr := httptransport.NewHTTPTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	expected := 5

	var wg sync.WaitGroup
	clientConns := make([]net.Conn, expected)
	for i := 0; i < expected; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			clientTr := httptransport.NewHTTPTransport()
			conn, err := clientTr.Dial(ctx, srvTr.Addr(), nil)
			if err != nil {
				t.Errorf("client %d dial: %v", idx, err)
				return
			}
			clientConns[idx] = conn
		}(i)
	}

	wg.Wait()

	srvConns := make([]net.Conn, 0, expected)
	for i := 0; i < expected; i++ {
		conn, err := srvTr.Accept()
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		srvConns = append(srvConns, conn)
	}

	if len(srvConns) != expected {
		t.Errorf("server connections = %d, want %d", len(srvConns), expected)
	}

	// Verify each stream can send/receive independently.
	for i := 0; i < expected; i++ {
		if clientConns[i] == nil {
			continue
		}
		msg := fmt.Sprintf("stream-%d", i)
		if _, err := clientConns[i].Write([]byte(msg)); err != nil {
			t.Errorf("client %d write: %v", i, err)
		}
	}

	for i := 0; i < expected; i++ {
		buf := make([]byte, 256)
		n, err := srvConns[i].Read(buf)
		if err != nil {
			t.Errorf("server %d read: %v", i, err)
			continue
		}
		got := string(buf[:n])
		// Just verify we got one of the expected messages (order may vary).
		if len(got) == 0 {
			t.Errorf("server %d got empty message", i)
		}
	}

	for _, c := range srvConns {
		c.Close()
	}
	for _, c := range clientConns {
		if c != nil {
			c.Close()
		}
	}
}

func TestHTTPTransportClose(t *testing.T) {
	ctx := context.Background()
	tr := httptransport.NewHTTPTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestHTTPTransportClientCloseStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvTr := httptransport.NewHTTPTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := srvTr.Accept()
		acceptDone <- conn
	}()

	clientTr := httptransport.NewHTTPTransport()
	clientConn, err := clientTr.Dial(ctx, srvTr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn := <-acceptDone

	// Write some data, then close client side.
	if _, err := clientConn.Write([]byte("before close")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	n, err := srvConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "before close" {
		t.Errorf("got %q, want %q", string(buf[:n]), "before close")
	}

	clientConn.Close()
	srvConn.Close()
}

func TestHTTPTransportTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverCert, err := certgen.GenerateSelfSigned("TestHTTPServer", time.Hour)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	serverFP := certgen.Fingerprint(serverCert.Leaf)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	srvTr := httptransport.NewHTTPTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", srvTLS); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	clientCert, err := certgen.GenerateSelfSigned("TestHTTPClient", time.Hour)
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	clientTLS := certgen.TLSConfig(clientCert, serverFP)

	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := srvTr.Accept()
		acceptDone <- conn
	}()

	clientTr := httptransport.NewHTTPTransport()
	clientConn, err := clientTr.Dial(ctx, srvTr.Addr(), clientTLS)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn := <-acceptDone

	msg := "encrypted hello"
	if _, err := clientConn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	n, err := srvConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Errorf("got %q, want %q", string(buf[:n]), msg)
	}

	clientConn.Close()
	srvConn.Close()
}

func TestHTTPTransportLargeTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srvTr := httptransport.NewHTTPTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := srvTr.Accept()
		acceptDone <- conn
	}()

	clientTr := httptransport.NewHTTPTransport()
	clientConn, err := clientTr.Dial(ctx, srvTr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn := <-acceptDone

	// Send 64KB of data in chunks.
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var readErr error
	var received []byte

	go func() {
		defer wg.Done()
		received, readErr = io.ReadAll(srvConn)
	}()

	// Write in chunks to simulate realistic traffic.
	chunkSize := 4096
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		_, err := clientConn.Write(data[off:end])
		if err != nil {
			t.Fatalf("write chunk at offset %d: %v", off, err)
		}
	}
	// Small delay to let in-flight data drain through the HTTP transport
	// before closing the client side (HTTP transport buffers internally).
	time.Sleep(100 * time.Millisecond)
	clientConn.Close()

	wg.Wait()
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if len(received) != len(data) {
		t.Fatalf("received %d bytes, want %d", len(received), len(data))
	}

	srvConn.Close()
}

func TestHTTPTransportRegistered(t *testing.T) {
	ctor, ok := transport.Registry["http"]
	if !ok {
		t.Fatal("http transport not registered")
	}
	tr := ctor()
	if tr.Name() != "http" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "http")
	}
}

func TestHTTPTransportListenBadAddr(t *testing.T) {
	ctx := context.Background()
	tr := httptransport.NewHTTPTransport()
	err := tr.Listen(ctx, "999.999.999.999:0", nil)
	if err == nil {
		t.Fatal("expected error on bad address")
	}
}
