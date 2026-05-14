package ws_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/transport"
	"github.com/loudmumble/burrow/internal/transport/ws"
)

var _ transport.Transport = (*ws.WSTransport)(nil)

func TestWSTransportInterface(t *testing.T) {
	var _ transport.Transport = ws.NewWSTransport()
}

func TestWSTransportListenClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tr := ws.NewWSTransport()
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

func TestWSTransportName(t *testing.T) {
	tr := ws.NewWSTransport()
	if tr.Name() != "ws" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "ws")
	}
}

func TestWSTransportDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	clientTr := ws.NewWSTransport()
	conn, err := clientTr.Dial(ctx, "ws://"+tr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	srvConn, err := tr.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if srvConn == nil {
		t.Fatal("server connection is nil")
	}
	srvConn.Close()
}

func TestWSTransportBidirectional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	clientTr := ws.NewWSTransport()
	clientConn, err := clientTr.Dial(ctx, "ws://"+tr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn, err := tr.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

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

func TestWSTransportLargeTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	clientTr := ws.NewWSTransport()
	clientConn, err := clientTr.Dial(ctx, "ws://"+tr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn, err := tr.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	data := make([]byte, 1<<20)
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

	_, err = clientConn.Write(data)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	clientConn.Close()

	wg.Wait()
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if len(received) != len(data) {
		t.Errorf("received %d bytes, want %d", len(received), len(data))
	}

	srvConn.Close()
}

func TestWSTransportTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverCert, err := certgen.GenerateSelfSigned("TestServer", time.Hour)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	serverFP := certgen.Fingerprint(serverCert.Leaf)

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", srvTLS); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	clientCert, err := certgen.GenerateSelfSigned("TestClient", time.Hour)
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	clientTLS := certgen.TLSConfig(clientCert, serverFP)

	clientTr := ws.NewWSTransport()
	clientConn, err := clientTr.Dial(ctx, "wss://"+tr.Addr(), clientTLS)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn, err := tr.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

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

func TestWSTransportDialWithRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	clientTr := ws.NewWSTransport()
	conn, err := clientTr.DialWithRetry(ctx, "ws://"+tr.Addr(), nil, 100*time.Millisecond, 3)
	if err != nil {
		t.Fatalf("DialWithRetry: %v", err)
	}
	defer conn.Close()

	srvConn, err := tr.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	srvConn.Close()
}

func TestWSTransportDialWithRetryFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientTr := ws.NewWSTransport()
	_, err := clientTr.DialWithRetry(ctx, "ws://127.0.0.1:1", nil, 50*time.Millisecond, 2)
	if err == nil {
		t.Fatal("expected error on retry failure")
	}
	if !strings.Contains(err.Error(), "max retries") {
		t.Errorf("expected max retries error, got: %v", err)
	}
}

func TestWSTransportDialWithRetryContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	clientTr := ws.NewWSTransport()
	_, err := clientTr.DialWithRetry(ctx, "ws://127.0.0.1:1", nil, 2*time.Second, 100)
	if err == nil {
		t.Fatal("expected error on context cancel")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error, got: %v", err)
	}
}

func TestWSTransportMultipleClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	expected := 5

	var wg sync.WaitGroup
	clientConns := make([]net.Conn, expected)
	for i := 0; i < expected; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			clientTr := ws.NewWSTransport()
			conn, err := clientTr.Dial(ctx, "ws://"+tr.Addr(), nil)
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
		conn, err := tr.Accept()
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		srvConns = append(srvConns, conn)
	}

	if len(srvConns) != expected {
		t.Errorf("server connections = %d, want %d", len(srvConns), expected)
	}

	// Close clients first so servers receive the close frame,
	// then close servers. Use goroutines to parallelize.
	var closeWg sync.WaitGroup
	for _, c := range clientConns {
		if c != nil {
			closeWg.Add(1)
			go func(c net.Conn) { defer closeWg.Done(); c.Close() }(c)
		}
	}
	closeWg.Wait()
	for _, c := range srvConns {
		closeWg.Add(1)
		go func(c net.Conn) { defer closeWg.Done(); c.Close() }(c)
	}
	closeWg.Wait()
}

func TestWSTransportCustomTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverCert, err := certgen.GenerateSelfSigned("CustomTLS", time.Hour)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	serverFP := certgen.Fingerprint(serverCert.Leaf)

	customTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	tr := ws.NewWSTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", customTLS); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tr.Close()

	clientCert, err := certgen.GenerateSelfSigned("Client", time.Hour)
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	clientTLS := certgen.TLSConfig(clientCert, serverFP)
	clientTLS.MinVersion = tls.VersionTLS13

	clientTr := ws.NewWSTransport()
	conn, err := clientTr.Dial(ctx, fmt.Sprintf("wss://%s", tr.Addr()), clientTLS)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	srvConn, err := tr.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	srvConn.Close()
}

func TestWSTransportListenBadAddr(t *testing.T) {
	ctx := context.Background()
	tr := ws.NewWSTransport()
	err := tr.Listen(ctx, "999.999.999.999:0", nil)
	if err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestWSTransportRegistered(t *testing.T) {
	ctor, ok := transport.Registry["ws"]
	if !ok {
		t.Fatal("ws transport not registered")
	}
	tr := ctor()
	if tr.Name() != "ws" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "ws")
	}
}
