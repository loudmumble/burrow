package transport

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
)

func TestServerStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connCh := make(chan net.Conn, 1)
	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		Handler: func(conn net.Conn) {
			connCh <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty")
	}

	// Verify it's listening
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad addr %q: %v", addr, err)
	}
	if port == "0" {
		t.Fatal("port should not be 0 after Start")
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestServerNilHandler(t *testing.T) {
	srv := &Server{ListenAddr: "127.0.0.1:0"}
	err := srv.Start(context.Background())
	if err != ErrNoHandler {
		t.Errorf("expected ErrNoHandler, got %v", err)
	}
}

func TestClientConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connReady := make(chan net.Conn, 1)

	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		Handler: func(conn net.Conn) {
			connReady <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	client := &Client{
		ServerURL: "ws://" + srv.Addr(),
	}

	conn, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	select {
	case srvConn := <-connReady:
		if srvConn == nil {
			t.Fatal("server connection is nil")
		}
		srvConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("server handler not called")
	}
}

func TestBidirectionalTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverReady := make(chan net.Conn, 1)
	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		Handler: func(conn net.Conn) {
			serverReady <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	client := &Client{
		ServerURL: "ws://" + srv.Addr(),
	}

	clientConn, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var srvConn net.Conn
	select {
	case srvConn = <-serverReady:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server connection")
	}

	// Client -> Server
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

	// Server -> Client
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

func TestLargeTransfer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverReady := make(chan net.Conn, 1)
	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		Handler: func(conn net.Conn) {
			serverReady <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	client := &Client{ServerURL: "ws://" + srv.Addr()}
	clientConn, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var srvConn net.Conn
	select {
	case srvConn = <-serverReady:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	// Send 1MB of data
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

func TestHTTPSMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate certs
	serverCert, err := certgen.GenerateSelfSigned("TestServer", time.Hour)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	serverFP := certgen.Fingerprint(serverCert.Leaf)

	serverReady := make(chan net.Conn, 1)
	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    &serverCert,
		Handler: func(conn net.Conn) {
			serverReady <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	// Client with fingerprint verification
	clientCert, err := certgen.GenerateSelfSigned("TestClient", time.Hour)
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	clientTLS := certgen.TLSConfig(clientCert, serverFP)

	client := &Client{
		ServerURL: "wss://" + srv.Addr(),
		TLSConfig: clientTLS,
	}

	clientConn, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var srvConn net.Conn
	select {
	case srvConn = <-serverReady:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}

	// Bidirectional over TLS
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

func TestConnectWithRetrySuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverReady := make(chan net.Conn, 1)
	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		Handler: func(conn net.Conn) {
			serverReady <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	client := &Client{
		ServerURL:        "ws://" + srv.Addr(),
		ReconnectBackoff: 100 * time.Millisecond,
	}

	conn, err := client.ConnectWithRetry(ctx, 3)
	if err != nil {
		t.Fatalf("ConnectWithRetry: %v", err)
	}
	defer conn.Close()

	select {
	case srvConn := <-serverReady:
		srvConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectWithRetryFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := &Client{
		ServerURL:        "ws://127.0.0.1:1", // Nothing listening
		ReconnectBackoff: 50 * time.Millisecond,
	}

	_, err := client.ConnectWithRetry(ctx, 2)
	if err == nil {
		t.Fatal("expected error on retry failure")
	}
	if !strings.Contains(err.Error(), "max retries") {
		t.Errorf("expected max retries error, got: %v", err)
	}
}

func TestConnectWithRetryContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	client := &Client{
		ServerURL:        "ws://127.0.0.1:1",
		ReconnectBackoff: 2 * time.Second, // Long backoff to trigger context cancel
	}

	_, err := client.ConnectWithRetry(ctx, 100)
	if err == nil {
		t.Fatal("expected error on context cancel")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("expected context error, got: %v", err)
	}
}

func TestMultipleClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	serverConns := make([]net.Conn, 0)
	allConnected := make(chan struct{})
	expected := 5

	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		Handler: func(conn net.Conn) {
			mu.Lock()
			serverConns = append(serverConns, conn)
			count := len(serverConns)
			mu.Unlock()
			if count == expected {
				close(allConnected)
			}
			// Hold connections open
			<-ctx.Done()
			conn.Close()
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	var wg sync.WaitGroup
	clientConns := make([]net.Conn, expected)
	for i := 0; i < expected; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client := &Client{ServerURL: "ws://" + srv.Addr()}
			conn, err := client.Connect(ctx)
			if err != nil {
				t.Errorf("client %d connect: %v", idx, err)
				return
			}
			clientConns[idx] = conn
		}(i)
	}

	wg.Wait()

	select {
	case <-allConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("not all clients connected")
	}

	mu.Lock()
	got := len(serverConns)
	mu.Unlock()
	if got != expected {
		t.Errorf("server connections = %d, want %d", got, expected)
	}
}

func TestBackoff(t *testing.T) {
	base := time.Second

	// Attempt 0: ~1s
	d0 := backoff(base, 0)
	if d0 < 900*time.Millisecond || d0 > 1100*time.Millisecond {
		t.Errorf("attempt 0 delay = %v, want ~1s", d0)
	}

	// Attempt 3: ~8s
	d3 := backoff(base, 3)
	if d3 < 7*time.Second || d3 > 9*time.Second {
		t.Errorf("attempt 3 delay = %v, want ~8s", d3)
	}

	// Attempt 100: capped at ~30s
	d100 := backoff(base, 100)
	if d100 > 33*time.Second {
		t.Errorf("attempt 100 delay = %v, should be capped at ~30s", d100)
	}
}

func TestServerCustomTLSConfig(t *testing.T) {
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

	serverReady := make(chan net.Conn, 1)
	srv := &Server{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  customTLS,
		Handler: func(conn net.Conn) {
			serverReady <- conn
		},
	}

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	clientCert, err := certgen.GenerateSelfSigned("Client", time.Hour)
	if err != nil {
		t.Fatalf("generate client cert: %v", err)
	}

	clientTLS := certgen.TLSConfig(clientCert, serverFP)
	clientTLS.MinVersion = tls.VersionTLS13

	client := &Client{
		ServerURL: fmt.Sprintf("wss://%s", srv.Addr()),
		TLSConfig: clientTLS,
	}

	conn, err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close()

	select {
	case srvConn := <-serverReady:
		srvConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
