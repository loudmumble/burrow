package raw_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
	"github.com/loudmumble/burrow/internal/transport/raw"
)

var _ transport.Transport = (*raw.RawTransport)(nil)

func TestRawTransportInterface(t *testing.T) {
	var _ transport.Transport = raw.NewRawTransport()
}

func TestRawTransportName(t *testing.T) {
	tr := raw.NewRawTransport()
	if tr.Name() != "raw" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "raw")
	}
}

func TestRawTransportListenAcceptDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvTr := raw.NewRawTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	addr := srvTr.Addr()
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

	clientTr := raw.NewRawTransport()
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

func TestRawTransportBidirectional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srvTr := raw.NewRawTransport()
	if err := srvTr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srvTr.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := srvTr.Accept()
		acceptDone <- conn
	}()

	clientTr := raw.NewRawTransport()
	clientConn, err := clientTr.Dial(ctx, srvTr.Addr(), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	srvConn := <-acceptDone

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

func TestRawTransportClose(t *testing.T) {
	ctx := context.Background()
	tr := raw.NewRawTransport()
	if err := tr.Listen(ctx, "127.0.0.1:0", nil); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("double Close should not error: %v", err)
	}
}

func TestRawTransportRegistered(t *testing.T) {
	ctor, ok := transport.Registry["raw"]
	if !ok {
		t.Fatal("raw transport not registered")
	}
	tr := ctor()
	if tr.Name() != "raw" {
		t.Errorf("Name() = %q, want %q", tr.Name(), "raw")
	}
}
