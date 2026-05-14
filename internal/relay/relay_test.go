package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestParseSpecTCPListen(t *testing.T) {
	tests := []struct {
		spec    string
		wantErr bool
		wantTyp string
		addr    string
	}{
		{"tcp-listen:8080", false, "TCPListen", "0.0.0.0:8080"},
		{"tcp-listen:127.0.0.1:9090", false, "TCPListen", "127.0.0.1:9090"},
	}

	for _, tt := range tests {
		ep, err := ParseSpec(tt.spec)
		if (err != nil) != tt.wantErr {
			t.Fatalf("ParseSpec(%q) err = %v, wantErr %v", tt.spec, err, tt.wantErr)
		}
		if err != nil {
			continue
		}
		tcp, ok := ep.(*TCPListenEndpoint)
		if !ok {
			t.Fatalf("ParseSpec(%q) = %T, want *TCPListenEndpoint", tt.spec, ep)
		}
		if tcp.Addr != tt.addr {
			t.Fatalf("ParseSpec(%q).Addr = %q, want %q", tt.spec, tcp.Addr, tt.addr)
		}
	}
}

func TestParseSpecTCPConnect(t *testing.T) {
	ep, err := ParseSpec("tcp-connect:10.0.0.5:80")
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := ep.(*TCPConnectEndpoint)
	if !ok {
		t.Fatalf("got %T, want *TCPConnectEndpoint", ep)
	}
	if tcp.Addr != "10.0.0.5:80" {
		t.Fatalf("addr = %q, want %q", tcp.Addr, "10.0.0.5:80")
	}
}

func TestParseSpecUDPListen(t *testing.T) {
	ep, err := ParseSpec("udp-listen:5353")
	if err != nil {
		t.Fatal(err)
	}
	udp, ok := ep.(*UDPListenEndpoint)
	if !ok {
		t.Fatalf("got %T, want *UDPListenEndpoint", ep)
	}
	if udp.Addr != "0.0.0.0:5353" {
		t.Fatalf("addr = %q, want %q", udp.Addr, "0.0.0.0:5353")
	}
}

func TestParseSpecUDPConnect(t *testing.T) {
	ep, err := ParseSpec("udp-connect:8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	udp, ok := ep.(*UDPConnectEndpoint)
	if !ok {
		t.Fatalf("got %T, want *UDPConnectEndpoint", ep)
	}
	if udp.Addr != "8.8.8.8:53" {
		t.Fatalf("addr = %q, want %q", udp.Addr, "8.8.8.8:53")
	}
}

func TestParseSpecUnixListen(t *testing.T) {
	ep, err := ParseSpec("unix-listen:/tmp/test.sock")
	if err != nil {
		t.Fatal(err)
	}
	u, ok := ep.(*UnixListenEndpoint)
	if !ok {
		t.Fatalf("got %T, want *UnixListenEndpoint", ep)
	}
	if u.Path != "/tmp/test.sock" {
		t.Fatalf("path = %q, want %q", u.Path, "/tmp/test.sock")
	}
}

func TestParseSpecUnixConnect(t *testing.T) {
	ep, err := ParseSpec("unix-connect:/var/run/app.sock")
	if err != nil {
		t.Fatal(err)
	}
	u, ok := ep.(*UnixConnectEndpoint)
	if !ok {
		t.Fatalf("got %T, want *UnixConnectEndpoint", ep)
	}
	if u.Path != "/var/run/app.sock" {
		t.Fatalf("path = %q, want %q", u.Path, "/var/run/app.sock")
	}
}

func TestParseSpecExec(t *testing.T) {
	ep, err := ParseSpec("exec:cat")
	if err != nil {
		t.Fatal(err)
	}
	e, ok := ep.(*ExecEndpoint)
	if !ok {
		t.Fatalf("got %T, want *ExecEndpoint", ep)
	}
	if e.Command != "cat" {
		t.Fatalf("command = %q, want %q", e.Command, "cat")
	}
}

func TestParseSpecStdio(t *testing.T) {
	ep, err := ParseSpec("stdio")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ep.(*StdioEndpoint); !ok {
		t.Fatalf("got %T, want *StdioEndpoint", ep)
	}
}

func TestParseSpecErrors(t *testing.T) {
	badSpecs := []string{
		"invalid",
		"unknown-type:foo",
		"tcp-connect:noport",
		"unix-listen:",
		"unix-connect:",
		"exec:",
	}
	for _, s := range badSpecs {
		_, err := ParseSpec(s)
		if err == nil {
			t.Fatalf("ParseSpec(%q) expected error", s)
		}
	}
}

func TestRelayBidirectional(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		Relay(ctx, a2, b1)
	}()

	msgAtoB := []byte("hello from A")
	msgBtoA := []byte("hello from B")

	var writeWg sync.WaitGroup
	writeWg.Add(2)

	go func() {
		defer writeWg.Done()
		a1.Write(msgAtoB)
	}()
	go func() {
		defer writeWg.Done()
		b2.Write(msgBtoA)
	}()

	bufB := make([]byte, len(msgAtoB))
	b2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(b2, bufB); err != nil {
		t.Fatalf("read B side: %v", err)
	}
	if string(bufB) != string(msgAtoB) {
		t.Fatalf("B got %q, want %q", bufB, msgAtoB)
	}

	bufA := make([]byte, len(msgBtoA))
	a1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(a1, bufA); err != nil {
		t.Fatalf("read A side: %v", err)
	}
	if string(bufA) != string(msgBtoA) {
		t.Fatalf("A got %q, want %q", bufA, msgBtoA)
	}

	a1.Close()
	b2.Close()
	wg.Wait()
}

func TestTCPRelay(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	listenEp := &TCPListenEndpoint{Addr: "127.0.0.1:0"}
	connectEp := &TCPConnectEndpoint{Addr: echoLn.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// We need to know the actual listen port. Open the listener side first
	// by listening manually, then connecting.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := ln.Addr().String()

	var relayErr error
	var relayWg sync.WaitGroup
	relayWg.Add(1)
	go func() {
		defer relayWg.Done()
		conn, err := ln.Accept()
		if err != nil {
			relayErr = err
			return
		}
		ln.Close()

		dstConn, err := connectEp.Open(ctx)
		if err != nil {
			conn.Close()
			relayErr = err
			return
		}

		relayErr = Relay(ctx, conn, dstConn)
	}()

	_ = listenEp // used listenAddr from manual listener instead

	client, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	msg := []byte("tcp relay test data")
	client.Write(msg)

	buf := make([]byte, len(msg))
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	client.Close()
	relayWg.Wait()

	if relayErr != nil {
		t.Logf("relay finished with: %v", relayErr)
	}
}

func TestUnixSocketRelay(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	listenEp := &UnixListenEndpoint{Path: sockPath}
	connectEp := &TCPConnectEndpoint{Addr: echoLn.Addr().String()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var relayWg sync.WaitGroup
	relayWg.Add(1)
	go func() {
		defer relayWg.Done()
		srcConn, err := listenEp.Open(ctx)
		if err != nil {
			return
		}
		dstConn, err := connectEp.Open(ctx)
		if err != nil {
			srcConn.Close()
			return
		}
		Relay(ctx, srcConn, dstConn)
	}()

	time.Sleep(50 * time.Millisecond)

	client, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer client.Close()

	msg := []byte("unix socket relay")
	client.Write(msg)

	buf := make([]byte, len(msg))
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}

	client.Close()
	relayWg.Wait()
}

func TestExecEndpoint(t *testing.T) {
	ep := &ExecEndpoint{Command: "cat"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := ep.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("exec echo via cat")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

func TestStdioEndpointMock(t *testing.T) {
	origIn := os.Stdin
	origOut := os.Stdout
	defer func() {
		os.Stdin = origIn
		os.Stdout = origOut
	}()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	os.Stdin = inR
	os.Stdout = outW

	ep := &StdioEndpoint{}
	conn, err := ep.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("stdio test")
	inW.Write(msg)

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read stdin: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("stdin got %q, want %q", buf, msg)
	}

	outMsg := []byte("stdout test")
	conn.Write(outMsg)

	outBuf := make([]byte, len(outMsg))
	if _, err := io.ReadFull(outR, outBuf); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if !bytes.Equal(outBuf, outMsg) {
		t.Fatalf("stdout got %q, want %q", outBuf, outMsg)
	}

	conn.Close()
	inW.Close()
	outW.Close()
}
