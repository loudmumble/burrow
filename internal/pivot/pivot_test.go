package pivot

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestChainEstablish(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, port := parseHostPort(t, echoAddr)

	chain := NewChain([]Hop{{Host: host, Port: port}})

	if err := chain.Establish(); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer chain.Close()

	if !chain.IsActive() {
		t.Fatal("chain should be active")
	}
	if chain.Depth() != 1 {
		t.Fatalf("depth = %d, want 1", chain.Depth())
	}
	if chain.Latency() <= 0 {
		t.Fatal("latency should be positive")
	}
}

func TestChainEstablishFail(t *testing.T) {
	chain := NewChain([]Hop{{Host: "192.0.2.1", Port: 1}})
	chain.dialTimeout = 200 * time.Millisecond

	err := chain.Establish()
	if err == nil {
		t.Fatal("should fail to connect to unreachable host")
	}
	if chain.IsActive() {
		t.Fatal("chain should not be active after failure")
	}
}

func TestChainRoute(t *testing.T) {
	chain := NewChain([]Hop{
		{Host: "10.0.0.1", Port: 22},
		{Host: "10.0.0.2", Port: 443},
		{Host: "10.0.0.3", Port: 8443},
	})

	expected := "10.0.0.1:22 -> 10.0.0.2:443 -> 10.0.0.3:8443"
	if route := chain.Route(); route != expected {
		t.Fatalf("route = %q, want %q", route, expected)
	}
}

func TestChainEmptyRoute(t *testing.T) {
	chain := NewChain(nil)
	if route := chain.Route(); route != "(empty chain)" {
		t.Fatalf("route = %q, want empty chain", route)
	}
}

func TestChainListener(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, port := parseHostPort(t, echoAddr)

	chain := NewChain([]Hop{{Host: host, Port: port}})
	if err := chain.Establish(); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer chain.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := chain.StartListener(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("StartListener: %v", err)
	}

	conn, err := net.DialTimeout("tcp", chain.listenAddr, time.Second)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()

	msg := []byte("pivot relay test")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestChainDial(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, port := parseHostPort(t, echoAddr)

	chain := NewChain([]Hop{{Host: host, Port: port}})
	if err := chain.Establish(); err != nil {
		t.Fatal(err)
	}
	defer chain.Close()

	conn, err := chain.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
}

func TestChainDialNotEstablished(t *testing.T) {
	chain := NewChain([]Hop{{Host: "10.0.0.1", Port: 22}})
	_, err := chain.Dial("tcp", "10.0.0.1:22")
	if err == nil {
		t.Fatal("Dial should fail on unestablished chain")
	}
}

func TestChainClose(t *testing.T) {
	echoAddr := startEchoServer(t)
	host, port := parseHostPort(t, echoAddr)

	chain := NewChain([]Hop{{Host: host, Port: port}})
	chain.Establish()
	chain.Close()

	if chain.IsActive() {
		t.Fatal("chain should not be active after close")
	}
}

func TestHopEndpoint(t *testing.T) {
	h := Hop{Host: "10.0.0.1", Port: 8443}
	if ep := h.Endpoint(); ep != "10.0.0.1:8443" {
		t.Fatalf("endpoint = %q, want 10.0.0.1:8443", ep)
	}
}

func parseHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}
