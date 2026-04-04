package tunnel

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

func TestLocalForward(t *testing.T) {
	echoAddr := startEchoServer(t)

	tun := NewLocalForward("127.0.0.1:0", echoAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tun.StartWithContext(ctx); err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	defer tun.Stop()

	listenAddr := tun.Addr()
	if listenAddr == "" {
		t.Fatal("tunnel has no listen address")
	}

	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("tunnel forward test")
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

func TestRemoteForward(t *testing.T) {
	echoAddr := startEchoServer(t)

	tun := NewRemoteForward("127.0.0.1:0", echoAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tun.StartWithContext(ctx); err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	defer tun.Stop()

	conn, err := net.DialTimeout("tcp", tun.Addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("remote forward test")
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

func TestReverseTunnelForward(t *testing.T) {
	echoAddr := startEchoServer(t)

	cfg := DefaultReverseConfig()
	cfg.AgentAddr = "127.0.0.1:0"
	cfg.LocalTarget = echoAddr

	rt := NewReverseTunnelWithConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rt.StartWithContext(ctx); err != nil {
		t.Fatalf("start reverse tunnel: %v", err)
	}
	defer rt.Stop()

	addr := rt.Addr()
	if addr == "" {
		t.Fatal("reverse tunnel has no address")
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial reverse tunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("reverse tunnel echo")
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

func TestTunnelStop(t *testing.T) {
	echoAddr := startEchoServer(t)
	tun := NewLocalForward("127.0.0.1:0", echoAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := tun.StartWithContext(ctx); err != nil {
		t.Fatal(err)
	}

	addr := tun.Addr()
	tun.Stop()

	_, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Fatal("connection should fail after stop")
	}

	if tun.Status != StatusClosed {
		t.Fatalf("status = %v, want closed", tun.Status)
	}
}

func TestTunnelBytesTransferred(t *testing.T) {
	echoAddr := startEchoServer(t)
	tun := NewLocalForward("127.0.0.1:0", echoAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tun.StartWithContext(ctx)
	defer tun.Stop()

	conn, _ := net.DialTimeout("tcp", tun.Addr(), time.Second)
	msg := []byte("bytes test")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(time.Second))
	io.ReadFull(conn, buf)
	conn.Close()

	time.Sleep(50 * time.Millisecond)

	bIn, bOut := tun.BytesTransferred()
	if bIn == 0 && bOut == 0 {
		t.Fatal("no bytes transferred")
	}
}

func TestBackoffDelay(t *testing.T) {
	cfg := DefaultReverseConfig()
	rt := NewReverseTunnelWithConfig(cfg)

	d0 := rt.backoffDelay(0)
	d1 := rt.backoffDelay(1)
	d5 := rt.backoffDelay(5)

	if d0 <= 0 {
		t.Fatal("delay at attempt 0 should be positive")
	}
	if d1 <= d0/2 {
		t.Fatalf("delay should increase: d0=%v d1=%v", d0, d1)
	}

	if d5 > cfg.MaxDelay+time.Duration(float64(cfg.MaxDelay)*cfg.Jitter)+time.Millisecond {
		t.Fatalf("delay %v exceeds max %v", d5, cfg.MaxDelay)
	}
}
