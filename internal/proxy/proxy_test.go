package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func startTestProxy(t *testing.T, username, password string) (*SOCKS5, string) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Username = username
	cfg.Password = password

	s := NewSOCKS5WithConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Stop()
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.StartWithContext(ctx)
	}()

	// Wait for listener to be ready
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		if addr := s.Addr(); addr != "" {
			return s, addr
		}
	}
	t.Fatal("proxy didn't start in time")
	return nil, ""
}

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

func socks5Connect(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	// Greeting: version 5, 1 method (no auth)
	conn.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read greeting resp: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("unexpected greeting: %x", resp)
	}

	host, portStr, _ := net.SplitHostPort(targetAddr)
	ip := net.ParseIP(host)

	// Build CONNECT request
	req := []byte{0x05, 0x01, 0x00}
	if ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	req = append(req, portBuf...)

	conn.Write(req)

	// Read reply
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read reply: %w", err)
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("connect failed: reply code %d", reply[1])
	}

	return conn, nil
}

func TestSOCKS5NoAuth(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestProxy(t, "", "")

	conn, err := socks5Connect(proxyAddr, echoAddr)
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello socks5")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestSOCKS5WithAuth(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestProxy(t, "testuser", "testpass")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting with username/password method
	conn.Write([]byte{0x05, 0x01, 0x02})

	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[1] != 0x02 {
		t.Fatalf("expected auth method 0x02, got 0x%02x", resp[1])
	}

	// Send credentials: VER=1, ULEN=8, UNAME, PLEN=8, PASSWD
	username := "testuser"
	password := "testpass"
	authReq := []byte{0x01, byte(len(username))}
	authReq = append(authReq, []byte(username)...)
	authReq = append(authReq, byte(len(password)))
	authReq = append(authReq, []byte(password)...)
	conn.Write(authReq)

	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: status 0x%02x", authResp[1])
	}

	// Now send CONNECT
	host, portStr, _ := net.SplitHostPort(echoAddr)
	ip := net.ParseIP(host).To4()
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	connectReq = append(connectReq, ip...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	connectReq = append(connectReq, portBuf...)
	conn.Write(connectReq)

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("connect reply code: %d", reply[1])
	}

	msg := []byte("authenticated echo test")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(conn, buf)
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestSOCKS5BadAuth(t *testing.T) {
	_, proxyAddr := startTestProxy(t, "admin", "secret")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	authReq := []byte{0x01, 5}
	authReq = append(authReq, []byte("wrong")...)
	authReq = append(authReq, 5)
	authReq = append(authReq, []byte("creds")...)
	conn.Write(authReq)

	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[1] == 0x00 {
		t.Fatal("auth should have failed")
	}
}

func TestSOCKS5UnsupportedCommand(t *testing.T) {
	_, proxyAddr := startTestProxy(t, "", "")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	// Invalid command (0xFF)
	conn.Write([]byte{0x05, 0xFF, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != RepCmdNotSupported {
		t.Fatalf("expected RepCmdNotSupported (7), got %d", reply[1])
	}
}

func TestSOCKS5Stats(t *testing.T) {
	s, _ := startTestProxy(t, "", "")
	active, total, _, _ := s.Stats()
	if active != 0 || total != 0 {
		t.Fatalf("initial stats: active=%d total=%d", active, total)
	}
}

func startTestProxyWithDialer(t *testing.T, dialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*SOCKS5, string) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Dialer = dialer

	s := NewSOCKS5WithConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Stop()
	})

	go func() {
		s.StartWithContext(ctx)
	}()

	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		if addr := s.Addr(); addr != "" {
			return s, addr
		}
	}
	t.Fatal("proxy didn't start in time")
	return nil, ""
}

func TestSOCKS5CustomDialer(t *testing.T) {
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

	dialerCalled := make(chan string, 1)
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled <- addr
		return net.DialTimeout("tcp", echoLn.Addr().String(), 2*time.Second)
	}

	_, proxyAddr := startTestProxyWithDialer(t, customDialer)

	conn, err := socks5Connect(proxyAddr, "10.99.99.99:9999")
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-dialerCalled:
		if got != "10.99.99.99:9999" {
			t.Fatalf("dialer called with %q, want %q", got, "10.99.99.99:9999")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("custom dialer was not called")
	}

	msg := []byte("custom dialer echo")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestSOCKS5CustomDialerPipe(t *testing.T) {
	pipeDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			io.Copy(server, server)
		}()
		return client, nil
	}

	_, proxyAddr := startTestProxyWithDialer(t, pipeDialer)

	conn, err := socks5Connect(proxyAddr, "192.168.1.1:80")
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()

	msg := []byte("pipe echo test")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestSOCKS5NilDialerUsesDefault(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestProxyWithDialer(t, nil)

	conn, err := socks5Connect(proxyAddr, echoAddr)
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()

	msg := []byte("nil dialer default path")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestParseUDPHeaderIPv4(t *testing.T) {
	// Build a SOCKS5 UDP datagram: RSV(0,0) FRAG(0) ATYP(1=IPv4) IP(127.0.0.1) PORT(53) DATA(hello)
	data := []byte{
		0x00, 0x00, 0x00, 0x01, // RSV, RSV, FRAG, ATYP=IPv4
		127, 0, 0, 1,           // IP
		0x00, 0x35,             // Port 53
		'h', 'e', 'l', 'l', 'o',
	}
	target, hdrLen, err := parseUDPHeader(data)
	if err != nil {
		t.Fatalf("parseUDPHeader: %v", err)
	}
	if target != "127.0.0.1:53" {
		t.Errorf("target = %q, want %q", target, "127.0.0.1:53")
	}
	if hdrLen != 10 {
		t.Errorf("headerLen = %d, want 10", hdrLen)
	}
	payload := data[hdrLen:]
	if string(payload) != "hello" {
		t.Errorf("payload = %q, want %q", payload, "hello")
	}
}

func TestParseUDPHeaderDomain(t *testing.T) {
	// ATYP=domain, domain="dns.test", port=53
	domain := "dns.test"
	data := []byte{0x00, 0x00, 0x00, 0x03, byte(len(domain))}
	data = append(data, []byte(domain)...)
	data = append(data, 0x00, 0x35) // port 53
	data = append(data, []byte("query")...)

	target, hdrLen, err := parseUDPHeader(data)
	if err != nil {
		t.Fatalf("parseUDPHeader: %v", err)
	}
	if target != "dns.test:53" {
		t.Errorf("target = %q, want %q", target, "dns.test:53")
	}
	payload := data[hdrLen:]
	if string(payload) != "query" {
		t.Errorf("payload = %q, want %q", payload, "query")
	}
}

func TestBuildUDPHeaderIPv4(t *testing.T) {
	resp := buildUDPHeader("1.2.3.4:53", []byte("response"))
	// Parse it back
	target, hdrLen, err := parseUDPHeader(resp)
	if err != nil {
		t.Fatalf("parseUDPHeader: %v", err)
	}
	if target != "1.2.3.4:53" {
		t.Errorf("target = %q, want %q", target, "1.2.3.4:53")
	}
	payload := resp[hdrLen:]
	if string(payload) != "response" {
		t.Errorf("payload = %q, want %q", payload, "response")
	}
}

func TestUDPAssociateLocal(t *testing.T) {
	// Start a local UDP echo server.
	echoUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoUDP.Close()
	echoAddr := echoUDP.LocalAddr().String()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echoUDP.ReadFrom(buf)
			if err != nil {
				return
			}
			echoUDP.WriteTo(buf[:n], addr)
		}
	}()

	// Start SOCKS5 proxy (no session dialer — direct mode).
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	srv := NewSOCKS5WithConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartWithContext(ctx)
	time.Sleep(100 * time.Millisecond)
	proxyAddr := srv.Addr()

	// Connect and send UDP ASSOCIATE.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	greetResp := make([]byte, 2)
	io.ReadFull(conn, greetResp)

	// UDP ASSOCIATE request
	conn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00})
	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != RepSucceeded {
		t.Fatalf("expected RepSucceeded, got %d", reply[1])
	}

	// Parse bound UDP address from reply.
	bindIP := net.IP(reply[4:8])
	bindPort := binary.BigEndian.Uint16(reply[8:10])
	udpRelayAddr := net.JoinHostPort(bindIP.String(), fmt.Sprintf("%d", bindPort))

	// Send a SOCKS5 UDP datagram to the echo server through the relay.
	udpConn, err := net.Dial("udp", udpRelayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	// Parse echoAddr for the SOCKS5 header.
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoIP := net.ParseIP(echoHost).To4()
	echoPort := 0
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	// Build SOCKS5 UDP datagram.
	udpDatagram := []byte{0x00, 0x00, 0x00, 0x01}
	udpDatagram = append(udpDatagram, echoIP...)
	udpDatagram = append(udpDatagram, byte(echoPort>>8), byte(echoPort&0xff))
	udpDatagram = append(udpDatagram, []byte("udp-test")...)

	udpConn.Write(udpDatagram)

	// Read response.
	udpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 65535)
	n, err := udpConn.Read(respBuf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}

	// Parse response — should contain "udp-test" as payload.
	_, hdrLen, err := parseUDPHeader(respBuf[:n])
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	payload := string(respBuf[hdrLen:n])
	if payload != "udp-test" {
		t.Fatalf("payload = %q, want %q", payload, "udp-test")
	}
}

func TestSOCKS5Bind(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	srv := NewSOCKS5WithConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartWithContext(ctx)
	time.Sleep(100 * time.Millisecond)
	proxyAddr := srv.Addr()

	// Connect and send BIND request.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	greetResp := make([]byte, 2)
	io.ReadFull(conn, greetResp)

	// BIND request (cmd=0x02)
	conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00})

	// First reply: bound address.
	reply1 := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, reply1); err != nil {
		t.Fatalf("read first reply: %v", err)
	}
	if reply1[1] != RepSucceeded {
		t.Fatalf("expected RepSucceeded, got %d", reply1[1])
	}

	// Parse bound address.
	bindIP := net.IP(reply1[4:8])
	bindPort := binary.BigEndian.Uint16(reply1[8:10])
	bindAddr := net.JoinHostPort(bindIP.String(), fmt.Sprintf("%d", bindPort))

	// Connect to the bound address (simulating an incoming connection).
	incoming, err := net.DialTimeout("tcp", bindAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to bind addr %s: %v", bindAddr, err)
	}
	defer incoming.Close()

	// Second reply: connecting client's address.
	reply2 := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, reply2); err != nil {
		t.Fatalf("read second reply: %v", err)
	}
	if reply2[1] != RepSucceeded {
		t.Fatalf("expected RepSucceeded in second reply, got %d", reply2[1])
	}

	// Test bidirectional relay.
	msg := []byte("bind-test-data")
	incoming.Write(msg)
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read relayed data: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("relayed = %q, want %q", buf, msg)
	}

	// Test reverse direction.
	msg2 := []byte("reverse-bind")
	conn.Write(msg2)
	buf2 := make([]byte, len(msg2))
	incoming.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(incoming, buf2); err != nil {
		t.Fatalf("read reverse: %v", err)
	}
	if string(buf2) != string(msg2) {
		t.Fatalf("reverse = %q, want %q", buf2, msg2)
	}
}
