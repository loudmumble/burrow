package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startTestHTTPProxy(t *testing.T, username, password string) (*HTTPProxy, string) {
	t.Helper()
	cfg := DefaultHTTPProxyConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Username = username
	cfg.Password = password

	p := NewHTTPProxyWithConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		p.Stop()
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.StartWithContext(ctx)
	}()

	// Wait for listener to be ready
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		if addr := p.Addr(); addr != "" {
			return p, addr
		}
	}
	t.Fatal("http proxy didn't start in time")
	return nil, ""
}

func startTestHTTPProxyWithDialer(t *testing.T, dialer func(ctx context.Context, network, addr string) (net.Conn, error)) (*HTTPProxy, string) {
	t.Helper()
	cfg := DefaultHTTPProxyConfig()
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.Dialer = dialer

	p := NewHTTPProxyWithConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		p.Stop()
	})

	go func() {
		p.StartWithContext(ctx)
	}()

	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		if addr := p.Addr(); addr != "" {
			return p, addr
		}
	}
	t.Fatal("http proxy didn't start in time")
	return nil, ""
}

// startHTTPEchoServer starts an HTTP server that echoes the request body back.
func startHTTPEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		if r.Body != nil {
			io.Copy(w, r.Body)
		}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String()
}

func TestHTTPProxyCONNECT(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestHTTPProxy(t, "", "")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	conn.Write([]byte(connectReq))

	// Read response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Now the tunnel is established — send data through it
	msg := []byte("hello http connect tunnel")
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

func TestHTTPProxyForwardGET(t *testing.T) {
	echoAddr := startHTTPEchoServer(t)
	_, proxyAddr := startTestHTTPProxy(t, "", "")

	// Use the proxy for a regular HTTP GET
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send an absolute-form HTTP request (as a proxy client would)
	reqStr := fmt.Sprintf("GET http://%s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr, echoAddr)
	conn.Write([]byte(reqStr))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	method := resp.Header.Get("X-Echo-Method")
	if method != "GET" {
		t.Fatalf("echoed method = %q, want GET", method)
	}

	path := resp.Header.Get("X-Echo-Path")
	if path != "/test" {
		t.Fatalf("echoed path = %q, want /test", path)
	}
}

func TestHTTPProxyForwardPOST(t *testing.T) {
	echoAddr := startHTTPEchoServer(t)
	_, proxyAddr := startTestHTTPProxy(t, "", "")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	body := "post body data"
	reqStr := fmt.Sprintf(
		"POST http://%s/submit HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		echoAddr, echoAddr, len(body), body,
	)
	conn.Write([]byte(reqStr))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != body {
		t.Fatalf("echo body = %q, want %q", respBody, body)
	}
}

func TestHTTPProxyAuth(t *testing.T) {
	echoAddr := startEchoServer(t)
	_, proxyAddr := startTestHTTPProxy(t, "proxyuser", "proxypass")

	// Test with correct credentials
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	creds := base64.StdEncoding.EncodeToString([]byte("proxyuser:proxypass"))
	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		echoAddr, echoAddr, creds,
	)
	conn.Write([]byte(connectReq))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Verify tunnel works
	msg := []byte("authenticated tunnel")
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

func TestHTTPProxyAuthFailed(t *testing.T) {
	_, proxyAddr := startTestHTTPProxy(t, "admin", "secret")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// No auth header
	conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 407 {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

func TestHTTPProxyAuthWrongCreds(t *testing.T) {
	_, proxyAddr := startTestHTTPProxy(t, "admin", "secret")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	creds := base64.StdEncoding.EncodeToString([]byte("wrong:creds"))
	connectReq := fmt.Sprintf(
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		creds,
	)
	conn.Write([]byte(connectReq))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 407 {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
}

func TestHTTPProxyStats(t *testing.T) {
	p, _ := startTestHTTPProxy(t, "", "")
	active, total, _, _ := p.Stats()
	if active != 0 || total != 0 {
		t.Fatalf("initial stats: active=%d total=%d", active, total)
	}
}

func TestHTTPProxyStatsAfterConnect(t *testing.T) {
	echoAddr := startEchoServer(t)
	p, proxyAddr := startTestHTTPProxy(t, "", "")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	conn.Write([]byte(connectReq))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Send some data through the tunnel
	msg := []byte("stats test data")
	conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(conn, buf)

	conn.Close()

	// Give goroutines time to finish
	time.Sleep(100 * time.Millisecond)

	_, total, bytesIn, bytesOut := p.Stats()
	if total < 1 {
		t.Fatalf("total = %d, want >= 1", total)
	}
	if bytesIn == 0 {
		t.Fatal("bytesIn = 0, want > 0")
	}
	if bytesOut == 0 {
		t.Fatal("bytesOut = 0, want > 0")
	}
}

func TestHTTPProxyCustomDialer(t *testing.T) {
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

	_, proxyAddr := startTestHTTPProxyWithDialer(t, customDialer)

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := "CONNECT 10.99.99.99:9999 HTTP/1.1\r\nHost: 10.99.99.99:9999\r\n\r\n"
	conn.Write([]byte(connectReq))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

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

func TestHTTPProxyCONNECTDefaultPort(t *testing.T) {
	// CONNECT to a host without port should default to 443
	dialerCalled := make(chan string, 1)
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled <- addr
		// Return a pipe so we don't need a real server
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			io.Copy(server, server)
		}()
		return client, nil
	}

	_, proxyAddr := startTestHTTPProxyWithDialer(t, customDialer)

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	select {
	case got := <-dialerCalled:
		if !strings.HasSuffix(got, ":443") {
			t.Fatalf("dialer called with %q, want suffix :443", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("custom dialer was not called")
	}
}

func TestHTTPProxyBadGateway(t *testing.T) {
	// Use a dialer that always fails
	failDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}

	_, proxyAddr := startTestHTTPProxyWithDialer(t, failDialer)

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("CONNECT unreachable.host:443 HTTP/1.1\r\nHost: unreachable.host:443\r\n\r\n"))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 502 {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestHTTPProxyHopByHopStripping(t *testing.T) {
	// Start an HTTP server that echoes received headers
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	receivedHeaders := make(chan http.Header, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header
		w.WriteHeader(200)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	_, proxyAddr := startTestHTTPProxy(t, "", "")

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	targetAddr := ln.Addr().String()
	reqStr := fmt.Sprintf(
		"GET http://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nConnection: close\r\nX-Custom: preserved\r\n\r\n",
		targetAddr, targetAddr,
	)
	conn.Write([]byte(reqStr))

	select {
	case hdrs := <-receivedHeaders:
		if hdrs.Get("Proxy-Connection") != "" {
			t.Fatal("Proxy-Connection should have been stripped")
		}
		if hdrs.Get("Connection") != "" {
			t.Fatal("Connection should have been stripped")
		}
		if hdrs.Get("X-Custom") != "preserved" {
			t.Fatalf("X-Custom = %q, want 'preserved'", hdrs.Get("X-Custom"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream server didn't receive request")
	}
}
