package httptunnel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- Protocol Tests ---

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := []byte("testkey123")
	data := []byte("hello world, this is sensitive data!")

	encrypted := Encrypt(data, key)
	if string(encrypted) == string(data) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted := Decrypt(encrypted, key)
	if string(decrypted) != string(data) {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, data)
	}
}

func TestEncryptDecryptEmptyKey(t *testing.T) {
	data := []byte("no encryption")
	encrypted := Encrypt(data, nil)
	if string(encrypted) != string(data) {
		t.Fatal("empty key should return data unchanged")
	}

	encrypted = Encrypt(data, []byte{})
	if string(encrypted) != string(data) {
		t.Fatal("zero-length key should return data unchanged")
	}
}

func TestEncodeDecodePayloadRoundtrip(t *testing.T) {
	key := []byte("secretkey")
	data := []byte("payload with binary \x00\x01\x02 bytes")

	encoded := EncodePayload(data, key)
	if encoded == string(data) {
		t.Fatal("encoded payload should differ from raw data")
	}

	decoded, err := DecodePayload(encoded, key)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("roundtrip failed: got %q, want %q", decoded, data)
	}
}

func TestDecodePayloadInvalidBase64(t *testing.T) {
	_, err := DecodePayload("not-valid-base64!!!", []byte("key"))
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestGenerateSessionID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateSessionID()
		if len(id) != 16 {
			t.Fatalf("session ID should be 16 hex chars, got %d: %s", len(id), id)
		}
		if ids[id] {
			t.Fatalf("duplicate session ID: %s", id)
		}
		ids[id] = true
	}
}

func TestAuthToken(t *testing.T) {
	key := []byte("mysecret")
	token1 := AuthToken(key)
	token2 := AuthToken(key)
	if token1 != token2 {
		t.Fatal("same key should produce same token")
	}
	if len(token1) != 64 { // SHA256 hex = 64 chars
		t.Fatalf("token should be 64 hex chars, got %d", len(token1))
	}

	differentToken := AuthToken([]byte("different"))
	if differentToken == token1 {
		t.Fatal("different keys should produce different tokens")
	}
}

// --- Server Tests ---

func newTestServer(key []byte) (*Server, *httptest.Server) {
	cfg := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Key:        key,
		Path:       "/b",
	}
	srv := NewServer(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc(srv.path, srv.handleTunnel)
	mux.HandleFunc("/", srv.handleCover)

	ts := httptest.NewServer(mux)
	return srv, ts
}

func TestServerCoverPage(t *testing.T) {
	_, ts := newTestServer(nil)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "It works!") {
		t.Fatal("cover page should contain 'It works!'")
	}
}

func TestServerPing(t *testing.T) {
	_, ts := newTestServer(nil)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/b?cmd=ping", "", nil)
	if err != nil {
		t.Fatalf("ping failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Fatalf("expected 'pong', got %q", body)
	}
}

func TestServerAuthValid(t *testing.T) {
	key := []byte("secret")
	_, ts := newTestServer(key)
	defer ts.Close()

	// With valid token
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/b?cmd=ping", nil)
	req.Header.Set("X-Token", AuthToken(key))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token should return 200, got %d", resp.StatusCode)
	}
}

func TestServerAuthInvalid(t *testing.T) {
	key := []byte("secret")
	_, ts := newTestServer(key)
	defer ts.Close()

	// With invalid token
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/b?cmd=ping", nil)
	req.Header.Set("X-Token", "wrongtoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("invalid token should return 404, got %d", resp.StatusCode)
	}
}

func TestServerAuthMissing(t *testing.T) {
	key := []byte("secret")
	_, ts := newTestServer(key)
	defer ts.Close()

	// Without token
	resp, err := http.Post(ts.URL+"/b?cmd=ping", "", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing token should return 404, got %d", resp.StatusCode)
	}
}

func TestServerGetMethodRejects(t *testing.T) {
	_, ts := newTestServer(nil)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/b?cmd=ping")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET to tunnel path should return 404, got %d", resp.StatusCode)
	}
}

func TestServerConnectSendRecvDisconnect(t *testing.T) {
	_, ts := newTestServer(nil)
	defer ts.Close()

	// Start a TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
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

	echoAddr := echoLn.Addr().String()

	// Connect
	resp, err := http.Post(
		fmt.Sprintf("%s/b?cmd=connect&target=%s", ts.URL, echoAddr),
		"", nil,
	)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Parse session ID
	var cr connectResponse
	if err := parseJSON(body, &cr); err != nil {
		t.Fatalf("parse connect response: %v", err)
	}
	if cr.SID == "" {
		t.Fatal("empty session ID")
	}
	sid := cr.SID

	// Send data
	testData := "hello echo server"
	resp, err = http.Post(
		fmt.Sprintf("%s/b?cmd=send&sid=%s", ts.URL, sid),
		"application/octet-stream",
		strings.NewReader(testData),
	)
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send: expected 200, got %d", resp.StatusCode)
	}

	// Recv data (with retries since echo may not be instant)
	var recvData []byte
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		resp, err = http.Post(
			fmt.Sprintf("%s/b?cmd=recv&sid=%s", ts.URL, sid),
			"", nil,
		)
		if err != nil {
			t.Fatalf("recv failed: %v", err)
		}
		recvData, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("recv: expected 200, got %d", resp.StatusCode)
		}
		if len(recvData) > 0 {
			break
		}
	}

	if string(recvData) != testData {
		t.Fatalf("recv: got %q, want %q", recvData, testData)
	}

	// Disconnect
	resp, err = http.Post(
		fmt.Sprintf("%s/b?cmd=disconnect&sid=%s", ts.URL, sid),
		"", nil,
	)
	if err != nil {
		t.Fatalf("disconnect failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect: expected 200, got %d", resp.StatusCode)
	}

	// Verify session is gone
	resp, err = http.Post(
		fmt.Sprintf("%s/b?cmd=recv&sid=%s", ts.URL, sid),
		"", nil,
	)
	if err != nil {
		t.Fatalf("post-disconnect recv: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-disconnect recv should return 404, got %d", resp.StatusCode)
	}
}

func TestServerConnectSendRecvWithEncryption(t *testing.T) {
	key := []byte("encryptionkey")
	srv, ts := newTestServer(key)
	_ = srv
	defer ts.Close()

	// Start a TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
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

	echoAddr := echoLn.Addr().String()
	authToken := AuthToken(key)

	// Connect
	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/b?cmd=connect&target=%s", ts.URL, echoAddr), nil)
	req.Header.Set("X-Token", authToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect: %d", resp.StatusCode)
	}

	// Decode encrypted response
	jsonBody, err := DecodePayload(string(body), key)
	if err != nil {
		t.Fatalf("decode connect response: %v", err)
	}
	var cr connectResponse
	if err := parseJSON(jsonBody, &cr); err != nil {
		t.Fatalf("parse connect response: %v", err)
	}
	sid := cr.SID

	// Send encrypted data
	testData := "encrypted hello"
	encoded := EncodePayload([]byte(testData), key)
	req, _ = http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/b?cmd=send&sid=%s", ts.URL, sid),
		strings.NewReader(encoded))
	req.Header.Set("X-Token", authToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	resp.Body.Close()

	// Recv encrypted data
	var recvData []byte
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		req, _ = http.NewRequest(http.MethodPost,
			fmt.Sprintf("%s/b?cmd=recv&sid=%s", ts.URL, sid),
			nil)
		req.Header.Set("X-Token", authToken)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(body) > 0 {
			recvData, err = DecodePayload(string(body), key)
			if err != nil {
				t.Fatalf("decode recv: %v", err)
			}
			break
		}
	}

	if string(recvData) != testData {
		t.Fatalf("recv: got %q, want %q", recvData, testData)
	}

	// Disconnect
	req, _ = http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/b?cmd=disconnect&sid=%s", ts.URL, sid), nil)
	req.Header.Set("X-Token", authToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	resp.Body.Close()
}

// --- Full Tunnel Test (Client SOCKS5 -> HTTP -> Server -> TCP) ---

func TestFullTunnelSOCKS5(t *testing.T) {
	// 1. Start TCP echo server (simulates internal host)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
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

	echoAddr := echoLn.Addr().String()

	// 2. Start HTTP tunnel server
	srv, ts := newTestServer(nil)
	_ = srv
	defer ts.Close()

	// 3. Start HTTP tunnel client with SOCKS5
	clientCfg := &ClientConfig{
		ServerURL: ts.URL + "/b",
		SocksAddr: "127.0.0.1:0",
	}
	client := NewClient(clientCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- client.Start(ctx)
	}()

	// Wait for client to start listening
	var socksAddr string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		socksAddr = client.Addr()
		if socksAddr != "" {
			break
		}
	}
	if socksAddr == "" {
		t.Fatal("client did not start listening")
	}

	// 4. Connect through SOCKS5
	socksConn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to SOCKS5: %v", err)
	}
	defer socksConn.Close()

	// SOCKS5 greeting
	socksConn.Write([]byte{0x05, 0x01, 0x00}) // version 5, 1 method, no auth
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if greetResp[0] != 0x05 || greetResp[1] != 0x00 {
		t.Fatalf("unexpected greeting response: %v", greetResp)
	}

	// SOCKS5 CONNECT to echo server
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoIP := net.ParseIP(echoHost)
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	connectReq := make([]byte, 10)
	connectReq[0] = 0x05 // version
	connectReq[1] = 0x01 // CONNECT
	connectReq[2] = 0x00 // RSV
	connectReq[3] = 0x01 // IPv4
	copy(connectReq[4:8], echoIP.To4())
	binary.BigEndian.PutUint16(connectReq[8:10], uint16(echoPort))
	socksConn.Write(connectReq)

	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, connectResp); err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed with reply: %d", connectResp[1])
	}

	// 5. Send data through the tunnel and verify echo
	testMsg := "hello through the tunnel!"
	socksConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := socksConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}

	socksConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(socksConn, buf); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}

	if string(buf) != testMsg {
		t.Fatalf("echo mismatch: got %q, want %q", buf, testMsg)
	}

	// Cleanup
	socksConn.Close()
	cancel()
}

func TestFullTunnelWithEncryption(t *testing.T) {
	key := []byte("tunnel-key")

	// 1. Start TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
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

	echoAddr := echoLn.Addr().String()

	// 2. Start server with key
	srv, ts := newTestServer(key)
	_ = srv
	defer ts.Close()

	// 3. Start client with matching key
	clientCfg := &ClientConfig{
		ServerURL: ts.URL + "/b",
		SocksAddr: "127.0.0.1:0",
		Key:       key,
	}
	client := NewClient(clientCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go client.Start(ctx)

	var socksAddr string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		socksAddr = client.Addr()
		if socksAddr != "" {
			break
		}
	}
	if socksAddr == "" {
		t.Fatal("client did not start")
	}

	// 4. SOCKS5 handshake
	socksConn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect SOCKS5: %v", err)
	}
	defer socksConn.Close()

	socksConn.Write([]byte{0x05, 0x01, 0x00})
	greetResp := make([]byte, 2)
	io.ReadFull(socksConn, greetResp)

	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoIP := net.ParseIP(echoHost)
	var echoPort int
	fmt.Sscanf(echoPortStr, "%d", &echoPort)

	connectReq := make([]byte, 10)
	connectReq[0] = 0x05
	connectReq[1] = 0x01
	connectReq[3] = 0x01
	copy(connectReq[4:8], echoIP.To4())
	binary.BigEndian.PutUint16(connectReq[8:10], uint16(echoPort))
	socksConn.Write(connectReq)

	connectResp := make([]byte, 10)
	io.ReadFull(socksConn, connectResp)
	if connectResp[1] != 0x00 {
		t.Fatalf("CONNECT failed: %d", connectResp[1])
	}

	// 5. Echo test
	testMsg := "encrypted tunnel test!"
	socksConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	socksConn.Write([]byte(testMsg))

	socksConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(socksConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != testMsg {
		t.Fatalf("got %q, want %q", buf, testMsg)
	}

	socksConn.Close()
	cancel()
}

// --- Session Cleanup Test ---

func TestSessionCleanup(t *testing.T) {
	srv, ts := newTestServer(nil)
	defer ts.Close()

	// Start a TCP server that accepts and holds connections
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer tcpLn.Close()

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			// Hold connection open
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()

	// Connect
	resp, err := http.Post(
		fmt.Sprintf("%s/b?cmd=connect&target=%s", ts.URL, tcpLn.Addr().String()),
		"", nil,
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var cr connectResponse
	parseJSON(body, &cr)
	sid := cr.SID

	// Verify session exists
	_, exists := srv.sessions.Load(sid)
	if !exists {
		t.Fatal("session should exist after connect")
	}

	// Manually set lastUse to past to trigger cleanup
	val, _ := srv.sessions.Load(sid)
	sess := val.(*tcpSession)
	sess.mu.Lock()
	sess.lastUse = time.Now().Add(-10 * time.Minute)
	sess.mu.Unlock()

	// Run cleanup directly
	srv.cleanupIdleSessions()

	_, exists = srv.sessions.Load(sid)
	if exists {
		t.Fatal("session should be cleaned up after idle timeout")
	}
}

// helper
func parseJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
