package httptunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Secure Crypto Tests ---

func TestSecureEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	copy(key, []byte("test-key-for-aes-256-gcm-12345"))

	data := []byte("hello world, this is sensitive data via AES-GCM!")

	encrypted, err := SecureEncrypt(data, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(encrypted) == string(data) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted, err := SecureDecrypt(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(data) {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, data)
	}
}

func TestSecureDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	copy(key1, []byte("key-one-aaaaaaaaaaaaaaaaaaaaaa"))
	copy(key2, []byte("key-two-bbbbbbbbbbbbbbbbbbbbbb"))

	encrypted, err := SecureEncrypt([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = SecureDecrypt(encrypted, key2)
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}

func TestSecureDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := SecureDecrypt([]byte("short"), key)
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestDeriveSecureKeys(t *testing.T) {
	keys1, err := DeriveSecureKeys([]byte("test-psk"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(keys1.EncKey) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(keys1.EncKey))
	}
	if keys1.CookieName == "" {
		t.Fatal("empty cookie name")
	}

	// Same PSK should produce same keys
	keys2, err := DeriveSecureKeys([]byte("test-psk"))
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if string(keys1.EncKey) != string(keys2.EncKey) {
		t.Fatal("same PSK should produce same encryption key")
	}
	if keys1.CookieName != keys2.CookieName {
		t.Fatal("same PSK should produce same cookie name")
	}

	// Different PSK should produce different keys
	keys3, err := DeriveSecureKeys([]byte("different-psk"))
	if err != nil {
		t.Fatalf("derive 3: %v", err)
	}
	if string(keys1.EncKey) == string(keys3.EncKey) {
		t.Fatal("different PSK should produce different keys")
	}
}

func TestDeriveSecureKeysEmpty(t *testing.T) {
	_, err := DeriveSecureKeys(nil)
	if err == nil {
		t.Fatal("expected error for nil PSK")
	}
	_, err = DeriveSecureKeys([]byte{})
	if err == nil {
		t.Fatal("expected error for empty PSK")
	}
}

func TestSecureCommandRoundtrip(t *testing.T) {
	keys, err := DeriveSecureKeys([]byte("cmd-test"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	tests := []SecureCommand{
		{Action: ActionPing},
		{Action: ActionConnect, Target: "192.168.1.50:445"},
		{Action: ActionSend, SID: "abc123def456"},
		{Action: ActionRecv, SID: "abc123def456"},
		{Action: ActionDisconnect, SID: "abc123def456"},
	}

	for _, tc := range tests {
		encoded, err := EncodeSecureCommand(tc, keys.EncKey)
		if err != nil {
			t.Fatalf("encode %+v: %v", tc, err)
		}

		decoded, err := DecodeSecureCommand(encoded, keys.EncKey)
		if err != nil {
			t.Fatalf("decode %+v: %v", tc, err)
		}

		if decoded.Action != tc.Action || decoded.Target != tc.Target || decoded.SID != tc.SID {
			t.Fatalf("roundtrip mismatch: got %+v, want %+v", decoded, tc)
		}
	}
}

func TestSecurePayloadRoundtrip(t *testing.T) {
	keys, err := DeriveSecureKeys([]byte("payload-test"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	data := []byte("binary payload with \x00\x01\x02 bytes")
	encoded, err := EncodeSecurePayload(data, keys.EncKey)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := DecodeSecurePayload(encoded, keys.EncKey)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("roundtrip: got %q, want %q", decoded, data)
	}
}

func TestSecureResponseWrapUnwrap(t *testing.T) {
	keys, err := DeriveSecureKeys([]byte("wrap-test"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	data := []byte(`{"sid":"abc123"}`)
	html, err := WrapSecureResponse(data, StatusOK, keys.EncKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// Should contain data-cfg attribute
	if len(html) == 0 {
		t.Fatal("empty HTML response")
	}

	status, unwrapped, err := UnwrapSecureResponse(html, keys.EncKey)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if status != StatusOK {
		t.Fatalf("expected StatusOK, got %d", status)
	}
	if string(unwrapped) != string(data) {
		t.Fatalf("unwrap: got %q, want %q", unwrapped, data)
	}
}

func TestSecureResponseEmpty(t *testing.T) {
	keys, err := DeriveSecureKeys([]byte("empty-test"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	html := WrapSecureEmpty()
	status, _, err := UnwrapSecureResponse(html, keys.EncKey)
	if err != nil {
		t.Fatalf("unwrap empty: %v", err)
	}
	if status != StatusEmpty {
		t.Fatalf("expected StatusEmpty, got %d", status)
	}
}

func TestSecureResponseError(t *testing.T) {
	keys, err := DeriveSecureKeys([]byte("error-test"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	errMsg := []byte("connection failed")
	html, err := WrapSecureResponse(errMsg, StatusError, keys.EncKey)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	status, data, err := UnwrapSecureResponse(html, keys.EncKey)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if status != StatusError {
		t.Fatalf("expected StatusError, got %d", status)
	}
	if string(data) != "connection failed" {
		t.Fatalf("error msg: got %q, want %q", data, "connection failed")
	}
}

// --- Secure Server Tests ---

func newSecureTestServer(key []byte) (*Server, *httptest.Server) {
	cfg := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		Key:        key,
		Path:       "/app",
		Secure:     true,
	}
	srv := NewServer(cfg)

	mux := http.NewServeMux()
	mux.HandleFunc(srv.path, srv.handleTunnel)
	mux.HandleFunc("/", srv.handleCover)

	ts := httptest.NewServer(mux)
	return srv, ts
}

func TestSecureServerCoverOnGET(t *testing.T) {
	_, ts := newSecureTestServer([]byte("test-key"))
	defer ts.Close()

	// GET to tunnel path should return cover page (not 404)
	resp, err := http.Get(ts.URL + "/app")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSecureServerNoCookie(t *testing.T) {
	_, ts := newSecureTestServer([]byte("test-key"))
	defer ts.Close()

	// POST without cookie should return empty HTML 200
	resp, err := http.Post(ts.URL+"/app", "", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSecureServerPing(t *testing.T) {
	key := []byte("ping-test-key")
	srv, ts := newSecureTestServer(key)
	_ = srv
	defer ts.Close()

	keys, _ := DeriveSecureKeys(key)
	cmd := SecureCommand{Action: ActionPing}
	cookieValue, _ := EncodeSecureCommand(cmd, keys.EncKey)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/app", nil)
	req.AddCookie(&http.Cookie{Name: keys.CookieName, Value: cookieValue})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	status, data, err := UnwrapSecureResponse(string(body), keys.EncKey)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if status != StatusOK {
		t.Fatalf("expected StatusOK, got %d", status)
	}
	if string(data) != "pong" {
		t.Fatalf("expected 'pong', got %q", data)
	}
}

// --- Full Secure Tunnel Test ---

func TestFullSecureTunnel(t *testing.T) {
	key := []byte("full-secure-test-key")

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

	// 2. Start secure HTTP tunnel server
	_, ts := newSecureTestServer(key)
	defer ts.Close()

	// 3. Start secure HTTP tunnel client
	clientCfg := &ClientConfig{
		ServerURL: ts.URL + "/app",
		SocksAddr: "127.0.0.1:0",
		Key:       key,
		Secure:    true,
	}
	client := NewClient(clientCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- client.Start(ctx)
	}()

	// Wait for client to start
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
	socksConn.Write([]byte{0x05, 0x01, 0x00})
	greetResp := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greetResp); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if greetResp[0] != 0x05 || greetResp[1] != 0x00 {
		t.Fatalf("unexpected greeting: %v", greetResp)
	}

	// SOCKS5 CONNECT
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
	if _, err := io.ReadFull(socksConn, connectResp); err != nil {
		t.Fatalf("read connect: %v", err)
	}
	if connectResp[1] != 0x00 {
		t.Fatalf("CONNECT failed: %d", connectResp[1])
	}

	// 5. Send data through the secure tunnel and verify echo
	testMsg := "hello through the SECURE tunnel!"
	socksConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := socksConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	socksConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(socksConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf) != testMsg {
		t.Fatalf("echo mismatch: got %q, want %q", buf, testMsg)
	}

	socksConn.Close()
	cancel()
}
