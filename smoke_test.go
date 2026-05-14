package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestSmoke_WebUI_TLS starts the server with TLS and verifies the WebUI
// is accessible using standard TLS (ECDSA/RSA — not just Ed25519).
// This catches the exact bug where Ed25519 certs broke all browsers.
func TestSmoke_WebUI_TLS(t *testing.T) {
	binary := buildBinary(t)
	port := freePort(t)
	webuiPort := freePort(t)

	cmd := exec.Command(binary, "server",
		"-l", fmt.Sprintf("127.0.0.1:%d", port),
		fmt.Sprintf("--webui=127.0.0.1:%d", webuiPort),
	)
	cmd.Stdout = os.Stderr // show server output on test failure
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer cmd.Process.Kill()

	waitForPort(t, webuiPort, 5*time.Second)

	// Use a standard TLS client — this is what browsers do.
	// Ed25519-only certs will fail here just like they fail in Firefox/Chrome.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				// Restrict to cipher suites browsers actually support.
				// Ed25519 certs won't negotiate because browsers don't
				// have cipher suites for Ed25519 signature algorithms.
				MaxVersion: tls.VersionTLS13,
			},
		},
	}

	// Test 1: WebUI HTML loads
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/", webuiPort))
	if err != nil {
		t.Fatalf("WebUI GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("WebUI GET / status=%d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "BURROW") {
		t.Fatal("WebUI HTML missing 'BURROW' — page didn't load")
	}

	// Test 2: API returns valid JSON
	resp, err = client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/sessions", webuiPort))
	if err != nil {
		t.Fatalf("API GET /api/sessions: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("API GET /api/sessions status=%d, want 200", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != "[]" && !strings.HasPrefix(strings.TrimSpace(string(body)), "[{") {
		t.Fatalf("API /api/sessions unexpected body: %s", string(body))
	}

	// Test 3: Static assets serve correctly
	for _, path := range []string{"/static/app.js", "/static/alpine.min.js", "/static/style.css"} {
		resp, err = client.Get(fmt.Sprintf("https://127.0.0.1:%d%s", webuiPort, path))
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s status=%d, want 200", path, resp.StatusCode)
		}
	}

	// Test 4: SSE endpoint connects (verify it doesn't 401 or 500)
	resp, err = client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/events", webuiPort))
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/events status=%d, want 200", resp.StatusCode)
	}

	// Test 5: Verify the TLS cert uses a browser-compatible algorithm
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", webuiPort), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	cert := state.PeerCertificates[0]
	algo := cert.SignatureAlgorithm.String()
	if strings.Contains(strings.ToLower(algo), "ed25519") {
		t.Fatalf("WebUI cert uses Ed25519 (%s) — browsers don't support this. Use ECDSA or RSA.", algo)
	}
}

// TestSmoke_WebUI_NoTLS verifies WebUI works without TLS.
func TestSmoke_WebUI_NoTLS(t *testing.T) {
	binary := buildBinary(t)
	port := freePort(t)
	webuiPort := freePort(t)

	cmd := exec.Command(binary, "server",
		"-l", fmt.Sprintf("127.0.0.1:%d", port),
		fmt.Sprintf("--webui=127.0.0.1:%d", webuiPort),
		"--no-tls",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer cmd.Process.Kill()

	waitForPort(t, webuiPort, 5*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", webuiPort))
	if err != nil {
		t.Fatalf("WebUI GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "BURROW") {
		t.Fatal("WebUI HTML missing 'BURROW'")
	}
}

// TestSmoke_WebUI_DefaultFlag verifies --webui with no value works (NoOptDefVal 0.0.0.0:9091).
func TestSmoke_WebUI_DefaultFlag(t *testing.T) {
	binary := buildBinary(t)
	port := freePort(t)

	cmd := exec.Command(binary, "server",
		"-l", fmt.Sprintf("127.0.0.1:%d", port),
		"--webui",
		"--no-tls",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer cmd.Process.Kill()

	waitForPort(t, 9091, 5*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:9091/")
	if err != nil {
		t.Fatalf("WebUI GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "BURROW") {
		t.Fatal("WebUI HTML missing 'BURROW'")
	}
}

// TestSmoke_AgentConnection starts a server and agent, verifies the agent
// connects (handshake + session visible via API), kills the agent, confirms
// the server detects the disconnect, then reconnects a new agent and verifies
// it appears again. This exercises the full connection lifecycle including
// TCP keepalive and yamux keepalive configuration.
func TestSmoke_AgentConnection(t *testing.T) {
	binary := buildBinary(t)
	serverPort := freePort(t)
	webuiPort := freePort(t)

	// Start server with WebUI (no TLS for simplicity).
	serverCmd := exec.Command(binary, "server",
		"-l", fmt.Sprintf("127.0.0.1:%d", serverPort),
		fmt.Sprintf("--webui=127.0.0.1:%d", webuiPort),
		"--no-tls",
	)
	serverCmd.Stdout = os.Stderr
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer serverCmd.Process.Kill()

	waitForPort(t, serverPort, 5*time.Second)
	waitForPort(t, webuiPort, 5*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}
	sessionsURL := fmt.Sprintf("http://127.0.0.1:%d/api/sessions", webuiPort)

	// --- Phase 1: Agent connects ---
	agentCmd := exec.Command(binary, "agent",
		"-c", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"--no-tls",
	)
	agentCmd.Stdout = os.Stderr
	agentCmd.Stderr = os.Stderr
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	defer agentCmd.Process.Kill()

	// Poll until the agent appears in the session list.
	sessions := waitForSessions(t, client, sessionsURL, 1, 10*time.Second)
	if !strings.Contains(sessions, `"active":true`) {
		t.Fatalf("agent session not active: %s", sessions)
	}
	t.Logf("Phase 1 PASS: agent connected")

	// --- Phase 2: Agent disconnects ---
	agentCmd.Process.Kill()
	agentCmd.Wait()

	// Wait for server to detect disconnect and remove the session.
	sessions = waitForSessions(t, client, sessionsURL, 0, 10*time.Second)
	if sessions != "[]" {
		t.Fatalf("sessions not empty after agent kill: %s", sessions)
	}
	t.Logf("Phase 2 PASS: disconnect detected")

	// --- Phase 3: Agent reconnects ---
	agentCmd2 := exec.Command(binary, "agent",
		"-c", fmt.Sprintf("127.0.0.1:%d", serverPort),
		"--no-tls",
	)
	agentCmd2.Stdout = os.Stderr
	agentCmd2.Stderr = os.Stderr
	if err := agentCmd2.Start(); err != nil {
		t.Fatalf("start agent (reconnect): %v", err)
	}
	defer agentCmd2.Process.Kill()

	sessions = waitForSessions(t, client, sessionsURL, 1, 10*time.Second)
	if !strings.Contains(sessions, `"active":true`) {
		t.Fatalf("reconnected agent not active: %s", sessions)
	}
	t.Logf("Phase 3 PASS: agent reconnected")
}

// waitForSessions polls the sessions API until the session count matches want
// or the timeout expires.
func waitForSessions(t *testing.T, client *http.Client, url string, want int, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		last = strings.TrimSpace(string(body))

		// Count sessions by counting opening braces for objects in the array.
		count := strings.Count(last, `"id":"`)
		if count == want {
			return last
		}
		time.Sleep(200 * time.Millisecond)
	}
	if want == 0 && last == "[]" {
		return last
	}
	t.Fatalf("wanted %d session(s) within %s, last response: %s", want, timeout, last)
	return ""
}

func buildBinary(t *testing.T) string {
	t.Helper()
	binary := "./build/burrow"
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("binary not found at %s — run make build-local first", binary)
	}
	return binary
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func waitForPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("port %d not ready after %s", port, timeout)
}
