package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/protocol"
)

// mockProvider implements SessionProvider with canned data.
type mockProvider struct {
	sessions []SessionInfo
	tunnels  map[string][]TunnelInfo
	routes   map[string][]RouteInfo
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		sessions: []SessionInfo{
			{
				ID:        "abc",
				Hostname:  "target-1",
				OS:        "linux",
				IPs:       []string{"10.0.0.5", "192.168.1.10"},
				Active:    true,
				CreatedAt: "2025-01-01T00:00:00Z",
				Tunnels:   1,
				Routes:    1,
				BytesIn:   1024,
				BytesOut:  2048,
			},
			{
				ID:        "def",
				Hostname:  "target-2",
				OS:        "windows",
				IPs:       []string{"10.0.0.6"},
				Active:    false,
				CreatedAt: "2025-01-02T00:00:00Z",
			},
		},
		tunnels: map[string][]TunnelInfo{
			"abc": {
				{
					ID:         "t1",
					SessionID:  "abc",
					Direction:  "local",
					ListenAddr: "127.0.0.1:8080",
					RemoteAddr: "10.0.0.5:80",
					Protocol:   "tcp",
					Active:     true,
				},
			},
		},
		routes: map[string][]RouteInfo{
			"abc": {
				{CIDR: "10.0.0.0/24", SessionID: "abc", Active: true},
			},
		},
	}
}

func (m *mockProvider) ListSessions() []SessionInfo { return m.sessions }

func (m *mockProvider) GetSession(id string) (SessionInfo, bool) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, true
		}
	}
	return SessionInfo{}, false
}

func (m *mockProvider) GetTunnels(sessionID string) []TunnelInfo {
	return m.tunnels[sessionID]
}

func (m *mockProvider) GetRoutes(sessionID string) []RouteInfo {
	return m.routes[sessionID]
}

func (m *mockProvider) AddTunnel(sessionID, direction, listen, remote, proto string) (TunnelInfo, error) {
	t := TunnelInfo{
		ID:         fmt.Sprintf("t%d", len(m.tunnels[sessionID])+1),
		SessionID:  sessionID,
		Direction:  direction,
		ListenAddr: listen,
		RemoteAddr: remote,
		Protocol:   proto,
		Active:     true,
	}
	m.tunnels[sessionID] = append(m.tunnels[sessionID], t)
	return t, nil
}

func (m *mockProvider) RemoveTunnel(sessionID, tunnelID string) error {
	tunnels := m.tunnels[sessionID]
	for i, t := range tunnels {
		if t.ID == tunnelID {
			m.tunnels[sessionID] = append(tunnels[:i], tunnels[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("tunnel %s not found", tunnelID)
}

func (m *mockProvider) StopTunnel(sessionID, tunnelID string) error {
	tunnels := m.tunnels[sessionID]
	for _, t := range tunnels {
		if t.ID == tunnelID {
			t.Active = false
			return nil
		}
	}
	return fmt.Errorf("tunnel %s not found", tunnelID)
}

func (m *mockProvider) StartTunnel(sessionID, tunnelID string) error {
	tunnels := m.tunnels[sessionID]
	for _, t := range tunnels {
		if t.ID == tunnelID {
			t.Active = true
			return nil
		}
	}
	return fmt.Errorf("tunnel %s not found", tunnelID)
}

func (m *mockProvider) AddRoute(sessionID, cidr string) (RouteInfo, error) {
	r := RouteInfo{CIDR: cidr, SessionID: sessionID, Active: true}
	m.routes[sessionID] = append(m.routes[sessionID], r)
	return r, nil
}

func (m *mockProvider) RemoveRoute(sessionID, cidr string) error {
	routes := m.routes[sessionID]
	for i, r := range routes {
		if r.CIDR == cidr {
			m.routes[sessionID] = append(routes[:i], routes[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("route %s not found", cidr)
}

func (m *mockProvider) StartTun(sessionID string) error  { return nil }
func (m *mockProvider) StopTun(sessionID string) error   { return nil }
func (m *mockProvider) IsTunActive(sessionID string) bool { return false }
func (m *mockProvider) IsSOCKS5Active(sessionID string) bool { return false }
func (m *mockProvider) SOCKS5Addr(sessionID string) string     { return "127.0.0.1:1080" }
func (m *mockProvider) KillSession(sessionID string) error     { return nil }
func (m *mockProvider) ExecCommand(sessionID, command string) (string, error) {
	return "mock exec output", nil
}
func (m *mockProvider) DownloadFile(sessionID, filePath string) (*protocol.FileDownloadResponsePayload, error) {
	return &protocol.FileDownloadResponsePayload{
		ID:       "dl1",
		FileName: "test.txt",
		Data:     []byte("mock file data"),
		Size:     14,
	}, nil
}
func (m *mockProvider) UploadFile(sessionID, filePath string, data []byte) (*protocol.FileUploadResponsePayload, error) {
	return &protocol.FileUploadResponsePayload{
		ID:   "ul1",
		Size: int64(len(data)),
	}, nil
}

type authTransport struct {
	http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer test-token")
	if t.RoundTripper == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.RoundTripper.RoundTrip(req)
}

// newTestServer creates an httptest.Server with full API wired up.
func newTestServer(provider SessionProvider, events *EventBus) *httptest.Server {
	mux := http.NewServeMux()
	registerAPIRoutes(mux, provider, "test-token")

	h := &apiHandler{apiToken: "test-token"}
	mux.Handle("GET /api/events", h.AuthMiddleware(events))

	// static files
	staticHandler := http.FileServer(http.FS(StaticFS))
	mux.Handle("/static/", staticHandler)

	ts := httptest.NewServer(mux)

	// Set the default client to always inject the authorization header
	http.DefaultClient.Transport = &authTransport{http.DefaultTransport}

	return ts
}

func TestListSessions(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %s", ct)
	}

	var sessions []SessionInfo
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	if sessions[0].ID != "abc" {
		t.Errorf("expected first session ID 'abc', got %q", sessions[0].ID)
	}
}

func TestGetSession(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// Found
	resp, err := http.Get(ts.URL + "/api/sessions/abc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var sess SessionInfo
	json.NewDecoder(resp.Body).Decode(&sess)
	if sess.Hostname != "target-1" {
		t.Errorf("expected hostname 'target-1', got %q", sess.Hostname)
	}

	// Not found
	resp2, err := http.Get(ts.URL + "/api/sessions/unknown")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp2.StatusCode)
	}
}

func TestGetTunnels(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/sessions/abc/tunnels")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var tunnels []TunnelInfo
	json.NewDecoder(resp.Body).Decode(&tunnels)
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(tunnels))
	}
	if tunnels[0].ID != "t1" {
		t.Errorf("expected tunnel ID 't1', got %q", tunnels[0].ID)
	}
}

func TestAddTunnel(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"direction":"remote","listen":"0.0.0.0:9090","remote":"10.0.0.5:8080","protocol":"tcp"}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/tunnels", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var tunnel TunnelInfo
	json.NewDecoder(resp.Body).Decode(&tunnel)
	if tunnel.Direction != "remote" {
		t.Errorf("expected direction 'remote', got %q", tunnel.Direction)
	}
	if tunnel.ListenAddr != "0.0.0.0:9090" {
		t.Errorf("expected listen '0.0.0.0:9090', got %q", tunnel.ListenAddr)
	}
}

func TestRemoveTunnel(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/sessions/abc/tunnels/t1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	// Verify removed
	if len(mp.tunnels["abc"]) != 0 {
		t.Errorf("expected 0 tunnels, got %d", len(mp.tunnels["abc"]))
	}

	// Remove non-existent
	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/sessions/abc/tunnels/nonexistent", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp2.StatusCode)
	}
}

func TestGetRoutes(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/sessions/abc/routes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var routes []RouteInfo
	json.NewDecoder(resp.Body).Decode(&routes)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
}

func TestAddRoute(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"cidr":"172.16.0.0/16"}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/routes", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var route RouteInfo
	json.NewDecoder(resp.Body).Decode(&route)
	if route.CIDR != "172.16.0.0/16" {
		t.Errorf("expected CIDR '172.16.0.0/16', got %q", route.CIDR)
	}
}

func TestRemoveRoute(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// URL-encode the slash in CIDR
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/sessions/abc/routes/10.0.0.0%2F24", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if len(mp.routes["abc"]) != 0 {
		t.Errorf("expected 0 routes after remove, got %d", len(mp.routes["abc"]))
	}
}

func TestEventBus(t *testing.T) {
	eb := NewEventBus()

	ch := eb.Subscribe()
	defer eb.Unsubscribe(ch)

	evt := Event{Type: EventSessionConnect, Data: map[string]string{"id": "abc"}}
	eb.Publish(evt)

	select {
	case received := <-ch:
		if received.Type != EventSessionConnect {
			t.Errorf("expected event type %s, got %s", EventSessionConnect, received.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventBusDropsWhenFull(t *testing.T) {
	eb := NewEventBus()
	ch := eb.Subscribe()
	defer eb.Unsubscribe(ch)

	// Fill the buffer
	for i := 0; i < subscriberBufSize+10; i++ {
		eb.Publish(Event{Type: EventStats, Data: i})
	}

	// Should have exactly subscriberBufSize events
	count := len(ch)
	if count != subscriberBufSize {
		t.Errorf("expected %d buffered events, got %d", subscriberBufSize, count)
	}
}

func TestSSEHandler(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %s", ct)
	}

	// Publish an event after connection
	go func() {
		time.Sleep(100 * time.Millisecond)
		eb.Publish(Event{Type: EventSessionConnect, Data: map[string]string{"id": "xyz"}})
	}()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(line, "data: ")
			var evt Event
			if err := json.Unmarshal([]byte(payload), &evt); err != nil {
				t.Fatalf("failed to parse SSE data: %v", err)
			}
			if evt.Type != EventSessionConnect {
				t.Errorf("expected %s, got %s", EventSessionConnect, evt.Type)
			}
			return // success
		}
	}
	if ctx.Err() != nil {
		t.Fatal("timed out waiting for SSE event")
	}
}

func TestStaticFiles(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// index.html
	resp, err := http.Get(ts.URL + "/static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for index.html, got %d", resp.StatusCode)
	}

	// app.js
	resp2, err := http.Get(ts.URL + "/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for app.js, got %d", resp2.StatusCode)
	}

	// style.css
	resp3, err := http.Get(ts.URL + "/static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for style.css, got %d", resp3.StatusCode)
	}
}

func TestAuthMiddlewareNoToken(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// Create a client that does NOT inject the auth header.
	noAuthClient := &http.Client{}

	resp, err := noAuthClient.Get(ts.URL + "/api/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no token, got %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] == "" {
		t.Error("expected error message in response body")
	}
}

func TestAuthMiddlewareWrongToken(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	noAuthClient := &http.Client{}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	resp, err := noAuthClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", resp.StatusCode)
	}
}

func TestAuthMiddlewareQueryParam(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// Use query param token instead of header.
	noAuthClient := &http.Client{}
	resp, err := noAuthClient.Get(ts.URL + "/api/sessions?token=test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with query param token, got %d", resp.StatusCode)
	}
}

func TestExecEndpoint(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"command":"whoami"}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/exec", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["output"] != "mock exec output" {
		t.Errorf("expected 'mock exec output', got %q", result["output"])
	}
}

func TestExecEndpointEmptyCommand(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"command":""}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/exec", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty command, got %d", resp.StatusCode)
	}
}

func TestDownloadEndpoint(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"file_path":"/etc/passwd"}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/download", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["file_name"] != "test.txt" {
		t.Errorf("expected file_name 'test.txt', got %v", result["file_name"])
	}
}

func TestDownloadEndpointEmptyPath(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"file_path":""}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/download", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty file_path, got %d", resp.StatusCode)
	}
}

func TestUploadEndpoint(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"file_path":"/tmp/test.txt","data":"aGVsbG8="}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/upload", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestUploadEndpointMissingData(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	body := `{"file_path":"/tmp/test.txt","data":""}`
	resp, err := http.Post(ts.URL+"/api/sessions/abc/upload", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty data, got %d", resp.StatusCode)
	}
}

func TestStopStartTunnel(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// Stop tunnel
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/sessions/abc/tunnels/t1/stop", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for stop, got %d", resp.StatusCode)
	}

	// Start tunnel
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/sessions/abc/tunnels/t1/start", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for start, got %d", resp2.StatusCode)
	}
}

func TestTunStartStop(t *testing.T) {
	mp := newMockProvider()
	eb := NewEventBus()
	ts := newTestServer(mp, eb)
	defer ts.Close()

	// Start TUN
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/sessions/abc/tun", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for TUN start, got %d", resp.StatusCode)
	}

	// Stop TUN
	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/sessions/abc/tun", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for TUN stop, got %d", resp2.StatusCode)
	}
}
