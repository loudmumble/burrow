package session

import (
	"net"
	"testing"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/web"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.Count() != 0 {
		t.Errorf("new manager Count = %d, want 0", m.Count())
	}
}

func TestManagerAdd(t *testing.T) {
	m := NewManager()
	info := &Info{
		ID:        "abc12345",
		Hostname:  "target-1",
		OS:        "linux",
		IPs:       []string{"10.0.0.5"},
		PID:       1234,
		Remote:    "10.0.0.5:54321",
		CreatedAt: time.Now(),
		Active:    true,
	}
	m.Add(info)

	if m.Count() != 1 {
		t.Errorf("Count = %d, want 1", m.Count())
	}

	got := m.Get("abc12345")
	if got == nil {
		t.Fatal("Get returned nil for existing session")
	}
	if got.Hostname != "target-1" {
		t.Errorf("Hostname = %q, want %q", got.Hostname, "target-1")
	}
	if got.OS != "linux" {
		t.Errorf("OS = %q, want %q", got.OS, "linux")
	}
}

func TestManagerGetMissing(t *testing.T) {
	m := NewManager()
	got := m.Get("nonexistent")
	if got != nil {
		t.Errorf("Get nonexistent = %v, want nil", got)
	}
}

func TestManagerList(t *testing.T) {
	m := NewManager()
	for i := 0; i < 3; i++ {
		m.Add(&Info{
			ID:        string(rune('a'+i)) + "session",
			Hostname:  "host",
			Active:    true,
			CreatedAt: time.Now(),
		})
	}

	list := m.List()
	if len(list) != 3 {
		t.Errorf("List len = %d, want 3", len(list))
	}
}

func TestManagerRemove(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "sess1", Hostname: "h1", Active: true, CreatedAt: time.Now()})
	m.Add(&Info{ID: "sess2", Hostname: "h2", Active: true, CreatedAt: time.Now()})

	m.Remove("sess1")
	if m.Count() != 1 {
		t.Errorf("Count after remove = %d, want 1", m.Count())
	}
	if m.Get("sess1") != nil {
		t.Error("sess1 still exists after Remove")
	}
	if m.Get("sess2") == nil {
		t.Error("sess2 was unexpectedly removed")
	}
}

func TestManagerRemoveNonexistent(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "sess1", Active: true, CreatedAt: time.Now()})
	m.Remove("nonexistent") // should not panic
	if m.Count() != 1 {
		t.Errorf("Count = %d, want 1", m.Count())
	}
}

// SessionProvider interface tests

func TestListSessions(t *testing.T) {
	m := NewManager()
	m.Add(&Info{
		ID:        "sp1",
		Hostname:  "web-server",
		OS:        "ubuntu",
		IPs:       []string{"192.168.1.10", "10.0.0.1"},
		Active:    true,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	sessions := m.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("ListSessions len = %d, want 1", len(sessions))
	}

	s := sessions[0]
	if s.ID != "sp1" {
		t.Errorf("ID = %q, want %q", s.ID, "sp1")
	}
	if s.Hostname != "web-server" {
		t.Errorf("Hostname = %q, want %q", s.Hostname, "web-server")
	}
	if s.OS != "ubuntu" {
		t.Errorf("OS = %q, want %q", s.OS, "ubuntu")
	}
	if len(s.IPs) != 2 {
		t.Errorf("IPs len = %d, want 2", len(s.IPs))
	}
	if !s.Active {
		t.Error("Active = false, want true")
	}
	if s.CreatedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("CreatedAt = %q, want %q", s.CreatedAt, "2026-01-01T00:00:00Z")
	}
}

func TestGetSession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{
		ID:        "gs1",
		Hostname:  "db-server",
		OS:        "debian",
		IPs:       []string{"10.0.0.20"},
		Active:    true,
		CreatedAt: time.Now(),
	})

	s, ok := m.GetSession("gs1")
	if !ok {
		t.Fatal("GetSession returned false for existing session")
	}
	if s.Hostname != "db-server" {
		t.Errorf("Hostname = %q, want %q", s.Hostname, "db-server")
	}

	_, ok = m.GetSession("nonexistent")
	if ok {
		t.Error("GetSession returned true for nonexistent session")
	}
}

func TestGetTunnelsRoutes(t *testing.T) {
	m := NewManager()
	tunnels := m.GetTunnels("any")
	if tunnels != nil {
		t.Errorf("GetTunnels = %v, want nil (stub)", tunnels)
	}
	routes := m.GetRoutes("any")
	if routes != nil {
		t.Errorf("GetRoutes = %v, want nil (stub)", routes)
	}
}

func TestAddTunnelSessionNotFound(t *testing.T) {
	m := NewManager()
	_, err := m.AddTunnel("s1", "local", ":8080", "10.0.0.1:80", "tcp")
	if err == nil {
		t.Error("AddTunnel with nonexistent session should return error")
	}
}

func TestRemoveTunnelSessionNotFound(t *testing.T) {
	m := NewManager()
	err := m.RemoveTunnel("s1", "t1")
	if err == nil {
		t.Error("RemoveTunnel with nonexistent session should return error")
	}
}

func TestAddRouteSessionNotFound(t *testing.T) {
	m := NewManager()
	_, err := m.AddRoute("s1", "10.0.0.0/24")
	if err == nil {
		t.Error("AddRoute with nonexistent session should return error")
	}
}

func TestRemoveRouteSessionNotFound(t *testing.T) {
	m := NewManager()
	err := m.RemoveRoute("s1", "10.0.0.0/24")
	if err == nil {
		t.Error("RemoveRoute with nonexistent session should return error")
	}
}

// Verify Manager satisfies web.SessionProvider at compile time
var _ web.SessionProvider = (*Manager)(nil)

// Server tests

func TestNewServer(t *testing.T) {
	m := NewManager()
	srv := NewServer("127.0.0.1:0", nil, m)
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.ListenAddr != "127.0.0.1:0" {
		t.Errorf("ListenAddr = %q, want %q", srv.ListenAddr, "127.0.0.1:0")
	}
	if srv.Manager != m {
		t.Error("Manager not set correctly")
	}
}

func TestServerStartStop(t *testing.T) {
	m := NewManager()
	srv := NewServer("127.0.0.1:0", nil, m)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty after Start")
	}

	// Verify we can connect
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	conn.Close()

	// Stop
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop error: %v", err)
	}

	// Start should return nil after clean shutdown
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error after Stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestServerWithTLS(t *testing.T) {
	m := NewManager()

	cert, err := certgen.GenerateSelfSigned("test", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	tlsCfg := certgen.TLSConfig(cert, "")

	srv := NewServer("127.0.0.1:0", tlsCfg, m)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	time.Sleep(50 * time.Millisecond)

	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty after Start")
	}

	// Connect with TLS
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	conn.Close()

	srv.Stop()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestServerOnConnection(t *testing.T) {
	m := NewManager()
	srv := NewServer("127.0.0.1:0", nil, m)

	connected := make(chan string, 1)
	srv.OnConnection = func(conn net.Conn) {
		connected <- conn.RemoteAddr().String()
		conn.Close()
	}

	go srv.Start()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", srv.Addr(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	select {
	case addr := <-connected:
		if addr == "" {
			t.Error("OnConnection received empty address")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnConnection not called")
	}

	srv.Stop()
}

func TestFindByHostname(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "web-server", Active: true, CreatedAt: time.Now()})
	m.Add(&Info{ID: "s2", Hostname: "db-server", Active: true, CreatedAt: time.Now()})

	id, found := m.FindByHostname("web-server")
	if !found {
		t.Fatal("FindByHostname returned false for existing hostname")
	}
	if id != "s1" {
		t.Errorf("FindByHostname = %q, want %q", id, "s1")
	}

	_, found = m.FindByHostname("nonexistent")
	if found {
		t.Error("FindByHostname returned true for nonexistent hostname")
	}
}

func TestWasTunActive(t *testing.T) {
	m := NewManager()
	// Initially no TUN was active.
	if m.WasTunActive("any-host") {
		t.Error("WasTunActive should be false initially")
	}
}

func TestClearTunPrev(t *testing.T) {
	m := NewManager()
	// Manually set prev state to test clearing.
	m.mu.Lock()
	m.tunPrevHostname = "test-host"
	m.tunPrevRoutes = []string{"10.0.0.0/24"}
	m.mu.Unlock()

	if !m.WasTunActive("test-host") {
		t.Error("WasTunActive should be true after setting tunPrevHostname")
	}

	m.ClearTunPrev()
	if m.WasTunActive("test-host") {
		t.Error("WasTunActive should be false after ClearTunPrev")
	}
}

func TestTunPrevRoutes(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.tunPrevRoutes = []string{"10.0.0.0/24", "172.16.0.0/16"}
	m.mu.Unlock()

	routes := m.TunPrevRoutes()
	if len(routes) != 2 {
		t.Fatalf("TunPrevRoutes len = %d, want 2", len(routes))
	}
	if routes[0] != "10.0.0.0/24" {
		t.Errorf("routes[0] = %q, want %q", routes[0], "10.0.0.0/24")
	}
}

func TestAddTunnelValidSession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})

	tunnel, err := m.AddTunnel("s1", "local", "127.0.0.1:8080", "10.0.0.1:80", "tcp")
	if err != nil {
		t.Fatalf("AddTunnel error: %v", err)
	}
	if tunnel.Direction != "local" {
		t.Errorf("Direction = %q, want %q", tunnel.Direction, "local")
	}
	if tunnel.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q, want %q", tunnel.ListenAddr, "127.0.0.1:8080")
	}
	if tunnel.ID == "" {
		t.Error("tunnel ID should not be empty")
	}

	// Verify tunnel is tracked.
	tunnels := m.GetTunnels("s1")
	if len(tunnels) != 1 {
		t.Fatalf("GetTunnels len = %d, want 1", len(tunnels))
	}
}

func TestRemoveTunnelValidSession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})

	tunnel, _ := m.AddTunnel("s1", "local", "127.0.0.1:8080", "10.0.0.1:80", "tcp")
	err := m.RemoveTunnel("s1", tunnel.ID)
	if err != nil {
		t.Fatalf("RemoveTunnel error: %v", err)
	}

	tunnels := m.GetTunnels("s1")
	if len(tunnels) != 0 {
		t.Errorf("GetTunnels len = %d, want 0 after remove", len(tunnels))
	}
}

func TestAddRouteValidSession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})

	route, err := m.AddRoute("s1", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("AddRoute error: %v", err)
	}
	if route.CIDR != "10.0.0.0/24" {
		t.Errorf("CIDR = %q, want %q", route.CIDR, "10.0.0.0/24")
	}
	if !route.Active {
		t.Error("route should be active")
	}

	routes := m.GetRoutes("s1")
	if len(routes) != 1 {
		t.Fatalf("GetRoutes len = %d, want 1", len(routes))
	}
}

func TestRemoveRouteValidSession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})

	m.AddRoute("s1", "10.0.0.0/24")
	err := m.RemoveRoute("s1", "10.0.0.0/24")
	if err != nil {
		t.Fatalf("RemoveRoute error: %v", err)
	}

	routes := m.GetRoutes("s1")
	if len(routes) != 0 {
		t.Errorf("GetRoutes len = %d, want 0 after remove", len(routes))
	}
}

func TestManagerCount(t *testing.T) {
	m := NewManager()
	if m.Count() != 0 {
		t.Errorf("Count = %d, want 0", m.Count())
	}
	m.Add(&Info{ID: "s1", Active: true, CreatedAt: time.Now()})
	m.Add(&Info{ID: "s2", Active: true, CreatedAt: time.Now()})
	if m.Count() != 2 {
		t.Errorf("Count = %d, want 2", m.Count())
	}
}

func TestIsSessionDead(t *testing.T) {
	m := NewManager()

	// Non-existent session is dead.
	m.mu.RLock()
	dead := m.isSessionDead("nonexistent")
	m.mu.RUnlock()
	if !dead {
		t.Error("non-existent session should be dead")
	}

	// Add a session — should be alive.
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})
	m.mu.RLock()
	dead = m.isSessionDead("s1")
	m.mu.RUnlock()
	if dead {
		t.Error("existing session should not be dead")
	}

	// Remove the session — should be dead again.
	m.mu.Lock()
	delete(m.sessions, "s1")
	m.mu.Unlock()
	m.mu.RLock()
	dead = m.isSessionDead("s1")
	m.mu.RUnlock()
	if !dead {
		t.Error("removed session should be dead")
	}
}

func TestReclaimStaleTun(t *testing.T) {
	m := NewManager()

	// No TUN active — reclaim returns false.
	if m.reclaimStaleTun() {
		t.Error("should not reclaim when no TUN is active")
	}

	// Simulate stale TUN: set tunSession to a non-existent session.
	m.mu.Lock()
	m.tunSession = "dead-session"
	m.mu.Unlock()

	if !m.reclaimStaleTun() {
		t.Error("should reclaim when TUN owner is a dead session")
	}

	m.mu.RLock()
	if m.tunSession != "" {
		t.Error("tunSession should be cleared after reclaim")
	}
	m.mu.RUnlock()
}

func TestReclaimStaleTap(t *testing.T) {
	m := NewManager()

	if m.reclaimStaleTap() {
		t.Error("should not reclaim when no TAP is active")
	}

	m.mu.Lock()
	m.tapSession = "dead-session"
	m.mu.Unlock()

	if !m.reclaimStaleTap() {
		t.Error("should reclaim when TAP owner is a dead session")
	}

	m.mu.RLock()
	if m.tapSession != "" {
		t.Error("tapSession should be cleared after reclaim")
	}
	m.mu.RUnlock()
}

func TestReclaimSkipsAliveSession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})

	m.mu.Lock()
	m.tunSession = "s1"
	m.mu.Unlock()

	if m.reclaimStaleTun() {
		t.Error("should not reclaim TUN from alive session")
	}

	m.mu.RLock()
	if m.tunSession != "s1" {
		t.Error("tunSession should still be s1")
	}
	m.mu.RUnlock()
}

func TestPrevStateSaveOnRemove(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "pivot-host", Active: true, CreatedAt: time.Now()})

	// Add a tunnel and route to the session directly (bypassing ctrl).
	ac := m.getConn("s1")
	ac.mu.Lock()
	ac.tunnels["t1"] = &web.TunnelInfo{
		ID: "t1", Direction: "local", ListenAddr: "0.0.0.0:8080",
		RemoteAddr: "10.0.0.1:80", Protocol: "tcp", Active: true,
	}
	ac.routes["10.0.0.0/24"] = &web.RouteInfo{CIDR: "10.0.0.0/24", Active: true}
	ac.mu.Unlock()

	// Remove should save state for auto-restore.
	m.Remove("s1")

	prev := m.PrevState("pivot-host")
	if prev == nil {
		t.Fatal("PrevState should not be nil after Remove")
	}
	if len(prev.Tunnels) != 1 {
		t.Fatalf("expected 1 tunnel, got %d", len(prev.Tunnels))
	}
	if prev.Tunnels[0].ListenAddr != "0.0.0.0:8080" {
		t.Errorf("tunnel listen = %q, want %q", prev.Tunnels[0].ListenAddr, "0.0.0.0:8080")
	}
	if len(prev.Routes) != 1 || prev.Routes[0] != "10.0.0.0/24" {
		t.Errorf("routes = %v, want [10.0.0.0/24]", prev.Routes)
	}

	// Clear and verify.
	m.ClearPrevState("pivot-host")
	if m.PrevState("pivot-host") != nil {
		t.Error("PrevState should be nil after ClearPrevState")
	}
}

func TestPrevStateNotSavedForEmptySession(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "empty-host", Active: true, CreatedAt: time.Now()})

	m.Remove("s1")

	if m.PrevState("empty-host") != nil {
		t.Error("PrevState should not be saved for session with no tunnels/routes")
	}
}

func TestAddTunnelInvalidAddresses(t *testing.T) {
	m := NewManager()
	m.Add(&Info{ID: "s1", Hostname: "h1", Active: true, CreatedAt: time.Now()})

	// Invalid listen address (no port).
	_, err := m.AddTunnel("s1", "local", "127.0.0.1", "10.0.0.1:80", "tcp")
	if err == nil {
		t.Error("AddTunnel with invalid listen address should return error")
	}

	// Invalid remote address (no port).
	_, err = m.AddTunnel("s1", "local", "127.0.0.1:8080", "10.0.0.1", "tcp")
	if err == nil {
		t.Error("AddTunnel with invalid remote address should return error")
	}
}
