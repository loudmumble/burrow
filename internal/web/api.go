package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

// SessionInfo describes an agent session for the dashboard.
type SessionInfo struct {
	ID        string   `json:"id"`
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	IPs       []string `json:"ips"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at"`
	Tunnels   int      `json:"tunnel_count"`
	Routes    int      `json:"route_count"`
	BytesIn   int64    `json:"bytes_in"`
	BytesOut  int64    `json:"bytes_out"`
}

// TunnelInfo describes a tunnel for the dashboard.
type TunnelInfo struct {
	ID         string `json:"id"`
	SessionID  string `json:"session_id"`
	Direction  string `json:"direction"`
	ListenAddr string `json:"listen_addr"`
	RemoteAddr string `json:"remote_addr"`
	Protocol   string `json:"protocol"`
	Active     bool   `json:"active"`
}

// RouteInfo describes a network route for the dashboard.
type RouteInfo struct {
	CIDR      string `json:"cidr"`
	SessionID string `json:"session_id"`
	Active    bool   `json:"active"`
}

// SessionProvider is the interface the web API uses to query session state.
// It is implemented by session.Manager so the web package has no direct dependency.
type SessionProvider interface {
	ListSessions() []SessionInfo
	GetSession(id string) (SessionInfo, bool)
	GetTunnels(sessionID string) []TunnelInfo
	GetRoutes(sessionID string) []RouteInfo
	AddTunnel(sessionID, direction, listen, remote, proto string) (TunnelInfo, error)
	RemoveTunnel(sessionID, tunnelID string) error
	AddRoute(sessionID, cidr string) (RouteInfo, error)
	RemoveRoute(sessionID, cidr string) error
	StartTun(sessionID string) error
	StopTun(sessionID string) error
	IsTunActive(sessionID string) bool
}

// apiHandler holds references needed by all REST handlers.
type apiHandler struct {
	provider SessionProvider
	apiToken string
}

// writeJSON marshals v as JSON and writes it with the correct content type.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// AuthMiddleware wraps an http.Handler to enforce bearer token authentication.
func (h *apiHandler) AuthMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.apiToken == "" {
			writeError(w, http.StatusUnauthorized, "API token not configured")
			return
		}

		authHeader := r.Header.Get("Authorization")
		token := ""

		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				token = parts[1]
			}
		}

		// Fallback to query param for EventSource (SSE) which cannot send headers
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header or token")
			return
		}

		if token != h.apiToken {
			writeError(w, http.StatusUnauthorized, "invalid API token")
			return
		}

		next.ServeHTTP(w, r)
	}
}

// registerAPIRoutes wires all REST endpoints into the given mux.
func registerAPIRoutes(mux *http.ServeMux, provider SessionProvider, apiToken string) {
	h := &apiHandler{provider: provider, apiToken: apiToken}

	mux.HandleFunc("GET /api/sessions", h.AuthMiddleware(http.HandlerFunc(h.listSessions)))
	mux.HandleFunc("GET /api/sessions/{id}", h.AuthMiddleware(http.HandlerFunc(h.getSession)))
	mux.HandleFunc("GET /api/sessions/{id}/tunnels", h.AuthMiddleware(http.HandlerFunc(h.getTunnels)))
	mux.HandleFunc("POST /api/sessions/{id}/tunnels", h.AuthMiddleware(http.HandlerFunc(h.addTunnel)))
	mux.HandleFunc("DELETE /api/sessions/{id}/tunnels/{tid}", h.AuthMiddleware(http.HandlerFunc(h.removeTunnel)))
	mux.HandleFunc("GET /api/sessions/{id}/routes", h.AuthMiddleware(http.HandlerFunc(h.getRoutes)))
	mux.HandleFunc("POST /api/sessions/{id}/routes", h.AuthMiddleware(http.HandlerFunc(h.addRoute)))
	mux.HandleFunc("DELETE /api/sessions/{id}/routes/{cidr}", h.AuthMiddleware(http.HandlerFunc(h.removeRoute)))
	mux.HandleFunc("POST /api/sessions/{id}/tun", h.AuthMiddleware(http.HandlerFunc(h.startTun)))
	mux.HandleFunc("DELETE /api/sessions/{id}/tun", h.AuthMiddleware(http.HandlerFunc(h.stopTun)))
	}

func (h *apiHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions := h.provider.ListSessions()
	if sessions == nil {
		sessions = []SessionInfo{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (h *apiHandler) getSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok := h.provider.GetSession(id)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (h *apiHandler) getTunnels(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tunnels := h.provider.GetTunnels(id)
	if tunnels == nil {
		tunnels = []TunnelInfo{}
	}
	writeJSON(w, http.StatusOK, tunnels)
}

func (h *apiHandler) addTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		Direction string `json:"direction"`
		Listen    string `json:"listen"`
		Remote    string `json:"remote"`
		Protocol  string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	tunnel, err := h.provider.AddTunnel(id, req.Direction, req.Listen, req.Remote, req.Protocol)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, tunnel)
}

func (h *apiHandler) removeTunnel(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	tunnelID := r.PathValue("tid")

	if err := h.provider.RemoveTunnel(sessionID, tunnelID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *apiHandler) getRoutes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	routes := h.provider.GetRoutes(id)
	if routes == nil {
		routes = []RouteInfo{}
	}
	writeJSON(w, http.StatusOK, routes)
}

func (h *apiHandler) addRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	route, err := h.provider.AddRoute(id, req.CIDR)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, route)
}

func (h *apiHandler) removeRoute(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	cidr := r.PathValue("cidr")

	if err := h.provider.RemoveRoute(sessionID, cidr); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *apiHandler) startTun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.provider.StartTun(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "active",
		"interface": "burrow0",
		"magic_ip":  "240.0.0.1",
	})
}

func (h *apiHandler) stopTun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.provider.StopTun(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}
