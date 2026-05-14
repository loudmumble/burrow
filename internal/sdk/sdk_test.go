package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("http://localhost:8080", "test-token")
	if c.baseURL != "http://localhost:8080" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.token != "test-token" {
		t.Errorf("token = %q", c.token)
	}
}

func TestListSessions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sessions" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok123" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode([]SessionInfo{{ID: "s1", Hostname: "test"}})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok123")
	sessions, err := c.ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != "s1" {
		t.Errorf("sessions = %+v", sessions)
	}
}

func TestTopology(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"topology": "[Server]"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	topo, err := c.Topology()
	if err != nil {
		t.Fatal(err)
	}
	if topo != "[Server]" {
		t.Errorf("topology = %q", topo)
	}
}

func TestHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	_, err := c.ListSessions()
	if err == nil {
		t.Error("expected error for 404")
	}
}
