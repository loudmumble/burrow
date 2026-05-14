// Package sdk provides a Go SDK for programmatic control of Burrow.
// Enables automation of multi-session workflows: scan → pivot → relay → dump.
//
// Usage:
//
//	client := sdk.NewClient("https://burrow.local:8443", "your-api-token")
//	sessions, _ := client.ListSessions()
//	client.AddTunnel(sessions[0].ID, "remote", "0.0.0.0:8080", "10.0.0.1:80", "tcp")
//	client.ScanSubnet(sessions[0].ID, "10.0.0.0/24", "")
package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is a Burrow REST API client for automation.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient creates an SDK client pointed at the Burrow server.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// SessionInfo mirrors the server's session info.
type SessionInfo struct {
	ID       string   `json:"id"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	IPs      []string `json:"ips"`
	Active   bool     `json:"active"`
}

// ScanTarget mirrors the discovery target.
type ScanTarget struct {
	IP        string   `json:"ip"`
	OpenPorts []int    `json:"ports"`
	Services  []string `json:"services"`
	Pivotable bool     `json:"pivotable"`
}

// ListSessions returns all active sessions.
func (c *Client) ListSessions() ([]SessionInfo, error) {
	var result []SessionInfo
	err := c.get("/api/sessions", &result)
	return result, err
}

// AddTunnel creates a tunnel on a session.
func (c *Client) AddTunnel(sessionID, direction, listen, remote, proto string) error {
	body := map[string]string{
		"direction": direction, "listen": listen,
		"remote": remote, "protocol": proto,
	}
	return c.post(fmt.Sprintf("/api/sessions/%s/tunnels", sessionID), body, nil)
}

// AddRoute adds a network route to a session.
func (c *Client) AddRoute(sessionID, cidr string) error {
	return c.post(fmt.Sprintf("/api/sessions/%s/routes", sessionID), map[string]string{"cidr": cidr}, nil)
}

// StartTun activates TUN on a session.
func (c *Client) StartTun(sessionID string) error {
	return c.post(fmt.Sprintf("/api/sessions/%s/tun", sessionID), nil, nil)
}

// StopTun deactivates TUN on a session.
func (c *Client) StopTun(sessionID string) error {
	return c.del(fmt.Sprintf("/api/sessions/%s/tun", sessionID))
}

// StartSOCKS5 starts a SOCKS5 proxy on a session.
func (c *Client) StartSOCKS5(sessionID, listenAddr string) error {
	return c.post(fmt.Sprintf("/api/sessions/%s/socks5", sessionID), map[string]string{"listen": listenAddr}, nil)
}

// Exec runs a command on the agent and returns the output.
func (c *Client) Exec(sessionID, command string) (string, error) {
	var result struct {
		Output string `json:"output"`
	}
	err := c.post(fmt.Sprintf("/api/sessions/%s/exec", sessionID), map[string]string{"command": command}, &result)
	return result.Output, err
}

// Sleep sends the agent to sleep for the given duration.
func (c *Client) Sleep(sessionID string, seconds int64) error {
	return c.post(fmt.Sprintf("/api/sessions/%s/sleep", sessionID), map[string]int64{"seconds": seconds}, nil)
}

// ScanSubnet runs a port scan through the session.
func (c *Client) ScanSubnet(sessionID, cidr, ports string) ([]ScanTarget, error) {
	var result []ScanTarget
	err := c.post(fmt.Sprintf("/api/sessions/%s/scan", sessionID), map[string]string{"cidr": cidr, "ports": ports}, &result)
	return result, err
}

// Topology returns the ASCII network topology.
func (c *Client) Topology() (string, error) {
	var result struct {
		Topology string `json:"topology"`
	}
	err := c.get("/api/topology", &result)
	return result.Topology, err
}

func (c *Client) get(path string, result interface{}) error {
	req, _ := http.NewRequest("GET", c.baseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func (c *Client) post(path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, _ := http.NewRequest("POST", c.baseURL+path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func (c *Client) del(path string) error {
	req, _ := http.NewRequest("DELETE", c.baseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}
