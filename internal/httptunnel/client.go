package httptunnel

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SOCKS5 constants for the client-side SOCKS5 listener.
const (
	socksVersion   = 0x05
	authNoAuth     = 0x00
	authNoAccept   = 0xFF
	cmdConnect     = 0x01
	addrIPv4       = 0x01
	addrDomain     = 0x03
	addrIPv6       = 0x04
	repSucceeded   = 0x00
	repGeneralFail = 0x01
	repHostUnreach = 0x04
	repCmdNotSupp  = 0x07
	repAddrNotSupp = 0x08
)

// Client provides a local SOCKS5 proxy that tunnels through HTTP to the server.
type Client struct {
	serverURL  string
	key        []byte
	socksAddr  string
	httpClient *http.Client
	logger     *log.Logger
	listener   net.Listener
	mu         sync.Mutex
	connWg     sync.WaitGroup
}

// ClientConfig holds configuration for the HTTP tunnel client.
type ClientConfig struct {
	ServerURL string // Full URL to the tunnel server endpoint
	Key       []byte
	SocksAddr string // Local SOCKS5 listen address
	Logger    *log.Logger
}

// NewClient creates a new HTTP tunnel client.
func NewClient(cfg *ClientConfig) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	socksAddr := cfg.SocksAddr
	if socksAddr == "" {
		socksAddr = "127.0.0.1:1080"
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &Client{
		serverURL: cfg.ServerURL,
		key:       cfg.Key,
		socksAddr: socksAddr,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		logger: logger,
	}
}

// Start begins the SOCKS5 listener. Blocks until context is cancelled.
func (c *Client) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.socksAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}

	c.mu.Lock()
	c.listener = ln
	c.mu.Unlock()

	c.logger.Printf("[httptunnel-client] SOCKS5 listening on %s -> %s", c.socksAddr, c.serverURL)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				c.connWg.Wait()
				return nil
			}
			continue
		}

		c.connWg.Add(1)
		go func() {
			defer c.connWg.Done()
			c.handleSOCKS5(ctx, conn)
		}()
	}
}

// Addr returns the listener address.
func (c *Client) Addr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return ""
}

// handleSOCKS5 processes a single SOCKS5 client connection.
func (c *Client) handleSOCKS5(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 greeting
	if err := c.socksGreeting(conn); err != nil {
		c.logger.Printf("[httptunnel-client] greeting error: %v", err)
		return
	}

	// SOCKS5 request — parse target
	target, err := c.socksRequest(conn)
	if err != nil {
		c.logger.Printf("[httptunnel-client] request error: %v", err)
		return
	}

	// Connect through HTTP tunnel
	sid, err := c.tunnelConnect(ctx, target)
	if err != nil {
		c.socksSendReply(conn, repHostUnreach)
		c.logger.Printf("[httptunnel-client] tunnel connect to %s failed: %v", target, err)
		return
	}

	// Send SOCKS5 success reply
	c.socksSendReply(conn, repSucceeded)
	conn.SetDeadline(time.Time{}) // Clear deadline for relay phase

	c.logger.Printf("[httptunnel-client] %s -> tunnel -> %s (sid: %s)", conn.RemoteAddr(), target, sid)

	// Relay data between SOCKS client and HTTP tunnel
	c.relayTunnel(ctx, conn, sid)
}

// socksGreeting handles SOCKS5 version/method negotiation (no-auth only).
func (c *Client) socksGreeting(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if header[0] != socksVersion {
		conn.Write([]byte{socksVersion, authNoAccept})
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		conn.Write([]byte{socksVersion, authNoAccept})
		return fmt.Errorf("no auth methods")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == authNoAuth {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{socksVersion, authNoAccept})
		return fmt.Errorf("no-auth method not offered")
	}

	conn.Write([]byte{socksVersion, authNoAuth})
	return nil
}

// socksRequest parses the SOCKS5 CONNECT request and returns the target address.
func (c *Client) socksRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request: %w", err)
	}
	if header[0] != socksVersion {
		return "", fmt.Errorf("bad version in request: %d", header[0])
	}
	if header[1] != cmdConnect {
		c.socksSendReply(conn, repCmdNotSupp)
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	atyp := header[3]
	var host string

	switch atyp {
	case addrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		host = net.IP(addr).String()

	case addrDomain:
		dlenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, dlenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, dlenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)

	case addrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		host = net.IP(addr).String()

	default:
		c.socksSendReply(conn, repAddrNotSupp)
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// socksSendReply sends a SOCKS5 reply to the client.
func (c *Client) socksSendReply(conn net.Conn, rep byte) {
	resp := make([]byte, 10)
	resp[0] = socksVersion
	resp[1] = rep
	resp[2] = 0x00 // RSV
	resp[3] = addrIPv4
	// BND.ADDR and BND.PORT are zero
	conn.Write(resp)
}

// tunnelConnect sends a connect command to the HTTP tunnel server.
func (c *Client) tunnelConnect(ctx context.Context, target string) (string, error) {
	url := fmt.Sprintf("%s?cmd=%s&target=%s", c.serverURL, CmdConnect, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	c.setAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var jsonBody []byte
	if len(c.key) > 0 {
		jsonBody, err = DecodePayload(string(body), c.key)
		if err != nil {
			return "", fmt.Errorf("decode response: %w", err)
		}
	} else {
		jsonBody = body
	}

	var cr connectResponse
	if err := json.Unmarshal(jsonBody, &cr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if cr.SID == "" {
		return "", fmt.Errorf("empty session ID in response")
	}

	return cr.SID, nil
}

// relayTunnel relays data between a local connection and the HTTP tunnel.
func (c *Client) relayTunnel(ctx context.Context, conn net.Conn, sid string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{}, 2)

	// Send loop: read from SOCKS client, send to tunnel
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32768)
		for {
			if ctx.Err() != nil {
				return
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				if sendErr := c.tunnelSend(ctx, sid, buf[:n]); sendErr != nil {
					c.logger.Printf("[httptunnel-client] send error sid=%s: %v", sid, sendErr)
					return
				}
			}
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
		}
	}()

	// Recv loop: poll tunnel for data, write to SOCKS client
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			if ctx.Err() != nil {
				return
			}
			data, err := c.tunnelRecv(ctx, sid)
			if err != nil {
				c.logger.Printf("[httptunnel-client] recv error sid=%s: %v", sid, err)
				return
			}
			if len(data) > 0 {
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write(data); err != nil {
					return
				}
			}
			// Short poll interval for responsiveness
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// Wait for either direction to finish
	<-done
	cancel()

	// Disconnect the tunnel session
	c.tunnelDisconnect(context.Background(), sid)
}

// tunnelSend sends data to the tunnel server.
func (c *Client) tunnelSend(ctx context.Context, sid string, data []byte) error {
	url := fmt.Sprintf("%s?cmd=%s&sid=%s", c.serverURL, CmdSend, sid)

	var body string
	if len(c.key) > 0 {
		body = EncodePayload(data, c.key)
	} else {
		body = string(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	c.setAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("send: server returned %d", resp.StatusCode)
	}
	return nil
}

// tunnelRecv receives data from the tunnel server.
func (c *Client) tunnelRecv(ctx context.Context, sid string) ([]byte, error) {
	url := fmt.Sprintf("%s?cmd=%s&sid=%s", c.serverURL, CmdRecv, sid)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	c.setAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("recv: server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) == 0 {
		return nil, nil
	}

	if len(c.key) > 0 {
		return DecodePayload(string(body), c.key)
	}
	return body, nil
}

// tunnelDisconnect sends a disconnect command to the tunnel server.
func (c *Client) tunnelDisconnect(ctx context.Context, sid string) {
	url := fmt.Sprintf("%s?cmd=%s&sid=%s", c.serverURL, CmdDisconnect, sid)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return
	}
	c.setAuthHeader(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// setAuthHeader adds the X-Token authentication header if a key is configured.
func (c *Client) setAuthHeader(req *http.Request) {
	if len(c.key) > 0 {
		req.Header.Set("X-Token", AuthToken(c.key))
	}
}
