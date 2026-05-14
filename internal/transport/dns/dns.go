// Package dns provides a DNS tunnel transport for Burrow. It encodes tunnel
// traffic inside DNS queries and responses, allowing data exfiltration through
// networks that only permit DNS traffic. Upstream data (client->server) is
// base32-encoded in query subdomain labels; downstream data (server->client) is
// base64-encoded in TXT records. The client polls the server periodically to
// pull downstream data.
//
// Query format: <data-labels>.<seq>.<session-id>.t.tun.
// Response format: TXT record containing base64-encoded payload.
package dns

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/loudmumble/burrow/internal/transport"
)

func init() {
	transport.Registry["dns"] = func() transport.Transport { return NewDNSTransport() }
}

// b32 is base32 without padding, safe for DNS labels (case-insensitive).
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	// maxLabelLen is the max characters per DNS label.
	maxLabelLen = 63
	// maxPayloadPerQuery is the max raw bytes encodable per query (~110 bytes
	// after base32 encoding across multiple labels of 63 chars each).
	maxPayloadPerQuery = 110
	// maxTXTPayload is the max raw bytes in a single TXT response.
	maxTXTPayload = 400
	// pollInterval is how often the client polls for downstream data.
	pollInterval = 50 * time.Millisecond
	// tunnelZone is the fixed DNS zone suffix for tunnel queries.
	tunnelZone = "t.tun."
)

// ---------------------------------------------------------------------------
// streamBuffer: thread-safe byte buffer with blocking reads and non-blocking
// drain. Used for both upstream (client->server) and downstream (server->client).
// ---------------------------------------------------------------------------

type streamBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

func newStreamBuffer() *streamBuffer {
	sb := &streamBuffer{}
	sb.cond = sync.NewCond(&sb.mu)
	return sb
}

// Append adds data to the buffer and wakes any blocked readers.
func (sb *streamBuffer) Append(data []byte) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.closed {
		return
	}
	sb.buf = append(sb.buf, data...)
	sb.cond.Broadcast()
}

// Read blocks until data is available, then copies into p.
func (sb *streamBuffer) Read(p []byte) (int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	for len(sb.buf) == 0 {
		if sb.closed {
			return 0, io.EOF
		}
		sb.cond.Wait()
	}
	n := copy(p, sb.buf)
	sb.buf = sb.buf[n:]
	return n, nil
}

// Drain removes and returns up to max bytes without blocking.
func (sb *streamBuffer) Drain(max int) []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if len(sb.buf) == 0 {
		return nil
	}
	n := max
	if n > len(sb.buf) {
		n = len(sb.buf)
	}
	data := make([]byte, n)
	copy(data, sb.buf[:n])
	sb.buf = sb.buf[n:]
	return data
}

// Close marks the buffer as closed and wakes all blocked readers.
func (sb *streamBuffer) Close() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.closed = true
	sb.cond.Broadcast()
}

// ---------------------------------------------------------------------------
// DNSTransport: implements transport.Transport
// ---------------------------------------------------------------------------

// DNSTransport implements transport.Transport over DNS query-response pairs.
// Server side: listens as a UDP DNS server, decodes upstream data from query
// subdomain labels, returns downstream data in TXT records.
// Client side: encodes writes as DNS queries, polls for downstream TXT data.
type DNSTransport struct {
	server    *mdns.Server
	sessions  map[string]*tunnelSession
	connCh    chan net.Conn
	mu        sync.Mutex
	addr      string
	done      chan struct{}
	closeOnce sync.Once
}

// tunnelSession holds per-session buffers on the server side.
type tunnelSession struct {
	upstream   *streamBuffer // client->server: DNS handler writes, app reads
	downstream *streamBuffer // server->client: app writes, DNS handler drains
}

// NewDNSTransport creates a new DNS tunnel transport.
func NewDNSTransport() *DNSTransport {
	return &DNSTransport{
		sessions: make(map[string]*tunnelSession),
		connCh:   make(chan net.Conn, 64),
		done:     make(chan struct{}),
	}
}

// Name returns the transport identifier.
func (t *DNSTransport) Name() string { return "dns" }

// Listen starts a UDP DNS server on addr (e.g. ":15353") that handles tunnel
// queries. Non-blocking: returns once the server is accepting packets.
func (t *DNSTransport) Listen(_ context.Context, addr string, _ *tls.Config) error {
	network := transport.NetworkForAddr(addr, "udp")
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return fmt.Errorf("dns transport listen: %w", err)
	}
	transport.TunePacketConn(pc)

	t.mu.Lock()
	t.addr = pc.LocalAddr().String()
	t.mu.Unlock()

	mux := mdns.NewServeMux()
	mux.HandleFunc(tunnelZone, t.handleDNS)

	started := make(chan struct{})
	t.server = &mdns.Server{
		PacketConn:        pc,
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}

	go func() {
		if err := t.server.ActivateAndServe(); err != nil {
			log.Printf("[dns] server error: %v", err)
		}
	}()

	<-started
	return nil
}

// handleDNS processes an incoming DNS query, extracts upstream data from
// subdomain labels, feeds it to the session's upstream buffer, and returns
// buffered downstream data in a TXT record.
func (t *DNSTransport) handleDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	parts := strings.Split(name, ".")

	// Minimum valid query: p.0.SESSIONID.t.tun (5 labels)
	if len(parts) < 5 {
		replyNXDomain(w, r)
		return
	}

	// Last two labels must be "t" and "tun"
	zi := len(parts) - 2
	if parts[zi] != "t" || parts[zi+1] != "tun" {
		replyNXDomain(w, r)
		return
	}

	sessionID := parts[zi-1]
	// parts[zi-2] is the sequence number (used for DNS-level identification)
	dataLabels := parts[:zi-2]

	// Decode upstream payload from data labels
	var payload []byte
	if len(dataLabels) > 0 {
		encoded := strings.Join(dataLabels, "")
		if encoded != "" && encoded != "p" {
			dec, err := b32.DecodeString(strings.ToUpper(encoded))
			if err != nil {
				replyNXDomain(w, r)
				return
			}
			payload = dec
		}
	}

	// Get or create session
	t.mu.Lock()
	sess, exists := t.sessions[sessionID]
	if !exists {
		sess = &tunnelSession{
			upstream:   newStreamBuffer(),
			downstream: newStreamBuffer(),
		}
		t.sessions[sessionID] = sess
		t.mu.Unlock()

		// Create app-facing conn and deliver via Accept()
		appConn := &dnsConn{
			sessionID:  sessionID,
			readBuf:    sess.upstream,
			writeBuf:   sess.downstream,
			localAddr:  &dnsAddr{session: sessionID},
			remoteAddr: &dnsAddr{session: sessionID},
			closed:     make(chan struct{}),
		}

		select {
		case t.connCh <- appConn:
		case <-t.done:
			appConn.Close()
			return
		}
	} else {
		t.mu.Unlock()
	}

	// Feed upstream data
	if len(payload) > 0 {
		sess.upstream.Append(payload)
	}

	// Drain downstream data for the response
	downstream := sess.downstream.Drain(maxTXTPayload)

	// Build TXT response
	msg := new(mdns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	txtVal := ""
	if len(downstream) > 0 {
		txtVal = base64.StdEncoding.EncodeToString(downstream)
	}
	msg.Answer = append(msg.Answer, &mdns.TXT{
		Hdr: mdns.RR_Header{
			Name:   q.Name,
			Rrtype: mdns.TypeTXT,
			Class:  mdns.ClassINET,
			Ttl:    0,
		},
		Txt: splitTXT(txtVal),
	})

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[dns] write response for session %s: %v", sessionID, err)
	}
}

// Accept returns the next inbound connection from a DNS tunnel client. Blocks.
func (t *DNSTransport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.done:
		return nil, transport.ErrTransportClosed
	}
}

// Dial creates a client-side DNS tunnel connection to a server at addr.
// addr should be "host:port" (e.g. "127.0.0.1:15353").
func (t *DNSTransport) Dial(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
	return newClientConn(randomHex(8), addr), nil
}

// Close shuts down the DNS transport and all sessions.
func (t *DNSTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.done)

		t.mu.Lock()
		for _, s := range t.sessions {
			s.upstream.Close()
			s.downstream.Close()
		}
		t.sessions = make(map[string]*tunnelSession)
		t.mu.Unlock()

		if t.server != nil {
			err = t.server.Shutdown()
		}
	})
	return err
}

// Addr returns the actual listen address after Listen.
func (t *DNSTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}

// ---------------------------------------------------------------------------
// dnsConn: net.Conn over DNS queries/responses
// ---------------------------------------------------------------------------

// dnsConn implements net.Conn. On the server side it wraps shared session
// buffers. On the client side it sends DNS queries and polls for responses.
type dnsConn struct {
	sessionID  string
	readBuf    *streamBuffer
	writeBuf   *streamBuffer
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     chan struct{}
	closeOnce  sync.Once

	// Client-only fields
	isClient   bool
	serverAddr string
	sendMu     sync.Mutex // serializes all DNS queries to preserve ordering
	seq        uint32
	pollDone   chan struct{}

	// Deadline support for net.Conn compliance
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer
}

// newClientConn creates a client-side dnsConn that tunnels data via DNS queries.
func newClientConn(sessionID, serverAddr string) *dnsConn {
	c := &dnsConn{
		sessionID:  sessionID,
		readBuf:    newStreamBuffer(),
		writeBuf:   newStreamBuffer(),
		localAddr:  &dnsAddr{session: sessionID},
		remoteAddr: &dnsAddr{session: sessionID},
		closed:     make(chan struct{}),
		isClient:   true,
		serverAddr: serverAddr,
		pollDone:   make(chan struct{}),
	}
	go c.pollLoop()
	return c
}

// pollLoop periodically sends DNS queries to pull downstream data from
// the server. All sends are serialized via sendMu to preserve ordering.
func (c *dnsConn) pollLoop() {
	defer close(c.pollDone)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			c.sendMu.Lock()
			resp, err := c.doQuery(nil)
			c.sendMu.Unlock()
			if err == nil && len(resp) > 0 {
				c.readBuf.Append(resp)
			}
		}
	}
}

// doQuery sends a single DNS query with optional payload data and returns
// any downstream payload from the TXT response. Caller must hold sendMu.
func (c *dnsConn) doQuery(data []byte) ([]byte, error) {
	seq := c.seq
	c.seq++

	qname := buildQueryName(data, seq, c.sessionID)

	msg := new(mdns.Msg)
	msg.SetQuestion(qname, mdns.TypeTXT)
	msg.RecursionDesired = false

	client := &mdns.Client{
		Net:     transport.NetworkForAddr(c.serverAddr, "udp"),
		Timeout: 2 * time.Second,
	}

	resp, _, err := client.Exchange(msg, c.serverAddr)
	if err != nil {
		return nil, err
	}

	return extractTXTPayload(resp), nil
}

// Read reads downstream data from the DNS tunnel.
func (c *dnsConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.EOF
	default:
	}

	sb := c.readBuf
	sb.mu.Lock()
	defer sb.mu.Unlock()

	for len(sb.buf) == 0 {
		if sb.closed {
			return 0, io.EOF
		}
		c.deadlineMu.Lock()
		dl := c.readDeadline
		c.deadlineMu.Unlock()
		if !dl.IsZero() && !time.Now().Before(dl) {
			return 0, os.ErrDeadlineExceeded
		}
		sb.cond.Wait()
	}
	n := copy(p, sb.buf)
	sb.buf = sb.buf[n:]
	return n, nil
}

// Write writes data to the DNS tunnel. On the client side, data is sent
// immediately as DNS queries (chunked if > maxPayloadPerQuery). On the
// server side, data is buffered for delivery in the next TXT response.
func (c *dnsConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	c.deadlineMu.Lock()
	dl := c.writeDeadline
	c.deadlineMu.Unlock()
	if !dl.IsZero() && !time.Now().Before(dl) {
		return 0, os.ErrDeadlineExceeded
	}

	if !c.isClient {
		c.writeBuf.Append(p)
		return len(p), nil
	}

	// Client: send data immediately, serialized with poll loop
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	written := 0
	remaining := p
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > maxPayloadPerQuery {
			chunk = remaining[:maxPayloadPerQuery]
		}
		remaining = remaining[len(chunk):]

		resp, err := c.doQuery(chunk)
		if err != nil {
			return written, err
		}
		written += len(chunk)

		if len(resp) > 0 {
			c.readBuf.Append(resp)
		}
	}

	return written, nil
}

// Close closes the DNS tunnel connection.
func (c *dnsConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.readBuf.Close()
		c.deadlineMu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		c.deadlineMu.Unlock()
		if c.isClient && c.pollDone != nil {
			<-c.pollDone
		}
	})
	return nil
}

func (c *dnsConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *dnsConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *dnsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *dnsConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	if !t.IsZero() {
		d := time.Until(t)
		if d <= 0 {
			c.readBuf.cond.Broadcast()
		} else {
			c.readTimer = time.AfterFunc(d, func() {
				c.readBuf.cond.Broadcast()
			})
		}
	}
	return nil
}

func (c *dnsConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return nil
}

// ---------------------------------------------------------------------------
// dnsAddr: net.Addr for DNS tunnel connections
// ---------------------------------------------------------------------------

type dnsAddr struct {
	session string
}

func (a *dnsAddr) Network() string { return "dns" }
func (a *dnsAddr) String() string  { return "dns://" + a.session }

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

// buildQueryName constructs a DNS query name encoding the payload.
// Format: <label1>.<label2>...<seq>.<sessionID>.t.tun.
func buildQueryName(data []byte, seq uint32, sessionID string) string {
	var labels []string

	if len(data) > 0 {
		encoded := strings.ToLower(b32.EncodeToString(data))
		for len(encoded) > 0 {
			end := maxLabelLen
			if end > len(encoded) {
				end = len(encoded)
			}
			labels = append(labels, encoded[:end])
			encoded = encoded[end:]
		}
	} else {
		labels = append(labels, "p") // poll/keepalive marker
	}

	labels = append(labels, fmt.Sprintf("%d", seq), sessionID, "t", "tun")
	return strings.Join(labels, ".") + "."
}

// extractTXTPayload extracts and base64-decodes the payload from a TXT response.
func extractTXTPayload(msg *mdns.Msg) []byte {
	if msg == nil {
		return nil
	}
	for _, rr := range msg.Answer {
		txt, ok := rr.(*mdns.TXT)
		if !ok {
			continue
		}
		joined := strings.Join(txt.Txt, "")
		if joined == "" {
			return nil
		}
		data, err := base64.StdEncoding.DecodeString(joined)
		if err != nil {
			return nil
		}
		return data
	}
	return nil
}

// splitTXT splits a string into chunks of at most 255 bytes for TXT records.
func splitTXT(s string) []string {
	if s == "" {
		return []string{""}
	}
	var chunks []string
	for len(s) > 0 {
		end := 255
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[:end])
		s = s[end:]
	}
	return chunks
}

// replyNXDomain sends an NXDOMAIN response for non-tunnel queries.
func replyNXDomain(w mdns.ResponseWriter, r *mdns.Msg) {
	msg := new(mdns.Msg)
	msg.SetReply(r)
	msg.Rcode = mdns.RcodeNameError
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("[dns] write NXDOMAIN response: %v", err)
	}
}

// randomHex generates n random hex characters.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}
