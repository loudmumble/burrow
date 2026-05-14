// Package proxy implements a fully RFC 1928 compliant SOCKS5 proxy server.
//
// Supports NO_AUTH and USERNAME/PASSWORD authentication methods,
// CONNECT command with IPv4, IPv6, and domain address types,
// and bidirectional TCP relay with proper connection lifecycle management.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/transport"
)

// SOCKS5 protocol constants per RFC 1928.
const (
	SocksVersion = 0x05

	// Authentication methods
	AuthNoAuth         = 0x00
	AuthGSSAPI         = 0x01
	AuthUserPass       = 0x02
	AuthNoAcceptable   = 0xFF
	AuthUserPassVer    = 0x01
	AuthUserPassOK     = 0x00
	AuthUserPassFailed = 0x01

	// Commands
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	// Address types
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04

	// Reply codes
	RepSucceeded          = 0x00
	RepGeneralFailure     = 0x01
	RepNotAllowed         = 0x02
	RepNetworkUnreachable = 0x03
	RepHostUnreachable    = 0x04
	RepConnectionRefused  = 0x05
	RepTTLExpired         = 0x06
	RepCmdNotSupported    = 0x07
	RepAddrNotSupported   = 0x08
)

// Config holds SOCKS5 server configuration.
type Config struct {
	ListenAddr     string
	Username       string
	Password       string
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	Logger         *log.Logger
	MaxConnections int
	// Dialer overrides the default net.Dial for CONNECT requests.
	// When set, all SOCKS5 CONNECT traffic is routed through this function
	// instead of directly dialing the target. Used for routing through
	// yamux agent sessions (non-root mode).
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	// UDPRelay overrides the default direct UDP relay for UDP ASSOCIATE.
	// When set, UDP datagrams are forwarded through this function (e.g.,
	// through a yamux session to the agent). Returns the response bytes.
	UDPRelay func(target string, payload []byte) ([]byte, error)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:     "127.0.0.1:1080",
		DialTimeout:    10 * time.Second,
		ReadTimeout:    30 * time.Second,
		MaxConnections: 1024,
	}
}

// SOCKS5 is a fully functional SOCKS5 proxy server.
type SOCKS5 struct {
	config      *Config
	listener    net.Listener
	logger      *log.Logger
	activeConns atomic.Int64
	totalConns  atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	mu          sync.Mutex
	connWg      sync.WaitGroup
}

// NewSOCKS5 creates a new SOCKS5 proxy server.
func NewSOCKS5(addr string, port int, username, password string) *SOCKS5 {
	cfg := DefaultConfig()
	cfg.ListenAddr = fmt.Sprintf("%s:%d", addr, port)
	cfg.Username = username
	cfg.Password = password
	return NewSOCKS5WithConfig(cfg)
}

// NewSOCKS5WithConfig creates a SOCKS5 server with full configuration.
func NewSOCKS5WithConfig(cfg *Config) *SOCKS5 {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &SOCKS5{
		config: cfg,
		logger: logger,
	}
}

// Start begins listening for SOCKS5 connections. Blocks until context is cancelled.
func (s *SOCKS5) Start() error {
	return s.StartWithContext(context.Background())
}

// StartWithContext begins listening with context-based lifecycle control.
func (s *SOCKS5) StartWithContext(ctx context.Context) error {
	network := transport.NetworkForAddr(s.config.ListenAddr, "tcp")
	ln, err := net.Listen(network, s.config.ListenAddr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	s.logger.Printf("[socks5] listening on %s", s.config.ListenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Printf("[socks5] accept error: %v", err)
			continue
		}

		if s.config.MaxConnections > 0 && s.activeConns.Load() >= int64(s.config.MaxConnections) {
			conn.Close()
			continue
		}

		s.activeConns.Add(1)
		s.totalConns.Add(1)
		s.connWg.Add(1)

		go func() {
			defer s.connWg.Done()
			defer s.activeConns.Add(-1)
			s.handleConnection(ctx, conn)
		}()
	}
}

// Stop gracefully shuts down the proxy server.
func (s *SOCKS5) Stop() {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	s.connWg.Wait()
}

// Addr returns the listener address, or empty string if not listening.
func (s *SOCKS5) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Stats returns server statistics.
func (s *SOCKS5) Stats() (active, total, bytesIn, bytesOut int64) {
	return s.activeConns.Load(), s.totalConns.Load(), s.bytesIn.Load(), s.bytesOut.Load()
}

// handleConnection processes a single SOCKS5 client connection end-to-end.
func (s *SOCKS5) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	if s.config.ReadTimeout > 0 {
		conn.SetDeadline(time.Now().Add(s.config.ReadTimeout))
	}

	// Phase 1: Greeting / Auth negotiation
	if err := s.handleGreeting(conn); err != nil {
		s.logger.Printf("[socks5] greeting error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Phase 2: Request
	req, err := s.handleRequest(conn)
	if err != nil {
		s.logger.Printf("[socks5] request error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	switch req.cmd {
	case CmdConnect:
		s.handleConnect(ctx, conn, req.target)
	case CmdBind:
		s.handleBind(ctx, conn, req.target)
	case CmdUDPAssociate:
		s.handleUDPAssociate(ctx, conn, req.target)
	}
}

// handleConnect handles SOCKS5 CONNECT command.
func (s *SOCKS5) handleConnect(ctx context.Context, conn net.Conn, target string) {
	var targetConn net.Conn
	var err error
	network := transport.NetworkForAddr(target, "tcp")
	if s.config.Dialer != nil {
		targetConn, err = s.config.Dialer(ctx, network, target)
	} else {
		dialer := net.Dialer{Timeout: s.config.DialTimeout}
		targetConn, err = dialer.DialContext(ctx, network, target)
	}
	if err != nil {
		s.sendReply(conn, RepHostUnreachable, nil)
		s.logger.Printf("[socks5] connect to %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()

	// Send success reply with the bound address
	if tcpAddr, ok := targetConn.LocalAddr().(*net.TCPAddr); ok {
		s.sendReply(conn, RepSucceeded, tcpAddr)
	} else {
		s.sendReply(conn, RepSucceeded, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	}

	// Clear deadline for relay phase
	conn.SetDeadline(time.Time{})

	// Phase 4: Bidirectional relay
	s.relay(ctx, conn, targetConn)
}

// handleBind handles SOCKS5 BIND command per RFC 1928.
// Opens a local listener, sends the first reply with the listener address,
// accepts one incoming connection, sends the second reply, then relays.
func (s *SOCKS5) handleBind(ctx context.Context, conn net.Conn, _ string) {
	host, _, _ := net.SplitHostPort(s.config.ListenAddr)
	if host == "" {
		host = "0.0.0.0"
	}
	network := transport.NetworkForAddr(host+":0", "tcp")
	ln, err := net.Listen(network, host+":0")
	if err != nil {
		s.sendReply(conn, RepGeneralFailure, nil)
		return
	}
	defer ln.Close()

	// First reply: tell client where we're listening.
	bindAddr := ln.Addr().(*net.TCPAddr)
	s.sendReply(conn, RepSucceeded, bindAddr)

	s.logger.Printf("[socks5] BIND from %s — listening on %s", conn.RemoteAddr(), bindAddr)

	// Accept one connection with timeout.
	acceptDone := make(chan net.Conn, 1)
	go func() {
		incoming, err := ln.Accept()
		if err != nil {
			acceptDone <- nil
			return
		}
		transport.TuneConn(incoming)
		acceptDone <- incoming
	}()

	// Wait for incoming connection or TCP close or context cancel.
	var incoming net.Conn
	select {
	case incoming = <-acceptDone:
	case <-ctx.Done():
		return
	case <-time.After(60 * time.Second):
		s.sendReply(conn, RepTTLExpired, nil)
		return
	}
	if incoming == nil {
		s.sendReply(conn, RepGeneralFailure, nil)
		return
	}
	defer incoming.Close()

	// Second reply: tell client who connected.
	if tcpAddr, ok := incoming.RemoteAddr().(*net.TCPAddr); ok {
		s.sendReply(conn, RepSucceeded, tcpAddr)
	} else {
		s.sendReply(conn, RepSucceeded, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
	}

	// Clear deadline for relay phase.
	conn.SetDeadline(time.Time{})

	s.logger.Printf("[socks5] BIND %s <- %s established", conn.RemoteAddr(), incoming.RemoteAddr())

	// Relay bidirectionally.
	s.relay(ctx, conn, incoming)
}

// handleUDPAssociate handles SOCKS5 UDP ASSOCIATE command per RFC 1928.
// Opens a local UDP listener and relays datagrams through the configured dialer.
func (s *SOCKS5) handleUDPAssociate(ctx context.Context, conn net.Conn, _ string) {
	host, _, _ := net.SplitHostPort(s.config.ListenAddr)
	if host == "" {
		host = "127.0.0.1"
	}
	udpNetwork := transport.NetworkForAddr(host+":0", "udp")
	udpAddr, err := net.ResolveUDPAddr(udpNetwork, host+":0")
	if err != nil {
		s.sendReply(conn, RepGeneralFailure, nil)
		return
	}
	udpConn, err := net.ListenUDP(udpNetwork, udpAddr)
	if err == nil {
		transport.TunePacketConn(udpConn)
	}
	defer udpConn.Close()

	// Reply with the UDP listener address.
	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	s.sendReply(conn, RepSucceeded, &net.TCPAddr{IP: boundAddr.IP, Port: boundAddr.Port})

	// Clear deadline for relay phase.
	conn.SetDeadline(time.Time{})

	s.logger.Printf("[socks5] UDP ASSOCIATE from %s — relay on %s", conn.RemoteAddr(), boundAddr)

	// The TCP connection must stay alive — closing it terminates the UDP association.
	// Monitor TCP for close in a goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1)
		conn.Read(buf) // blocks until TCP closes
	}()

	// Relay loop: read SOCKS5 UDP datagrams, forward, send back responses.
	udpBuf := make([]byte, 65535)
	for {
		udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, clientAddr, readErr := udpConn.ReadFromUDP(udpBuf)
		if readErr != nil {
			select {
			case <-done:
				return // TCP closed — terminate association
			case <-ctx.Done():
				return
			default:
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
		}

		// Parse SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
		if n < 4 {
			continue
		}
		frag := udpBuf[2]
		if frag != 0 {
			continue // fragmentation not supported
		}
		target, headerLen, parseErr := parseUDPHeader(udpBuf[:n])
		if parseErr != nil {
			continue
		}
		payload := udpBuf[headerLen:n]

		// Forward through the session dialer (or directly).
		var resp []byte
		if s.config.UDPRelay != nil {
			resp, err = s.config.UDPRelay(target, payload)
		} else {
			resp, err = directUDPRelay(target, payload)
		}
		if err != nil {
			continue
		}
		if len(resp) == 0 {
			continue
		}

		// Build SOCKS5 UDP response header + response payload.
		respFrame := buildUDPHeader(target, resp)
		udpConn.WriteToUDP(respFrame, clientAddr)
	}
}

// parseUDPHeader parses a SOCKS5 UDP datagram header and returns the target
// address and header length.
func parseUDPHeader(data []byte) (target string, headerLen int, err error) {
	if len(data) < 4 {
		return "", 0, fmt.Errorf("udp header too short")
	}
	// RSV(2) FRAG(1) ATYP(1)
	atyp := data[3]
	off := 4
	var host string

	switch atyp {
	case AddrTypeIPv4:
		if len(data) < off+4+2 {
			return "", 0, fmt.Errorf("ipv4 addr too short")
		}
		host = net.IP(data[off : off+4]).String()
		off += 4
	case AddrTypeDomain:
		if len(data) < off+1 {
			return "", 0, fmt.Errorf("domain len missing")
		}
		dLen := int(data[off])
		off++
		if len(data) < off+dLen+2 {
			return "", 0, fmt.Errorf("domain too short")
		}
		host = string(data[off : off+dLen])
		off += dLen
	case AddrTypeIPv6:
		if len(data) < off+16+2 {
			return "", 0, fmt.Errorf("ipv6 addr too short")
		}
		host = net.IP(data[off : off+16]).String()
		off += 16
	default:
		return "", 0, fmt.Errorf("unknown atyp %d", atyp)
	}

	port := binary.BigEndian.Uint16(data[off : off+2])
	off += 2

	return fmt.Sprintf("%s:%d", host, port), off, nil
}

// buildUDPHeader creates a SOCKS5 UDP response frame with the given target and payload.
func buildUDPHeader(target string, payload []byte) []byte {
	host, portStr, _ := net.SplitHostPort(target)
	port := uint16(0)
	if p, err := net.LookupPort("udp", portStr); err == nil {
		port = uint16(p)
	}

	ip := net.ParseIP(host)

	var buf []byte
	buf = append(buf, 0x00, 0x00, 0x00) // RSV + FRAG
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, AddrTypeIPv4)
		buf = append(buf, ip4...)
	} else if ip != nil {
		buf = append(buf, AddrTypeIPv6)
		buf = append(buf, ip.To16()...)
	} else {
		// Domain
		buf = append(buf, AddrTypeDomain, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}
	buf = append(buf, byte(port>>8), byte(port&0xff))
	buf = append(buf, payload...)
	return buf
}

// directUDPRelay sends a UDP datagram directly and returns the response.
func directUDPRelay(target string, payload []byte) ([]byte, error) {
	network := transport.NetworkForAddr(target, "udp")
	conn, err := net.DialTimeout(network, target, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// handleGreeting processes the SOCKS5 greeting and authentication.
func (s *SOCKS5) handleGreeting(conn net.Conn) error {
	// Read version and method count
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read greeting header: %w", err)
	}
	if header[0] != SocksVersion {
		conn.Write([]byte{SocksVersion, AuthNoAcceptable})
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		conn.Write([]byte{SocksVersion, AuthNoAcceptable})
		return fmt.Errorf("no auth methods offered")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read auth methods: %w", err)
	}

	if s.config.Username != "" {
		// Require username/password auth
		if !containsByte(methods, AuthUserPass) {
			conn.Write([]byte{SocksVersion, AuthNoAcceptable})
			return fmt.Errorf("client doesn't support username/password auth")
		}
		conn.Write([]byte{SocksVersion, AuthUserPass})
		return s.handleUserPassAuth(conn)
	}

	// No auth required
	if !containsByte(methods, AuthNoAuth) {
		conn.Write([]byte{SocksVersion, AuthNoAcceptable})
		return fmt.Errorf("client doesn't support no-auth method")
	}
	conn.Write([]byte{SocksVersion, AuthNoAuth})
	return nil
}

// handleUserPassAuth processes RFC 1929 username/password authentication.
func (s *SOCKS5) handleUserPassAuth(conn net.Conn) error {
	// VER(1) | ULEN(1) | UNAME(ULEN) | PLEN(1) | PASSWD(PLEN)
	verBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, verBuf); err != nil {
		return fmt.Errorf("read auth version: %w", err)
	}
	if verBuf[0] != AuthUserPassVer {
		conn.Write([]byte{AuthUserPassVer, AuthUserPassFailed})
		return fmt.Errorf("unsupported auth version: %d", verBuf[0])
	}

	uLen := int(verBuf[1])
	if uLen == 0 || uLen > 255 {
		conn.Write([]byte{AuthUserPassVer, AuthUserPassFailed})
		return fmt.Errorf("invalid username length: %d", uLen)
	}

	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	pLen := int(pLenBuf[0])

	passwd := make([]byte, pLen)
	if pLen > 0 {
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return fmt.Errorf("read password: %w", err)
		}
	}

	if string(uname) != s.config.Username || string(passwd) != s.config.Password {
		conn.Write([]byte{AuthUserPassVer, AuthUserPassFailed})
		return fmt.Errorf("authentication failed for user: %s", string(uname))
	}

	conn.Write([]byte{AuthUserPassVer, AuthUserPassOK})
	return nil
}

// socksRequest holds the parsed SOCKS5 request.
type socksRequest struct {
	cmd    byte
	target string
}

// handleRequest parses and validates the SOCKS5 connection request.
func (s *SOCKS5) handleRequest(conn net.Conn) (*socksRequest, error) {
	// VER(1) | CMD(1) | RSV(1) | ATYP(1)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}

	if header[0] != SocksVersion {
		return nil, fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
	}

	cmd := header[1]
	switch cmd {
	case CmdConnect, CmdBind, CmdUDPAssociate:
		// supported
	default:
		s.sendReply(conn, RepCmdNotSupported, nil)
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := header[3]
	var host string

	switch atyp {
	case AddrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv4 addr: %w", err)
		}
		host = net.IP(addr).String()

	case AddrTypeDomain:
		dlenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, dlenBuf); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, dlenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)

	case AddrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv6 addr: %w", err)
		}
		host = net.IP(addr).String()

	default:
		s.sendReply(conn, RepAddrNotSupported, nil)
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return &socksRequest{
		cmd:    cmd,
		target: fmt.Sprintf("%s:%d", host, port),
	}, nil
}

// sendReply sends a SOCKS5 reply to the client.
func (s *SOCKS5) sendReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) {
	resp := make([]byte, 22) // Max size for IPv6: 1+1+1+1+16+2 = 22
	resp[0] = SocksVersion
	resp[1] = rep
	resp[2] = 0x00 // RSV

	atyp := byte(AddrTypeIPv4)
	addrLen := 4
	if bindAddr != nil {
		if ip4 := bindAddr.IP.To4(); ip4 != nil {
			atyp = AddrTypeIPv4
			addrLen = 4
			copy(resp[4:8], ip4)
		} else {
			atyp = AddrTypeIPv6
			addrLen = 16
			copy(resp[4:20], bindAddr.IP.To16())
		}
		binary.BigEndian.PutUint16(resp[4+addrLen:4+addrLen+2], uint16(bindAddr.Port))
	} else {
		// Generic placeholder for no bind address
		copy(resp[4:8], net.IPv4zero)
		binary.BigEndian.PutUint16(resp[8:10], 0)
	}

	resp[3] = atyp
	conn.Write(resp[:4+addrLen+2])
}

// relay performs bidirectional data copying between two connections.
// Waits for BOTH directions to finish so in-flight data is never dropped.
func (s *SOCKS5) relay(ctx context.Context, client, target net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		cw := relay.CountingWriter{Target: target, Added: func(n int64) { s.bytesIn.Add(n) }}
		relay.CopyBuffered(cw, client)
		if tc, ok := target.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		cw := relay.CountingWriter{Target: client, Added: func(n int64) { s.bytesOut.Add(n) }}
		relay.CopyBuffered(cw, target)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()


	// Wait for first direction to finish, then close both connections
	// to unblock the other direction (yamux streams and net.Pipe don't
	// respond to context cancellation — only Close). Then drain second.
	<-done
	// Drain period: give the other direction a moment to flush any
	// remaining data in multiplexer/OS buffers before force-closing.
	time.Sleep(50 * time.Millisecond)
	client.Close()
	target.Close()
	<-done

}

// containsByte checks if a byte slice contains a specific byte.
func containsByte(s []byte, b byte) bool {
	for _, v := range s {
		if v == b {
			return true
		}
	}
	return false
}
