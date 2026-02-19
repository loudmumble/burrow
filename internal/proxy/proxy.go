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
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
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
	target, err := s.handleRequest(conn)
	if err != nil {
		s.logger.Printf("[socks5] request error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Phase 3: Connect to target
	dialer := net.Dialer{Timeout: s.config.DialTimeout}
	targetConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		s.sendReply(conn, RepHostUnreachable, nil)
		s.logger.Printf("[socks5] connect to %s failed: %v", target, err)
		return
	}
	defer targetConn.Close()

	// Send success reply with the bound address
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	s.sendReply(conn, RepSucceeded, localAddr)

	// Clear deadline for relay phase
	conn.SetDeadline(time.Time{})

	s.logger.Printf("[socks5] %s -> %s established", conn.RemoteAddr(), target)

	// Phase 4: Bidirectional relay
	s.relay(ctx, conn, targetConn)
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

// handleRequest parses and validates the SOCKS5 connection request.
func (s *SOCKS5) handleRequest(conn net.Conn) (string, error) {
	// VER(1) | CMD(1) | RSV(1) | ATYP(1)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if header[0] != SocksVersion {
		return "", fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
	}

	cmd := header[1]
	if cmd != CmdConnect {
		s.sendReply(conn, RepCmdNotSupported, nil)
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := header[3]
	var host string

	switch atyp {
	case AddrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4 addr: %w", err)
		}
		host = net.IP(addr).String()

	case AddrTypeDomain:
		dlenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, dlenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, dlenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)

	case AddrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6 addr: %w", err)
		}
		host = net.IP(addr).String()

	default:
		s.sendReply(conn, RepAddrNotSupported, nil)
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// sendReply sends a SOCKS5 reply to the client.
func (s *SOCKS5) sendReply(conn net.Conn, rep byte, bindAddr *net.TCPAddr) {
	resp := make([]byte, 10)
	resp[0] = SocksVersion
	resp[1] = rep
	resp[2] = 0x00 // RSV
	resp[3] = AddrTypeIPv4

	if bindAddr != nil {
		ip4 := bindAddr.IP.To4()
		if ip4 != nil {
			copy(resp[4:8], ip4)
		}
		binary.BigEndian.PutUint16(resp[8:10], uint16(bindAddr.Port))
	}
	conn.Write(resp)
}

// relay performs bidirectional data copying between two connections.
func (s *SOCKS5) relay(ctx context.Context, client, target net.Conn) {
	done := make(chan struct{}, 2)

	copyFunc := func(dst, src net.Conn, counter *atomic.Int64) {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(dst, src)
		counter.Add(n)
		// Signal the other direction to stop by closing write side
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copyFunc(target, client, &s.bytesIn)
	go copyFunc(client, target, &s.bytesOut)

	// Wait for either direction to finish or context cancellation
	select {
	case <-done:
	case <-ctx.Done():
	}
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
