package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/loudmumble/burrow/internal/mux"
)

// Stream type bytes for the proxy protocol.
// The high byte of the old 2-byte addr length was always 0x00, so using it
// as a type discriminator is backwards-compatible with old agents.
const (
	proxyTypeTCP byte = 0x00
	proxyTypeUDP byte = 0x01
)

// NewSessionDialer returns a Dialer that routes SOCKS5 connections through
// a yamux session. Each CONNECT opens a new yamux stream to the remote agent.
// Wire format: [type:1][addr_len:2 BE][addr]
func NewSessionDialer(sess *mux.Session) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		stream, err := sess.Open()
		if err != nil {
			return nil, fmt.Errorf("open mux stream: %w", err)
		}

		addrBytes := []byte(addr)
		header := make([]byte, 1+2+len(addrBytes))
		header[0] = proxyTypeTCP
		binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
		copy(header[3:], addrBytes)
		if _, err := stream.Write(header); err != nil {
			stream.Close()
			return nil, fmt.Errorf("write connect header: %w", err)
		}
		return stream, nil
	}
}

func NewChainedSessionDialer(sessions []*mux.Session) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(sessions) == 1 {
		return NewSessionDialer(sessions[0])
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		stream, err := sessions[0].Open()
		if err != nil {
			return nil, fmt.Errorf("open first hop stream: %w", err)
		}

		addrBytes := []byte(addr)
		header := make([]byte, 1+2+len(addrBytes))
		header[0] = proxyTypeTCP
		binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
		copy(header[3:], addrBytes)
		if _, err := stream.Write(header); err != nil {
			stream.Close()
			return nil, fmt.Errorf("write connect header: %w", err)
		}
		return stream, nil
	}
}

// UDPRelayViaSession sends a UDP datagram through a yamux stream and returns
// the response. Opens a fresh stream for each round-trip (cheap over yamux).
func UDPRelayViaSession(sess *mux.Session, target string, payload []byte, timeout time.Duration) ([]byte, error) {
	stream, err := sess.Open()
	if err != nil {
		return nil, fmt.Errorf("open mux stream: %w", err)
	}
	defer stream.Close()

	addrBytes := []byte(target)
	// Header: [type=0x01][addr_len:2][addr][payload_len:2][payload]
	header := make([]byte, 1+2+len(addrBytes)+2+len(payload))
	header[0] = proxyTypeUDP
	binary.BigEndian.PutUint16(header[1:3], uint16(len(addrBytes)))
	copy(header[3:3+len(addrBytes)], addrBytes)
	off := 3 + len(addrBytes)
	binary.BigEndian.PutUint16(header[off:off+2], uint16(len(payload)))
	copy(header[off+2:], payload)

	if _, err := stream.Write(header); err != nil {
		return nil, fmt.Errorf("write udp header: %w", err)
	}

	// Read response: [resp_len:2][resp bytes]
	if tc, ok := stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		tc.SetReadDeadline(time.Now().Add(timeout))
	}
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, respLenBuf); err != nil {
		return nil, fmt.Errorf("read udp response len: %w", err)
	}
	respLen := binary.BigEndian.Uint16(respLenBuf)
	if respLen == 0 {
		return nil, nil
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(stream, resp); err != nil {
		return nil, fmt.Errorf("read udp response: %w", err)
	}
	return resp, nil
}
