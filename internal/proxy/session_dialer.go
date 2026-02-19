package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/loudmumble/burrow/internal/mux"
)

// NewSessionDialer returns a Dialer that routes SOCKS5 connections through
// a yamux session. Each CONNECT opens a new yamux stream to the remote agent.
func NewSessionDialer(sess *mux.Session) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		stream, err := sess.Open()
		if err != nil {
			return nil, fmt.Errorf("open mux stream: %w", err)
		}

		addrBytes := []byte(addr)
		header := make([]byte, 2+len(addrBytes))
		binary.BigEndian.PutUint16(header[:2], uint16(len(addrBytes)))
		copy(header[2:], addrBytes)
		if _, err := stream.Write(header); err != nil {
			stream.Close()
			return nil, fmt.Errorf("write connect header: %w", err)
		}
		return stream, nil
	}
}
