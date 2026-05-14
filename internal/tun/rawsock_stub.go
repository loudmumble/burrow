//go:build !linux

package tun

import (
	"fmt"
	"net"
)

// RawSocket is not supported on this platform.
type RawSocket struct{}

func NewRawSocket(ifName string, filterIP net.IP) (*RawSocket, error) {
	return nil, fmt.Errorf("rawsock: AF_PACKET not supported on this platform")
}

func (r *RawSocket) Read(buf []byte) (int, error)  { return 0, fmt.Errorf("not supported") }
func (r *RawSocket) Write(buf []byte) (int, error) { return 0, fmt.Errorf("not supported") }
func (r *RawSocket) Close() error                  { return nil }

func DefaultInterface() (string, error) {
	return "", fmt.Errorf("rawsock: not supported on this platform")
}
