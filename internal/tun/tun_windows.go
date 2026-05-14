//go:build windows

package tun

import (
	"errors"
	"net"
)

const (
	DefaultName = "burrow0"
	DefaultMTU  = 1500
)

var errNotSupported = errors.New("tun: not supported on windows")

// Interface is a stub for Windows — TUN is only used on the operator (Linux/macOS).
type Interface struct {
	Name string
	MTU  int
}

func New(name string) (*Interface, error)                       { return nil, errNotSupported }
func (i *Interface) Configure(ip net.IP, mask net.IPMask) error { return errNotSupported }
func (i *Interface) AddRoute(cidr string) error                 { return errNotSupported }
func (i *Interface) RemoveRoute(cidr string) error              { return errNotSupported }
func (i *Interface) Read(buf []byte) (int, error)               { return 0, errNotSupported }
func (i *Interface) Write(buf []byte) (int, error)              { return 0, errNotSupported }
func (i *Interface) Close() error                               { return errNotSupported }
func DefaultMagicIP() (net.IP, net.IPMask)                      { return net.IPv4(240, 0, 0, 1), net.CIDRMask(32, 32) }
func NextMagicIP(sessionIndex int) (net.IP, net.IPMask) {
	return net.IPv4(240, 0, 0, byte(sessionIndex+1)), net.CIDRMask(32, 32)
}
