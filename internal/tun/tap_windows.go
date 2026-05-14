//go:build windows

package tun

import (
	"net"
)

const (
	DefaultTAPName = "burrow-tap0"
	DefaultTAPMTU  = 1500
	EthHeaderLen   = 14
	MaxFrameSize   = DefaultTAPMTU + EthHeaderLen + 4
)

// TAPInterface is a stub for Windows — TAP is only used on the operator (Linux/macOS).
type TAPInterface struct {
	Name string
	MTU  int
	MAC  net.HardwareAddr
}

func NewTAP(name string) (*TAPInterface, error)                       { return nil, errNotSupported }
func (t *TAPInterface) Configure(ip net.IP, mask net.IPMask) error    { return errNotSupported }
func (t *TAPInterface) Read(buf []byte) (int, error)                  { return 0, errNotSupported }
func (t *TAPInterface) Write(buf []byte) (int, error)                 { return 0, errNotSupported }
func (t *TAPInterface) Close() error                                  { return errNotSupported }
