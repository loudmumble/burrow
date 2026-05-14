//go:build !windows

package tun

import (
	"fmt"
	"os"
	"net"
	"strconv"

	"github.com/songgao/water"
)

const (
	// DefaultTAPName is the default TAP interface name.
	DefaultTAPName = "burrow-tap0"

	// DefaultTAPMTU is the default MTU for the TAP interface.
	DefaultTAPMTU = 1500

	// EthHeaderLen is the Ethernet header length (dst MAC + src MAC + EtherType).
	EthHeaderLen = 14

	// MaxFrameSize is the maximum Ethernet frame size (MTU + header).
	MaxFrameSize = DefaultTAPMTU + EthHeaderLen + 4 // +4 for possible VLAN tag
)

// TAPInterface wraps a water.Interface to provide a TAP device for
// Layer 2 Ethernet frame I/O. Used on the operator side to receive
// broadcast/multicast traffic from the target network.
type TAPInterface struct {
	Name string
	MTU  int
	MAC  net.HardwareAddr // interface MAC — used as dst in response frames
	ifce *water.Interface
}

// NewTAP creates a new TAP interface. If name is empty, DefaultTAPName is used.
// Requires root or CAP_NET_ADMIN.
func NewTAP(name string) (*TAPInterface, error) {
	if name == "" {
		name = DefaultTAPName
	}

	// Clean up stale interface from previous crash.
	_ = runIP("link", "delete", name)

	cfg := water.Config{
		DeviceType: water.TAP,
	}
	cfg.Name = name

	ifce, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("tap: create %q: %w", name, err)
	}

	tap := &TAPInterface{
		Name: ifce.Name(),
		MTU:  DefaultTAPMTU,
		ifce: ifce,
	}

	// Read the interface's MAC for use as dst in response frames.
	if iface, err := net.InterfaceByName(tap.Name); err == nil {
		tap.MAC = iface.HardwareAddr
	}

	return tap, nil
}

// Configure sets up the TAP interface. If ip is non-nil, assigns the address.
// Always sets MTU and brings the interface up.
func (t *TAPInterface) Configure(ip net.IP, mask net.IPMask) error {
	// Set MTU.
	if err := runIP("link", "set", t.Name, "mtu", strconv.Itoa(t.MTU)); err != nil {
		return fmt.Errorf("tap: set MTU: %w", err)
	}

	// Disable ARP before bringing up — netstack handles IP, not Ethernet.
	if err := runIP("link", "set", t.Name, "arp", "off"); err != nil {
		return fmt.Errorf("tap: disable arp: %w", err)
	}

	// Bring up BEFORE assigning IP/routes — some kernels reject config on down interfaces.
	if err := runIP("link", "set", t.Name, "up"); err != nil {
		return fmt.Errorf("tap: bring up: %w", err)
	}

	// Assign IP and add route.
	if ip != nil && mask != nil {
		prefix, _ := mask.Size()
		cidr := ip.String() + "/" + strconv.Itoa(prefix)
		if err := runIP("addr", "add", cidr, "dev", t.Name); err != nil {
			return fmt.Errorf("tap: add address %s: %w", cidr, err)
		}
		// Explicit subnet route as safety — ip addr add should create a connected
		// route, but verify it exists.
		subnet := net.IP(make([]byte, 4))
		for i := range subnet {
			subnet[i] = ip[i] & mask[i]
		}
		subnetCIDR := subnet.String() + "/" + strconv.Itoa(prefix)
		if err := runIP("route", "replace", subnetCIDR, "dev", t.Name); err != nil {
			fmt.Fprintf(os.Stderr, "[!] TAP route %s: %v\n", subnetCIDR, err)
		}
	}

	return nil
}

// Read reads a single Ethernet frame from the TAP interface.
func (t *TAPInterface) Read(buf []byte) (int, error) {
	return t.ifce.Read(buf)
}

// Write writes an Ethernet frame to the TAP interface.
func (t *TAPInterface) Write(buf []byte) (int, error) {
	return t.ifce.Write(buf)
}

// Close tears down the TAP interface.
func (t *TAPInterface) Close() error {
	return t.ifce.Close()
}
