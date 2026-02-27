//go:build !windows

// Package tun provides a TUN virtual network interface with magic IP (240.0.0.0/4)
// routing for transparent network pivoting, following the ligolo-ng model.
//
// The operator creates a TUN interface on their machine, assigns it a "magic IP"
// from the 240.0.0.0/4 reserved range, and adds routes for target networks.
// Any packet sent to those networks arrives at the TUN interface, gets read by
// Burrow, forwarded through the agent's yamux session, and delivered on the
// target network. This allows nmap, curl, ssh, etc. to work transparently
// without SOCKS proxy configuration.
package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

const (
	// DefaultName is the default TUN interface name.
	DefaultName = "burrow0"

	// DefaultMTU is the default Maximum Transmission Unit for the TUN interface.
	DefaultMTU = 1500

	// magicIPBase is the base address for the 240.0.0.0/4 reserved range.
	// Each session gets a unique IP: 240.0.0.{sessionIndex+1}.
	magicIPBase byte = 240
)

// Interface wraps a water.Interface to provide a TUN device with
// configuration helpers for IP assignment and routing.
type Interface struct {
	// Name is the OS-visible interface name (e.g., "burrow0").
	Name string

	// MTU is the Maximum Transmission Unit for the interface.
	MTU int

	ifce *water.Interface
}

// New creates a new TUN interface. If name is empty, DefaultName ("burrow0") is used.
// The interface is created but not yet configured — call Configure() to assign an IP
// and bring it up.
//
// Requires root or CAP_NET_ADMIN capability.
func New(name string) (*Interface, error) {
	if name == "" {
		name = DefaultName
	}

	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = name

	ifce, err := water.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("tun: failed to create interface %q: %w", name, err)
	}

	return &Interface{
		Name: ifce.Name(),
		MTU:  DefaultMTU,
		ifce: ifce,
	}, nil
}

// Configure assigns an IP address to the interface, sets the MTU, and brings it up.
// The mask determines the prefix length (e.g., /32 for a point-to-point magic IP).
//
// Equivalent to:
//
//	ip addr add {ip}/{prefix} dev {name}
//	ip link set {name} mtu {mtu}
//	ip link set {name} up
func (i *Interface) Configure(ip net.IP, mask net.IPMask) error {
	prefix, _ := mask.Size()
	cidr := ip.String() + "/" + strconv.Itoa(prefix)

	// Assign IP address.
	if err := runIP("addr", "add", cidr, "dev", i.Name); err != nil {
		return fmt.Errorf("tun: failed to add address %s to %s: %w", cidr, i.Name, err)
	}

	// Set MTU.
	if err := runIP("link", "set", i.Name, "mtu", strconv.Itoa(i.MTU)); err != nil {
		return fmt.Errorf("tun: failed to set MTU %d on %s: %w", i.MTU, i.Name, err)
	}

	// Bring interface up.
	if err := runIP("link", "set", i.Name, "up"); err != nil {
		return fmt.Errorf("tun: failed to bring up %s: %w", i.Name, err)
	}

	return nil
}

// AddRoute adds a route for the given CIDR through this TUN interface.
// For example, AddRoute("10.0.0.0/24") makes all traffic to 10.0.0.0/24
// flow through this interface, where Burrow can read and forward it.
//
// Equivalent to: ip route add {cidr} dev {name}
func (i *Interface) AddRoute(cidr string) error {
	if err := runIP("route", "add", cidr, "dev", i.Name); err != nil {
		return fmt.Errorf("tun: failed to add route %s via %s: %w", cidr, i.Name, err)
	}
	return nil
}

// RemoveRoute removes a previously added route for the given CIDR.
//
// Equivalent to: ip route del {cidr} dev {name}
func (i *Interface) RemoveRoute(cidr string) error {
	if err := runIP("route", "del", cidr, "dev", i.Name); err != nil {
		return fmt.Errorf("tun: failed to remove route %s from %s: %w", cidr, i.Name, err)
	}
	return nil
}

// Read reads a single raw IP packet from the TUN interface into buf.
// Returns the number of bytes read. The caller is responsible for
// providing a buffer large enough for the MTU (typically 1500 bytes).
func (i *Interface) Read(buf []byte) (int, error) {
	return i.ifce.Read(buf)
}

// Write writes a raw IP packet to the TUN interface.
// The packet will appear as if it arrived from the network,
// allowing the OS to deliver it to the appropriate application.
func (i *Interface) Write(buf []byte) (int, error) {
	return i.ifce.Write(buf)
}

// Close tears down the TUN interface and releases resources.
func (i *Interface) Close() error {
	return i.ifce.Close()
}

// DefaultMagicIP returns the default magic IP (240.0.0.1) with a /32 mask.
// This is used when only a single session is active.
func DefaultMagicIP() (net.IP, net.IPMask) {
	return net.IPv4(magicIPBase, 0, 0, 1), net.CIDRMask(32, 32)
}

// NextMagicIP returns a unique magic IP for the given session index.
// Session 0 gets 240.0.0.1, session 1 gets 240.0.0.2, etc.
// Each session gets its own magic IP for routing isolation — routes for
// different target networks can be pointed at different sessions.
func NextMagicIP(sessionIndex int) (net.IP, net.IPMask) {
	return net.IPv4(magicIPBase, 0, 0, byte(sessionIndex+1)), net.CIDRMask(32, 32)
}

// runIP executes "ip" with the given arguments. Factored out to keep
// command execution in one place.
func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}
