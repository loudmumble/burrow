//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// Ethernet protocol numbers for AF_PACKET.
const (
	ethPAll  = 0x0003 // Capture all protocols
	ethPIP   = 0x0800 // IPv4
	ethPARP  = 0x0806 // ARP
	ethPIPv6 = 0x86DD // IPv6
)

// RawSocket captures and injects Ethernet frames on a network interface
// using AF_PACKET. Used on the agent side for TAP mode.
type RawSocket struct {
	fd        int
	ifIndex   int
	ifName    string
	filterIP  net.IP // tunnel endpoint IPv4 — frames to/from this IP are filtered out
	filterIP6 net.IP // tunnel endpoint IPv6 (16-byte form)
}

// NewRawSocket opens an AF_PACKET raw socket on the named interface.
// filterIP is the tunnel server IP — any IPv4 frame with this src or dst
// is silently dropped to prevent forwarding tunnel traffic back through itself.
// Requires root or CAP_NET_RAW.
func NewRawSocket(ifName string, filterIP net.IP) (*RawSocket, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("rawsock: socket: %w", err)
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("rawsock: interface %q: %w", ifName, err)
	}

	// Bind to the specific interface.
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("rawsock: bind to %s: %w", ifName, err)
	}

	// Enable promiscuous mode to see all L2 traffic.
	if err := setPromiscuous(fd, iface.Index); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("rawsock: promiscuous on %s: %w", ifName, err)
	}

	return &RawSocket{
		fd:        fd,
		ifIndex:   iface.Index,
		ifName:    ifName,
		filterIP:  filterIP.To4(),
		filterIP6: filterIP.To16(),
	}, nil
}

// Read reads the next Ethernet frame, skipping tunnel traffic.
func (r *RawSocket) Read(buf []byte) (int, error) {
	for {
		n, _, err := syscall.Recvfrom(r.fd, buf, 0)
		if err != nil {
			return 0, fmt.Errorf("rawsock: read: %w", err)
		}
		if n == 0 {
			continue
		}
		if r.isTunnelTraffic(buf[:n]) {
			continue
		}
		return n, nil
	}
}

// Write injects an Ethernet frame onto the network.
func (r *RawSocket) Write(buf []byte) (int, error) {
	addr := &syscall.SockaddrLinklayer{
		Ifindex:  r.ifIndex,
		Protocol: htons(ethPAll),
	}
	if len(buf) >= 6 {
		addr.Halen = 6
		copy(addr.Addr[:6], buf[0:6]) // destination MAC from frame
	}
	if err := syscall.Sendto(r.fd, buf, 0, addr); err != nil {
		return 0, fmt.Errorf("rawsock: write: %w", err)
	}
	return len(buf), nil
}

// Close closes the raw socket.
func (r *RawSocket) Close() error {
	return syscall.Close(r.fd)
}

// isTunnelTraffic returns true if the frame is IP traffic to/from the
// tunnel endpoint, which must not be forwarded to prevent loops.
func (r *RawSocket) isTunnelTraffic(frame []byte) bool {
	if len(frame) < EthHeaderLen+20 {
		return false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	ip := frame[EthHeaderLen:]

	switch etherType {
	case ethPIP:
		if r.filterIP == nil || len(ip) < 20 {
			return false
		}
		srcIP := net.IP(ip[12:16])
		dstIP := net.IP(ip[16:20])
		return srcIP.Equal(r.filterIP) || dstIP.Equal(r.filterIP)
	case ethPIPv6:
		if r.filterIP6 == nil || len(ip) < 40 {
			return false
		}
		srcIP := net.IP(ip[8:24])
		dstIP := net.IP(ip[24:40])
		return srcIP.Equal(r.filterIP6) || dstIP.Equal(r.filterIP6)
	default:
		return false // ARP, etc. — always forward
	}
}

// DefaultInterface returns the name of the interface with a default route.
func DefaultInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		// Return the first non-loopback, up interface with addresses.
		return iface.Name, nil
	}
	return "", fmt.Errorf("no suitable network interface found")
}

// packetMreq matches struct packet_mreq for PACKET_ADD_MEMBERSHIP.
type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	address [8]byte
}

func setPromiscuous(fd int, ifIndex int) error {
	mreq := packetMreq{
		ifindex: int32(ifIndex),
		typ:     syscall.PACKET_MR_PROMISC,
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_PACKET),
		uintptr(syscall.PACKET_ADD_MEMBERSHIP),
		uintptr(unsafe.Pointer(&mreq)),
		unsafe.Sizeof(mreq),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return *(*uint16)(unsafe.Pointer(&buf[0]))
}
