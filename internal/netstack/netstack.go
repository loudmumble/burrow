// Package netstack provides a userspace TCP/IP stack using gvisor for
// agent-side raw IP packet termination. It receives raw IP packets (from a
// yamux stream), processes them through gvisor's netstack, and creates real
// outbound TCP/UDP connections on the agent's network.
//
// This is the agent-side counterpart to the operator's TUN interface: the
// operator captures packets via TUN and forwards them over yamux; this package
// terminates those packets and dials the real destinations.
package netstack

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/relay"
	"github.com/nicocha30/gvisor-ligolo/pkg/buffer"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/adapters/gonet"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/link/channel"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv4"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/network/ipv6"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/stack"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/icmp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/tcp"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/transport/udp"
	"github.com/nicocha30/gvisor-ligolo/pkg/waiter"
	"golang.org/x/time/rate"
)

const (
	// nicID is the fixed NIC identifier for the single virtual interface.
	nicID tcpip.NICID = 1

	// channelSize is the outbound packet queue depth for the channel endpoint.
	channelSize = 2048

	// tcpDialTimeout is how long to wait when dialing a real TCP connection.
	tcpDialTimeout = 15 * time.Second

	// udpDialTimeout is how long to wait when dialing a real UDP connection.
	udpDialTimeout = 5 * time.Second

	// udpIdleTimeout is the idle timeout for UDP relay. After this duration
	// with no traffic in either direction, the relay is torn down.
	udpIdleTimeout = 30 * time.Second
)

// Stack wraps gvisor's netstack for userspace TCP/IP processing.
// It receives raw IP packets, terminates TCP/UDP connections, and
// dials real connections on the agent's network.
type Stack struct {
	ns     *stack.Stack
	ep     *channel.Endpoint
	mtu    uint32
	logger *log.Logger
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Opts configures the netstack.
type Opts struct {
	// MTU is the Maximum Transmission Unit. Default: 1500.
	MTU uint32

	// TCPBufSize is the TCP receive window size in bytes. 0 uses gvisor's default.
	TCPBufSize int

	// MaxInFlight is the maximum number of half-open TCP connections.
	// Default: 4096.
	MaxInFlight int

	// Logger is used for connection logging. Default: log.Default().
	Logger *log.Logger
}

// New creates a gvisor userspace network stack configured for packet
// termination. The stack intercepts raw IP packets injected via InjectPacket,
// completes the TCP/UDP handshake internally, and dials real outbound
// connections on the host network.
func New(opts Opts) (*Stack, error) {
	if opts.MTU == 0 {
		opts.MTU = 1500
	}
	if opts.TCPBufSize == 0 {
		opts.TCPBufSize = 4 * 1024 * 1024 // 4MB receive window for high throughput
	}
	if opts.MaxInFlight == 0 {
		opts.MaxInFlight = 4096
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}

	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	// Disable ICMP rate limiting so all ICMP messages are delivered.
	// NOTE: SetICMPLimit(0) means rate=0 which BLOCKS all ICMP.
	// rate.Inf means no limit.
	ns.SetICMPLimit(rate.Inf)
	ns.SetICMPBurst(1 << 30) // effectively unlimited burst

	// Create the channel-backed virtual NIC.
	ep := channel.New(channelSize, opts.MTU, "")
	if tcpipErr := ns.CreateNIC(nicID, ep); tcpipErr != nil {
		return nil, fmt.Errorf("netstack: create NIC: %v", tcpipErr)
	}

	// Route all traffic (any destination) through our NIC.
	ns.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// Enable promiscuous mode: accept packets addressed to any IP.
	if tcpipErr := ns.SetPromiscuousMode(nicID, true); tcpipErr != nil {
		return nil, fmt.Errorf("netstack: set promiscuous mode: %v", tcpipErr)
	}

	// Enable spoofing: allow sending packets from any source IP.
	if tcpipErr := ns.SetSpoofing(nicID, true); tcpipErr != nil {
		return nil, fmt.Errorf("netstack: set spoofing: %v", tcpipErr)
	}

	// Disable forwarding: we terminate connections, not route them.
	ns.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, false)
	ns.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, false)

	// Enable TCP SACK for better loss recovery and throughput.
	sackOpt := tcpip.TCPSACKEnabled(true)
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// Set TCP send buffer range to match receive buffer for symmetric throughput.
	// Default ~208KB is too small for RDP activation bursts (server→client).
	sndBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     65536,
		Default: 4 * 1024 * 1024,
		Max:     4 * 1024 * 1024,
	}
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBufOpt)

	// Set stack-level receive buffer range (supplements the forwarder rcvWnd).
	rcvBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     65536,
		Default: 4 * 1024 * 1024,
		Max:     4 * 1024 * 1024,
	}
	ns.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBufOpt)

	ctx, cancel := context.WithCancel(context.Background())

	s := &Stack{
		ns:     ns,
		ep:     ep,
		mtu:    opts.MTU,
		logger: opts.Logger,
		ctx:    ctx,
		cancel: cancel,
	}

	// Register TCP forwarder: intercepts SYN packets and spawns handlers.
	tcpFwd := tcp.NewForwarder(ns, opts.TCPBufSize, opts.MaxInFlight, s.handleTCP)
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// Register UDP forwarder: intercepts inbound UDP datagrams.
	udpFwd := udp.NewForwarder(ns, s.handleUDP)
	ns.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return s, nil
}

// InjectPacket injects a raw IP packet into the netstack for processing.
// The packet is parsed to determine the IP version and delivered to the
// appropriate protocol handler. Invalid or unrecognized packets are silently
// dropped. This method is safe for concurrent use.
func (s *Stack) InjectPacket(raw []byte) {
	if len(raw) == 0 {
		return
	}

	// Copy the packet data -- gvisor takes ownership of the buffer.
	cp := make([]byte, len(raw))
	copy(cp, raw)

	buf := buffer.MakeWithData(cp)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buf,
	})
	defer pkt.DecRef()

	switch header.IPVersion(raw) {
	case 4:
		s.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	case 6:
		s.ep.InjectInbound(header.IPv6ProtocolNumber, pkt)
	}
}

// ReadPacket reads an outbound packet from the netstack (the return path).
// It blocks until a packet is available or ctx is cancelled. The returned
// byte slice is a copy safe for the caller to retain.
func (s *Stack) ReadPacket(ctx context.Context) ([]byte, error) {
	pkt := s.ep.ReadContext(ctx)
	if pkt == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("netstack: endpoint closed")
	}
	defer pkt.DecRef()

	view := pkt.ToView()
	defer view.Release()

	size := view.Size()
	data := protocol.GetPacketBuf(size)
	copy(data, view.AsSlice())
	return data, nil
}

// Close shuts down the netstack, cancels pending operations, and waits for
// all relay goroutines to finish.
func (s *Stack) Close() error {
	s.cancel()
	s.ep.Close() // close channel endpoint first to unblock all gvisor reads/writes
	s.wg.Wait()  // now safe — relay goroutines will exit on endpoint close
	s.ns.Close()
	return nil
}

// handleTCP is called by the TCP forwarder for each new inbound SYN.
// It dials the real destination FIRST, then completes the gvisor handshake
// only if the dial succeeds. This ensures port scans (nmap) see only
// actually-open ports instead of every port appearing open.
func (s *Stack) handleTCP(req *tcp.ForwarderRequest) {
	if s.ctx.Err() != nil {
		req.Complete(true)
		return
	}

	id := req.ID()
	dst := net.JoinHostPort(
		id.LocalAddress.String(),
		fmt.Sprintf("%d", id.LocalPort),
	)

	// Dial the real destination BEFORE completing the gvisor handshake.
	// Closed ports get an immediate RST with zero gvisor resource allocation.
	// This prevents nmap from seeing all 65535 ports as open and eliminates
	// thousands of wasted goroutines + endpoint allocations during scans.
	dialer := net.Dialer{Timeout: tcpDialTimeout}
	remote, err := dialer.DialContext(s.ctx, "tcp", dst)
	if err != nil {
		req.Complete(true) // RST — port not reachable
		return
	}
	relay.TuneConn(remote)

	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		req.Complete(true)
		remote.Close()
		s.logger.Printf("netstack: tcp: endpoint for %s: %v", dst, tcpipErr)
		return
	}
	req.Complete(false)
	// Disable Nagle's algorithm on the gvisor endpoint. Critical for relay:
	// Nagle + delayed ACKs across the tunnel causes sub-MSS segments to stall
	// ~200ms each, killing RDP activation (50KB = ~34 segments × 200ms > 16s timeout).
	// relay.TuneConn only handles *net.TCPConn; this is a gonet.TCPConn.
	ep.SocketOptions().SetDelayOption(false)

	netstackConn := gonet.NewTCPConn(&wq, ep)

	s.logger.Printf("netstack: tcp: %s:%d -> %s",
		id.RemoteAddress, id.RemotePort, dst)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		relayTCP(netstackConn, remote)
	}()
}

// handleUDP is called by the UDP forwarder for each new inbound UDP flow.
// It creates a connected UDP endpoint via gvisor, dials the real destination,
// and relays datagrams bidirectionally with an idle timeout.
func (s *Stack) handleUDP(req *udp.ForwarderRequest) {
	if s.ctx.Err() != nil {
		return
	}

	id := req.ID()
	dst := net.JoinHostPort(
		id.LocalAddress.String(),
		fmt.Sprintf("%d", id.LocalPort),
	)

	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		s.logger.Printf("netstack: udp: endpoint for %s: %v", dst, tcpipErr)
		return
	}

	netstackConn := gonet.NewUDPConn(s.ns, &wq, ep)

	dialer := net.Dialer{Timeout: udpDialTimeout}
	remote, err := dialer.DialContext(s.ctx, "udp", dst)
	if err != nil {
		netstackConn.Close()
		s.logger.Printf("netstack: udp: dial %s: %v", dst, err)
		return
	}

	s.logger.Printf("netstack: udp: %s:%d -> %s",
		id.RemoteAddress, id.RemotePort, dst)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		relayUDP(netstackConn, remote, udpIdleTimeout)
	}()
}

// relayTCP copies data bidirectionally between two connections. Both connections
// are closed when relay returns. Uses centralized 256KB pooled buffers with
// writeOnly wrapper to prevent ReaderFrom bypass.
func relayTCP(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{})
	go func() {
		relay.CopyBuffered(b, a)
		// Signal the other direction to unblock by closing a's read side.
		a.Close()
		close(done)
	}()
	relay.CopyBuffered(a, b)
	// Signal the goroutine to unblock by closing b's read side.
	b.Close()
	<-done
}

// relayUDP copies datagrams bidirectionally between two connections with an
// idle timeout. Both connections are closed when relay returns.
func relayUDP(a, b net.Conn, idleTimeout time.Duration) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{})

	// a -> b
	go func() {
		buf := make([]byte, 65535)
		a.SetReadDeadline(time.Now().Add(idleTimeout))
		for {
			n, err := a.Read(buf)
			if err != nil {
				break
			}
			a.SetReadDeadline(time.Now().Add(idleTimeout))
			b.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := b.Write(buf[:n]); err != nil {
				break
			}
		}
		close(done)
	}()

	// b -> a
	buf := make([]byte, 65535)
	b.SetReadDeadline(time.Now().Add(idleTimeout))
	for {
		n, err := b.Read(buf)
		if err != nil {
			break
		}
		b.SetReadDeadline(time.Now().Add(idleTimeout))
		a.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.Write(buf[:n]); err != nil {
			break
		}
	}
	<-done
}
