// Package mesh provides agent-to-agent peer networking for resilient
// pivoting. Agents can listen for peer connections and relay traffic
// through each other, maintaining connectivity if the server drops.
//
// Mesh topology:
//
//	Server ← Agent A ← Agent B (peer)
//	                  ← Agent C (peer)
//
// If the server drops, B and C maintain their peer connections to A.
// When A reconnects to the server, B and C's traffic flows again.
package mesh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Peer represents a connected mesh peer.
type Peer struct {
	ID       string
	Addr     string
	Conn     net.Conn
	Inbound  bool // true if peer connected to us
	JoinedAt time.Time
}

// Node is a mesh participant that can accept and initiate peer connections.
type Node struct {
	id       string
	listener net.Listener
	peers    map[string]*Peer
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	onPeer   func(*Peer) // callback when a new peer connects
}

// NewNode creates a mesh node with the given ID.
func NewNode(id string) *Node {
	ctx, cancel := context.WithCancel(context.Background())
	return &Node{
		id:     id,
		peers:  make(map[string]*Peer),
		ctx:    ctx,
		cancel: cancel,
	}
}

// ID returns the node's identifier.
func (n *Node) ID() string { return n.id }

// OnPeer registers a callback for new peer connections.
func (n *Node) OnPeer(fn func(*Peer)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onPeer = fn
}

// Listen starts accepting peer connections on the given address.
func (n *Node) Listen(addr string, tlsCfg *tls.Config) error {
	var ln net.Listener
	var err error
	network := "tcp"
	if !strings.Contains(addr, "[") {
		network = "tcp4"
	}
	if tlsCfg != nil {
		ln, err = tls.Listen(network, addr, tlsCfg)
	} else {
		ln, err = net.Listen(network, addr)
	}
	if err != nil {
		return fmt.Errorf("mesh listen: %w", err)
	}
	n.mu.Lock()
	n.listener = ln
	n.mu.Unlock()

	go n.acceptLoop(ln)
	return nil
}

// ListenAddr returns the listener address, or empty if not listening.
func (n *Node) ListenAddr() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.listener != nil {
		return n.listener.Addr().String()
	}
	return ""
}

func (n *Node) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			default:
				continue
			}
		}
		go n.handleInbound(conn)
	}
}

func (n *Node) handleInbound(conn net.Conn) {
	// Read peer ID (first 32 bytes as hex string).
	idBuf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(idBuf); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	peerID := string(idBuf)

	// Send our ID back.
	conn.Write([]byte(fmt.Sprintf("%-32s", n.id)))

	peer := &Peer{
		ID:       peerID,
		Addr:     conn.RemoteAddr().String(),
		Conn:     conn,
		Inbound:  true,
		JoinedAt: time.Now(),
	}
	n.mu.Lock()
	n.peers[peerID] = peer
	cb := n.onPeer
	n.mu.Unlock()

	if cb != nil {
		cb(peer)
	}
}

// Connect initiates a peer connection to another agent.
func (n *Node) Connect(addr string, tlsCfg *tls.Config) (*Peer, error) {
	var conn net.Conn
	var err error
	network := "tcp"
	if !strings.Contains(addr, "[") {
		network = "tcp4"
	}
	if tlsCfg != nil {
		conn, err = tls.Dial(network, addr, tlsCfg)
	} else {
		d := net.Dialer{Timeout: 10 * time.Second}
		conn, err = d.DialContext(n.ctx, network, addr)
	}
	if err != nil {
		return nil, fmt.Errorf("mesh connect: %w", err)
	}

	// Send our ID.
	conn.Write([]byte(fmt.Sprintf("%-32s", n.id)))

	// Read peer ID.
	idBuf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(idBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("mesh handshake: %w", err)
	}
	conn.SetReadDeadline(time.Time{})
	peerID := string(idBuf)

	peer := &Peer{
		ID:       peerID,
		Addr:     addr,
		Conn:     conn,
		Inbound:  false,
		JoinedAt: time.Now(),
	}
	n.mu.Lock()
	n.peers[peerID] = peer
	n.mu.Unlock()
	return peer, nil
}

// Peers returns all connected peers.
func (n *Node) Peers() []*Peer {
	n.mu.RLock()
	defer n.mu.RUnlock()
	result := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		result = append(result, p)
	}
	return result
}

// RemovePeer disconnects and removes a peer.
func (n *Node) RemovePeer(id string) {
	n.mu.Lock()
	p, ok := n.peers[id]
	if ok {
		delete(n.peers, id)
	}
	n.mu.Unlock()
	if ok && p.Conn != nil {
		p.Conn.Close()
	}
}

// PeerCount returns the number of connected peers.
func (n *Node) PeerCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.peers)
}

// Close shuts down the mesh node: stops listener and disconnects all peers.
func (n *Node) Close() error {
	n.cancel()
	n.mu.Lock()
	if n.listener != nil {
		n.listener.Close()
		n.listener = nil
	}
	for id, p := range n.peers {
		p.Conn.Close()
		delete(n.peers, id)
	}
	n.mu.Unlock()
	return nil
}
