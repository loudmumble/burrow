package mesh

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestNodeListenConnect(t *testing.T) {
	nodeA := NewNode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	nodeB := NewNode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	defer nodeA.Close()
	defer nodeB.Close()

	// A listens.
	if err := nodeA.Listen("127.0.0.1:0", nil); err != nil {
		t.Fatal(err)
	}
	addr := nodeA.ListenAddr()
	if addr == "" {
		t.Fatal("listen addr empty")
	}

	// B connects to A.
	var peerSeen atomic.Bool
	nodeA.OnPeer(func(p *Peer) { peerSeen.Store(true) })

	peer, err := nodeB.Connect(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if peer == nil {
		t.Fatal("peer nil")
	}

	// Wait for A to accept.
	time.Sleep(200 * time.Millisecond)

	if !peerSeen.Load() {
		t.Error("OnPeer callback not called")
	}
	if nodeA.PeerCount() != 1 {
		t.Errorf("A peers = %d, want 1", nodeA.PeerCount())
	}
	if nodeB.PeerCount() != 1 {
		t.Errorf("B peers = %d, want 1", nodeB.PeerCount())
	}
}

func TestNodeRemovePeer(t *testing.T) {
	node := NewNode("cccccccccccccccccccccccccccccccc")
	defer node.Close()

	node.RemovePeer("nonexistent") // no panic
	if node.PeerCount() != 0 {
		t.Error("count should be 0")
	}
}

func TestNodeClose(t *testing.T) {
	node := NewNode("dddddddddddddddddddddddddddddd")
	node.Listen("127.0.0.1:0", nil)
	if node.ListenAddr() == "" {
		t.Fatal("should be listening")
	}
	node.Close()
	if node.ListenAddr() != "" {
		t.Error("should not be listening after close")
	}
}
