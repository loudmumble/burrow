package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
)

type Tunnel struct {
	lhost    string
	lport    int
	rhost    string
	rport    int
	protocol string
	listener net.Listener
	running  bool
	mu       sync.Mutex
	conns    []net.Conn
}

func NewTunnel(lhost string, lport int, rhost string, rport int, protocol string) *Tunnel {
	return &Tunnel{
		lhost:    lhost,
		lport:    lport,
		rhost:    rhost,
		rport:    rport,
		protocol: protocol,
		conns:    make([]net.Conn, 0),
	}
}

func (t *Tunnel) Start() error {
	addr := fmt.Sprintf("%s:%d", t.lhost, t.lport)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	t.listener = listener
	t.running = true

	go t.accept()

	return nil
}

func (t *Tunnel) accept() {
	for t.running {
		conn, err := t.listener.Accept()
		if err != nil {
			if t.running {
				continue
			}
			break
		}

		go t.handle(conn)
	}
}

func (t *Tunnel) handle(local net.Conn) {
	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", t.rhost, t.rport))
	if err != nil {
		local.Close()
		return
	}

	t.mu.Lock()
	t.conns = append(t.conns, local, remote)
	t.mu.Unlock()

	go t.relay(local, remote)
	go t.relay(remote, local)
}

func (t *Tunnel) relay(dst io.Writer, src io.Reader) {
	io.Copy(dst, src)
}

func (t *Tunnel) Stop() {
	t.mu.Lock()
	t.running = false
	t.mu.Unlock()

	if t.listener != nil {
		t.listener.Close()
	}

	t.mu.Lock()
	for _, conn := range t.conns {
		conn.Close()
	}
	t.mu.Unlock()
}

type ReverseTunnel struct {
	lhost string
	lport int
	thost string
	tport int
	ln    net.Listener
	wg    sync.WaitGroup
}

func NewReverseTunnel(lhost string, lport int, thost string, tport int) *ReverseTunnel {
	return &ReverseTunnel{
		lhost: lhost,
		lport: lport,
		thost: thost,
		tport: tport,
	}
}

func (t *ReverseTunnel) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", t.lhost, t.lport))
	if err != nil {
		return err
	}
	t.ln = ln

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go t.handle(conn)
		}
	}()

	return nil
}

func (t *ReverseTunnel) handle(incoming net.Conn) {
	target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", t.thost, t.tport))
	if err != nil {
		incoming.Close()
		return
	}

	go func() {
		io.Copy(target, incoming)
		target.Close()
		incoming.Close()
	}()

	io.Copy(incoming, target)
	incoming.Close()
	target.Close()
}

func (t *ReverseTunnel) Stop() {
	if t.ln != nil {
		t.ln.Close()
	}
	t.wg.Wait()
}
