package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Endpoint represents one side of a bidirectional relay.
type Endpoint interface {
	Open(ctx context.Context) (io.ReadWriteCloser, error)
}

// ParseSpec parses an address specification string into an Endpoint.
//
// Supported formats:
//
//	tcp-listen:<port>              TCP listener on all interfaces
//	tcp-listen:<host>:<port>       TCP listener on specific host
//	tcp-connect:<host>:<port>      TCP client connection
//	udp-listen:<port>              UDP listener (recvfrom)
//	udp-connect:<host>:<port>      UDP client (sendto)
//	unix-listen:<path>             Unix domain socket listener
//	unix-connect:<path>            Unix domain socket client
//	exec:<command>                 Spawn process, relay stdin/stdout
//	stdio                          Relay from/to stdin/stdout
func ParseSpec(spec string) (Endpoint, error) {
	if spec == "stdio" {
		return &StdioEndpoint{}, nil
	}

	idx := strings.IndexByte(spec, ':')
	if idx < 0 {
		return nil, fmt.Errorf("invalid spec %q: missing type prefix", spec)
	}

	typ := spec[:idx]
	arg := spec[idx+1:]

	switch typ {
	case "tcp-listen":
		addr := normalizeListenAddr(arg)
		return &TCPListenEndpoint{Addr: addr}, nil

	case "tcp-connect":
		if !strings.Contains(arg, ":") {
			return nil, fmt.Errorf("tcp-connect requires host:port, got %q", arg)
		}
		return &TCPConnectEndpoint{Addr: arg}, nil

	case "udp-listen":
		addr := normalizeListenAddr(arg)
		return &UDPListenEndpoint{Addr: addr}, nil

	case "udp-connect":
		if !strings.Contains(arg, ":") {
			return nil, fmt.Errorf("udp-connect requires host:port, got %q", arg)
		}
		return &UDPConnectEndpoint{Addr: arg}, nil

	case "unix-listen":
		if arg == "" {
			return nil, fmt.Errorf("unix-listen requires a path")
		}
		return &UnixListenEndpoint{Path: arg}, nil

	case "unix-connect":
		if arg == "" {
			return nil, fmt.Errorf("unix-connect requires a path")
		}
		return &UnixConnectEndpoint{Path: arg}, nil

	case "exec":
		if arg == "" {
			return nil, fmt.Errorf("exec requires a command")
		}
		return &ExecEndpoint{Command: arg}, nil

	default:
		return nil, fmt.Errorf("unknown spec type %q", typ)
	}
}

func normalizeListenAddr(arg string) string {
	if strings.Contains(arg, ":") {
		return arg
	}
	return "0.0.0.0:" + arg
}

// BufSize is the relay buffer size (256KB). Drains a full default socket
// receive buffer in one syscall. 8x larger than Go's default 32KB io.Copy.
const BufSize = 256 * 1024

// bufPool is the shared relay buffer pool. All relay paths use this single
// pool instead of per-package duplicates.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, BufSize)
		return &b
	},
}

// writeOnly wraps an io.Writer to hide the io.ReaderFrom interface.
// This prevents io.CopyBuffer from bypassing our pooled buffer via
// TCPConn.ReadFrom → splice(2) fallback → genericReadFrom(make([]byte, 32KB)).
type writeOnly struct{ io.Writer }

// CopyBuffered copies src to dst using a pooled 256KB buffer.
// It wraps dst to prevent io.CopyBuffer from silently falling back to
// an unpooled 32KB buffer via the ReaderFrom interface.
func CopyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bp := bufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(writeOnly{dst}, src, *bp)
	bufPool.Put(bp)
	return n, err
}

// TuneConn applies TCP performance tuning to a connection:
// TCP_NODELAY (disable Nagle), 4MB socket buffers (SO_RCVBUF/SO_SNDBUF).
// Silently no-ops for non-TCP connections (yamux streams, unix sockets).
func TuneConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(4 * 1024 * 1024)
		_ = tc.SetWriteBuffer(4 * 1024 * 1024)
	}
}

// Relay performs bidirectional copy between two ReadWriteClosers.
// Returns when either direction encounters an error or EOF.
func Relay(ctx context.Context, a, b io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var once sync.Once
	var firstErr error
	setErr := func(err error) {
		once.Do(func() { firstErr = err })
	}

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		_, err := CopyBuffered(a, b)
		setErr(err)
		cancel()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		_, err := CopyBuffered(b, a)
		setErr(err)
		cancel()
	}()

	<-done
	a.Close()
	b.Close()
	<-done

	if firstErr != nil && firstErr != io.EOF {
		return firstErr
	}
	return nil
}

// --- Endpoint Implementations ---

type TCPListenEndpoint struct {
	Addr string
}

func (e *TCPListenEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", e.Addr)
	if err != nil {
		return nil, fmt.Errorf("tcp-listen %s: %w", e.Addr, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	conn, err := ln.Accept()
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("tcp-listen accept: %w", err)
	}
	ln.Close()
	return conn, nil
}

type TCPConnectEndpoint struct {
	Addr string
}

func (e *TCPConnectEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", e.Addr)
	if err != nil {
		return nil, fmt.Errorf("tcp-connect %s: %w", e.Addr, err)
	}
	return conn, nil
}

type UDPListenEndpoint struct {
	Addr string
}

func (e *UDPListenEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	laddr, err := net.ResolveUDPAddr("udp", e.Addr)
	if err != nil {
		return nil, fmt.Errorf("udp-listen resolve %s: %w", e.Addr, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("udp-listen %s: %w", e.Addr, err)
	}

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	return &udpListenConn{UDPConn: conn}, nil
}

// udpListenConn wraps a UDPConn to implement ReadWriteCloser by
// remembering the first remote address seen.
type udpListenConn struct {
	*net.UDPConn
	remote *net.UDPAddr
	mu     sync.Mutex
}

func (c *udpListenConn) Read(b []byte) (int, error) {
	n, addr, err := c.UDPConn.ReadFromUDP(b)
	if err != nil {
		return n, err
	}
	c.mu.Lock()
	if c.remote == nil {
		c.remote = addr
	}
	c.mu.Unlock()
	return n, nil
}

func (c *udpListenConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	r := c.remote
	c.mu.Unlock()
	if r == nil {
		return 0, fmt.Errorf("udp-listen: no remote address yet")
	}
	return c.UDPConn.WriteToUDP(b, r)
}

type UDPConnectEndpoint struct {
	Addr string
}

func (e *UDPConnectEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	raddr, err := net.ResolveUDPAddr("udp", e.Addr)
	if err != nil {
		return nil, fmt.Errorf("udp-connect resolve %s: %w", e.Addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("udp-connect %s: %w", e.Addr, err)
	}

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	return conn, nil
}

type UnixListenEndpoint struct {
	Path string
}

func (e *UnixListenEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	os.Remove(e.Path)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "unix", e.Path)
	if err != nil {
		return nil, fmt.Errorf("unix-listen %s: %w", e.Path, err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(e.Path)
	}()

	conn, err := ln.Accept()
	if err != nil {
		ln.Close()
		os.Remove(e.Path)
		return nil, fmt.Errorf("unix-listen accept: %w", err)
	}
	ln.Close()
	return conn, nil
}

type UnixConnectEndpoint struct {
	Path string
}

func (e *UnixConnectEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", e.Path)
	if err != nil {
		return nil, fmt.Errorf("unix-connect %s: %w", e.Path, err)
	}
	return conn, nil
}

type ExecEndpoint struct {
	Command string
}

func (e *ExecEndpoint) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", e.Command)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("exec stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("exec stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("exec start %q: %w", e.Command, err)
	}

	return &execConn{
		Reader: stdout,
		Writer: stdin,
		cmd:    cmd,
	}, nil
}

type execConn struct {
	io.Reader
	io.Writer
	cmd  *exec.Cmd
	once sync.Once
}

func (c *execConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func (c *execConn) Write(p []byte) (int, error) {
	return c.Writer.Write(p)
}

func (c *execConn) Close() error {
	var closeErr error
	c.once.Do(func() {
		if w, ok := c.Writer.(io.Closer); ok {
			w.Close()
		}
		closeErr = c.cmd.Wait()
	})
	return closeErr
}

type StdioEndpoint struct{}

func (e *StdioEndpoint) Open(_ context.Context) (io.ReadWriteCloser, error) {
	return &stdioConn{}, nil
}

type stdioConn struct{}

func (c *stdioConn) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (c *stdioConn) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (c *stdioConn) Close() error                { return nil }
