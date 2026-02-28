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

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/netstack"
	"github.com/loudmumble/burrow/internal/protocol"
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
tunnel and route commands. TLS is enabled by default.

Examples:
  burrow agent --connect 10.0.0.1:11601
  burrow agent -c 10.0.0.1:11601 --fingerprint AB:CD:EF:...
  burrow agent --connect wss://10.0.0.1:443 --transport ws
  burrow agent --connect 10.0.0.1:5353 --transport dns
  burrow agent --connect 10.0.0.1 --transport icmp
  burrow agent -c 10.0.0.1:11601 --max-retries 5`,
	Run: runAgent,
}

func init() {
	rootCmd.AddCommand(agentCmd)

	agentCmd.Flags().StringP("connect", "c", "", "Server address to connect to (required)")
	agentCmd.Flags().String("fingerprint", "", "Expected server TLS fingerprint for verification")
	agentCmd.Flags().Int("max-retries", 0, "Max reconnection attempts (0 = infinite)")
	agentCmd.Flags().StringP("transport", "t", "raw", "Transport protocol (raw, ws, dns, icmp, http)")
	agentCmd.Flags().Bool("no-tls", false, "Connect without TLS")
	agentCmd.MarkFlagRequired("connect")
}

func runAgent(cmd *cobra.Command, _ []string) {
	serverAddr, _ := cmd.Flags().GetString("connect")
	fingerprint, _ := cmd.Flags().GetString("fingerprint")
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

	expected := fingerprint
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
			if actual != expected {
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

	return commandLoop(ctx, ctrl, sess)
}

func commandLoop(ctx context.Context, ctrl net.Conn, sess *mux.Session) error {
	activeTunnels := make(map[string]*tunnel.Tunnel)
	activeListeners := make(map[string]net.Listener)
	activeRoutes := make(map[string]string)

	var tunNS *netstack.Stack
	var tunStream net.Conn
	var tunCancel context.CancelFunc

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

	msgCh := make(chan *protocol.Message, 4)
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
				if err := protocol.WriteMessage(ctrl, protocol.NewPong()); err != nil {
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
					ackMsg, _ := protocol.EncodeTunnelAck(ackPayload)
					protocol.WriteMessage(ctrl, ackMsg)

				case "remote", "reverse":
					// Remote tunnel: agent listens, forwards connections through yamux back to server
					ln, listenErr := net.Listen(req.Protocol, req.ListenAddr)
					ackPayload := &protocol.TunnelAckPayload{ID: req.ID}
					if listenErr != nil {
						ackPayload.Error = listenErr.Error()
					} else {
						ackPayload.BoundAddr = ln.Addr().String()
						activeListeners[req.ID] = ln
						go remoteTunnelAcceptLoop(ctx, ln, sess, req.RemoteAddr)
					}
					ackMsg, _ := protocol.EncodeTunnelAck(ackPayload)
					protocol.WriteMessage(ctrl, ackMsg)

				default:
					ackPayload := &protocol.TunnelAckPayload{
						ID:    req.ID,
						Error: fmt.Sprintf("unknown direction: %s", req.Direction),
					}
					ackMsg, _ := protocol.EncodeTunnelAck(ackPayload)
					protocol.WriteMessage(ctrl, ackMsg)
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
				ackMsg, _ := protocol.EncodeListenerAck(ackPayload)
				protocol.WriteMessage(ctrl, ackMsg)

			case protocol.MsgTunStart:
				fmt.Println("[*] TUN start requested by server")
				ns, nsErr := netstack.New(netstack.Opts{})
				ackPayload := &protocol.TunStartAckPayload{}
				if nsErr != nil {
					ackPayload.Error = nsErr.Error()
				}
				ackMsg, _ := protocol.EncodeTunStartAck(ackPayload)
				protocol.WriteMessage(ctrl, ackMsg)
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
				dataStream.Write([]byte{0x01}) // Stream type: TUN data
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
				if tunNS != nil {
					tunNS.Close()
					tunNS = nil
				}
				fmt.Println("[*] TUN mode stopped")

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
			remote, err := net.DialTimeout("tcp", forwardAddr, 10*time.Second)
			if err != nil {
				return
			}
			defer remote.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(remote, c); done <- struct{}{} }()
			go func() { io.Copy(c, remote); done <- struct{}{} }()
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
			return
		}
	}
}

func remoteTunnelAcceptLoop(ctx context.Context, ln net.Listener, sess *mux.Session, remoteAddr string) {
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
	go func() { io.Copy(stream, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, stream); done <- struct{}{} }()
	<-done
}
