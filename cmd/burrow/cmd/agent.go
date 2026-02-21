package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/transport"
	_ "github.com/loudmumble/burrow/internal/transport/dns"
	_ "github.com/loudmumble/burrow/internal/transport/icmp"
	_ "github.com/loudmumble/burrow/internal/transport/raw"
	_ "github.com/loudmumble/burrow/internal/transport/ws"
	"github.com/spf13/cobra"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Connect back to a Burrow proxy server",
	Long: `Start the Burrow agent that connects back to a proxy server.

The agent establishes a multiplexed connection to the server and waits for
tunnel and route commands. TLS is enabled by default.

Examples:
  burrow agent --server 10.0.0.1:11601
  burrow agent --server 10.0.0.1:11601 --fingerprint AB:CD:EF:...
  burrow agent --server wss://10.0.0.1:443 --transport ws
  burrow agent --server 10.0.0.1:5353 --transport dns
  burrow agent --server 10.0.0.1 --transport icmp
  burrow agent --server 10.0.0.1:11601 --retry 5`,
	Run: runAgent,
}

func init() {
	rootCmd.AddCommand(agentCmd)

	agentCmd.Flags().StringP("server", "s", "", "Proxy server address (required)")
	agentCmd.Flags().String("fingerprint", "", "Expected server TLS fingerprint for verification")
	agentCmd.Flags().Int("retry", 0, "Max reconnection attempts (0 = infinite)")
	agentCmd.Flags().StringP("transport", "t", "raw", "Transport protocol (raw, ws, dns, icmp)")
	agentCmd.Flags().Bool("no-tls", false, "Connect without TLS")
	agentCmd.MarkFlagRequired("server")
}

func runAgent(cmd *cobra.Command, _ []string) {
	serverAddr, _ := cmd.Flags().GetString("server")
	fingerprint, _ := cmd.Flags().GetString("fingerprint")
	maxRetry, _ := cmd.Flags().GetInt("retry")
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

// buildClientTLSConfig returns a client TLS config. When a fingerprint is
// provided the cert chain is not validated by the CA — instead the peer's
// SHA-256 fingerprint is checked directly. No client certificate is sent
// because the server does not request mutual TLS.
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

				ackPayload := &protocol.TunnelAckPayload{
					ID:    req.ID,
					Error: "not yet implemented",
				}
				ackMsg, _ := protocol.EncodeTunnelAck(ackPayload)
				protocol.WriteMessage(ctrl, ackMsg)

			case protocol.MsgRouteAdd:
				route, err := protocol.DecodeRouteAdd(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad route add: %v\n", err)
					continue
				}
				fmt.Printf("[*] Route add: %s via %s (not yet implemented)\n", route.CIDR, route.Gateway)

			case protocol.MsgRouteRemove:
				route, err := protocol.DecodeRouteRemove(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad route remove: %v\n", err)
					continue
				}
				fmt.Printf("[*] Route remove: %s (not yet implemented)\n", route.CIDR)

			case protocol.MsgTunnelClose:
				tunnelID, _ := protocol.DecodeTunnelClose(msg)
				fmt.Printf("[*] Tunnel close: %s (not yet implemented)\n", tunnelID)

			case protocol.MsgListenerRequest:
				req, err := protocol.DecodeListenerRequest(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad listener request: %v\n", err)
					continue
				}
				fmt.Printf("[*] Listener request: %s -> %s (not yet implemented)\n",
					req.ListenAddr, req.ForwardAddr)

			case protocol.MsgError:
				errStr, _ := protocol.DecodeError(msg)
				return fmt.Errorf("server error: %s", errStr)

			default:
				fmt.Fprintf(os.Stderr, "[!] Unknown message type: %s\n", msg.Type)
			}
		}
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
