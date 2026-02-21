package cmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/session"
	"github.com/loudmumble/burrow/internal/transport"
	_ "github.com/loudmumble/burrow/internal/transport/dns"
	_ "github.com/loudmumble/burrow/internal/transport/icmp"
	_ "github.com/loudmumble/burrow/internal/transport/raw"
	_ "github.com/loudmumble/burrow/internal/transport/ws"
	"github.com/loudmumble/burrow/internal/web"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the proxy server for agent connections",
	Long: `Start the Burrow proxy server that listens for incoming agent connections.

Agents connect back to this server to establish multiplexed tunnels. TLS is
enabled by default with auto-generated self-signed certificates.

Examples:
  burrow server
  burrow server --listen 0.0.0.0:11601
  burrow server --cert server.pem --key server-key.pem
  burrow server --webui --webui-addr 127.0.0.1:8080
  burrow server --transport ws --listen 0.0.0.0:443
  burrow server --transport dns --listen 0.0.0.0:5353`,
	Run: runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringP("listen", "l", "0.0.0.0:11601", "Listen address for agent connections")
	serverCmd.Flags().String("cert", "", "Path to TLS certificate PEM file")
	serverCmd.Flags().String("key", "", "Path to TLS private key PEM file")
	serverCmd.Flags().Bool("webui", false, "Enable WebUI dashboard")
	serverCmd.Flags().String("webui-addr", "127.0.0.1:8080", "WebUI listen address")
	serverCmd.Flags().Bool("no-tls", false, "Disable TLS (use plain TCP)")
	serverCmd.Flags().StringP("transport", "t", "raw", "Transport protocol (raw, ws, dns, icmp)")
}

func runServer(cmd *cobra.Command, _ []string) {
	listen, _ := cmd.Flags().GetString("listen")
	certPath, _ := cmd.Flags().GetString("cert")
	keyPath, _ := cmd.Flags().GetString("key")
	enableWebUI, _ := cmd.Flags().GetBool("webui")
	webuiAddr, _ := cmd.Flags().GetString("webui-addr")
	noTLS, _ := cmd.Flags().GetBool("no-tls")
	transportName, _ := cmd.Flags().GetString("transport")

	var tlsCfg *tls.Config
	var tlsCert tls.Certificate

	if !noTLS {
		var err error
		if certPath != "" && keyPath != "" {
			tlsCert, err = certgen.LoadPEM(certPath, keyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to load TLS cert: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[*] Loaded TLS certificate from %s\n", certPath)
		} else {
			tlsCert, err = certgen.GenerateSelfSigned("Burrow", 365*24*time.Hour)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to generate TLS cert: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[*] Generated self-signed TLS certificate")
		}

		fingerprint, err := certgen.FingerprintFromTLSCert(tlsCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to compute fingerprint: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Fingerprint: %s\n", fingerprint)

		tlsCfg = certgen.TLSConfig(tlsCert, "")
	}

	mgr := session.NewManager()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newTransport, ok := transport.Registry[transportName]
	if !ok {
		fmt.Fprintf(os.Stderr, "[!] Unknown transport: %s\n", transportName)
		os.Exit(1)
	}

	t := newTransport()
	if err := t.Listen(ctx, listen, tlsCfg); err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s transport listen error: %v\n", t.Name(), err)
		os.Exit(1)
	}
	defer t.Close()

	fmt.Printf("[*] Burrow server listening on %s (%s)\n", listen, t.Name())

	go func() {
		for {
			conn, err := t.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				return
			}
			go handleAgentConn(conn, mgr)
		}
	}()

	if enableWebUI {
		events := web.NewEventBus()
		webSrv := web.NewServer(webuiAddr, mgr, events)
		go func() {
			if err := webSrv.Start(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "[!] WebUI error: %v\n", err)
			}
		}()
		defer webSrv.Stop()
		fmt.Printf("[*] WebUI at http://%s\n", webuiAddr)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[*] Shutting down...")
	cancel()
}

func handleAgentConn(conn net.Conn, mgr *session.Manager) {
	defer conn.Close()

	fmt.Printf("[*] New agent connection from %s\n", conn.RemoteAddr())

	sess, err := mux.NewServerSession(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Mux session error from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	defer sess.Close()
	ctrl, err := sess.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Accept control stream from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	defer ctrl.Close()
	msg, err := protocol.ReadMessage(ctrl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Read handshake from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	handshake, err := protocol.DecodeHandshake(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Decode handshake from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	sessionID := newSessionID()
	info := &session.Info{
		ID:        sessionID,
		Hostname:  handshake.Hostname,
		OS:        handshake.OS,
		IPs:       handshake.IPs,
		PID:       handshake.PID,
		Remote:    conn.RemoteAddr().String(),
		CreatedAt: time.Now(),
		Active:    true,
	}
	mgr.Add(info)
	defer mgr.Remove(sessionID)
	ackPayload := &protocol.HandshakeAckPayload{
		SessionID:    sessionID,
		ProxyVersion: version,
	}
	ackMsg, err := protocol.EncodeHandshakeAck(ackPayload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Encode handshake ack: %v\n", err)
		return
	}
	if err := protocol.WriteMessage(ctrl, ackMsg); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Send handshake ack to %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	fmt.Printf("[*] Agent registered: session=%s host=%s os=%s ips=%v\n",
		sessionID, handshake.Hostname, handshake.OS, handshake.IPs)
	if err := serverCommandLoop(ctrl); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Session %s lost: %v\n", sessionID, err)
	}

	fmt.Printf("[*] Agent disconnected: session=%s\n", sessionID)
}

// serverCommandLoop sends periodic pings to keep the agent alive and reads
// any replies. It returns when the underlying connection fails.
func serverCommandLoop(ctrl net.Conn) error {
	const pingInterval = 30 * time.Second
	const pingWriteTimeout = 10 * time.Second

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
			msgCh <- msg
		}
	}()

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			return err

		case msg := <-msgCh:
			switch msg.Type {
			case protocol.MsgPong:
			case protocol.MsgError:
				errStr, _ := protocol.DecodeError(msg)
				return fmt.Errorf("agent error: %s", errStr)
			default:
				fmt.Fprintf(os.Stderr, "[!] Unexpected message from agent: %s\n", msg.Type)
			}

		case <-ticker.C:
			ctrl.SetWriteDeadline(time.Now().Add(pingWriteTimeout))
			if err := protocol.WriteMessage(ctrl, protocol.NewPing()); err != nil {
				ctrl.SetWriteDeadline(time.Time{})
				return fmt.Errorf("ping failed: %w", err)
			}
			ctrl.SetWriteDeadline(time.Time{})
		}
	}
}

// newSessionID returns a random 8-byte hex session identifier.
func newSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if crypto/rand is unavailable.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
