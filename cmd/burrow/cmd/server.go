package cmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/session"
	"github.com/loudmumble/burrow/internal/transport"
	_ "github.com/loudmumble/burrow/internal/transport/dns"
	_ "github.com/loudmumble/burrow/internal/transport/icmp"
	_ "github.com/loudmumble/burrow/internal/transport/raw"
	_ "github.com/loudmumble/burrow/internal/transport/ws"
	_ "github.com/loudmumble/burrow/internal/transport/http"
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
  burrow server --webui
  burrow server --webui 0.0.0.0:9090
  burrow server --mcp-api
  burrow server --tui
  burrow server --transport ws --listen 0.0.0.0:443`,
	Run: runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringP("listen", "l", "0.0.0.0:11601", "Listen address for agent connections")
	serverCmd.Flags().String("cert", "", "Path to TLS certificate PEM file")
	serverCmd.Flags().String("key", "", "Path to TLS private key PEM file")
	serverCmd.Flags().Bool("mcp-api", false, "Enable agent REST API for MCP server integration")
	serverCmd.Flags().String("api-token", "", "Token for API authentication (auto-generated if empty)")
	serverCmd.Flags().String("webui", "", "Enable WebUI dashboard (default: 0.0.0.0:9090)")
	serverCmd.Flags().Lookup("webui").NoOptDefVal = "0.0.0.0:9090"
	serverCmd.Flags().Bool("no-tls", false, "Disable TLS (use plain TCP)")
	serverCmd.Flags().StringP("transport", "t", "raw", "Transport protocol (raw, ws, dns, icmp, http)")
	serverCmd.Flags().Bool("tui", false, "Launch interactive TUI dashboard")
}

func runServer(cmd *cobra.Command, _ []string) {
	listen, _ := cmd.Flags().GetString("listen")
	certPath, _ := cmd.Flags().GetString("cert")
	keyPath, _ := cmd.Flags().GetString("key")
	enableAPI, _ := cmd.Flags().GetBool("mcp-api")
	apiToken, _ := cmd.Flags().GetString("api-token")
	webuiAddr, _ := cmd.Flags().GetString("webui")
	tuiEnabled, _ := cmd.Flags().GetBool("tui")
	noTLS, _ := cmd.Flags().GetBool("no-tls")
	transportName, _ := cmd.Flags().GetString("transport")

	webuiEnabled := webuiAddr != ""

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

	webAddr := "127.0.0.1:9091"
	if webuiEnabled {
		webAddr = webuiAddr
	}

	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}

	if enableAPI || webuiEnabled || tuiEnabled {
		if enableAPI && apiToken == "" {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to generate API token: %v\n", err)
				os.Exit(1)
			}
			apiToken = hex.EncodeToString(b)
		}

		if enableAPI {
			fmt.Printf("\n[!] ========================================\n")
			if webuiEnabled {
				fmt.Printf("[!] WebUI & API ENABLED\n")
				fmt.Printf("[!] URL: %s://%s/\n", scheme, webAddr)
			} else {
				fmt.Printf("[!] MCP API ENABLED\n")
				fmt.Printf("[!] Endpoint: %s://%s/api\n", scheme, webAddr)
			}
			fmt.Printf("[!] API Token: %s\n", apiToken)
			fmt.Printf("[!] Keep this token secret. It is required to interact with the API.\n")
			fmt.Printf("[!] ========================================\n\n")
		} else if webuiEnabled {
			fmt.Printf("\n[*] WebUI: %s://%s/\n\n", scheme, webAddr)
		}

		events := web.NewEventBus()
		webSrv := web.NewServer(webAddr, mgr, events, apiToken, true, tlsCfg, webuiEnabled)
		go func() {
			if err := webSrv.Start(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Web server error: %v\n", err)
			}
		}()
		defer webSrv.Stop()
	}

	if tuiEnabled {
		time.Sleep(200 * time.Millisecond)
		if err := RunTUI(mgr); err != nil {
			fmt.Fprintf(os.Stderr, "[!] TUI error: %v\n", err)
		}
		fmt.Println("\n[*] TUI exited, shutting down...")
		mgr.Shutdown()
		cancel()
	} else {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\n[*] Shutting down...")
		mgr.Shutdown()
		cancel()
	}
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
	mgr.AddConn(info, sess, ctrl)
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

	go acceptDataStreams(sess, mgr, sessionID)

	// Auto-restore TUN if previous session for this agent had it active.
	if mgr.WasTunActive(handshake.Hostname) {
		go func() {
			time.Sleep(500 * time.Millisecond) // let data stream acceptor start
			if err := mgr.StartTun(sessionID); err != nil {
				fmt.Fprintf(os.Stderr, "[!] TUN auto-restore failed for %s: %v\n", sessionID, err)
			} else {
				mgr.ClearTunPrev() // Only clear after successful restore
				fmt.Printf("[*] TUN auto-restored for reconnected agent %s\n", handshake.Hostname)
			}
		}()
	}

	fmt.Printf("[*] Agent registered: session=%s host=%s os=%s ips=%v\n",
		sessionID, handshake.Hostname, handshake.OS, handshake.IPs)
	if err := serverCommandLoop(ctrl, mgr, sessionID); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Session %s lost: %v\n", sessionID, err)
	}

	fmt.Printf("[*] Agent disconnected: session=%s\n", sessionID)
}

func serverCommandLoop(ctrl net.Conn, mgr *session.Manager, sessionID string) error {
	const pingInterval = 30 * time.Second

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
			case protocol.MsgTunnelAck:
				ack, err := protocol.DecodeTunnelAck(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad tunnel ack: %v\n", err)
					continue
				}
				mgr.UpdateTunnelStatus(sessionID, ack.ID, ack.BoundAddr, ack.Error)
				if ack.Error != "" {
					fmt.Fprintf(os.Stderr, "[!] Tunnel %s error: %s\n", ack.ID, ack.Error)
				} else {
					fmt.Printf("[*] Tunnel %s active on %s\n", ack.ID, ack.BoundAddr)
				}
			case protocol.MsgListenerAck:
				ack, err := protocol.DecodeListenerAck(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad listener ack: %v\n", err)
					continue
				}
				if ack.Error != "" {
					fmt.Fprintf(os.Stderr, "[!] Listener %s error: %s\n", ack.ID, ack.Error)
				} else {
					fmt.Printf("[*] Listener %s active on %s\n", ack.ID, ack.BoundAddr)
				}
			case protocol.MsgError:
				errStr, _ := protocol.DecodeError(msg)
				return fmt.Errorf("agent error: %s", errStr)
			case protocol.MsgTunStartAck:
				ack, err := protocol.DecodeTunStartAck(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad TUN start ack: %v\n", err)
					continue
				}
				if ack.Error != "" {
					fmt.Fprintf(os.Stderr, "[!] Agent TUN start failed: %s\n", ack.Error)
					mgr.HandleTunAck(sessionID, ack.Error)
				} else {
					fmt.Printf("[*] Agent TUN mode ready\n")
					mgr.HandleTunAck(sessionID, "")
				}
			case protocol.MsgExecResponse:
				resp, err := protocol.DecodeExecResponse(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad exec response: %v\n", err)
					continue
				}
				mgr.HandleExecResponse(sessionID, resp)
			case protocol.MsgFileDownloadResponse:
				resp, err := protocol.DecodeFileDownloadResponse(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad file download response: %v\n", err)
					continue
				}
				mgr.HandleDownloadResponse(sessionID, resp)
			case protocol.MsgFileUploadResponse:
				resp, err := protocol.DecodeFileUploadResponse(msg)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Bad file upload response: %v\n", err)
					continue
				}
				mgr.HandleUploadResponse(sessionID, resp)
			default:
				fmt.Fprintf(os.Stderr, "[!] Unexpected message from agent: %s\n", msg.Type)
			}

		case <-ticker.C:
			if err := mgr.WriteCtrl(sessionID, protocol.NewPing()); err != nil {
				return fmt.Errorf("ping failed: %w", err)
			}
		}
	}
}

func newSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func acceptDataStreams(sess *mux.Session, mgr *session.Manager, sessionID string) {
	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}

		// Read 1-byte stream type header
		typeBuf := make([]byte, 1)
		if _, err := io.ReadFull(stream, typeBuf); err != nil {
			stream.Close()
			continue
		}

		switch typeBuf[0] {
		case 0x01: // TUN data stream
			mgr.HandleDataStream(sessionID, stream)
		case 0x02: // Remote tunnel connection
			go handleRemoteTunnelStream(stream)
		default:
			fmt.Fprintf(os.Stderr, "[!] Unknown stream type 0x%02x from session %s\n", typeBuf[0], sessionID)
			stream.Close()
		}
	}
}

func handleRemoteTunnelStream(stream net.Conn) {
	defer stream.Close()

	// Read address header: [2-byte addr len BE] [addr bytes]
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Remote tunnel: failed to read addr length: %v\n", err)
		return
	}
	addrLen := binary.BigEndian.Uint16(lenBuf)
	if addrLen == 0 || addrLen > 512 {
		fmt.Fprintf(os.Stderr, "[!] Remote tunnel: invalid addr length: %d\n", addrLen)
		return
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Remote tunnel: failed to read addr: %v\n", err)
		return
	}
	remoteAddr := string(addrBuf)

	// Dial the target on the SERVER machine (operator's machine)
	conn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Remote tunnel: failed to dial %s: %v\n", remoteAddr, err)
		return
	}
	defer conn.Close()

	relay.TuneConn(conn)

	fmt.Printf("[*] Remote tunnel: relaying to %s\n", remoteAddr)

	// Bidirectional relay between yamux stream and local connection
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
		done <- struct{}{}
	}()
	<-done
	<-done // Wait for both goroutines to finish
}
