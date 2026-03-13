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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/loudmumble/burrow/internal/certgen"
	"github.com/loudmumble/burrow/internal/mux"
	"github.com/loudmumble/burrow/internal/protocol"
	"github.com/loudmumble/burrow/internal/relay"
	"github.com/loudmumble/burrow/internal/session"
	"github.com/loudmumble/burrow/internal/transport"
	_ "github.com/loudmumble/burrow/internal/transport/dns"
	_ "github.com/loudmumble/burrow/internal/transport/http"
	_ "github.com/loudmumble/burrow/internal/transport/icmp"
	_ "github.com/loudmumble/burrow/internal/transport/raw"
	_ "github.com/loudmumble/burrow/internal/transport/ws"
	"github.com/loudmumble/burrow/internal/web"
	"github.com/spf13/cobra"
)

var serverLog io.Writer = os.Stdout
var serverErrLog io.Writer = os.Stderr

// tuiLogCapture captures log output for the TUI log panel.
type tuiLogCapture struct {
	mu      sync.Mutex
	entries []string
}

func (c *tuiLogCapture) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	text := strings.TrimRight(string(p), "\n")
	if text != "" {
		c.entries = append(c.entries, text)
	}
	return len(p), nil
}

func (c *tuiLogCapture) drain() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]string, len(c.entries))
	copy(cp, c.entries)
	c.entries = c.entries[:0]
	return cp
}

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
	serverCmd.Flags().String("log-file", "", "Write server logs to file")
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
	logFilePath, _ := cmd.Flags().GetString("log-file")

	webuiEnabled := webuiAddr != ""

	// Set up log file if requested.
	var logFile *os.File
	if logFilePath != "" {
		var openErr error
		logFile, openErr = os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if openErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to open log file: %v\n", openErr)
			os.Exit(1)
		}
		defer logFile.Close()
		serverLog = io.MultiWriter(os.Stdout, logFile)
		serverErrLog = io.MultiWriter(os.Stderr, logFile)
	}

	var tlsCfg *tls.Config
	var tlsCert tls.Certificate
	var fingerprint string

	if !noTLS {
		var err error
		if certPath != "" && keyPath != "" {
			tlsCert, err = certgen.LoadPEM(certPath, keyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to load TLS cert: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(serverLog, "[*] Loaded TLS certificate from %s\n", certPath)
		} else {
			// Auto-persist self-signed cert to ~/.burrow/
			homeDir, homeErr := os.UserHomeDir()
			if homeErr != nil {
				fmt.Fprintf(os.Stderr, "[!] Cannot determine home directory: %v\n", homeErr)
				os.Exit(1)
			}
			certDir := filepath.Join(homeDir, ".burrow")
			certPath = filepath.Join(certDir, "server.pem")
			keyPath = filepath.Join(certDir, "server-key.pem")

			if _, statErr := os.Stat(certPath); statErr == nil {
				tlsCert, err = certgen.LoadPEM(certPath, keyPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Failed to load TLS cert from %s: %v\n", certPath, err)
					os.Exit(1)
				}
				fmt.Fprintf(serverLog, "[*] TLS certificate loaded from %s\n", certPath)
			} else {
				tlsCert, err = certgen.GenerateSelfSigned("Burrow", 365*24*time.Hour)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Failed to generate TLS cert: %v\n", err)
					os.Exit(1)
				}
				if mkErr := os.MkdirAll(certDir, 0700); mkErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Failed to create cert directory %s: %v\n", certDir, mkErr)
					os.Exit(1)
				}
				certPEM, keyPEM, encErr := certgen.EncodePEM(tlsCert)
				if encErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Failed to encode TLS cert: %v\n", encErr)
					os.Exit(1)
				}
				if saveErr := certgen.SavePEM(certPEM, keyPEM, certPath, keyPath); saveErr != nil {
					fmt.Fprintf(os.Stderr, "[!] Failed to save TLS cert: %v\n", saveErr)
					os.Exit(1)
				}
				fmt.Fprintf(serverLog, "[*] TLS certificate saved to %s\n", certPath)
			}
		}

		fingerprint, err = certgen.FingerprintFromTLSCert(tlsCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to compute fingerprint: %v\n", err)
			os.Exit(1)
		}
		// Only print fingerprint to stdout when TUI is not active;
		// when TUI is active, it is displayed in the dashboard header.
		if !tuiEnabled {
			fmt.Fprintf(serverLog, "[*] Fingerprint: %s\n", fingerprint)
		}

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

	fmt.Fprintf(serverLog, "[*] Burrow server listening on %s (%s)\n", listen, t.Name())

	go func() {
		for {
			conn, err := t.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				fmt.Fprintf(serverErrLog, "[!] Accept error: %v\n", err)
				continue
			}
			go handleAgentConn(conn, mgr, transportName)
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
			fmt.Fprintf(serverLog, "\n[!] ========================================\n")
			if webuiEnabled {
				fmt.Fprintf(serverLog, "[!] WebUI & API ENABLED\n")
				fmt.Fprintf(serverLog, "[!] URL: %s://%s/\n", scheme, webAddr)
			} else {
				fmt.Fprintf(serverLog, "[!] MCP API ENABLED\n")
				fmt.Fprintf(serverLog, "[!] Endpoint: %s://%s/api\n", scheme, webAddr)
			}
			fmt.Fprintf(serverLog, "[!] API Token: %s\n", apiToken)
			fmt.Fprintf(serverLog, "[!] Keep this token secret. It is required to interact with the API.\n")
			fmt.Fprintf(serverLog, "[!] ========================================\n\n")
		} else if webuiEnabled {
			fmt.Fprintf(serverLog, "\n[*] WebUI: %s://%s/\n\n", scheme, webAddr)
		}

		events := web.NewEventBus()
		mgr.SetEventBus(events)
		webSrv := web.NewServer(webAddr, mgr, events, apiToken, true, tlsCfg, webuiEnabled)
		go func() {
			if err := webSrv.Start(ctx); err != nil {
				fmt.Fprintf(serverErrLog, "[!] Web server error: %v\n", err)
			}
		}()
		defer webSrv.Stop()
	}

	if tuiEnabled {
		time.Sleep(200 * time.Millisecond)
		logBuf := &tuiLogCapture{}
		if logFile != nil {
			serverLog = io.MultiWriter(logBuf, logFile)
			serverErrLog = io.MultiWriter(logBuf, logFile)
		} else {
			serverLog = logBuf
			serverErrLog = logBuf
		}
		if err := RunTUI(mgr, fingerprint, logBuf); err != nil {
			serverLog = os.Stdout
			serverErrLog = os.Stderr
			fmt.Fprintf(os.Stderr, "[!] TUI error: %v\n", err)
			fmt.Fprintln(os.Stdout, "[*] TUI failed, server still running. Ctrl+C to stop.")
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan
		}
		fmt.Fprintln(os.Stdout, "\n[*] Shutting down...")
		mgr.Shutdown()
		cancel()
	} else {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Fprintln(os.Stdout, "\n[*] Shutting down...")
		mgr.Shutdown()
		cancel()
	}
}

func handleAgentConn(conn net.Conn, mgr *session.Manager, transportName string) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(serverErrLog, "[!] Panic in agent handler for %s: %v\n", conn.RemoteAddr(), r)
		}
	}()

	fmt.Fprintf(serverLog, "[*] New agent connection from %s\n", conn.RemoteAddr())

	sess, err := mux.NewServerSession(conn)
	if err != nil {
		fmt.Fprintf(serverErrLog, "[!] Mux session error from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	defer sess.Close()
	ctrl, err := sess.Accept()
	if err != nil {
		fmt.Fprintf(serverErrLog, "[!] Accept control stream from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	defer ctrl.Close()
	msg, err := protocol.ReadMessage(ctrl)
	if err != nil {
		fmt.Fprintf(serverErrLog, "[!] Read handshake from %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	handshake, err := protocol.DecodeHandshake(msg)
	if err != nil {
		fmt.Fprintf(serverErrLog, "[!] Decode handshake from %s: %v\n", conn.RemoteAddr(), err)
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
	info.Transport = transportName
	info.Version = handshake.Version
	// Evict stale session for same hostname to prevent resource leaks.
	if existingID, found := mgr.FindByHostname(handshake.Hostname); found {
		fmt.Fprintf(serverLog, "[*] Evicting stale session %s for reconnecting agent %s\n", existingID, handshake.Hostname)
		mgr.Remove(existingID)
	}
	mgr.AddConn(info, sess, ctrl)
	defer mgr.Remove(sessionID)
	ackPayload := &protocol.HandshakeAckPayload{
		SessionID:    sessionID,
		ProxyVersion: version,
	}
	ackMsg, err := protocol.EncodeHandshakeAck(ackPayload)
	if err != nil {
		fmt.Fprintf(serverErrLog, "[!] Encode handshake ack: %v\n", err)
		return
	}
	if err := protocol.WriteMessage(ctrl, ackMsg); err != nil {
		fmt.Fprintf(serverErrLog, "[!] Send handshake ack to %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	go acceptDataStreams(sess, mgr, sessionID)

	// Auto-restore TUN if previous session for this agent had it active.
	if mgr.WasTunActive(handshake.Hostname) {
		go func() {
			time.Sleep(500 * time.Millisecond) // let data stream acceptor start
			if err := mgr.StartTun(sessionID); err != nil {
				fmt.Fprintf(serverErrLog, "[!] TUN auto-restore failed for %s: %v\n", sessionID, err)
			} else {
				routes := mgr.TunPrevRoutes()
				for _, cidr := range routes {
					if _, routeErr := mgr.AddRoute(sessionID, cidr); routeErr != nil {
						fmt.Fprintf(serverErrLog, "[!] Auto-restore route %s failed: %v\n", cidr, routeErr)
					} else {
						fmt.Fprintf(serverLog, "[*] Route %s auto-restored\n", cidr)
					}
				}
				mgr.ClearTunPrev() // Only clear after successful restore
				fmt.Fprintf(serverLog, "[*] TUN auto-restored for reconnected agent %s\n", handshake.Hostname)
			}
		}()
	}

	fmt.Fprintf(serverLog, "[*] Agent registered: session=%s host=%s os=%s ips=%v\n",
		sessionID, handshake.Hostname, handshake.OS, handshake.IPs)
	if err := serverCommandLoop(ctrl, mgr, sessionID); err != nil {
		fmt.Fprintf(serverErrLog, "[!] Session %s lost: %v\n", sessionID, err)
	}

	fmt.Fprintf(serverLog, "[*] Agent disconnected: session=%s\n", sessionID)
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
				mgr.MarkPongReceived(sessionID)
			case protocol.MsgTunnelAck:
				ack, err := protocol.DecodeTunnelAck(msg)
				if err != nil {
					fmt.Fprintf(serverErrLog, "[!] Bad tunnel ack: %v\n", err)
					continue
				}
				mgr.UpdateTunnelStatus(sessionID, ack.ID, ack.BoundAddr, ack.Error)
				if ack.Error != "" {
					fmt.Fprintf(serverErrLog, "[!] Tunnel %s error: %s\n", ack.ID, ack.Error)
				} else {
					fmt.Fprintf(serverLog, "[*] Tunnel %s active on %s\n", ack.ID, ack.BoundAddr)
				}
			case protocol.MsgListenerAck:
				ack, err := protocol.DecodeListenerAck(msg)
				if err != nil {
					fmt.Fprintf(serverErrLog, "[!] Bad listener ack: %v\n", err)
					continue
				}
				if ack.Error != "" {
					fmt.Fprintf(serverErrLog, "[!] Listener %s error: %s\n", ack.ID, ack.Error)
				} else {
					fmt.Fprintf(serverLog, "[*] Listener %s active on %s\n", ack.ID, ack.BoundAddr)
				}
			case protocol.MsgError:
				errStr, _ := protocol.DecodeError(msg)
				return fmt.Errorf("agent error: %s", errStr)
			case protocol.MsgTunStartAck:
				ack, err := protocol.DecodeTunStartAck(msg)
				if err != nil {
					fmt.Fprintf(serverErrLog, "[!] Bad TUN start ack: %v\n", err)
					continue
				}
				if ack.Error != "" {
					fmt.Fprintf(serverErrLog, "[!] Agent TUN start failed: %s\n", ack.Error)
					mgr.HandleTunAck(sessionID, ack.Error)
				} else {
					fmt.Fprintf(serverLog, "[*] Agent TUN mode ready\n")
					mgr.HandleTunAck(sessionID, "")
				}
			case protocol.MsgExecResponse:
				resp, err := protocol.DecodeExecResponse(msg)
				if err != nil {
					fmt.Fprintf(serverErrLog, "[!] Bad exec response: %v\n", err)
					continue
				}
				mgr.HandleExecResponse(sessionID, resp)
			case protocol.MsgFileDownloadResponse:
				resp, err := protocol.DecodeFileDownloadResponse(msg)
				if err != nil {
					fmt.Fprintf(serverErrLog, "[!] Bad file download response: %v\n", err)
					continue
				}
				mgr.HandleDownloadResponse(sessionID, resp)
			case protocol.MsgFileUploadResponse:
				resp, err := protocol.DecodeFileUploadResponse(msg)
				if err != nil {
					fmt.Fprintf(serverErrLog, "[!] Bad file upload response: %v\n", err)
					continue
				}
				mgr.HandleUploadResponse(sessionID, resp)
			default:
				fmt.Fprintf(serverErrLog, "[!] Unexpected message from agent: %s\n", msg.Type)
			}

		case <-ticker.C:
			mgr.MarkPingSent(sessionID)
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
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(serverErrLog, "[!] Panic in data stream acceptor for %s: %v\n", sessionID, r)
		}
	}()
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
			fmt.Fprintf(serverErrLog, "[!] Unknown stream type 0x%02x from session %s\n", typeBuf[0], sessionID)
			stream.Close()
		}
	}
}

func handleRemoteTunnelStream(stream net.Conn) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(serverErrLog, "[!] Panic in remote tunnel stream: %v\n", r)
		}
	}()
	// Read address header: [2-byte addr len BE] [addr bytes]
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		fmt.Fprintf(serverErrLog, "[!] Remote tunnel: failed to read addr length: %v\n", err)
		return
	}
	addrLen := binary.BigEndian.Uint16(lenBuf)
	if addrLen == 0 || addrLen > 512 {
		fmt.Fprintf(serverErrLog, "[!] Remote tunnel: invalid addr length: %d\n", addrLen)
		return
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		fmt.Fprintf(serverErrLog, "[!] Remote tunnel: failed to read addr: %v\n", err)
		return
	}
	remoteAddr := string(addrBuf)

	// Dial the target on the SERVER machine (operator's machine)
	conn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
	if err != nil {
		fmt.Fprintf(serverErrLog, "[!] Remote tunnel: failed to dial %s: %v\n", remoteAddr, err)
		return
	}
	defer conn.Close()

	relay.TuneConn(conn)

	fmt.Fprintf(serverLog, "[*] Remote tunnel: relaying to %s\n", remoteAddr)

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
