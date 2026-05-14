# Burrow Architecture

## Package Map

```
cmd/burrow/cmd/          CLI (cobra) + TUI (bubbletea)
  root.go              Cobra root command, version 3.0.0
  proxy.go             SOCKS5 + HTTP forward proxy commands
  forward.go           Local port forward command
  reverse.go           Reverse tunnel command
  pivot.go             Multi-hop pivot command
  discover.go          Subnet scan command
  server.go            Proxy server command (listens for agents)
  agent.go             Agent command (connects back to proxy server)
  session.go           Session list/info/use commands (--webui, --token, --no-tls persistent flags)
  relay.go             Socat-style bidirectional relay command
  tunnel.go            HTTP tunnel server + client commands (basic + secure modes)
  generate.go          Webshell generator command (PHP/ASPX/JSP)
  tui.go               Interactive TUI dashboard (bubbletea, --tui flag on server)

internal/crypto/       X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM frame encryption
internal/proxy/        SOCKS5 + HTTP forward proxy with session routing (Dialer hook)
internal/tunnel/       Local, remote, and reverse TCP port forwarders
internal/pivot/        Multi-hop chain orchestration
internal/discovery/    Ping sweep + TCP port scanner
internal/certgen/      Ed25519 self-signed TLS cert generation + SHA256 fingerprint
internal/transport/    Pluggable transport interface + registry
  raw/                 Raw TCP/TLS transport (default)
  ws/                  WebSocket transport (nhooyr.io/websocket)
  http/                HTTP polling transport (virtual net.Conn over HTTP request/response pairs)
  dns/                 DNS tunnel transport
  icmp/                ICMP tunnel transport (requires raw socket privileges)
internal/httptunnel/   HTTP tunnel relay (basic + secure modes)
  protocol.go          Basic mode: XOR encryption, base64 encoding, SHA256 auth token generation
  secure.go            Secure mode: AES-256-GCM, HKDF key derivation, cookie commands, HTML wrapping
  server.go            HTTP handler: connect/send/recv/disconnect/ping with TCP session management
  client.go            SOCKS5-to-HTTP tunnel client with polling (basic + secure)
  webshell/            Webshell generator (PHP/ASPX/JSP templates for both modes)
internal/relay/        Socat-style bidirectional relay (TCP, UDP, Unix, exec, stdio)
internal/mux/          yamux stream multiplexer (stream 0 = control, N = data)
internal/protocol/     Binary message protocol (12 types, JSON payload, 1MB max)
internal/session/      Agent session manager, proxy server, web.SessionProvider
internal/tun/          TUN device + magic IP 240.0.0.0/4 + IPv4 packet parser
internal/udp/          UDP port forwarder with per-client tracking + idle reaper
internal/netstack/     gvisor userspace TCP/IP (agent-side packet termination)
internal/web/          Embedded WebUI: REST API + SSE + Alpine.js/Pico CSS dashboard
```

## Agent Data Flow (Transparent VPN / TUN Mode)

Routes are managed manually by the operator (ligolo-ng style). The server cannot
auto-detect target subnets vs C2 subnets, so routing the wrong network would kill
the agent connection via a routing loop.

```
Operator Side (root required)                 Agent Side (no root)
+-----------+                                 +-------------+
|  TUN      |  raw IP packets                 | netstack    |
|  240.0.0.x| -----> yamux stream 1+ -------> | (gvisor)    |
|  device   | <----- yamux stream 1+ <------- | TCP/UDP     |
+-----------+                                 | forwarder   |
      |                                       +------+------+
      v                                              |
  Operator's                                   net.Dial() to
  routing table                                real targets on
  (manual routes only)                         agent's network
  e.g. ip route add 10.10.10.0/24
       dev tun0

Control channel (yamux stream 0):
  MsgHandshake / MsgHandshakeAck  -- agent registration
  MsgTunnelRequest / MsgTunnelAck -- create port forwards
  MsgRouteAdd / MsgRouteRemove    -- manage routes
  MsgTunnelClose                  -- tear down

Key implementation details:
  - tunAgentRelay: bidirectional goroutine pair with injectDone channel
    to detect inner goroutine death and clean up both directions
  - tunRelayToStream: retries on nil stream (continue, not return)
  - ICMP: rate.Inf (unlimited) — SetICMPLimit(0) blocks all ICMP
  - No auto-route: removed subnetAlreadyRouted() — manual only
```

## HTTP Tunnel Data Flow (Egress-Blocked Scenario)

```
Attacker                                Target (no outbound)
+------------------+                    +--------------------+
| httptunnel       |  HTTP POST         | httptunnel server  |
| client           | ---- cmd=connect -> | (or webshell)      |
| (SOCKS5 :1080)   | ---- cmd=send ----> | net.Dial() to      |
|                  | <--- cmd=recv ----- | internal hosts     |
|                  | ---- cmd=disconnect> |                    |
+------------------+                    +--------------------+

Protocol:
  POST /b?cmd=connect&target=10.0.0.5:22   -> {"sid":"a1b2c3"}
  POST /b?cmd=send&sid=a1b2c3               -> XOR+base64 payload
  POST /b?cmd=recv&sid=a1b2c3               <- XOR+base64 response
  POST /b?cmd=disconnect&sid=a1b2c3         -> session closed
  POST /b?cmd=ping                          -> "pong"

Auth: X-Token header = SHA256(key) as hex string
Encryption: XOR with shared key, then base64 encode
```

## HTTP Transport Data Flow

```
Agent                                   Server
+------------------+                    +------------------+
| Virtual net.Conn |  HTTP polling      | Virtual net.Conn |
| over HTTP        | -- POST /send ---> | over HTTP        |
|                  | -- GET /recv -----> |                  |
|                  | <- response data -- |                  |
+------------------+                    +------------------+

Fake cover page served on GET / ("It works!" HTML page)
TLS optional. Works through web proxies and WAFs.
```

## Port Forward Data Flow (Tunnel Mode)

```
Operator                    Agent
burrow tunnel local         burrow agent
  :8080 ----TCP----> yamux stream N ----TCP----> 10.0.0.5:80
```

## WebUI / REST API Architecture

The REST API is exclusively for MCP (Model Context Protocol) server integration.
It is only enabled when `--mcp-api` is passed. The WebUI dashboard is enabled
with `--webui`. The TUI dashboard (`--tui`) connects to the same session manager
in-process.

```
Browser/HTTP Client --> GET /static/* --> embedded Alpine.js + Pico CSS SPA
             (Auth: Bearer Token required for API, only with --mcp-api)
         --> GET /api/sessions --> JSON session list
         --> GET /api/sessions/{id}/tunnels --> JSON tunnel list
         --> POST /api/sessions/{id}/tunnels --> create tunnel
         --> POST /api/sessions/{id}/tun --> start TUN
         --> DELETE /api/sessions/{id}/tun --> stop TUN
         --> GET /api/events --> SSE stream (live session/tunnel updates)
```

## Security Model

- Agent-to-server: TLS with auto-generated Ed25519 self-signed certs
- Fingerprint verification: SHA256 hash of cert DER, verified on agent connect
- WebSocket mode: TLS over HTTPS for firewall evasion (looks like normal HTTPS)
- Frame encryption: X25519 ECDH key exchange, HKDF-SHA256 derivation, AEAD per frame
- Key rotation: hourly, with 4-byte counter for anti-replay
- HTTP tunnel: XOR encryption + base64 encoding + SHA256 X-Token auth (simpler model for webshell compat)
- HTTP transport: same framing as other transports, tunneled over HTTP polling

- **Sentinel**: Encrypted C2 channel relay

## IPv4 Defaulting Policy (Dual-Stack Reliability)

Burrow enforces a strict IPv4-defaulting policy to ensure stability on dual-stack
systems where IPv6 might be incorrectly prioritized for generic addresses.

- When a host address is specified without square brackets (e.g., `127.0.0.1` or
  `example.com`), Burrow forcing `tcp4`, `udp4`, or `ip4` for all dial and listen
  operations.
- If IPv6 is explicitly required, the address must be wrapped in square brackets
  (e.g., `[:1]` or `[fe80::1]:8080`).
- This policy applies to all components: transports (Raw, WS, HTTP, DNS, ICMP),
  proxies (SOCKS5, HTTP), tunnels (Local, Remote, Reverse), and agents.

## Traffic Monitoring

All transport components use `CountingWriter` for real-time monitoring. This ensures
that the TUI and WebUI dashboards accurately reflect traffic as it happens, rather
than waiting for entire chunks to be transferred. This is critical for monitoring
large file transfers or identifying UI hangs.
