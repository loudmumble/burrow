# Burrow Architecture

## Package Map

```
cmd/burrow/cmd/
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
  httptunnel.go        HTTP tunnel server + client commands (reGeorg-style)
  generate.go          Webshell generator command (PHP/ASPX/JSP)

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
internal/httptunnel/   reGeorg-style HTTP tunnel (server + client + binary protocol)
  protocol.go          XOR encryption, base64 encoding, SHA256 auth token generation
  server.go            HTTP handler: connect/send/recv/disconnect/ping with TCP session management
  client.go            SOCKS5-to-HTTP tunnel client with polling
  webshell/            Webshell generator (PHP/ASPX/JSP templates matching httptunnel protocol)
internal/relay/        Socat-style bidirectional relay (TCP, UDP, Unix, exec, stdio)
internal/mux/          yamux stream multiplexer (stream 0 = control, N = data)
internal/protocol/     Binary message protocol (12 types, JSON payload, 1MB max)
internal/session/      Agent session manager, proxy server, web.SessionProvider
internal/tun/          TUN device + magic IP 240.0.0.0/4 + IPv4 packet parser
internal/udp/          UDP port forwarder with per-client tracking + idle reaper
internal/netstack/     gvisor userspace TCP/IP (agent-side packet termination)
internal/web/          Embedded WebUI: REST API + SSE + Alpine.js/Pico CSS dashboard
```

## Agent Data Flow (Transparent VPN Mode)

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
  routes 240.0.0.0/4                           agent's network
  through TUN

Control channel (yamux stream 0):
  MsgHandshake / MsgHandshakeAck  -- agent registration
  MsgTunnelRequest / MsgTunnelAck -- create port forwards
  MsgRouteAdd / MsgRouteRemove    -- manage routes
  MsgTunnelClose                  -- tear down
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

## WebUI Architecture

```
Browser/HTTP Client --> GET /static/* --> embedded Alpine.js + Pico CSS SPA
             (Auth: Bearer Token required for below APIs)
         --> GET /api/sessions --> JSON session list
         --> GET /api/sessions/{id}/tunnels --> JSON tunnel list
         --> POST /api/sessions/{id}/tunnels --> create tunnel
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

## Integration Points

- Post-exploitation tunneling for lateral movement
- **Phantom**: Internal network scanning through pivots
- **Sentinel**: Encrypted C2 channel relay
