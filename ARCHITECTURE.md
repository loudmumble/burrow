# Burrow Architecture

## Package Map

```
cmd/burrow/cmd/
  root.go              Cobra root command, version 3.0.0
  proxy.go             SOCKS5 proxy command
  forward.go           Local port forward command
  reverse.go           Reverse tunnel command
  pivot.go             Multi-hop pivot command
  discover.go          Subnet scan command
  server.go            Proxy server command (listens for agents)
  agent.go             Agent command (connects back to proxy server)
  session.go           Session list/info/use commands (--webui, --token, --no-tls persistent flags)
  relay.go             Socat-style bidirectional relay command

internal/crypto/       X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM frame encryption
internal/proxy/        SOCKS5 server implementing RFC 1928
internal/tunnel/       Local, remote, and reverse TCP port forwarders
internal/pivot/        Multi-hop chain orchestration
internal/discovery/    Ping sweep + TCP port scanner
internal/certgen/      Ed25519 self-signed TLS cert generation + SHA256 fingerprint
internal/transport/    Pluggable transport interface + registry
  raw/                 Raw TCP/TLS transport (default)
  ws/                  WebSocket transport (nhooyr.io/websocket)
  dns/                 DNS tunnel transport
  icmp/                ICMP tunnel transport (requires raw socket privileges)
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

## Integration Points

- Post-exploitation tunneling for lateral movement
- **Phantom**: Internal network scanning through pivots
- **Sentinel**: Encrypted C2 channel relay
