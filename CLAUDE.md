# CLAUDE.md — Burrow

## Overview
Multi-transport network pivoting and tunneling tool for post-exploitation network traversal. Pluggable transport architecture (Raw TCP/TLS, WebSocket, DNS, ICMP) with multiplexed yamux sessions, X25519/ChaCha20-Poly1305 encryption, and TUN/SOCKS5 routing.

## Tech Stack
- Go 1.24+ (CGO_ENABLED=0, static binary)
- Cobra CLI framework
- yamux for session multiplexing
- gvisor netstack for userspace TUN
- Python MCP server module (`src/`)
- Anvil toolkit for obfuscation/packing (optional)

## Build Commands
```bash
make build-local         # current platform -> build/burrow
make build               # cross-compile all platforms
make build-linux-amd64   # single platform
make build-all           # all platforms + stager + evasion + packed
make build-stager        # minimal agent (linux + windows)
make build-stager-evasion  # obfuscated stager (requires anvil)
make build-stager-packed   # evasion + packed
```

## Project Structure
```
cmd/burrow/          Main CLI entrypoint
cmd/stager/          Minimal agent for initial access
internal/certgen/    TLS certificate generation
internal/crypto/     X25519, HKDF-SHA256, AEAD encryption
internal/discovery/  Network discovery
internal/httptunnel/ HTTP tunnel transport
internal/mux/        yamux session multiplexing
internal/netstack/   gvisor userspace netstack (TUN)
internal/pivot/      Pivot chain management
internal/protocol/   Wire protocol
internal/proxy/      SOCKS5 proxy
internal/relay/      Traffic relay
internal/session/    Session management
internal/transport/  Pluggable transport layer (raw, ws, dns, icmp)
internal/tun/        TUN interface management
internal/tunnel/     Tunnel orchestration
internal/udp/        UDP handling
internal/web/        WebUI dashboard
src/                 Python MCP server module
tests/               Python tests
tools/               Utility scripts
```

## Transports
| Transport | Flag | Notes |
|-----------|------|-------|
| Raw TCP/TLS | `raw` (default) | Ed25519 self-signed certs, fingerprint verification |
| WebSocket | `ws` | HTTP/HTTPS upgrade, firewall evasion |
| DNS tunnel | `dns` | DNS query/response encoding |
| ICMP tunnel | `icmp` | ICMP echo payloads, requires raw socket |

## Hard Rules
- GitLab only — no GitHub
- CGO_ENABLED=0 always (static binary)
- Both sides must use the same transport
- Root mode = TUN interface; non-root = SOCKS5
- Stager is separate binary — minimal footprint, no TUI/TUN/SOCKS5
