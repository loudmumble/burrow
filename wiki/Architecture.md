# Architecture

## Session Lifecycle

```
AGENT                                              SERVER
  │                                                  │
  │──── Transport Connect (TCP/WS/DNS/ICMP) ────────►│
  │                                                  │
  │◄─── TLS Handshake (Ed25519 self-signed) ────────►│
  │     Agent verifies server fingerprint             │
  │                                                  │
  │◄═══ yamux Session Established ══════════════════►│
  │     (multiplexed over single connection)          │
  │                                                  │
  │──── Control Stream ─────────────────────────────►│
  │     MsgHandshake: hostname, OS, IPs, PID          │
  │                                                  │
  │◄─── MsgHandshakeAck: session ID ────────────────│
  │                                                  │
  │     Session is now ACTIVE                         │
  │     Server can send commands on control stream    │
  │     Additional yamux streams opened as needed     │
  │                                                  │
```

## Multiplexing: One Connection, Many Streams

yamux (Yet Another MUltipleXer) turns one TCP connection into many independent bidirectional streams. This is why Burrow can run SOCKS5, TUN, TAP, port forwards, and file transfers all over a single agent connection simultaneously.

```
Single TCP Connection (encrypted via TLS)
┌──────────────────────────────────────────────────────┐
│                                                      │
│  Stream 0: Control ──── commands, keepalive, ping    │
│  Stream 1: TUN Data ─── IP packets (L3)              │
│  Stream 2: SOCKS5 #1 ── proxied TCP connection       │
│  Stream 3: SOCKS5 #2 ── another proxied connection   │
│  Stream 4: TAP Data ─── Ethernet frames (L2)         │
│  Stream 5: Tunnel #1 ── port forward                 │
│  Stream 6: File xfer ── download/upload              │
│  ...                                                 │
│                                                      │
└──────────────────────────────────────────────────────┘
```

Each stream is independent — a stall in one doesn't block others. A slow file download won't freeze your SOCKS5 connections.

## Stream Types

When the agent opens a new yamux stream, the first byte identifies its purpose:

| Type Byte | Purpose | Direction |
|-----------|---------|-----------|
| `0x01` | TUN packet relay | Agent → Server |
| `0x02` | Remote tunnel connection | Agent → Server |
| `0x03` | TAP frame relay | Agent → Server |

SOCKS5 streams are opened by the server (server → agent) and carry a 2-byte address length header followed by the target address.

## Control Protocol

All commands between server and agent flow over the control stream using a simple binary protocol:

```
┌──────┬────────────┬─────────────────┐
│ Type │   Length   │     Payload     │
│ 1 B  │   4 B BE  │  0..1MB JSON    │
└──────┴────────────┴─────────────────┘
```

Key message types:

| Code | Message | Direction | Purpose |
|------|---------|-----------|---------|
| 0x01 | Handshake | Agent → Server | Agent identifies itself |
| 0x02 | HandshakeAck | Server → Agent | Server assigns session ID |
| 0x10 | TunnelRequest | Server → Agent | Create a port forward |
| 0x20 | RouteAdd | Server → Agent | Add a network route |
| 0x40/41 | Ping/Pong | Both | Keepalive + RTT measurement |
| 0x50 | TunStart | Server → Agent | Activate TUN mode |
| 0x53 | TapStart | Server → Agent | Activate TAP mode |
| 0x60 | ExecRequest | Server → Agent | Run a command |
| 0x70 | FileDownload | Server → Agent | Download a file |

## Encryption

Two layers of encryption protect all traffic:

**Layer 1 — TLS (transport encryption):**
- Ed25519 self-signed certificates generated at startup
- Server fingerprint verification prevents MITM
- Standard TLS 1.3 with modern cipher suites

**Layer 2 — Application encryption (handshake):**
- X25519 key exchange (Diffie-Hellman on Curve25519)
- HKDF-SHA256 key derivation
- ChaCha20-Poly1305 AEAD for payload encryption

Both layers are always active. Even if TLS is stripped by an intercepting proxy, the inner encryption protects the data.

## Agent vs Stager

```
FULL AGENT                          STAGER
┌─────────────────────┐             ┌──────────────────┐
│ All transports      │             │ Raw transport     │
│ TUN/TAP support     │             │ No TUN/TAP       │
│ SOCKS5 routing      │             │ No SOCKS5        │
│ Command execution   │             │ No exec          │
│ File transfer       │             │ No file transfer  │
│ Dynamic tunnels     │             │ Static tunnels    │
│ Keepalive/reconnect │             │ Basic reconnect   │
│ ~16 MB              │             │ ~5 MB             │
└─────────────────────┘             └──────────────────┘
```

The stager is a minimal agent for initial access. It connects back, creates port forwards, and that's it. Use it when:
- You need the smallest possible binary
- You only need a few port forwards
- Full agent features aren't needed yet
- You want to stage the full agent through the stager's tunnel later

## Data Flow: How a Packet Reaches Its Target

**SOCKS5 flow:**
```
Your Tool ──► SOCKS5 Proxy (127.0.0.1:1080) ──► yamux stream ──► Agent
                                                                    │
                                                              net.Dial()
                                                                    │
                                                              Target:Port
```

**TUN flow:**
```
Your Tool ──► Kernel Route ──► burrow0 (TUN) ──► yamux stream ──► Agent
                                                                    │
                                                           gvisor netstack
                                                          (userspace TCP/IP)
                                                                    │
                                                              net.Dial()
                                                                    │
                                                              Target:Port
```

**TAP flow:**
```
Your Tool ──► burrow-tap0 (TAP) ──► yamux stream ──► Agent
              Ethernet frames                          │
                                                 AF_PACKET raw socket
                                                 (promiscuous mode)
                                                       │
                                                 Physical NIC
                                                 (same L2 segment)
```

The key difference: SOCKS5 and TUN terminate connections on the agent (the agent makes a new TCP connection to the target). TAP doesn't terminate anything — it passes raw Ethernet frames, so your machine appears to be physically on the target network.
