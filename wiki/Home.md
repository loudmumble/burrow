# Burrow Wiki

Burrow is a multi-transport network pivoting tool for post-exploitation. It creates encrypted tunnels through compromised hosts, giving you access to internal networks that your attack machine can't reach directly.

## Architecture at a Glance

```
YOUR MACHINE (Kali)                         TARGET NETWORK
┌─────────────────────┐                     ┌─────────────────────────┐
│                     │                     │                         │
│  ┌───────────────┐  │    Encrypted        │  ┌─────────────────┐   │
│  │ Burrow Server │◄─┼────Tunnel───────────┼──│  Burrow Agent   │   │
│  │   (TUI)       │  │  (yamux mux)        │  │  (on comp host) │   │
│  └───────┬───────┘  │                     │  └────────┬────────┘   │
│          │          │                     │           │             │
│  ┌───────▼───────┐  │                     │  ┌────────▼────────┐   │
│  │  Your Tools   │  │                     │  │ Internal Hosts  │   │
│  │ nmap,responder│  │                     │  │ DC, file server │   │
│  │ ntlmrelayx    │  │                     │  │ web apps, etc.  │   │
│  └───────────────┘  │                     │  └─────────────────┘   │
│                     │                     │                         │
└─────────────────────┘                     └─────────────────────────┘
```

## Components

| Component | What It Is | Where It Runs |
|-----------|-----------|---------------|
| **Server** | Accepts agent connections, provides TUI for managing sessions, tunnels, and routes | Your attack machine |
| **Agent** | Connects back to server, executes tunneling commands, forwards traffic | Compromised host |
| **Stager** | Minimal agent — just connects and creates port forwards, no TUI/TUN/SOCKS | Initial access (small footprint) |

## Core Concepts

**Sessions** — Each agent connection creates a session. Sessions are multiplexed over yamux, meaning one TCP connection carries many independent streams (tunnels, SOCKS5, TUN, TAP) simultaneously.

**Transports** — The protocol used for the agent-to-server connection (Raw TCP/TLS, WebSocket, DNS, ICMP). This is the carrier — it determines how traffic gets out of the target network.

**Pivoting Methods** — How your tools' traffic actually reaches internal targets (SOCKS5, port forwards, TUN, TAP). This is the payload — it determines what kind of traffic you can send.

## Commands

| Command | Purpose |
|---------|---------|
| `burrow server` | Start proxy server (accepts agent connections) |
| `burrow agent` | Connect to server from compromised host |
| `burrow scan -s <subnet>` | Network enumeration with service detection |
| `burrow topology` | Show pivot infrastructure from server |
| `burrow session` | Manage sessions (list, info, use) |
| `burrow tunnel` | Port forwarding (local, remote, reverse) |
| `burrow proxy` | SOCKS5/HTTP proxy servers |
| `burrow relay` | Socat-style bidirectional relay |

## Wiki Pages

| Page | What It Covers |
|------|---------------|
| [Quick Start](Quick-Start.md) | Get running in 5 minutes |
| [Architecture](Architecture.md) | How the internals work — sessions, multiplexing, encryption |
| [Transports](Transports.md) | Getting traffic out of restricted networks |
| [Pivoting Methods](Pivoting-Methods.md) | SOCKS5, TUN, TAP, port forwards — what, when, why |
| [Engagement Patterns](Engagement-Patterns.md) | Real-world scenarios and tool setups |
| [TUI Reference](TUI-Reference.md) | Keyboard shortcuts and interface guide |
| [Troubleshooting](Troubleshooting.md) | When things don't work |
