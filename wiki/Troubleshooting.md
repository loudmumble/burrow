# Troubleshooting

## Connection Issues

### Agent won't connect

**Symptom:** Agent starts but no session appears in the TUI.

**Check these in order:**

1. **Firewall** — Can the agent reach your server? Test with `curl` or `nc` from the target.

2. **Transport match** — Server and agent MUST use the same transport. If server is `--transport ws`, agent must also be `--transport ws`.

3. **TLS fingerprint** — If using TLS (default), the agent needs the correct `--fp` value. Copy it exactly from the server startup output.

4. **Port** — Make sure the server port isn't already in use. Check with `ss -tlnp | grep PORT`.

### Agent connects then immediately disconnects

**Symptom:** Session appears briefly then disappears.

- **TLS mismatch** — Wrong fingerprint causes TLS handshake failure. The agent drops silently.
- **Keepalive timeout** — If the network is very slow (e.g., DNS transport), keepalive might timeout. Check server logs for keepalive errors.

### Session shows as disconnected but agent is still running

**Symptom:** TUI shows gray dot, agent process is alive.

- **Network interruption** — The underlying TCP connection broke. The agent will auto-reconnect with exponential backoff (1s, 2s, 4s... up to 60s).
- **Kill the agent and restart** — If auto-reconnect isn't working, the session may be stale. Kill and redeploy the agent.

---

## SOCKS5 Issues

### "connection refused" through proxychains

- Is SOCKS5 actually started? Check the TUI — the `S` flag should be green.
- Is it on the right address? Default is `127.0.0.1:1080`. Check with `ss -tlnp | grep 1080`.
- Does your `/etc/proxychains4.conf` match? Should be `socks5 127.0.0.1 1080`.

### Proxychains hangs on DNS resolution

proxychains by default tries to resolve DNS through the proxy. SOCKS5 is TCP-only — UDP DNS doesn't work.

**Fix:** Edit `/etc/proxychains4.conf`:
```
proxy_dns
# Change to:
# proxy_dns
```
Or use `proxychains -q` and set a DNS server that's reachable directly.

**Better fix:** Use TUN mode — DNS works natively via UDP.

### Slow performance through SOCKS5

- Each connection has a SOCKS5 handshake overhead (a few round trips)
- For heavy scanning, TUN mode is faster (no per-connection handshake)
- If using DNS transport underneath, everything will be slow — that's the transport, not SOCKS5

---

## TUN Issues

### "create TUN: operation not permitted"

**Cause:** Server needs root (or CAP_NET_ADMIN) to create the TUN interface.

**Fix:** Run server with `sudo`:
```bash
sudo burrow server --listen 0.0.0.0:11601
```

### TUN starts but traffic doesn't flow

**Check routes:**
```bash
ip route | grep burrow0
```
Did you add routes for the target network? Press `r` in TUI detail view.

**Check interface:**
```bash
ip addr show burrow0
```
Should show `240.0.0.1/32` and UP state.

**Check agent-side:** Is the agent still connected? Can the agent reach the target?

### "TUN already active on session X"

Only one session can own TUN at a time. Stop TUN on the current session first (`Ctrl+T`), then start it on the new one.

---

## TAP Issues

### TAP starts but tools can't reach targets

1. **Did Burrow assign the IP?** Check the TUI detail view — it should show `TAP 10.10.10.200/24` with your assigned address. If it shows `TAP ▲` without an address, the IP wasn't assigned.

2. **Is the IP in use by another machine?** If you picked an IP that's already taken, you'll get ARP conflicts. Pick a different one — delete the TAP (`Ctrl+A` to stop), restart with a new IP.

3. **Is the agent on the same network as your targets?** The agent needs to be on the same subnet as the hosts you're trying to reach.

### Windows port 445 conflict (reverse tunnel)

**This is the #1 gotcha with NTLM relay through a Windows agent.**

If you set up a reverse tunnel on a Windows agent for port 445 (e.g., `0.0.0.0:445 → 127.0.0.1:445`), the tunnel may show "active" but receive **zero traffic**. The Windows kernel SMB driver (`srv2.sys`, PID 4) binds port 445 at the kernel level and intercepts all inbound connections before userspace (including Burrow) ever sees them.

**Symptoms:**
- Tunnel shows "active" with 0B in/out
- Coercion reports "Exploit Success" but ntlmrelayx gets nothing
- `netstat -ano | findstr :445` shows PID 4 (System) owns the port

**Fix options:**
1. **Use TAP instead** (recommended) — `Ctrl+A` on a Linux agent gives you an IP on the target subnet. Coerce to that IP. No port conflicts.
2. **Stop SMB on the Windows agent:**
   ```powershell
   sc.exe stop LanmanServer
   sc.exe stop srv2
   sc.exe stop srvnet
   ```
   Then recreate the 445 tunnel.
3. **Use a Linux agent for the listener** — Linux has no kernel SMB driver competing for port 445.

The same issue applies to ports 135 (RPC) and 139 (NetBIOS) on Windows.

### Nested agent topology (agent through agent)

When deploying a second agent through the first (e.g., internal Windows box connecting back through a pivot Linux box), set up a reverse tunnel on the first agent to relay the server port:

```
Pivot session: remote tunnel 0.0.0.0:11602 → 127.0.0.1:11601
Internal agent: burrow agent -c PIVOT_IP:11602 --fp FINGERPRINT
```

The internal agent connects to the pivot box on 11602, which tunnels back to your server on 11601. Both sessions appear independently in the TUI. Routes and tunnels on each session are independent — the internal agent doesn't need TUN or routes, it's already on the internal network natively.

---

## Tunnel Issues

### Port forward isn't accepting connections

- Check if the tunnel is in "active" state in the TUI
- Check if the local port is already in use: `ss -tlnp | grep PORT`
- If the tunnel shows an error, delete it (`d`) and recreate it

### Reverse port forward — victims can't connect to agent

- Is the agent actually listening? The reverse tunnel tells the agent to bind a port.
- Firewall on the agent host may block inbound connections.
- Check the correct IP — victims need to connect to the agent's IP, not yours.

---

## Performance

### General slow performance

**Check the transport.** DNS and ICMP transports are inherently slow (1-5 KB/s). If you started with DNS to get initial access, upgrade to a faster transport when possible.

**Check latency.** The TUI shows RTT per session. High RTT means every operation takes longer. This is usually a network issue, not a Burrow issue.

### Large file transfers are slow

File transfers go through the yamux-multiplexed session. They share bandwidth with everything else. For large files, consider:
- Using scp/sftp through a port forward (dedicated connection)
- Compressing before transfer
- Using a faster transport

---

## Build Issues

### Cross-compilation fails for Windows

Make sure Windows stubs exist for platform-specific code:
- `internal/tun/tun_windows.go` — TUN stub
- `internal/tun/tap_windows.go` — TAP stub
- `internal/tun/rawsock_stub.go` — Raw socket stub (covers Windows + macOS)

### "CGO_ENABLED=0" related errors

Burrow must be built with `CGO_ENABLED=0` for static binaries. All dependencies must be pure Go. If you're adding dependencies, verify they don't require CGO.
