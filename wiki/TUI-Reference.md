# TUI Reference

## Views

The TUI has several views, each with its own keyboard shortcuts.

### Session List (Main View)

The first thing you see. Shows all connected agent sessions.

```
╔══════════════════════════════════════════════════════════╗
║ BURROW v4.0.0                                            ║
╚══════════════════════════════════════════════════════════╝

  ● TS· web01        Linux  10.10.0.5       2T1R    1.2K
  ○ ··· dc01         Win    10.20.0.1       0T0R    0B
  ○ ··· jump-host    Linux  10.10.0.50      1T0R    450B

  ↑/k up │ ↓/j down │ g/G top/end │ enter select │ ^T TUN │ ^A TAP │ ^Q quit
  y cpy ID │ Y cpy fp │ F short fp │ l label │ E export │ T topo │ ? help
```

**Flags:** `T` = TUN active, `A` = TAP active, `S` = SOCKS5 active, `·` = inactive

| Key | Action |
|-----|--------|
| `↑/k`, `↓/j` | Navigate sessions |
| `g`, `G` | Jump to top / bottom |
| `Enter` | Open session detail view |
| `Ctrl+T` | Start TUN with route prompt / Stop TUN |
| `Ctrl+A` | Start TAP with IP prompt / Stop TAP |
| `y` | Copy session ID to clipboard |
| `Y` | Copy server fingerprint to clipboard |
| `F` | Copy server fingerprint (short) |
| `l` | Set a label for the session |
| `E` | Export engagement data (JSON) |
| `T` | Show network topology view |
| `?` | Help overlay |
| `Ctrl+Q` | Quit |

### Session Detail View

Opened by pressing `Enter` on a session. Shows tunnels, routes, and session info.

```
  ● Session: a1b2c3d4  Host: web01  OS: Linux  PID: 1234
  TUN ▲ │ TAP ▲ │ SOCKS 127.0.0.1:1080 │ IPs: 10.10.0.5
  BW: 1.2K in / 3.4K out │ Rate: 500B/s │ RTT: 12ms

  [ Tunnels ]  [ Routes ]
  ─────────────────────────────────
  L  127.0.0.1:3389 → 10.0.0.5:3389  active  1.2K/3.4K
  R  0.0.0.0:445 → 127.0.0.1:445     active  0B/0B

  ↑/↓ nav │ esc back │ t/r add │ ^D del │ u/^N start/stop │ x exec │ P prof │ w/p dl/upl
  ^T TUN │ ^A TAP │ ^S SK5 │ n/N scan/result │ C chain │ o hist │ Y cpy │ F fp │ ^K kill │ ? help
```

| Key | Action |
|-----|--------|
| `↑/↓` | Navigate tunnels/routes |
| `Esc` | Back to session list |
| `t` | Add tunnel (port forward) |
| `r` | Add route (for TUN mode) |
| `u` | Start selected tunnel (if stopped) |
| `Ctrl+N` | Stop selected tunnel (if active) |
| `Tab` | Switch between Tunnels/Routes tabs |
| `Ctrl+D` | Delete selected tunnel/route (with confirmation) |
| `x` | Execute command on agent |
| `w` | Download file from agent |
| `p` | Upload file to agent |
| `o` | View exec history |
| `Ctrl+T` | Start TUN (prompts for route) / Stop TUN |
| `Ctrl+A` | Start TAP (prompts for IP) / Stop TAP |
| `Ctrl+S` | Toggle SOCKS5 proxy |
| `C` | SOCKS5 chain builder |
| `n` | Open new scan form |
| `N` | View scan results |
| `Y` | Copy tunnel/route data |
| `y` | Copy session ID |
| `F` | Copy server fingerprint (short) |
| `P` | Tunnel profiles (save/load) |
| `Ctrl+K` | Kill session (tear down all infrastructure) |
| `?` | Help overlay |

### Adding a Tunnel

Press `t` in detail view:

```
  Direction: [local/remote]
  Listen:    [127.0.0.1:3389]
  Remote:    [10.0.0.5:3389]
  Protocol:  [tcp]

  enter save │ esc cancel
```

- **local**: Listen on YOUR machine, forward through agent to target
- **remote**: Listen on AGENT machine, forward back to your machine

### Adding a Route

Press `r` in detail view (only relevant when TUN is active):

```
  CIDR: [10.0.0.0/24]

  enter save │ esc cancel
```

### Starting TUN (Ctrl+T)

Pre-filled with a route from the agent's subnet:

```
┌ Start TUN ──────────────────────────────────────┐
│ Route (CIDR):  [10.10.10.0/24]                  │
│                                                  │
│ enter save │ esc cancel                          │
└──────────────────────────────────────────────────┘
```

Starts TUN and adds the route in one step. Press `Ctrl+T` again to stop.

### Starting TAP (Ctrl+A)

Pre-filled with IP (.200) and route from the agent's subnet:

```
┌ Start TAP ──────────────────────────────────────┐
│ TAP IP (CIDR):     [10.10.10.200/24]            │
│                                                  │
│ enter save │ esc cancel                          │
└──────────────────────────────────────────────────┘
```

**Verify the IP is not already in use on the target network before confirming.** Burrow creates the TAP interface, assigns your IP, and adds the subnet route automatically. The detail view then shows `TAP 10.10.10.200/24` with the assigned address. Press `Ctrl+A` again to stop.

### Delete Confirmation

Pressing `Ctrl+D` on a tunnel or route shows a confirmation with full details:

```
┌──────────────────────────────────────────────────┐
│                                                  │
│  Delete tunnel?                                  │
│  remote 0.0.0.0:445 → 127.0.0.1:445             │
│  (session b040e8bd5711)                          │
│                                                  │
│  Press y to confirm, n or esc to cancel          │
│                                                  │
└──────────────────────────────────────────────────┘
```

### Executing Commands

Press `x` in detail view:

```
  Command: [whoami]

  enter execute │ esc cancel
```

Output appears in the log panel. Commands run on the agent.

### File Transfer

Press `w` (download) or `p` (upload) in detail view:

```
  Download:
  Remote Path: [/etc/passwd]

  Upload:
  Local Path:  [./payload.exe]
  Remote Path: [/tmp/payload.exe]
```

## Status Bar

The bottom status bar shows:

```
  Sessions: 3 │ TUN: 1 │ ▲ 1.2K ▼ 3.4K │ Status message...
```

- **Sessions**: Total connected agents
- **TUN**: Number of sessions with TUN active
- **▲ ▼**: Total bytes in/out across all sessions
- **Status message**: Last action result or error

## Health Indicators

Each session has a health dot:

- `●` Green: Healthy, recent ping response
- `●` Yellow: Elevated RTT or missed pings
- `○` Gray: Disconnected or no recent activity
