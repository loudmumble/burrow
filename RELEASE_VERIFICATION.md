# Release Verification — 2026-04-04

## Test Results

### `go test ./...` — ALL PASS
```
ok   github.com/loudmumble/burrow                    0.832s
ok   github.com/loudmumble/burrow/internal/certgen   (cached)
ok   github.com/loudmumble/burrow/internal/crypto     0.002s
ok   github.com/loudmumble/burrow/internal/discovery  (cached)
ok   github.com/loudmumble/burrow/internal/httptunnel (cached)
ok   github.com/loudmumble/burrow/internal/httptunnel/webshell (cached)
ok   github.com/loudmumble/burrow/internal/mux        0.003s
ok   github.com/loudmumble/burrow/internal/netstack   0.056s
ok   github.com/loudmumble/burrow/internal/pivot      0.214s
ok   github.com/loudmumble/burrow/internal/protocol   (cached)
ok   github.com/loudmumble/burrow/internal/proxy      0.319s
ok   github.com/loudmumble/burrow/internal/relay      0.058s
ok   github.com/loudmumble/burrow/internal/session    0.156s
ok   github.com/loudmumble/burrow/internal/transport   (cached)
ok   github.com/loudmumble/burrow/internal/transport/dns   0.053s
ok   github.com/loudmumble/burrow/internal/transport/http  (cached)
ok   github.com/loudmumble/burrow/internal/transport/icmp  0.002s
ok   github.com/loudmumble/burrow/internal/transport/raw   (cached)
ok   github.com/loudmumble/burrow/internal/transport/ws    50.741s
ok   github.com/loudmumble/burrow/internal/tun        (cached)
ok   github.com/loudmumble/burrow/internal/tunnel     (cached)
ok   github.com/loudmumble/burrow/internal/udp        (cached)
ok   github.com/loudmumble/burrow/internal/web        (cached)
```

No failing tests found — all 24 packages pass.

### `go build ./...` — CLEAN
No errors.

### `go vet ./...` — CLEAN
No issues.

### `make build-all` — ALL 11 BINARIES VERIFIED
```
Binary sizes:
  burrow                                        16M
  burrow-darwin-amd64                           16M
  burrow-darwin-arm64                           16M
  burrow-linux-amd64                            16M
  burrow-linux-arm64                            15M
  burrow-windows-amd64.exe                      16M
  stager                                        4.9M
  stager-evasion-linux-amd64                    4.9M
  stager-evasion-windows-amd64.exe              5.0M
  stager-linux-amd64                            4.9M
  stager-packed-linux-amd64                     3.4M
  stager-packed-windows-amd64.exe               3.8M
  stager-windows-amd64.exe                      5.0M

Verifying binaries...
  OK  burrow-linux-amd64
  OK  burrow-linux-arm64
  OK  burrow-windows-amd64.exe
  OK  burrow-darwin-amd64
  OK  burrow-darwin-arm64
  OK  stager-linux-amd64
  OK  stager-windows-amd64.exe
  OK  stager-evasion-linux-amd64
  OK  stager-evasion-windows-amd64.exe
  OK  stager-packed-linux-amd64
  OK  stager-packed-windows-amd64.exe

All 11 binaries verified.
```

## Sanitization Audit

### Files excluded from `~/agent-hq/projects/github-releases/burrow/`:
- `CLAUDE.md` — internal development instructions
- `ARCHITECTURE.md` — internal architecture notes
- `MANUALTESTING.md` — internal testing procedures
- `.claude/` — Claude Code config
- `.remember/` — session memory logs
- `.playwright-mcp/` — Playwright MCP config
- `server.log` — contained leaked API token
- `build/` — compiled binaries
- `update_readme.sh` — internal utility script
- `.anvil/` — anvil toolkit cache
- `burrow`, `burrow-dev` — stale root-level binaries

### Sanitized content:
- `Makefile:62` — replaced `ssh://git@gitlab.loudmumble.com:2424/loudmumble/anvil.git` with `<anvil-repo-url>`

### Verified clean (no matches):
- No internal IPs (192.168.50.x, 192.168.122.x)
- No `gitlab.loudmumble.com` or `loudmumble.com` references
- No real API keys, tokens, or secrets
- No `.env`, `.pem`, `.key`, or `.log` files
- No SSH keys or certificate material
- Only allowed `.md` file is `README.md`
- `.gitignore` updated to prevent accidental inclusion of sensitive files
