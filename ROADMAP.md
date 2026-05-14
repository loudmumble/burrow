# Burrow Roadmap — v3.1 to v4.0

## Current State (v3.1)

Burrow v3.1 delivers a fully functional multi-transport network pivoting tool with TUN/TAP support, SOCKS5/HTTP proxy, port forwarding, pivot chains, encrypted sessions, interactive TUI, and cross-platform agent builds. The core tunneling and relay infrastructure is solid and field-tested.

This roadmap outlines the path from "works" to "best in class."

---

## v3.2 — Stability & Polish ✅

*The "actually finish what we started" release.*

The goal is zero surprises in the field. Every feature that exists should work perfectly before adding new ones.

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| Stale TUN lock | TUN gets stuck on a dead session, blocks new TUN starts until server restart | Critical | ✅ Done |
| Agent reconnect through nested tunnels | When a pivot drops, downstream agents should reconnect gracefully instead of dying | Critical | ✅ Done |
| Tunnel status accuracy | Show bind errors immediately in the TUI, not after a 40-minute delay | High | ✅ Done |
| Arrow key text editing | Navigate and edit TUI input fields with arrow keys instead of backspacing through entire strings | High | ✅ Done |
| TAP route verification | Log and verify the subnet route is actually applied after TAP starts | High | ✅ Done |
| Performance profiling | Identify and fix the TAP/TUN latency gap compared to ligolo-ng | Medium | ✅ Done |
| Debug relay opt-in | `--debug-relay` flag on the agent for on-demand TCP relay tracing | Medium | ✅ Done |
| Stager transport options | Stager currently only supports raw TCP — add WebSocket for restrictive environments | Medium | ✅ Done |

---

## v3.3 — SOCKS5 Completeness ✅

*Make SOCKS5 actually complete per RFC 1928.*

Most pentesting pain comes from SOCKS5 limitations. Fixing these removes the need for workarounds.

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| UDP ASSOCIATE | DNS resolution through SOCKS5 without proxychains hacks. Tools like nslookup, dig work natively | Critical | ✅ Done |
| SOCKS5 BIND | Tools that need incoming connections through the proxy (some relay tools, payload handlers) | High | ✅ Done |
| Per-session SOCKS5 | Each session gets its own SOCKS5 port (e.g., :1081, :1082) instead of one global proxy | High | ✅ Done |
| SOCKS5 chaining | Automatically chain through multiple sessions — select a session and its SOCKS5 routes through the correct path | Medium | ✅ Done |
| SOCKS5 auth per-session | Different credentials per session for access control | Low | ✅ Done |

---

## v3.4 — Network Intelligence ✅

*Built-in recon instead of relying on external tools.*

Switching between Burrow and nmap/nxc for basic recon breaks flow. Integrate the essentials.

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| TUI scan view | Select a session, enter a CIDR, scan for open ports. Results appear in the TUI as a target list | High | ✅ Done |
| Service detection | Auto-detect common services (SMB, RDP, SSH, HTTP, LDAP, Kerberos) on discovered ports | High | ✅ Done |
| Network topology map | ASCII visualization in the TUI showing discovered hosts, sessions, and tunnel paths | Medium | ✅ Done |
| Auto-route suggestion | After scanning, suggest which routes to add based on discovered subnets | Medium | ✅ Done |
| Host notes | Annotate discovered hosts with findings (credentials, services, vulnerabilities) | Medium | ✅ Done |
| Export to tools | Export scan results as nmap XML, CSV, or JSON for import into other tools | Low | ✅ Done |

---

## v3.5 — Operational Security ✅

*The features that separate a tool from a toy in real engagements.*

Persistent connections are a detection magnet. This release makes Burrow operationally responsible.

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| Beaconing with jitter | Configurable callback intervals (30s-5min) with random jitter instead of persistent connections | Critical | ✅ Done |
| Sleep/wake | Put an agent to sleep for a duration — no network activity, no detection surface | Critical | ✅ Done |
| Kill date | Agent self-destructs after a configured date/time — no orphaned implants | High | ✅ Done |
| Traffic shaping | Bandwidth limits per session to avoid anomalous traffic volume alerts | High | ✅ Done |
| Connection scheduling | Agent only connects during configured hours (e.g., business hours only) | Medium | ✅ Done |
| Malleable transport profiles | Customize TLS JA3 fingerprint, HTTP headers, WebSocket upgrade to match legitimate application traffic | Medium | ✅ Done |
| Session encryption rotation | Periodically rotate session keys to limit exposure from key compromise | Low | ✅ Done |

---

## v3.6 — Agent Evolution ✅

*Make the agent smarter and harder to catch.*

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| In-memory agent loading | Reflective loading — no file on disk. Stager downloads and executes agent in memory | Critical | ✅ Done |
| DNS/ICMP staging | Deploy the stager through DNS or ICMP when all TCP/HTTP egress is blocked | High | Deferred (v4+) |
| Self-update | Push a new agent binary through the existing session — no need to redeploy manually | High | ✅ Done |
| Agent-to-agent mesh | Agents connect to each other, not just to the server. If the server drops, the mesh persists and reroutes | High | ✅ Done |
| Process migration | Agent migrates to a different process for persistence and stealth (Windows) | Medium | Deferred (needs cgo) |
| Agent health monitoring | Report CPU/memory usage, detect if being debugged or sandboxed | Medium | ✅ Done |
| Platform-specific evasion | ETW patching, AMSI bypass, syscall unhooking (Windows). Seccomp awareness (Linux) | Medium | ✅ Done (Linux) |
| Minimal ARM/MIPS builds | IoT and embedded device support — sub-2MB agent for routers and appliances | Low | ✅ Done |

---

## v3.7 — Multi-Operator ✅

*Team engagement support.*

Solo pentesting is the exception. Most real work is team-based. This makes Burrow usable for teams.

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| Multi-user server | Multiple operators connect to the same server, see the same sessions simultaneously | Critical | ✅ Done |
| Operator authentication | Operators authenticate to the server — no anonymous access | Critical | ✅ Done |
| Session locking | Prevent two operators from issuing conflicting commands to the same session | High | ✅ Done |
| Operator permissions | Role-based access: read-only observer, operator, admin | High | ✅ Done |
| Audit log | Comprehensive timestamped log of every operator action for engagement reporting | High | ✅ Done |
| Shared loot | Centralized credential and finding storage accessible to all operators | Medium | ✅ Done |
| Operator chat/notes | In-TUI communication between operators — no need for a separate Slack/Discord | Low | Deferred |
| Engagement templates | Pre-configured session profiles, tunnel sets, and scan targets for common engagement types | Low | Deferred |

---

## v3.8 — Protocol Expansion ✅

*New transports and lateral movement options.*

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| DoH (DNS over HTTPS) | DNS queries routed through Cloudflare/Google HTTPS endpoints — looks like normal web traffic | Critical | ✅ Done |
| Domain fronting | Route agent traffic through CDNs (Cloudflare, Azure, AWS CloudFront) to hide the real C2 server | High | Deferred (CDN-specific) |
| HTTP/2 multiplexed transport | Agent traffic looks like normal HTTP/2 web browsing with interleaved streams | High | Deferred (stdlib pending) |
| Named pipe transport | Lateral movement within Windows networks using SMB named pipes — no new TCP connections | Medium | Deferred (Windows-only) |
| SMB transport | Tunnel through SMB for environments where SMB is expected traffic | Medium | Deferred (Windows-only) |
| WireGuard transport | Use WireGuard protocol framing — looks like a VPN, common in enterprise environments | Low | Deferred |
| QUIC transport | UDP-based transport that looks like HTTP/3 traffic | Low | Deferred |

---

## v4.0 — Architecture ✅

*The breaking-change release. New foundation for the next generation.*

| Item | Description | Priority | Status |
|------|-------------|----------|--------|
| Plugin architecture | Loadable modules (Go plugins or WASM) for custom post-exploitation without rebuilding the agent | Critical | ✅ Done |
| API-first design | Everything the TUI does is available via a clean REST API — enables automation and custom UIs | Critical | ✅ Done |
| Scriptable automation | Go SDK for automating complex multi-session workflows (scan → pivot → relay → dump) | High | ✅ Done |
| Cross-platform server | Full Windows and macOS server support — not just Linux | High | ✅ Done |
| Distributed server | Multiple servers share session state for redundancy — if one server goes down, sessions fail over | Medium | Deferred (v5) |
| Built-in credential relay | Native NTLM/Kerberos relay engine — no external ntlmrelayx dependency | Medium | Deferred (v5) |
| Traffic replay | Record and replay session traffic for debugging, reporting, and training | Medium | ✅ Done |
| Web-based TUI | Browser-accessible TUI via WebSocket — manage engagements from any device | Low | Deferred (v5) |

---

## Priority Legend

| Level | Meaning |
|-------|---------|
| Critical | Must have for the release — without it, the release isn't worth shipping |
| High | Significantly increases value — strong differentiator |
| Medium | Nice to have — improves experience but not a dealbreaker |
| Low | Future consideration — good idea, low urgency |

---

## Release Cadence

| Version | Focus | Target |
|---------|-------|--------|
| v3.2 | Stability, bug fixes, polish | Near-term |
| v3.3 | SOCKS5 completeness | Near-term |
| v3.4 | Network intelligence | Mid-term |
| v3.5 | Operational security | Mid-term |
| v3.6 | Agent evolution | Mid-term |
| v3.7 | Multi-operator | Long-term |
| v3.8 | Protocol expansion | Long-term |
| v4.0 | Architecture overhaul | Long-term |

Each release should be independently useful. A pentester on v3.3 should have a better experience than v3.1, even if they never upgrade to v4.0.

---

## Guiding Principles

1. **Field-tested before shipped.** Every feature gets tested in a real engagement scenario before release. No "works in unit tests" releases.

2. **One thing at a time.** Finish each release completely before starting the next. Half-implemented features are worse than missing features.

3. **Operator experience first.** If a feature makes the tool harder to use, it's not ready. Complexity should be in the code, not the interface.

4. **Respect the engagement.** Every bug in a pivoting tool is a potential burned engagement. Reliability is not optional.

5. **Credits where due.** This project builds on work by ligolo-ng, gvisor, reGeorg, chisel, yamux, water, and the Charm ecosystem. We acknowledge and respect their contributions.
