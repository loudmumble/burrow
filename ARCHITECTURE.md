# Burrow Architecture

## Module Overview

```
src/burrow/
  cli.py        Click CLI entry point (pivot, tunnel, proxy, scan)
  config.py     BurrowConfig via Pydantic (listen/remote addr, proxy type, encryption, hop chain)
  proxy.py      SOCKS5 proxy — RFC 1928 protocol parsing and connection handling
  tunnel.py     TCP port forwarding — local and remote forward management
  reverse.py    Reverse tunnel connections with keepalive and reconnect
  pivot.py      Multi-hop pivot chain — route optimization and sequential setup
  discovery.py  Network topology auto-discovery — subnet scan, gateway ID, graph building
  crypto.py     WireGuard-style encryption — X25519 key exchange, ChaCha20-Poly1305/AES-256-GCM
```

## Data Flow

```
[Operator] --> burrow CLI --> PivotChain --> TunnelManager --> SOCKS5Proxy
                                  |              |
                            NetworkDiscovery  TunnelCrypto
                                  |              |
                            ReverseConnector <---+
```

## Integration Points

- **HOG**: Post-exploitation tunneling for lateral movement
- **Phantom**: Internal network scanning through pivots
- **Sentinel**: Encrypted C2 channel relay
