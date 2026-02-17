# Burrow

One-command network pivoting and tunneling tool. Python prototype for the AI Attack Suite.

Inspired by ligolo-ng and chisel. Final production version will be a single Go static binary.

## Install

```bash
pip install -e .
```

## Usage

```bash
burrow pivot --target 10.0.0.1 --port 8443
burrow tunnel local --listen 127.0.0.1:8080 --remote 10.0.0.5:80
burrow tunnel remote --listen 0.0.0.0:9090 --remote 192.168.1.10:22
burrow proxy socks5 --listen 127.0.0.1:1080
burrow scan --subnet 10.0.0.0/24
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for module breakdown.
