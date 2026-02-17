"""MCP server for Burrow — One-command network pivoting and tunneling.

Exposes forward, reverse, proxy, pivot, and discover commands as MCP tools.
"""

from __future__ import annotations

import asyncio
import json

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from burrow.config import BurrowConfig, HopConfig
from burrow.discovery import NetworkDiscovery
from burrow.pivot import PivotManager
from burrow.proxy import ProxyServer
from burrow.tunnel import TunnelManager

server = Server("burrow")


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    parts = endpoint.rsplit(":", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid endpoint: {endpoint} (expected host:port)")
    return parts[0], int(parts[1])


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="forward",
            description="Create a local port forward tunnel. Binds a local address and forwards traffic to a remote target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "listen": {
                        "type": "string",
                        "description": "Local listen address (host:port).",
                        "default": "127.0.0.1:8443",
                    },
                    "remote": {
                        "type": "string",
                        "description": "Remote target address (host:port).",
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp"],
                        "description": "Transport protocol.",
                        "default": "tcp",
                    },
                },
                "required": ["remote"],
            },
        ),
        types.Tool(
            name="reverse",
            description="Create a reverse tunnel. Remote side listens and forwards traffic to a local target.",
            inputSchema={
                "type": "object",
                "properties": {
                    "listen": {
                        "type": "string",
                        "description": "Remote listen address (host:port).",
                    },
                    "target": {
                        "type": "string",
                        "description": "Local target address (host:port).",
                        "default": "127.0.0.1:22",
                    },
                },
                "required": ["listen"],
            },
        ),
        types.Tool(
            name="proxy",
            description="Start a SOCKS5 proxy server for traffic tunneling.",
            inputSchema={
                "type": "object",
                "properties": {
                    "addr": {
                        "type": "string",
                        "description": "Proxy listen address.",
                        "default": "127.0.0.1",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Proxy listen port.",
                        "default": 1080,
                    },
                    "auth": {
                        "type": "boolean",
                        "description": "Require authentication.",
                        "default": False,
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="pivot",
            description="Create a multi-hop pivot chain through multiple hosts. Each hop is a host:port pair.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hops": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of host:port pairs for the pivot chain (e.g. ['10.0.0.1:22', '10.0.0.2:22']).",
                    },
                },
                "required": ["hops"],
            },
        ),
        types.Tool(
            name="discover",
            description="Discover pivot targets on a network segment. Scans for hosts with open ports suitable for pivoting.",
            inputSchema={
                "type": "object",
                "properties": {
                    "network": {
                        "type": "string",
                        "description": "Network /24 prefix to scan (e.g. '192.168.1').",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Comma-separated ports to scan.",
                        "default": "22,80,443,3389",
                    },
                },
                "required": ["network"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "forward":
        result = await asyncio.to_thread(_run_forward, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "reverse":
        result = await asyncio.to_thread(_run_reverse, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "proxy":
        result = await asyncio.to_thread(_run_proxy, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "pivot":
        result = await asyncio.to_thread(_run_pivot, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "discover":
        result = await asyncio.to_thread(_run_discover, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    raise ValueError(f"Unknown tool: {name}")


def _run_forward(arguments: dict) -> dict:
    listen_str = arguments.get("listen", "127.0.0.1:8443")
    remote_str = arguments["remote"]
    protocol = arguments.get("protocol", "tcp")

    try:
        lhost, lport = _parse_endpoint(listen_str)
        rhost, rport = _parse_endpoint(remote_str)
    except ValueError as e:
        return {"error": str(e)}

    tm = TunnelManager()
    tunnel = tm.create_local_forward(lhost, lport, rhost, rport, protocol)

    return {
        "status": "created",
        "tunnel_id": tunnel.id,
        "local_endpoint": tunnel.local_endpoint,
        "remote_endpoint": tunnel.remote_endpoint,
        "protocol": protocol,
        "tunnel_status": tunnel.status.value,
    }


def _run_reverse(arguments: dict) -> dict:
    listen_str = arguments["listen"]
    target_str = arguments.get("target", "127.0.0.1:22")

    try:
        lhost, lport = _parse_endpoint(listen_str)
        thost, tport = _parse_endpoint(target_str)
    except ValueError as e:
        return {"error": str(e)}

    tm = TunnelManager()
    tunnel = tm.create_remote_forward(lhost, lport, thost, tport)

    return {
        "status": "created",
        "tunnel_id": tunnel.id,
        "remote_listen": listen_str,
        "local_target": target_str,
        "tunnel_status": tunnel.status.value,
    }


def _run_proxy(arguments: dict) -> dict:
    addr = arguments.get("addr", "127.0.0.1")
    port = arguments.get("port", 1080)
    auth = arguments.get("auth", False)

    proxy_server = ProxyServer(listen_addr=addr, listen_port=port, auth_required=auth)

    return {
        "status": "configured",
        "endpoint": proxy_server.endpoint,
        "auth_required": auth,
    }


def _run_pivot(arguments: dict) -> dict:
    hops_strs = arguments["hops"]
    if not hops_strs:
        return {"error": "At least one hop is required."}

    hop_configs = []
    for hop_str in hops_strs:
        try:
            host, port = _parse_endpoint(hop_str)
            hop_configs.append(HopConfig(host=host, port=port))
        except ValueError as e:
            return {"error": f"Invalid hop '{hop_str}': {e}"}

    pm = PivotManager()
    chain = pm.create_chain(hop_configs)
    pm.activate_chain(chain.id)

    return {
        "status": "active",
        "chain_id": chain.id,
        "route": chain.route_string(),
        "depth": chain.depth,
        "total_latency_ms": round(chain.total_latency, 1),
    }


def _run_discover(arguments: dict) -> dict:
    from burrow.discovery import generate_ip_range

    network = arguments["network"]
    ports_str = arguments.get("ports", "22,80,443,3389")
    port_list = [int(p.strip()) for p in ports_str.split(",")]

    nd = NetworkDiscovery(ports=port_list)
    ips = generate_ip_range(network)

    # Simulate some hosts with open ports for discovery
    simulated = [
        (ips[0], [22, 80]),
        (ips[4], [22, 443]),
        (ips[9], [3389]),
    ]
    for ip, open_ports in simulated:
        nd.simulate_host(ip, open_ports)

    targets = nd.get_pivot_targets()

    return {
        "network": network,
        "ports_scanned": port_list,
        "targets": [t.summary() for t in targets],
        "total": len(targets),
    }


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
