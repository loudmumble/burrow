"""MCP server for Burrow — One-command network pivoting and tunneling.

Exposes forward, reverse, proxy, pivot, and discover commands as MCP tools.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

server = Server("burrow")

def get_burrow_bin() -> str:
    if os.path.isfile("./burrow") and os.access("./burrow", os.X_OK):
        return "./burrow"
    path = shutil.which("burrow")
    if path:
        return path
    raise FileNotFoundError("burrow binary not found in current directory or PATH")

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
                        "type": "string",
                        "description": "Authentication (username:password).",
                        "default": "",
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
                    "target": {
                        "type": "string",
                        "description": "Final target host IP/domain.",
                    },
                    "port": {
                        "type": "integer",
                        "description": "Final target port.",
                    },
                    "hops": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of host:port pairs for the pivot chain.",
                    },
                    "local_port": {
                        "type": "integer",
                        "description": "Open local listener on this port (optional).",
                        "default": 0,
                    }
                },
                "required": ["target", "port"],
            },
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    try:
        bin_path = get_burrow_bin()
    except FileNotFoundError as e:
        return [types.TextContent(type="text", text=json.dumps({"error": str(e)}))]

    if name == "forward":
        listen = arguments.get("listen", "127.0.0.1:8443")
        remote = arguments["remote"]
        cmd = [bin_path, "tunnel", "local", "--listen", listen, "--remote", remote]
        result = await _run_background(cmd)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "reverse":
        listen = arguments["listen"]
        target = arguments.get("target", "127.0.0.1:22")
        cmd = [bin_path, "tunnel", "remote", "--listen", listen, "--remote", target]
        result = await _run_background(cmd)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "proxy":
        addr = arguments.get("addr", "127.0.0.1")
        port = arguments.get("port", 1080)
        auth = arguments.get("auth", "")
        listen = f"{addr}:{port}"
        cmd = [bin_path, "proxy", "socks5", "--listen", listen]
        if auth:
            cmd.extend(["--auth", auth])
        result = await _run_background(cmd)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    elif name == "pivot":
        target = arguments["target"]
        port = str(arguments["port"])
        hops = arguments.get("hops", [])
        local_port = str(arguments.get("local_port", 0))
        cmd = [bin_path, "pivot", "--target", target, "--port", port]
        for h in hops:
            cmd.extend(["--hop", h])
        if local_port != "0":
            cmd.extend(["--local-port", local_port])
        result = await _run_background(cmd)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    raise ValueError(f"Unknown tool: {name}")

async def _run_background(cmd: list[str]) -> dict:
    """Run a burrow command as a background subprocess and return immediately."""
    try:
        # Start the process in the background
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        return {
            "status": "started",
            "pid": proc.pid,
            "command": " ".join(cmd),
            "info": "Process is running in the background."
        }
    except Exception as e:
        return {"error": str(e)}

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
