"""Command-line interface for Burrow.

Provides subcommands for tunnel management, pivot chain setup,
network discovery, and proxy server control.
"""

from __future__ import annotations

import click

from burrow import __version__
from burrow.config import BurrowConfig, HopConfig, ProxyType
from burrow.discovery import NetworkDiscovery
from burrow.pivot import PivotManager
from burrow.proxy import ProxyServer
from burrow.tunnel import TunnelManager


@click.group()
@click.version_option(version=__version__, prog_name="burrow")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Burrow -- One-command network pivoting and tunneling."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = BurrowConfig()


@main.command()
@click.option(
    "--listen", "-l", default="127.0.0.1:8443", help="Local listen address (host:port)"
)
@click.option("--remote", "-r", required=True, help="Remote target address (host:port)")
@click.option("--protocol", type=click.Choice(["tcp", "udp"]), default="tcp")
@click.pass_context
def forward(ctx: click.Context, listen: str, remote: str, protocol: str) -> None:
    """Create a local port forward tunnel."""
    lhost, lport = _parse_endpoint(listen)
    rhost, rport = _parse_endpoint(remote)

    tm = TunnelManager()
    tunnel = tm.create_local_forward(lhost, lport, rhost, rport, protocol)
    click.echo(
        f"Tunnel {tunnel.id}: {tunnel.local_endpoint} -> {tunnel.remote_endpoint} [{protocol}]"
    )
    click.echo(f"Status: {tunnel.status.value}")


@main.command()
@click.option("--listen", "-l", required=True, help="Remote listen address (host:port)")
@click.option(
    "--target", "-t", default="127.0.0.1:22", help="Local target address (host:port)"
)
@click.pass_context
def reverse(ctx: click.Context, listen: str, target: str) -> None:
    """Create a reverse tunnel (remote listens, forwards to local)."""
    lhost, lport = _parse_endpoint(listen)
    thost, tport = _parse_endpoint(target)

    tm = TunnelManager()
    tunnel = tm.create_remote_forward(lhost, lport, thost, tport)
    click.echo(f"Reverse tunnel {tunnel.id}: {listen} -> {target}")
    click.echo(f"Status: {tunnel.status.value}")


@main.command()
@click.option("--addr", default="127.0.0.1", help="Proxy listen address")
@click.option("--port", default=1080, type=int, help="Proxy listen port")
@click.option("--auth/--no-auth", default=False, help="Require authentication")
@click.pass_context
def proxy(ctx: click.Context, addr: str, port: int, auth: bool) -> None:
    """Start a SOCKS5 proxy server (stub)."""
    server = ProxyServer(listen_addr=addr, listen_port=port, auth_required=auth)
    click.echo(f"SOCKS5 proxy configured: {server.endpoint}")
    click.echo(f"Auth required: {auth}")
    click.echo("Note: Full proxy server requires async runtime.")


@main.command()
@click.argument("hops", nargs=-1, required=True)
@click.pass_context
def pivot(ctx: click.Context, hops: tuple[str, ...]) -> None:
    """Create a multi-hop pivot chain.

    HOPS are specified as host:port pairs.
    Example: burrow pivot 10.0.0.1:22 10.0.0.2:22 10.0.0.3:443
    """
    hop_configs = []
    for hop_str in hops:
        host, port = _parse_endpoint(hop_str)
        hop_configs.append(HopConfig(host=host, port=port))

    pm = PivotManager()
    chain = pm.create_chain(hop_configs)
    pm.activate_chain(chain.id)

    click.echo(f"Pivot chain {chain.id}: {chain.route_string()}")
    click.echo(f"Depth: {chain.depth} hops")
    click.echo(f"Total latency: {chain.total_latency:.1f}ms")


@main.command()
@click.argument("network")
@click.option(
    "--ports", "-p", default="22,80,443,3389", help="Comma-separated ports to scan"
)
@click.pass_context
def discover(ctx: click.Context, network: str, ports: str) -> None:
    """Discover pivot targets on a network (simulated).

    NETWORK is a /24 prefix like '192.168.1'.
    """
    port_list = [int(p.strip()) for p in ports.split(",")]
    nd = NetworkDiscovery(ports=port_list)

    # Simulate some hosts with open ports
    from burrow.discovery import generate_ip_range

    ips = generate_ip_range(network)

    # For CLI demo, simulate first 5 hosts
    simulated = [
        (ips[0], [22, 80]),
        (ips[4], [22, 443]),
        (ips[9], [3389]),
    ]
    for ip, open_ports in simulated:
        nd.simulate_host(ip, open_ports)

    targets = nd.get_pivot_targets()
    if not targets:
        click.echo("No pivot targets found.")
        return

    click.echo(f"Found {len(targets)} pivot target(s):")
    for t in targets:
        s = t.summary()
        click.echo(
            f"  {s['ip']} | Services: {', '.join(s['services'])} | Pivot ports: {s['pivot_candidates']}"
        )


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Parse host:port string."""
    parts = endpoint.rsplit(":", 1)
    if len(parts) != 2:
        raise click.BadParameter(f"Invalid endpoint: {endpoint} (expected host:port)")
    try:
        port = int(parts[1])
    except ValueError:
        raise click.BadParameter(f"Invalid port: {parts[1]}")
    return parts[0], port


if __name__ == "__main__":
    main()
