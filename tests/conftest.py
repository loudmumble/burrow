"""Shared fixtures for Burrow test suite."""

import socket
import struct

import pytest

from burrow.config import BurrowConfig, HopConfig, EncryptionMode, ProxyType
from burrow.proxy import SOCKS_VERSION, AddressType, Command
from burrow.tunnel import TunnelManager


@pytest.fixture
def default_config():
    """Default BurrowConfig."""
    return BurrowConfig()


@pytest.fixture
def tunnel_manager():
    """Fresh TunnelManager."""
    return TunnelManager()


@pytest.fixture
def three_hops():
    """Three HopConfig objects for pivot chain testing."""
    return [
        HopConfig(host="10.0.0.1", port=22),
        HopConfig(host="10.0.0.2", port=443),
        HopConfig(host="10.0.0.3", port=8443),
    ]


def build_socks5_greeting(methods: list[int] | None = None) -> bytes:
    """Build a valid SOCKS5 greeting message."""
    if methods is None:
        methods = [0x00]  # NO_AUTH
    return bytes([SOCKS_VERSION, len(methods)] + methods)


def build_socks5_request(
    cmd: int = Command.CONNECT,
    addr: str = "10.0.0.1",
    port: int = 80,
    atyp: int = AddressType.IPV4,
) -> bytes:
    """Build a valid SOCKS5 request message."""
    header = struct.pack("BBBB", SOCKS_VERSION, cmd, 0x00, atyp)
    if atyp == AddressType.IPV4:
        addr_bytes = socket.inet_aton(addr)
    elif atyp == AddressType.DOMAIN:
        encoded = addr.encode("ascii")
        addr_bytes = bytes([len(encoded)]) + encoded
    else:
        addr_bytes = b"\x00" * 16  # IPv6 placeholder
    port_bytes = struct.pack("!H", port)
    return header + addr_bytes + port_bytes
