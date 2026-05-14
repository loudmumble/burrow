"""SOCKS5 proxy implementation (RFC 1928).

Handles protocol parsing, connection establishment, and proxy server lifecycle.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# SOCKS5 constants
SOCKS_VERSION = 0x05


class AuthMethod(IntEnum):
    """SOCKS5 authentication methods."""

    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


class AddressType(IntEnum):
    """SOCKS5 address types."""

    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04


class Command(IntEnum):
    """SOCKS5 request commands."""

    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class ReplyCode(IntEnum):
    """SOCKS5 reply codes."""

    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


@dataclass
class Socks5Greeting:
    """Parsed SOCKS5 client greeting."""

    version: int
    auth_methods: list[int]


@dataclass
class Socks5Request:
    """Parsed SOCKS5 client request."""

    version: int
    command: Command
    address_type: AddressType
    dest_addr: str
    dest_port: int


@dataclass
class Socks5Response:
    """SOCKS5 server response."""

    reply_code: ReplyCode
    bound_addr: str = "0.0.0.0"
    bound_port: int = 0


def parse_socks5_greeting(data: bytes) -> Socks5Greeting:
    """Parse a SOCKS5 client greeting message.

    Format: VER(1) | NMETHODS(1) | METHODS(NMETHODS)
    """
    if len(data) < 2:
        raise ValueError("Greeting too short")
    version = data[0]
    if version != SOCKS_VERSION:
        raise ValueError(f"Unsupported SOCKS version: {version}")
    n_methods = data[1]
    if len(data) < 2 + n_methods:
        raise ValueError(
            f"Greeting truncated: expected {2 + n_methods} bytes, got {len(data)}"
        )
    methods = list(data[2 : 2 + n_methods])
    return Socks5Greeting(version=version, auth_methods=methods)


def create_greeting_response(method: AuthMethod = AuthMethod.NO_AUTH) -> bytes:
    """Create server greeting response selecting an auth method.

    Format: VER(1) | METHOD(1)
    """
    return struct.pack("BB", SOCKS_VERSION, method)


def parse_socks5_request(data: bytes) -> Socks5Request:
    """Parse a SOCKS5 connection request.

    Format: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR(var) | DST.PORT(2)
    """
    if len(data) < 4:
        raise ValueError("Request too short")
    version = data[0]
    if version != SOCKS_VERSION:
        raise ValueError(f"Unsupported SOCKS version: {version}")
    command = Command(data[1])
    # data[2] is reserved
    atyp = AddressType(data[3])

    offset = 4
    if atyp == AddressType.IPV4:
        if len(data) < offset + 4 + 2:
            raise ValueError("IPv4 request too short")
        addr = socket.inet_ntoa(data[offset : offset + 4])
        offset += 4
    elif atyp == AddressType.DOMAIN:
        domain_len = data[offset]
        offset += 1
        if len(data) < offset + domain_len + 2:
            raise ValueError("Domain request too short")
        addr = data[offset : offset + domain_len].decode("ascii")
        offset += domain_len
    elif atyp == AddressType.IPV6:
        if len(data) < offset + 16 + 2:
            raise ValueError("IPv6 request too short")
        addr = socket.inet_ntop(socket.AF_INET6, data[offset : offset + 16])
        offset += 16
    else:
        raise ValueError(f"Unsupported address type: {atyp}")

    port = struct.unpack("!H", data[offset : offset + 2])[0]
    return Socks5Request(
        version=version,
        command=command,
        address_type=atyp,
        dest_addr=addr,
        dest_port=port,
    )


def create_socks5_response(
    reply_code: ReplyCode,
    bound_addr: str = "0.0.0.0",
    bound_port: int = 0,
) -> bytes:
    """Create a SOCKS5 response message.

    Format: VER(1) | REP(1) | RSV(1) | ATYP(1) | BND.ADDR(4) | BND.PORT(2)
    """
    addr_bytes = socket.inet_aton(bound_addr)
    return struct.pack(
        "!BBBB4sH",
        SOCKS_VERSION,
        reply_code,
        0x00,  # reserved
        AddressType.IPV4,
        addr_bytes,
        bound_port,
    )


def handle_connect(
    dest_addr: str, dest_port: int, timeout: float = 10.0
) -> socket.socket:
    """Resolve and connect to destination address.

    Returns a connected socket on success.
    Raises ConnectionError on failure.
    """
    try:
        addr_info = socket.getaddrinfo(
            dest_addr, dest_port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ConnectionError(f"Failed to resolve {dest_addr}: {exc}") from exc

    last_err: Exception | None = None
    for family, socktype, proto, _canonname, sockaddr in addr_info:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_err = exc
            sock.close()

    raise ConnectionError(f"Failed to connect to {dest_addr}:{dest_port}: {last_err}")


@dataclass
class ProxyServer:
    """SOCKS5 proxy server with start/stop lifecycle.

    NOTE: This prototype does not open real sockets in tests.
    The server logic manages state; actual I/O is deferred to Go production.
    """

    listen_addr: str = "127.0.0.1"
    listen_port: int = 1080
    auth_required: bool = False
    _running: bool = field(default=False, repr=False)
    _connections: int = field(default=0, repr=False)
    _bytes_relayed: int = field(default=0, repr=False)

    @property
    def is_running(self) -> bool:
        """Whether the proxy server is active."""
        return self._running

    @property
    def active_connections(self) -> int:
        """Number of active connections."""
        return self._connections

    @property
    def bytes_relayed(self) -> int:
        """Total bytes relayed through proxy."""
        return self._bytes_relayed

    @property
    def endpoint(self) -> str:
        """Return listen endpoint string."""
        return f"{self.listen_addr}:{self.listen_port}"

    def start(self) -> None:
        """Start the proxy server."""
        if self._running:
            raise RuntimeError("Proxy server already running")
        self._running = True
        self._connections = 0
        self._bytes_relayed = 0

    def stop(self) -> None:
        """Stop the proxy server."""
        if not self._running:
            raise RuntimeError("Proxy server not running")
        self._running = False
        self._connections = 0

    def record_connection(self) -> None:
        """Record a new connection."""
        self._connections += 1

    def record_bytes(self, n: int) -> None:
        """Record bytes relayed."""
        self._bytes_relayed += n

    def process_greeting(self, data: bytes) -> tuple[Socks5Greeting, bytes]:
        """Process a client greeting and return parsed greeting + server response."""
        greeting = parse_socks5_greeting(data)
        if (
            self.auth_required
            and AuthMethod.USERNAME_PASSWORD not in greeting.auth_methods
        ):
            response = create_greeting_response(AuthMethod.NO_ACCEPTABLE)
        elif AuthMethod.NO_AUTH in greeting.auth_methods:
            response = create_greeting_response(AuthMethod.NO_AUTH)
        else:
            response = create_greeting_response(AuthMethod.NO_ACCEPTABLE)
        return greeting, response

    def process_request(self, data: bytes) -> tuple[Socks5Request, Optional[bytes]]:
        """Process a client request. Returns parsed request and response bytes.

        Only CONNECT command is supported in prototype.
        """
        request = parse_socks5_request(data)
        if request.command != Command.CONNECT:
            response = create_socks5_response(ReplyCode.COMMAND_NOT_SUPPORTED)
            return request, response
        # For CONNECT, caller handles actual connection — return None for response
        return request, None
