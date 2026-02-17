"""TCP port forwarding — local and remote tunnel management."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class TunnelStatus(str, Enum):
    """Tunnel lifecycle states."""

    PENDING = "pending"
    ACTIVE = "active"
    CLOSED = "closed"
    ERROR = "error"


class TunnelDirection(str, Enum):
    """Tunnel direction type."""

    LOCAL = "local"  # listen locally, forward to remote
    REMOTE = "remote"  # listen remotely, forward to local


@dataclass
class Tunnel:
    """Represents a single port-forwarding tunnel."""

    id: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    direction: TunnelDirection
    protocol: str = "tcp"
    status: TunnelStatus = TunnelStatus.PENDING
    bytes_transferred: int = 0
    created_at: float = field(default_factory=time.time)
    closed_at: float | None = None

    @property
    def local_endpoint(self) -> str:
        return f"{self.local_addr}:{self.local_port}"

    @property
    def remote_endpoint(self) -> str:
        return f"{self.remote_addr}:{self.remote_port}"

    @property
    def is_active(self) -> bool:
        return self.status == TunnelStatus.ACTIVE

    @property
    def duration(self) -> float:
        """Duration in seconds since creation."""
        end = self.closed_at or time.time()
        return end - self.created_at

    def record_bytes(self, n: int) -> None:
        """Record bytes transferred through this tunnel."""
        self.bytes_transferred += n

    def close(self) -> None:
        """Close the tunnel."""
        self.status = TunnelStatus.CLOSED
        self.closed_at = time.time()


class TunnelManager:
    """Manages creation, listing, and teardown of tunnels."""

    def __init__(self) -> None:
        self._tunnels: dict[str, Tunnel] = {}

    @property
    def tunnels(self) -> list[Tunnel]:
        """Return all tunnels."""
        return list(self._tunnels.values())

    @property
    def active_tunnels(self) -> list[Tunnel]:
        """Return only active tunnels."""
        return [t for t in self._tunnels.values() if t.is_active]

    def create_local_forward(
        self,
        listen_addr: str,
        listen_port: int,
        remote_addr: str,
        remote_port: int,
        protocol: str = "tcp",
    ) -> Tunnel:
        """Create a local port forward: listen locally, forward to remote.

        In production, this would bind a local socket and relay traffic.
        """
        tunnel_id = str(uuid.uuid4())[:8]
        tunnel = Tunnel(
            id=tunnel_id,
            local_addr=listen_addr,
            local_port=listen_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            direction=TunnelDirection.LOCAL,
            protocol=protocol,
            status=TunnelStatus.ACTIVE,
        )
        self._tunnels[tunnel_id] = tunnel
        return tunnel

    def create_remote_forward(
        self,
        listen_addr: str,
        listen_port: int,
        remote_addr: str,
        remote_port: int,
        protocol: str = "tcp",
    ) -> Tunnel:
        """Create a remote port forward: listen remotely, forward to local.

        In production, the remote agent would open a listener.
        """
        tunnel_id = str(uuid.uuid4())[:8]
        tunnel = Tunnel(
            id=tunnel_id,
            local_addr=remote_addr,
            local_port=remote_port,
            remote_addr=listen_addr,
            remote_port=listen_port,
            direction=TunnelDirection.REMOTE,
            protocol=protocol,
            status=TunnelStatus.ACTIVE,
        )
        self._tunnels[tunnel_id] = tunnel
        return tunnel

    def get_tunnel(self, tunnel_id: str) -> Tunnel | None:
        """Get tunnel by ID."""
        return self._tunnels.get(tunnel_id)

    def list_tunnels(self, active_only: bool = False) -> list[Tunnel]:
        """List tunnels, optionally filtering to active only."""
        if active_only:
            return self.active_tunnels
        return self.tunnels

    def close_tunnel(self, tunnel_id: str) -> bool:
        """Close a tunnel by ID. Returns True if found and closed."""
        tunnel = self._tunnels.get(tunnel_id)
        if tunnel is None:
            return False
        if tunnel.status == TunnelStatus.CLOSED:
            return False
        tunnel.close()
        return True

    def close_all(self) -> int:
        """Close all active tunnels. Returns count closed."""
        count = 0
        for tunnel in self._tunnels.values():
            if tunnel.is_active:
                tunnel.close()
                count += 1
        return count

    def total_bytes_transferred(self) -> int:
        """Total bytes across all tunnels."""
        return sum(t.bytes_transferred for t in self._tunnels.values())
