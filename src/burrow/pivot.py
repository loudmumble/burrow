"""Multi-hop pivot chain management.

Orchestrates tunnel chains through multiple compromised hosts,
managing the connection graph and routing traffic through hops.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from burrow.config import HopConfig


class HopStatus(str, Enum):
    """Status of a single pivot hop."""

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass
class PivotHop:
    """A single hop in a pivot chain."""

    id: str
    host: str
    port: int
    hop_index: int
    status: HopStatus = HopStatus.PENDING
    latency_ms: float = 0.0
    bytes_forwarded: int = 0
    established_at: Optional[float] = None
    error: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.status == HopStatus.ACTIVE

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def activate(self) -> None:
        """Mark this hop as active."""
        self.status = HopStatus.ACTIVE
        self.established_at = time.time()

    def fail(self, reason: str = "connection failed") -> None:
        """Mark this hop as failed."""
        self.status = HopStatus.FAILED
        self.error = reason

    def close(self) -> None:
        """Close this hop."""
        self.status = HopStatus.CLOSED

    def record_bytes(self, n: int) -> None:
        """Record bytes forwarded through this hop."""
        self.bytes_forwarded += n


@dataclass
class PivotChain:
    """An ordered chain of hops for multi-hop pivoting."""

    id: str
    hops: list[PivotHop] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def depth(self) -> int:
        """Number of hops in the chain."""
        return len(self.hops)

    @property
    def is_complete(self) -> bool:
        """True if all hops are active."""
        return all(h.is_active for h in self.hops) and self.depth > 0

    @property
    def failed_hops(self) -> list[PivotHop]:
        """Return hops that have failed."""
        return [h for h in self.hops if h.status == HopStatus.FAILED]

    @property
    def total_latency(self) -> float:
        """Sum of latencies across all hops (ms)."""
        return sum(h.latency_ms for h in self.hops)

    @property
    def total_bytes(self) -> int:
        """Total bytes forwarded through the chain."""
        return sum(h.bytes_forwarded for h in self.hops)

    def route_string(self) -> str:
        """Human-readable route description."""
        if not self.hops:
            return "(empty chain)"
        parts = [h.endpoint for h in self.hops]
        return " -> ".join(parts)

    def summary(self) -> dict:
        """Return a structured summary."""
        return {
            "id": self.id,
            "depth": self.depth,
            "complete": self.is_complete,
            "route": self.route_string(),
            "total_latency_ms": self.total_latency,
            "total_bytes": self.total_bytes,
            "hops": [
                {
                    "index": h.hop_index,
                    "endpoint": h.endpoint,
                    "status": h.status.value,
                    "latency_ms": h.latency_ms,
                }
                for h in self.hops
            ],
        }


class PivotManager:
    """Manages multi-hop pivot chains.

    Builds chains from HopConfig lists, tracks active chains,
    and handles chain teardown.
    """

    def __init__(self) -> None:
        self._chains: dict[str, PivotChain] = {}

    def create_chain(self, hops: list[HopConfig]) -> PivotChain:
        """Create a pivot chain from a list of hop configurations.

        Args:
            hops: Ordered list of HopConfig objects.

        Returns:
            A new PivotChain with all hops initialized.
        """
        chain_id = str(uuid.uuid4())[:8]
        chain = PivotChain(id=chain_id)

        for i, hop_cfg in enumerate(hops):
            hop = PivotHop(
                id=str(uuid.uuid4())[:8],
                host=hop_cfg.host,
                port=hop_cfg.port,
                hop_index=i,
            )
            chain.hops.append(hop)

        self._chains[chain_id] = chain
        return chain

    def activate_chain(self, chain_id: str) -> bool:
        """Activate all hops in a chain (simulate successful connections).

        Args:
            chain_id: ID of the chain to activate.

        Returns:
            True if chain was found and activated.
        """
        chain = self._chains.get(chain_id)
        if chain is None:
            return False

        for hop in chain.hops:
            hop.activate()
            hop.latency_ms = 5.0 * (hop.hop_index + 1)  # simulated latency

        return True

    def fail_hop(
        self, chain_id: str, hop_index: int, reason: str = "connection lost"
    ) -> bool:
        """Fail a specific hop in a chain.

        Args:
            chain_id: Chain identifier.
            hop_index: Index of the hop to fail.
            reason: Failure reason.

        Returns:
            True if hop was found and failed.
        """
        chain = self._chains.get(chain_id)
        if chain is None:
            return False
        if hop_index < 0 or hop_index >= len(chain.hops):
            return False

        chain.hops[hop_index].fail(reason)
        return True

    def close_chain(self, chain_id: str) -> bool:
        """Close all hops in a chain.

        Args:
            chain_id: Chain identifier.

        Returns:
            True if chain was found and closed.
        """
        chain = self._chains.get(chain_id)
        if chain is None:
            return False

        for hop in chain.hops:
            hop.close()
        return True

    def get_chain(self, chain_id: str) -> Optional[PivotChain]:
        """Get a chain by ID."""
        return self._chains.get(chain_id)

    def get_all_chains(self) -> list[PivotChain]:
        """Return all chains."""
        return list(self._chains.values())

    def get_active_chains(self) -> list[PivotChain]:
        """Return chains where all hops are active."""
        return [c for c in self._chains.values() if c.is_complete]

    def remove_chain(self, chain_id: str) -> bool:
        """Remove a chain entirely."""
        return self._chains.pop(chain_id, None) is not None

    def reset(self) -> None:
        """Clear all chains."""
        self._chains.clear()
