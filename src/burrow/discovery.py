"""Network discovery for pivoting targets.

Scans local network segments to find reachable hosts and services,
identifying potential pivot points.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PortState(str, Enum):
    """State of a scanned port."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class ServiceGuess(str, Enum):
    """Common service identification by port."""

    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"
    RDP = "rdp"
    SMB = "smb"
    FTP = "ftp"
    TELNET = "telnet"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    REDIS = "redis"
    UNKNOWN = "unknown"


# Port to service mapping for quick identification
PORT_SERVICES: dict[int, ServiceGuess] = {
    21: ServiceGuess.FTP,
    22: ServiceGuess.SSH,
    23: ServiceGuess.TELNET,
    80: ServiceGuess.HTTP,
    443: ServiceGuess.HTTPS,
    445: ServiceGuess.SMB,
    3306: ServiceGuess.MYSQL,
    3389: ServiceGuess.RDP,
    5432: ServiceGuess.POSTGRES,
    6379: ServiceGuess.REDIS,
}

# Default ports to scan for pivot discovery
DEFAULT_PIVOT_PORTS = [22, 80, 443, 445, 3389, 8080, 8443]


@dataclass
class PortResult:
    """Result of scanning a single port."""

    port: int
    state: PortState
    service: ServiceGuess = ServiceGuess.UNKNOWN
    banner: Optional[str] = None
    latency_ms: float = 0.0

    @property
    def is_open(self) -> bool:
        return self.state == PortState.OPEN

    @property
    def is_pivot_candidate(self) -> bool:
        """True if this port could be used for pivoting."""
        return self.is_open and self.service in {
            ServiceGuess.SSH,
            ServiceGuess.HTTP,
            ServiceGuess.HTTPS,
            ServiceGuess.RDP,
        }


@dataclass
class HostResult:
    """Result of scanning a single host."""

    ip: str
    reachable: bool = False
    ports: list[PortResult] = field(default_factory=list)
    hostname: Optional[str] = None
    scan_time: float = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        """Return only open ports."""
        return [p for p in self.ports if p.is_open]

    @property
    def pivot_candidates(self) -> list[PortResult]:
        """Return ports usable for pivoting."""
        return [p for p in self.ports if p.is_pivot_candidate]

    @property
    def service_list(self) -> list[str]:
        """Return list of detected services."""
        return [
            p.service.value
            for p in self.open_ports
            if p.service != ServiceGuess.UNKNOWN
        ]

    def summary(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "reachable": self.reachable,
            "open_ports": [p.port for p in self.open_ports],
            "services": self.service_list,
            "pivot_candidates": [p.port for p in self.pivot_candidates],
            "scan_time": round(self.scan_time, 3),
        }


def guess_service(port: int) -> ServiceGuess:
    """Guess service from port number."""
    return PORT_SERVICES.get(port, ServiceGuess.UNKNOWN)


def scan_port_sync(host: str, port: int, timeout: float = 2.0) -> PortResult:
    """Scan a single TCP port synchronously.

    Args:
        host: Target IP or hostname.
        port: Port number to scan.
        timeout: Connection timeout in seconds.

    Returns:
        PortResult with state and timing.
    """
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result_code = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000  # ms

        if result_code == 0:
            state = PortState.OPEN
        else:
            state = PortState.CLOSED

        sock.close()
    except socket.timeout:
        elapsed = (time.time() - start) * 1000
        state = PortState.FILTERED
    except OSError:
        elapsed = (time.time() - start) * 1000
        state = PortState.CLOSED

    return PortResult(
        port=port,
        state=state,
        service=guess_service(port),
        latency_ms=elapsed,
    )


def generate_ip_range(network: str) -> list[str]:
    """Generate a list of IPs from a /24 network prefix.

    Args:
        network: Network prefix like '192.168.1' (assumes /24).

    Returns:
        List of 254 host IPs (1-254).
    """
    parts = network.strip().split(".")
    if len(parts) < 3:
        raise ValueError(f"Invalid network prefix: {network} (need at least 3 octets)")
    prefix = ".".join(parts[:3])
    return [f"{prefix}.{i}" for i in range(1, 255)]


class NetworkDiscovery:
    """Discovers potential pivot targets on the local network.

    Provides both simulated and real (sync) scanning capabilities.
    """

    def __init__(self, timeout: float = 2.0, ports: Optional[list[int]] = None) -> None:
        self.timeout = timeout
        self.ports = ports or DEFAULT_PIVOT_PORTS
        self._results: dict[str, HostResult] = {}

    def scan_host(self, ip: str) -> HostResult:
        """Scan a single host across configured ports.

        Note: Uses real socket connections. May be slow in tests.
        For unit tests, use simulate_host() instead.

        Args:
            ip: Target IP address.

        Returns:
            HostResult with port states.
        """
        start = time.time()
        host_result = HostResult(ip=ip)

        for port in self.ports:
            pr = scan_port_sync(ip, port, self.timeout)
            host_result.ports.append(pr)
            if pr.is_open:
                host_result.reachable = True

        host_result.scan_time = time.time() - start
        self._results[ip] = host_result
        return host_result

    def simulate_host(self, ip: str, open_ports: list[int]) -> HostResult:
        """Simulate a host scan result without real network I/O.

        Args:
            ip: Target IP address.
            open_ports: Ports to mark as open.

        Returns:
            Simulated HostResult.
        """
        host_result = HostResult(ip=ip, reachable=len(open_ports) > 0)

        for port in self.ports:
            state = PortState.OPEN if port in open_ports else PortState.CLOSED
            pr = PortResult(
                port=port,
                state=state,
                service=guess_service(port),
                latency_ms=1.0 if state == PortState.OPEN else 0.5,
            )
            host_result.ports.append(pr)

        host_result.scan_time = 0.01
        self._results[ip] = host_result
        return host_result

    def get_results(self) -> list[HostResult]:
        """Return all scan results."""
        return list(self._results.values())

    def get_pivot_targets(self) -> list[HostResult]:
        """Return hosts with pivot-candidate ports."""
        return [h for h in self._results.values() if h.pivot_candidates]

    def reset(self) -> None:
        """Clear all results."""
        self._results.clear()
