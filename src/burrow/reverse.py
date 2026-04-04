"""Reverse tunnel connections with keepalive and reconnect strategy."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class SessionState(str, Enum):
    """Reverse session states."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


@dataclass
class ReverseSession:
    """Tracks a reverse connection session."""

    id: str
    controller_addr: str
    controller_port: int
    state: SessionState = SessionState.DISCONNECTED
    connect_attempts: int = 0
    last_heartbeat: float | None = None
    established_at: float | None = None
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def is_connected(self) -> bool:
        return self.state == SessionState.CONNECTED

    @property
    def uptime(self) -> float:
        """Seconds since session was established. 0 if not connected."""
        if self.established_at is None:
            return 0.0
        return time.time() - self.established_at

    @property
    def endpoint(self) -> str:
        return f"{self.controller_addr}:{self.controller_port}"


class ReverseConnector:
    """Manages reverse tunnel connections back to a controller.

    Implements exponential backoff reconnection and keepalive heartbeats.
    """

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        max_retries: int = 10,
        keepalive_interval: float = 30.0,
        jitter: float = 0.1,
    ) -> None:
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.keepalive_interval = keepalive_interval
        self.jitter = jitter
        self._sessions: dict[str, ReverseSession] = {}
        self._retry_counts: dict[str, int] = {}

    @property
    def sessions(self) -> list[ReverseSession]:
        """All reverse sessions."""
        return list(self._sessions.values())

    def establish_reverse(
        self, controller_addr: str, controller_port: int
    ) -> ReverseSession:
        """Establish a reverse connection back to the controller.

        In production, this would open a TCP connection outbound.
        Here we create and track the session state.
        """
        session_id = str(uuid.uuid4())[:8]
        session = ReverseSession(
            id=session_id,
            controller_addr=controller_addr,
            controller_port=controller_port,
            state=SessionState.CONNECTING,
            connect_attempts=1,
        )
        # Simulate successful connection
        session.state = SessionState.CONNECTED
        session.established_at = time.time()
        session.last_heartbeat = time.time()
        self._sessions[session_id] = session
        self._retry_counts[session_id] = 0
        return session

    def maintain_keepalive(self, session_id: str) -> bool:
        """Send heartbeat for a session. Returns True if session is alive."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        if session.state != SessionState.CONNECTED:
            return False
        session.last_heartbeat = time.time()
        return True

    def is_heartbeat_overdue(self, session_id: str) -> bool:
        """Check if heartbeat is overdue for a session."""
        session = self._sessions.get(session_id)
        if session is None or session.last_heartbeat is None:
            return True
        elapsed = time.time() - session.last_heartbeat
        return elapsed > self.keepalive_interval

    def reconnect_delay(self, session_id: str) -> float:
        """Calculate next reconnection delay with exponential backoff.

        delay = min(base_delay * 2^retries, max_delay)
        """
        retries = self._retry_counts.get(session_id, 0)
        delay = min(self.base_delay * (2**retries), self.max_delay)
        return delay

    def reconnect_strategy(self, session_id: str) -> dict[str, object]:
        """Get the reconnection strategy for a session.

        Returns dict with delay, attempt number, and whether to keep trying.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return {"should_retry": False, "reason": "session_not_found"}

        retries = self._retry_counts.get(session_id, 0)
        should_retry = retries < self.max_retries

        return {
            "should_retry": should_retry,
            "attempt": retries + 1,
            "max_retries": self.max_retries,
            "delay": self.reconnect_delay(session_id),
            "reason": "ok" if should_retry else "max_retries_exceeded",
        }

    def simulate_disconnect(self, session_id: str) -> bool:
        """Simulate a disconnection for testing reconnect logic."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = SessionState.RECONNECTING
        self._retry_counts[session_id] = self._retry_counts.get(session_id, 0) + 1
        return True

    def simulate_reconnect(self, session_id: str) -> bool:
        """Simulate a successful reconnection."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = SessionState.CONNECTED
        session.last_heartbeat = time.time()
        session.connect_attempts += 1
        self._retry_counts[session_id] = 0
        return True

    def mark_failed(self, session_id: str) -> bool:
        """Mark a session as permanently failed."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = SessionState.FAILED
        return True

    def get_session(self, session_id: str) -> ReverseSession | None:
        """Get session by ID."""
        return self._sessions.get(session_id)

    def close_session(self, session_id: str) -> bool:
        """Close and remove a session."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.state = SessionState.DISCONNECTED
        self._retry_counts.pop(session_id, None)
        return True
