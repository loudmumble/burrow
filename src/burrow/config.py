"""Burrow configuration models."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ProxyType(str, Enum):
    """Supported proxy protocols."""

    SOCKS5 = "socks5"
    HTTP = "http"
    DIRECT = "direct"


class EncryptionMode(str, Enum):
    """Tunnel encryption modes."""

    NONE = "none"
    CHACHA20 = "chacha20-poly1305"
    AES_GCM = "aes-256-gcm"


class HopConfig(BaseModel):
    """Configuration for a single pivot hop."""

    host: str
    port: int = 8443
    credentials: Optional[str] = None
    tunnel_type: str = "tcp"


class BurrowConfig(BaseModel):
    """Main configuration for a Burrow session."""

    listen_addr: str = "127.0.0.1"
    listen_port: int = 8443
    remote_addr: str = ""
    remote_port: int = 0
    proxy_type: ProxyType = ProxyType.SOCKS5
    encryption: EncryptionMode = EncryptionMode.CHACHA20
    hop_chain: list[HopConfig] = Field(default_factory=list)
    keepalive_interval: int = 30
    reconnect_max_retries: int = 10
    reconnect_base_delay: float = 1.0

    def add_hop(self, host: str, port: int = 8443, **kwargs: object) -> None:
        """Append a hop to the chain."""
        self.hop_chain.append(HopConfig(host=host, port=port, **kwargs))  # type: ignore[arg-type]

    @property
    def listen_endpoint(self) -> str:
        """Return listen address as host:port string."""
        return f"{self.listen_addr}:{self.listen_port}"

    @property
    def remote_endpoint(self) -> str:
        """Return remote address as host:port string."""
        return f"{self.remote_addr}:{self.remote_port}"

    def to_dict(self) -> dict[str, object]:
        """Serialize config to dict."""
        return self.model_dump()
