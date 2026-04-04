"""Tests for Burrow configuration models."""

from __future__ import annotations

import pytest

from burrow.config import BurrowConfig, EncryptionMode, HopConfig, ProxyType


class TestEncryptionMode:
    def test_values(self):
        assert EncryptionMode.NONE == "none"
        assert EncryptionMode.CHACHA20 == "chacha20-poly1305"
        assert EncryptionMode.AES_GCM == "aes-256-gcm"

    def test_is_string_enum(self):
        assert isinstance(EncryptionMode.NONE, str)


class TestProxyType:
    def test_values(self):
        assert ProxyType.SOCKS5 == "socks5"
        assert ProxyType.HTTP == "http"
        assert ProxyType.DIRECT == "direct"

    def test_is_string_enum(self):
        assert isinstance(ProxyType.SOCKS5, str)


class TestHopConfig:
    def test_defaults(self):
        hop = HopConfig(host="10.0.0.1")
        assert hop.host == "10.0.0.1"
        assert hop.port == 8443
        assert hop.credentials is None
        assert hop.tunnel_type == "tcp"

    def test_custom_port(self):
        hop = HopConfig(host="192.168.1.1", port=22)
        assert hop.port == 22

    def test_with_credentials(self):
        hop = HopConfig(host="10.0.0.1", port=22, credentials="user:pass")
        assert hop.credentials == "user:pass"


class TestBurrowConfig:
    def test_defaults(self, default_config: BurrowConfig):
        assert default_config.listen_addr == "127.0.0.1"
        assert default_config.listen_port == 8443
        assert default_config.remote_addr == ""
        assert default_config.remote_port == 0
        assert default_config.proxy_type == ProxyType.SOCKS5
        assert default_config.encryption == EncryptionMode.CHACHA20
        assert default_config.hop_chain == []
        assert default_config.keepalive_interval == 30
        assert default_config.reconnect_max_retries == 10
        assert default_config.reconnect_base_delay == 1.0

    def test_listen_endpoint(self, default_config: BurrowConfig):
        assert default_config.listen_endpoint == "127.0.0.1:8443"

    def test_listen_endpoint_custom(self):
        cfg = BurrowConfig(listen_addr="0.0.0.0", listen_port=9000)
        assert cfg.listen_endpoint == "0.0.0.0:9000"

    def test_remote_endpoint(self, default_config: BurrowConfig):
        assert default_config.remote_endpoint == ":0"

    def test_remote_endpoint_custom(self):
        cfg = BurrowConfig(remote_addr="10.0.0.5", remote_port=4444)
        assert cfg.remote_endpoint == "10.0.0.5:4444"

    def test_add_hop(self, default_config: BurrowConfig):
        default_config.add_hop("10.0.0.1", port=22)
        assert len(default_config.hop_chain) == 1
        assert default_config.hop_chain[0].host == "10.0.0.1"
        assert default_config.hop_chain[0].port == 22

    def test_add_multiple_hops(self, default_config: BurrowConfig):
        default_config.add_hop("10.0.0.1", port=22)
        default_config.add_hop("10.0.0.2", port=443)
        default_config.add_hop("10.0.0.3", port=8443)
        assert len(default_config.hop_chain) == 3
        assert default_config.hop_chain[2].host == "10.0.0.3"

    def test_add_hop_default_port(self, default_config: BurrowConfig):
        default_config.add_hop("10.0.0.1")
        assert default_config.hop_chain[0].port == 8443

    def test_to_dict(self, default_config: BurrowConfig):
        d = default_config.to_dict()
        assert isinstance(d, dict)
        assert d["listen_addr"] == "127.0.0.1"
        assert d["listen_port"] == 8443
        assert d["proxy_type"] == "socks5"
        assert d["encryption"] == "chacha20-poly1305"
        assert d["hop_chain"] == []

    def test_to_dict_with_hops(self, default_config: BurrowConfig):
        default_config.add_hop("10.0.0.1", port=22)
        d = default_config.to_dict()
        assert len(d["hop_chain"]) == 1
        assert d["hop_chain"][0]["host"] == "10.0.0.1"

    def test_hop_chain_isolation(self):
        cfg1 = BurrowConfig()
        cfg2 = BurrowConfig()
        cfg1.add_hop("10.0.0.1")
        assert len(cfg2.hop_chain) == 0
