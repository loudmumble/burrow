"""Tests for TunnelManager and Tunnel lifecycle."""

from __future__ import annotations

import time

import pytest

from burrow.tunnel import Tunnel, TunnelDirection, TunnelManager, TunnelStatus


# ---------------------------------------------------------------------------
# TunnelManager — create_local_forward
# ---------------------------------------------------------------------------


class TestCreateLocalForward:
    def test_returns_tunnel(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        assert isinstance(t, Tunnel)

    def test_direction_is_local(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        assert t.direction == TunnelDirection.LOCAL

    def test_addresses_stored(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        assert t.local_addr == "127.0.0.1"
        assert t.local_port == 8080
        assert t.remote_addr == "10.0.0.5"
        assert t.remote_port == 80

    def test_status_is_active(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        assert t.status == TunnelStatus.ACTIVE
        assert t.is_active is True

    def test_custom_protocol(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward(
            "127.0.0.1", 8080, "10.0.0.5", 80, protocol="udp"
        )
        assert t.protocol == "udp"

    def test_stored_in_manager(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        assert tunnel_manager.get_tunnel(t.id) is t

    def test_unique_ids(self, tunnel_manager: TunnelManager):
        t1 = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        t2 = tunnel_manager.create_local_forward("127.0.0.1", 8081, "10.0.0.5", 81)
        assert t1.id != t2.id


# ---------------------------------------------------------------------------
# TunnelManager — create_remote_forward
# ---------------------------------------------------------------------------


class TestCreateRemoteForward:
    def test_returns_tunnel(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_remote_forward("0.0.0.0", 9090, "127.0.0.1", 22)
        assert isinstance(t, Tunnel)

    def test_direction_is_remote(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_remote_forward("0.0.0.0", 9090, "127.0.0.1", 22)
        assert t.direction == TunnelDirection.REMOTE

    def test_status_is_active(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_remote_forward("0.0.0.0", 9090, "127.0.0.1", 22)
        assert t.is_active is True

    def test_stored_in_manager(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_remote_forward("0.0.0.0", 9090, "127.0.0.1", 22)
        assert tunnel_manager.get_tunnel(t.id) is t


# ---------------------------------------------------------------------------
# TunnelManager — get_tunnel / list_tunnels / close_tunnel / close_all
# ---------------------------------------------------------------------------


class TestTunnelManagerOperations:
    def test_get_tunnel_missing_returns_none(self, tunnel_manager: TunnelManager):
        assert tunnel_manager.get_tunnel("nonexistent") is None

    def test_list_tunnels_empty(self, tunnel_manager: TunnelManager):
        assert tunnel_manager.list_tunnels() == []

    def test_list_tunnels_all(self, tunnel_manager: TunnelManager):
        tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        tunnel_manager.create_local_forward("127.0.0.1", 8081, "10.0.0.5", 81)
        assert len(tunnel_manager.list_tunnels()) == 2

    def test_list_tunnels_active_only(self, tunnel_manager: TunnelManager):
        t1 = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        t2 = tunnel_manager.create_local_forward("127.0.0.1", 8081, "10.0.0.5", 81)
        tunnel_manager.close_tunnel(t1.id)
        active = tunnel_manager.list_tunnels(active_only=True)
        assert len(active) == 1
        assert active[0].id == t2.id

    def test_close_tunnel_returns_true(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        assert tunnel_manager.close_tunnel(t.id) is True

    def test_close_tunnel_sets_closed_status(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        tunnel_manager.close_tunnel(t.id)
        assert t.status == TunnelStatus.CLOSED

    def test_close_tunnel_missing_returns_false(self, tunnel_manager: TunnelManager):
        assert tunnel_manager.close_tunnel("nonexistent") is False

    def test_close_already_closed_returns_false(self, tunnel_manager: TunnelManager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        tunnel_manager.close_tunnel(t.id)
        assert tunnel_manager.close_tunnel(t.id) is False

    def test_close_all_returns_count(self, tunnel_manager: TunnelManager):
        tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        tunnel_manager.create_local_forward("127.0.0.1", 8081, "10.0.0.5", 81)
        tunnel_manager.create_local_forward("127.0.0.1", 8082, "10.0.0.5", 82)
        count = tunnel_manager.close_all()
        assert count == 3

    def test_close_all_only_counts_active(self, tunnel_manager: TunnelManager):
        t1 = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        t2 = tunnel_manager.create_local_forward("127.0.0.1", 8081, "10.0.0.5", 81)
        tunnel_manager.close_tunnel(t1.id)
        count = tunnel_manager.close_all()
        assert count == 1

    def test_total_bytes_transferred_empty(self, tunnel_manager: TunnelManager):
        assert tunnel_manager.total_bytes_transferred() == 0

    def test_total_bytes_transferred_sum(self, tunnel_manager: TunnelManager):
        t1 = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)
        t2 = tunnel_manager.create_local_forward("127.0.0.1", 8081, "10.0.0.5", 81)
        t1.record_bytes(1000)
        t2.record_bytes(500)
        assert tunnel_manager.total_bytes_transferred() == 1500


# ---------------------------------------------------------------------------
# Tunnel — record_bytes / close / duration / endpoints
# ---------------------------------------------------------------------------


class TestTunnel:
    def _make_tunnel(self, tunnel_manager: TunnelManager) -> Tunnel:
        return tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.5", 80)

    def test_record_bytes_accumulates(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        t.record_bytes(100)
        t.record_bytes(200)
        assert t.bytes_transferred == 300

    def test_close_sets_closed_at(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        assert t.closed_at is None
        t.close()
        assert t.closed_at is not None

    def test_close_status(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        t.close()
        assert t.status == TunnelStatus.CLOSED
        assert t.is_active is False

    def test_duration_increases_while_open(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        d1 = t.duration
        time.sleep(0.05)
        d2 = t.duration
        assert d2 > d1

    def test_duration_fixed_after_close(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        t.close()
        d1 = t.duration
        time.sleep(0.05)
        d2 = t.duration
        assert abs(d2 - d1) < 0.01

    def test_local_endpoint(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        assert t.local_endpoint == "127.0.0.1:8080"

    def test_remote_endpoint(self, tunnel_manager: TunnelManager):
        t = self._make_tunnel(tunnel_manager)
        assert t.remote_endpoint == "10.0.0.5:80"
