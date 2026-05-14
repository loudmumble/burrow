"""Tests for PivotManager and PivotChain."""

from __future__ import annotations

import pytest

from burrow.config import HopConfig
from burrow.pivot import HopStatus, PivotChain, PivotHop, PivotManager


# ---------------------------------------------------------------------------
# PivotManager — create_chain
# ---------------------------------------------------------------------------


class TestCreateChain:
    def test_returns_pivot_chain(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert isinstance(chain, PivotChain)

    def test_hop_count(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert chain.depth == 3

    def test_hop_hosts_preserved(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert chain.hops[0].host == "10.0.0.1"
        assert chain.hops[1].host == "10.0.0.2"
        assert chain.hops[2].host == "10.0.0.3"

    def test_hop_ports_preserved(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert chain.hops[0].port == 22
        assert chain.hops[1].port == 443
        assert chain.hops[2].port == 8443

    def test_hop_indexes_set(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        for i, hop in enumerate(chain.hops):
            assert hop.hop_index == i

    def test_initial_status_pending(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        for hop in chain.hops:
            assert hop.status == HopStatus.PENDING

    def test_chain_stored_in_manager(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert mgr.get_chain(chain.id) is chain

    def test_empty_hops(self):
        mgr = PivotManager()
        chain = mgr.create_chain([])
        assert chain.depth == 0

    def test_unique_chain_ids(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        c1 = mgr.create_chain(three_hops)
        c2 = mgr.create_chain(three_hops)
        assert c1.id != c2.id


# ---------------------------------------------------------------------------
# PivotManager — activate_chain
# ---------------------------------------------------------------------------


class TestActivateChain:
    def test_activate_returns_true(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert mgr.activate_chain(chain.id) is True

    def test_all_hops_become_active(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        for hop in chain.hops:
            assert hop.status == HopStatus.ACTIVE

    def test_latency_set_after_activate(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        for hop in chain.hops:
            assert hop.latency_ms > 0.0

    def test_chain_is_complete_after_activate(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        assert chain.is_complete is True

    def test_activate_missing_chain_returns_false(self):
        mgr = PivotManager()
        assert mgr.activate_chain("nonexistent") is False


# ---------------------------------------------------------------------------
# PivotManager — fail_hop
# ---------------------------------------------------------------------------


class TestFailHop:
    def test_fail_hop_returns_true(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert mgr.fail_hop(chain.id, 0) is True

    def test_hop_status_is_failed(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.fail_hop(chain.id, 1, reason="timeout")
        assert chain.hops[1].status == HopStatus.FAILED
        assert chain.hops[1].error == "timeout"

    def test_chain_not_complete_after_fail(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        mgr.fail_hop(chain.id, 0)
        assert chain.is_complete is False

    def test_fail_invalid_index_returns_false(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert mgr.fail_hop(chain.id, 99) is False

    def test_fail_missing_chain_returns_false(self):
        mgr = PivotManager()
        assert mgr.fail_hop("nonexistent", 0) is False


# ---------------------------------------------------------------------------
# PivotManager — close_chain
# ---------------------------------------------------------------------------


class TestCloseChain:
    def test_close_returns_true(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert mgr.close_chain(chain.id) is True

    def test_all_hops_closed(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        mgr.close_chain(chain.id)
        for hop in chain.hops:
            assert hop.status == HopStatus.CLOSED

    def test_close_missing_chain_returns_false(self):
        mgr = PivotManager()
        assert mgr.close_chain("nonexistent") is False


# ---------------------------------------------------------------------------
# PivotChain properties
# ---------------------------------------------------------------------------


class TestPivotChainProperties:
    def test_is_complete_all_active(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        assert chain.is_complete is True

    def test_is_complete_false_when_pending(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert chain.is_complete is False

    def test_is_complete_false_empty_chain(self):
        mgr = PivotManager()
        chain = mgr.create_chain([])
        assert chain.is_complete is False

    def test_route_string(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        route = chain.route_string()
        assert "10.0.0.1:22" in route
        assert "10.0.0.2:443" in route
        assert "10.0.0.3:8443" in route
        assert " -> " in route

    def test_route_string_empty(self):
        mgr = PivotManager()
        chain = mgr.create_chain([])
        assert chain.route_string() == "(empty chain)"

    def test_total_latency(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        # activate_chain sets latency_ms = 5.0 * (hop_index + 1)
        # hop 0: 5.0, hop 1: 10.0, hop 2: 15.0 → total 30.0
        assert chain.total_latency == pytest.approx(30.0)

    def test_total_latency_zero_before_activate(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert chain.total_latency == 0.0

    def test_summary_structure(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        s = chain.summary()
        assert s["id"] == chain.id
        assert s["depth"] == 3
        assert s["complete"] is True
        assert "route" in s
        assert "total_latency_ms" in s
        assert "total_bytes" in s
        assert len(s["hops"]) == 3

    def test_summary_hop_fields(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        s = chain.summary()
        hop = s["hops"][0]
        assert "index" in hop
        assert "endpoint" in hop
        assert "status" in hop
        assert "latency_ms" in hop

    def test_failed_hops_list(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.fail_hop(chain.id, 1)
        assert len(chain.failed_hops) == 1
        assert chain.failed_hops[0].hop_index == 1


# ---------------------------------------------------------------------------
# PivotManager — get_active_chains / remove_chain / reset
# ---------------------------------------------------------------------------


class TestPivotManagerManagement:
    def test_get_active_chains_empty(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        mgr.create_chain(three_hops)
        assert mgr.get_active_chains() == []

    def test_get_active_chains_after_activate(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.activate_chain(chain.id)
        active = mgr.get_active_chains()
        assert len(active) == 1
        assert active[0].id == chain.id

    def test_get_all_chains(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        mgr.create_chain(three_hops)
        mgr.create_chain(three_hops)
        assert len(mgr.get_all_chains()) == 2

    def test_remove_chain_returns_true(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        assert mgr.remove_chain(chain.id) is True

    def test_remove_chain_removes_it(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        chain = mgr.create_chain(three_hops)
        mgr.remove_chain(chain.id)
        assert mgr.get_chain(chain.id) is None

    def test_remove_missing_chain_returns_false(self):
        mgr = PivotManager()
        assert mgr.remove_chain("nonexistent") is False

    def test_reset_clears_all(self, three_hops: list[HopConfig]):
        mgr = PivotManager()
        mgr.create_chain(three_hops)
        mgr.create_chain(three_hops)
        mgr.reset()
        assert mgr.get_all_chains() == []
