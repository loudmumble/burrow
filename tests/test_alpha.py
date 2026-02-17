"""Burrow alpha test suite — comprehensive coverage of all modules."""

import socket
import struct

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from burrow import __version__
from burrow.cli import main
from burrow.config import (
    BurrowConfig,
    EncryptionMode,
    HopConfig,
    ProxyType,
)
from burrow.crypto import (
    CipherSuite,
    CryptoSession,
    FRAME_HEADER_SIZE,
    decrypt_frame,
    derive_shared_key,
    encrypt_frame,
    generate_keypair,
)
from burrow.discovery import (
    DEFAULT_PIVOT_PORTS,
    HostResult,
    NetworkDiscovery,
    PortResult,
    PortState,
    ServiceGuess,
    generate_ip_range,
    guess_service,
)
from burrow.pivot import (
    HopStatus,
    PivotChain,
    PivotHop,
    PivotManager,
)
from burrow.proxy import (
    SOCKS_VERSION,
    AddressType,
    AuthMethod,
    Command,
    ProxyServer,
    ReplyCode,
    Socks5Greeting,
    Socks5Request,
    create_greeting_response,
    create_socks5_response,
    parse_socks5_greeting,
    parse_socks5_request,
)
from burrow.reverse import (
    ReverseConnector,
    ReverseSession,
    SessionState,
)
from burrow.tunnel import (
    Tunnel,
    TunnelDirection,
    TunnelManager,
    TunnelStatus,
)

from tests.conftest import build_socks5_greeting, build_socks5_request


# ═══════════════════════════════════════════════════════════════════
# CONFIG MODULE
# ═══════════════════════════════════════════════════════════════════


class TestBurrowConfig:
    def test_defaults(self, default_config):
        assert default_config.listen_addr == "127.0.0.1"
        assert default_config.listen_port == 8443
        assert default_config.proxy_type == ProxyType.SOCKS5
        assert default_config.encryption == EncryptionMode.CHACHA20
        assert default_config.keepalive_interval == 30
        assert default_config.reconnect_max_retries == 10

    def test_listen_endpoint(self, default_config):
        assert default_config.listen_endpoint == "127.0.0.1:8443"

    def test_remote_endpoint(self):
        c = BurrowConfig(remote_addr="10.0.0.1", remote_port=22)
        assert c.remote_endpoint == "10.0.0.1:22"

    def test_add_hop(self, default_config):
        default_config.add_hop("10.0.0.1", 22)
        assert len(default_config.hop_chain) == 1
        assert default_config.hop_chain[0].host == "10.0.0.1"

    def test_to_dict(self, default_config):
        d = default_config.to_dict()
        assert "listen_addr" in d
        assert d["proxy_type"] == "socks5"

    def test_hop_config_defaults(self):
        h = HopConfig(host="10.0.0.1")
        assert h.port == 8443
        assert h.tunnel_type == "tcp"

    def test_proxy_types(self):
        for pt in ProxyType:
            c = BurrowConfig(proxy_type=pt)
            assert c.proxy_type == pt

    def test_encryption_modes(self):
        for em in EncryptionMode:
            c = BurrowConfig(encryption=em)
            assert c.encryption == em


# ═══════════════════════════════════════════════════════════════════
# PROXY MODULE
# ═══════════════════════════════════════════════════════════════════


class TestSocks5Greeting:
    def test_parse_no_auth(self):
        data = build_socks5_greeting([0x00])
        g = parse_socks5_greeting(data)
        assert g.version == SOCKS_VERSION
        assert 0x00 in g.auth_methods

    def test_parse_multiple_methods(self):
        data = build_socks5_greeting([0x00, 0x02])
        g = parse_socks5_greeting(data)
        assert len(g.auth_methods) == 2

    def test_parse_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_socks5_greeting(b"\x05")

    def test_parse_wrong_version(self):
        with pytest.raises(ValueError, match="Unsupported"):
            parse_socks5_greeting(b"\x04\x01\x00")

    def test_parse_truncated(self):
        with pytest.raises(ValueError, match="truncated"):
            parse_socks5_greeting(b"\x05\x03\x00")  # says 3 methods, only 1


class TestSocks5Request:
    def test_parse_ipv4_connect(self):
        data = build_socks5_request(cmd=Command.CONNECT, addr="10.0.0.1", port=80)
        r = parse_socks5_request(data)
        assert r.command == Command.CONNECT
        assert r.dest_addr == "10.0.0.1"
        assert r.dest_port == 80
        assert r.address_type == AddressType.IPV4

    def test_parse_domain(self):
        data = build_socks5_request(
            cmd=Command.CONNECT,
            addr="example.com",
            port=443,
            atyp=AddressType.DOMAIN,
        )
        r = parse_socks5_request(data)
        assert r.dest_addr == "example.com"
        assert r.dest_port == 443

    def test_parse_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_socks5_request(b"\x05\x01")

    def test_parse_wrong_version(self):
        with pytest.raises(ValueError, match="Unsupported"):
            parse_socks5_request(b"\x04\x01\x00\x01" + b"\x00" * 6)


class TestSocks5Response:
    def test_create_success(self):
        resp = create_socks5_response(ReplyCode.SUCCEEDED)
        assert resp[0] == SOCKS_VERSION
        assert resp[1] == ReplyCode.SUCCEEDED

    def test_create_failure(self):
        resp = create_socks5_response(ReplyCode.CONNECTION_REFUSED)
        assert resp[1] == ReplyCode.CONNECTION_REFUSED


class TestGreetingResponse:
    def test_no_auth(self):
        resp = create_greeting_response(AuthMethod.NO_AUTH)
        assert resp == bytes([0x05, 0x00])

    def test_no_acceptable(self):
        resp = create_greeting_response(AuthMethod.NO_ACCEPTABLE)
        assert resp == bytes([0x05, 0xFF])


class TestProxyServer:
    def test_start_stop(self):
        p = ProxyServer()
        p.start()
        assert p.is_running
        p.stop()
        assert not p.is_running

    def test_double_start_raises(self):
        p = ProxyServer()
        p.start()
        with pytest.raises(RuntimeError):
            p.start()

    def test_stop_not_running_raises(self):
        p = ProxyServer()
        with pytest.raises(RuntimeError):
            p.stop()

    def test_endpoint(self):
        p = ProxyServer(listen_addr="0.0.0.0", listen_port=9999)
        assert p.endpoint == "0.0.0.0:9999"

    def test_record_connection(self):
        p = ProxyServer()
        p.start()
        p.record_connection()
        assert p.active_connections == 1

    def test_record_bytes(self):
        p = ProxyServer()
        p.start()
        p.record_bytes(1024)
        assert p.bytes_relayed == 1024

    def test_process_greeting_no_auth(self):
        p = ProxyServer()
        data = build_socks5_greeting([0x00])
        greeting, resp = p.process_greeting(data)
        assert resp == bytes([0x05, 0x00])

    def test_process_greeting_auth_required(self):
        p = ProxyServer(auth_required=True)
        data = build_socks5_greeting([0x00])  # only NO_AUTH
        greeting, resp = p.process_greeting(data)
        assert resp == bytes([0x05, 0xFF])  # NO_ACCEPTABLE

    def test_process_request_connect(self):
        p = ProxyServer()
        data = build_socks5_request(cmd=Command.CONNECT, addr="10.0.0.1", port=80)
        req, resp = p.process_request(data)
        assert req.command == Command.CONNECT
        assert resp is None  # caller handles connection

    def test_process_request_unsupported(self):
        p = ProxyServer()
        data = build_socks5_request(cmd=Command.BIND, addr="10.0.0.1", port=80)
        req, resp = p.process_request(data)
        assert resp is not None  # command not supported


# ═══════════════════════════════════════════════════════════════════
# CRYPTO MODULE
# ═══════════════════════════════════════════════════════════════════


class TestKeyExchange:
    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        assert priv is not None
        assert pub is not None

    def test_derive_shared_key(self):
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()
        key_ab = derive_shared_key(priv_a, pub_b)
        key_ba = derive_shared_key(priv_b, pub_a)
        assert key_ab == key_ba
        assert len(key_ab) == 32


class TestFrameEncryption:
    def test_encrypt_decrypt_chacha(self):
        key = derive_shared_key(*generate_keypair()[:1], generate_keypair()[1])
        # Simpler: just use 32 random bytes
        import os

        key = os.urandom(32)
        pt = b"hello world"
        frame = encrypt_frame(key, pt, 0, CipherSuite.CHACHA20_POLY1305)
        counter, decrypted = decrypt_frame(key, frame, CipherSuite.CHACHA20_POLY1305)
        assert decrypted == pt
        assert counter == 0

    def test_encrypt_decrypt_aes(self):
        import os

        key = os.urandom(32)
        pt = b"secret data"
        frame = encrypt_frame(key, pt, 42, CipherSuite.AES_256_GCM)
        counter, decrypted = decrypt_frame(key, frame, CipherSuite.AES_256_GCM)
        assert decrypted == pt
        assert counter == 42

    def test_frame_too_short(self):
        import os

        key = os.urandom(32)
        with pytest.raises(ValueError, match="too short"):
            decrypt_frame(key, b"\x00" * 5)

    def test_tampered_frame(self):
        import os
        from cryptography.exceptions import InvalidTag

        key = os.urandom(32)
        frame = encrypt_frame(key, b"test", 0)
        tampered = frame[:-1] + bytes([frame[-1] ^ 0xFF])
        with pytest.raises(InvalidTag):
            decrypt_frame(key, tampered)

    def test_encrypt_with_aad(self):
        import os

        key = os.urandom(32)
        pt = b"authenticated"
        aad = b"metadata"
        frame = encrypt_frame(key, pt, 1, aad=aad)
        _, decrypted = decrypt_frame(key, frame, aad=aad)
        assert decrypted == pt


class TestCryptoSession:
    def test_session_encrypt_decrypt(self):
        s1 = CryptoSession()
        s2 = CryptoSession()
        s1.set_peer_public(s2.local_public)
        s2.set_peer_public(s1.local_public)

        frame = s1.encrypt(b"ping")
        pt = s2.decrypt(frame)
        assert pt == b"ping"

    def test_counter_increment(self):
        s1 = CryptoSession()
        s2 = CryptoSession()
        s1.set_peer_public(s2.local_public)
        s2.set_peer_public(s1.local_public)

        s1.encrypt(b"a")
        assert s1.send_counter == 1
        s1.encrypt(b"b")
        assert s1.send_counter == 2

    def test_no_peer_key_raises(self):
        s = CryptoSession()
        with pytest.raises(ValueError, match="Peer public key"):
            s.encrypt(b"test")

    def test_rotate_key(self):
        s = CryptoSession()
        old_pub = s.local_public
        new_pub = s.rotate_key()
        # Public key should change
        assert s.send_counter == 0

    def test_needs_rotation_fresh(self):
        s = CryptoSession()
        s2 = CryptoSession()
        s.set_peer_public(s2.local_public)
        assert s.needs_rotation() is False

    def test_aes_session(self):
        s1 = CryptoSession(cipher_suite=CipherSuite.AES_256_GCM)
        s2 = CryptoSession(cipher_suite=CipherSuite.AES_256_GCM)
        s1.set_peer_public(s2.local_public)
        s2.set_peer_public(s1.local_public)

        frame = s1.encrypt(b"aes-test")
        pt = s2.decrypt(frame)
        assert pt == b"aes-test"


# ═══════════════════════════════════════════════════════════════════
# TUNNEL MODULE
# ═══════════════════════════════════════════════════════════════════


class TestTunnel:
    def test_endpoints(self):
        t = Tunnel(
            id="t1",
            local_addr="127.0.0.1",
            local_port=8080,
            remote_addr="10.0.0.1",
            remote_port=80,
            direction=TunnelDirection.LOCAL,
        )
        assert t.local_endpoint == "127.0.0.1:8080"
        assert t.remote_endpoint == "10.0.0.1:80"

    def test_is_active(self):
        t = Tunnel(
            id="t1",
            local_addr="a",
            local_port=1,
            remote_addr="b",
            remote_port=2,
            direction=TunnelDirection.LOCAL,
            status=TunnelStatus.ACTIVE,
        )
        assert t.is_active is True

    def test_record_bytes(self):
        t = Tunnel(
            id="t1",
            local_addr="a",
            local_port=1,
            remote_addr="b",
            remote_port=2,
            direction=TunnelDirection.LOCAL,
        )
        t.record_bytes(1000)
        assert t.bytes_transferred == 1000

    def test_close(self):
        t = Tunnel(
            id="t1",
            local_addr="a",
            local_port=1,
            remote_addr="b",
            remote_port=2,
            direction=TunnelDirection.LOCAL,
            status=TunnelStatus.ACTIVE,
        )
        t.close()
        assert t.status == TunnelStatus.CLOSED
        assert t.closed_at is not None

    def test_duration(self):
        t = Tunnel(
            id="t1",
            local_addr="a",
            local_port=1,
            remote_addr="b",
            remote_port=2,
            direction=TunnelDirection.LOCAL,
        )
        assert t.duration >= 0


class TestTunnelManager:
    def test_create_local_forward(self, tunnel_manager):
        t = tunnel_manager.create_local_forward("127.0.0.1", 8080, "10.0.0.1", 80)
        assert t.direction == TunnelDirection.LOCAL
        assert t.status == TunnelStatus.ACTIVE

    def test_create_remote_forward(self, tunnel_manager):
        t = tunnel_manager.create_remote_forward("0.0.0.0", 2222, "127.0.0.1", 22)
        assert t.direction == TunnelDirection.REMOTE

    def test_list_tunnels(self, tunnel_manager):
        tunnel_manager.create_local_forward("a", 1, "b", 2)
        tunnel_manager.create_local_forward("c", 3, "d", 4)
        assert len(tunnel_manager.tunnels) == 2

    def test_active_tunnels(self, tunnel_manager):
        t = tunnel_manager.create_local_forward("a", 1, "b", 2)
        tunnel_manager.close_tunnel(t.id)
        tunnel_manager.create_local_forward("c", 3, "d", 4)
        assert len(tunnel_manager.active_tunnels) == 1

    def test_get_tunnel(self, tunnel_manager):
        t = tunnel_manager.create_local_forward("a", 1, "b", 2)
        found = tunnel_manager.get_tunnel(t.id)
        assert found is not None
        assert found.id == t.id

    def test_get_tunnel_missing(self, tunnel_manager):
        assert tunnel_manager.get_tunnel("nope") is None

    def test_close_tunnel(self, tunnel_manager):
        t = tunnel_manager.create_local_forward("a", 1, "b", 2)
        assert tunnel_manager.close_tunnel(t.id) is True
        assert tunnel_manager.close_tunnel(t.id) is False  # already closed

    def test_close_nonexistent(self, tunnel_manager):
        assert tunnel_manager.close_tunnel("nope") is False

    def test_close_all(self, tunnel_manager):
        tunnel_manager.create_local_forward("a", 1, "b", 2)
        tunnel_manager.create_local_forward("c", 3, "d", 4)
        closed = tunnel_manager.close_all()
        assert closed == 2
        assert len(tunnel_manager.active_tunnels) == 0

    def test_total_bytes(self, tunnel_manager):
        t1 = tunnel_manager.create_local_forward("a", 1, "b", 2)
        t2 = tunnel_manager.create_local_forward("c", 3, "d", 4)
        t1.record_bytes(100)
        t2.record_bytes(200)
        assert tunnel_manager.total_bytes_transferred() == 300


# ═══════════════════════════════════════════════════════════════════
# REVERSE MODULE
# ═══════════════════════════════════════════════════════════════════


class TestReverseSession:
    def test_is_connected(self):
        s = ReverseSession(
            id="r1",
            controller_addr="10.0.0.1",
            controller_port=4443,
            state=SessionState.CONNECTED,
        )
        assert s.is_connected is True

    def test_not_connected(self):
        s = ReverseSession(id="r1", controller_addr="10.0.0.1", controller_port=4443)
        assert s.is_connected is False

    def test_endpoint(self):
        s = ReverseSession(id="r1", controller_addr="10.0.0.1", controller_port=4443)
        assert s.endpoint == "10.0.0.1:4443"

    def test_uptime_not_connected(self):
        s = ReverseSession(id="r1", controller_addr="a", controller_port=1)
        assert s.uptime == 0.0


class TestReverseConnector:
    def test_establish_reverse(self):
        rc = ReverseConnector()
        session = rc.establish_reverse("10.0.0.1", 4443)
        assert session.is_connected
        assert session.connect_attempts == 1

    def test_maintain_keepalive(self):
        rc = ReverseConnector()
        s = rc.establish_reverse("10.0.0.1", 4443)
        assert rc.maintain_keepalive(s.id) is True

    def test_keepalive_disconnected(self):
        rc = ReverseConnector()
        s = rc.establish_reverse("10.0.0.1", 4443)
        rc.simulate_disconnect(s.id)
        assert rc.maintain_keepalive(s.id) is False

    def test_keepalive_nonexistent(self):
        rc = ReverseConnector()
        assert rc.maintain_keepalive("nope") is False

    def test_reconnect_delay_exponential(self):
        rc = ReverseConnector(base_delay=1.0, max_delay=60.0)
        s = rc.establish_reverse("a", 1)
        assert rc.reconnect_delay(s.id) == 1.0
        rc.simulate_disconnect(s.id)
        assert rc.reconnect_delay(s.id) == 2.0
        rc.simulate_disconnect(s.id)
        assert rc.reconnect_delay(s.id) == 4.0

    def test_reconnect_strategy(self):
        rc = ReverseConnector(max_retries=3)
        s = rc.establish_reverse("a", 1)
        strat = rc.reconnect_strategy(s.id)
        assert strat["should_retry"] is True

    def test_reconnect_max_exceeded(self):
        rc = ReverseConnector(max_retries=2)
        s = rc.establish_reverse("a", 1)
        rc.simulate_disconnect(s.id)
        rc.simulate_disconnect(s.id)
        strat = rc.reconnect_strategy(s.id)
        assert strat["should_retry"] is False

    def test_simulate_reconnect(self):
        rc = ReverseConnector()
        s = rc.establish_reverse("a", 1)
        rc.simulate_disconnect(s.id)
        assert s.state == SessionState.RECONNECTING
        rc.simulate_reconnect(s.id)
        assert s.state == SessionState.CONNECTED

    def test_mark_failed(self):
        rc = ReverseConnector()
        s = rc.establish_reverse("a", 1)
        rc.mark_failed(s.id)
        assert s.state == SessionState.FAILED

    def test_close_session(self):
        rc = ReverseConnector()
        s = rc.establish_reverse("a", 1)
        assert rc.close_session(s.id) is True
        assert rc.close_session(s.id) is False

    def test_sessions_list(self):
        rc = ReverseConnector()
        rc.establish_reverse("a", 1)
        rc.establish_reverse("b", 2)
        assert len(rc.sessions) == 2


# ═══════════════════════════════════════════════════════════════════
# PIVOT MODULE
# ═══════════════════════════════════════════════════════════════════


class TestPivotHop:
    def test_activate(self):
        h = PivotHop(id="h1", host="10.0.0.1", port=22, hop_index=0)
        h.activate()
        assert h.is_active
        assert h.established_at is not None

    def test_fail(self):
        h = PivotHop(id="h1", host="10.0.0.1", port=22, hop_index=0)
        h.fail("timeout")
        assert h.status == HopStatus.FAILED
        assert h.error == "timeout"

    def test_endpoint(self):
        h = PivotHop(id="h1", host="10.0.0.1", port=22, hop_index=0)
        assert h.endpoint == "10.0.0.1:22"

    def test_record_bytes(self):
        h = PivotHop(id="h1", host="10.0.0.1", port=22, hop_index=0)
        h.record_bytes(500)
        assert h.bytes_forwarded == 500


class TestPivotChain:
    def test_empty_chain(self):
        c = PivotChain(id="c1")
        assert c.depth == 0
        assert c.is_complete is False
        assert c.route_string() == "(empty chain)"

    def test_chain_with_hops(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        assert chain.depth == 3

    def test_chain_complete(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        pm.activate_chain(chain.id)
        assert chain.is_complete is True

    def test_chain_not_complete_with_failure(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        pm.activate_chain(chain.id)
        pm.fail_hop(chain.id, 1)
        assert chain.is_complete is False
        assert len(chain.failed_hops) == 1

    def test_route_string(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        route = chain.route_string()
        assert "10.0.0.1:22" in route
        assert "10.0.0.3:8443" in route
        assert "->" in route

    def test_summary(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        pm.activate_chain(chain.id)
        s = chain.summary()
        assert s["depth"] == 3
        assert s["complete"] is True
        assert len(s["hops"]) == 3


class TestPivotManager:
    def test_create_chain(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        assert pm.get_chain(chain.id) is not None

    def test_activate_chain(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        assert pm.activate_chain(chain.id) is True
        for hop in chain.hops:
            assert hop.is_active

    def test_activate_nonexistent(self):
        pm = PivotManager()
        assert pm.activate_chain("nope") is False

    def test_fail_hop(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        pm.activate_chain(chain.id)
        assert pm.fail_hop(chain.id, 0, "test") is True
        assert chain.hops[0].status == HopStatus.FAILED

    def test_fail_hop_invalid_index(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        assert pm.fail_hop(chain.id, 99) is False

    def test_close_chain(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        pm.activate_chain(chain.id)
        assert pm.close_chain(chain.id) is True
        for hop in chain.hops:
            assert hop.status == HopStatus.CLOSED

    def test_get_active_chains(self, three_hops):
        pm = PivotManager()
        c1 = pm.create_chain(three_hops)
        pm.activate_chain(c1.id)
        c2 = pm.create_chain([HopConfig(host="1.2.3.4", port=22)])
        assert len(pm.get_active_chains()) == 1  # c2 not activated

    def test_remove_chain(self, three_hops):
        pm = PivotManager()
        chain = pm.create_chain(three_hops)
        assert pm.remove_chain(chain.id) is True
        assert pm.remove_chain(chain.id) is False

    def test_reset(self, three_hops):
        pm = PivotManager()
        pm.create_chain(three_hops)
        pm.reset()
        assert pm.get_all_chains() == []


# ═══════════════════════════════════════════════════════════════════
# DISCOVERY MODULE
# ═══════════════════════════════════════════════════════════════════


class TestGuessService:
    def test_known_port(self):
        assert guess_service(22) == ServiceGuess.SSH
        assert guess_service(80) == ServiceGuess.HTTP
        assert guess_service(443) == ServiceGuess.HTTPS

    def test_unknown_port(self):
        assert guess_service(31337) == ServiceGuess.UNKNOWN


class TestPortResult:
    def test_is_open(self):
        p = PortResult(port=22, state=PortState.OPEN, service=ServiceGuess.SSH)
        assert p.is_open is True

    def test_is_pivot_candidate(self):
        p = PortResult(port=22, state=PortState.OPEN, service=ServiceGuess.SSH)
        assert p.is_pivot_candidate is True

    def test_not_pivot_candidate(self):
        p = PortResult(port=3306, state=PortState.OPEN, service=ServiceGuess.MYSQL)
        assert p.is_pivot_candidate is False


class TestHostResult:
    def test_open_ports(self):
        h = HostResult(
            ip="10.0.0.1",
            ports=[
                PortResult(port=22, state=PortState.OPEN, service=ServiceGuess.SSH),
                PortResult(port=80, state=PortState.CLOSED, service=ServiceGuess.HTTP),
            ],
        )
        assert len(h.open_ports) == 1

    def test_service_list(self):
        h = HostResult(
            ip="10.0.0.1",
            ports=[
                PortResult(port=22, state=PortState.OPEN, service=ServiceGuess.SSH),
                PortResult(port=443, state=PortState.OPEN, service=ServiceGuess.HTTPS),
            ],
        )
        assert "ssh" in h.service_list
        assert "https" in h.service_list

    def test_summary(self):
        h = HostResult(
            ip="10.0.0.1",
            reachable=True,
            ports=[
                PortResult(port=22, state=PortState.OPEN, service=ServiceGuess.SSH),
            ],
        )
        s = h.summary()
        assert s["ip"] == "10.0.0.1"
        assert 22 in s["open_ports"]


class TestGenerateIPRange:
    def test_valid_range(self):
        ips = generate_ip_range("192.168.1")
        assert len(ips) == 254
        assert ips[0] == "192.168.1.1"
        assert ips[-1] == "192.168.1.254"

    def test_invalid_prefix(self):
        with pytest.raises(ValueError, match="Invalid"):
            generate_ip_range("10")


class TestNetworkDiscovery:
    def test_simulate_host(self):
        nd = NetworkDiscovery()
        h = nd.simulate_host("10.0.0.1", [22, 80])
        assert h.reachable is True
        assert len(h.open_ports) == 2

    def test_simulate_host_no_open(self):
        nd = NetworkDiscovery()
        h = nd.simulate_host("10.0.0.1", [])
        assert h.reachable is False

    def test_get_pivot_targets(self):
        nd = NetworkDiscovery()
        nd.simulate_host("10.0.0.1", [22, 80])
        nd.simulate_host("10.0.0.2", [])
        targets = nd.get_pivot_targets()
        assert len(targets) == 1

    def test_reset(self):
        nd = NetworkDiscovery()
        nd.simulate_host("10.0.0.1", [22])
        nd.reset()
        assert nd.get_results() == []

    def test_custom_ports(self):
        nd = NetworkDiscovery(ports=[22, 3389])
        h = nd.simulate_host("10.0.0.1", [22])
        assert len(h.ports) == 2  # scanned 2 ports


# ═══════════════════════════════════════════════════════════════════
# CLI MODULE
# ═══════════════════════════════════════════════════════════════════


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Burrow" in result.output

    def test_forward_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["forward", "--help"])
        assert result.exit_code == 0

    def test_reverse_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["reverse", "--help"])
        assert result.exit_code == 0

    def test_proxy_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["proxy", "--help"])
        assert result.exit_code == 0

    def test_pivot_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["pivot", "--help"])
        assert result.exit_code == 0

    def test_discover_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["discover", "--help"])
        assert result.exit_code == 0

    def test_forward_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["forward", "-r", "10.0.0.1:80"])
        assert result.exit_code == 0
        assert "Tunnel" in result.output

    def test_proxy_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["proxy"])
        assert result.exit_code == 0
        assert "SOCKS5" in result.output

    def test_pivot_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["pivot", "10.0.0.1:22", "10.0.0.2:443"])
        assert result.exit_code == 0
        assert "chain" in result.output.lower()

    def test_discover_command(self):
        runner = CliRunner()
        result = runner.invoke(main, ["discover", "192.168.1"])
        assert result.exit_code == 0
