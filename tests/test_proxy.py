"""Tests for SOCKS5 proxy protocol parsing and ProxyServer lifecycle."""

from __future__ import annotations

import struct

import pytest

from burrow.proxy import (
    AddressType,
    AuthMethod,
    Command,
    ProxyServer,
    ReplyCode,
    SOCKS_VERSION,
    Socks5Greeting,
    Socks5Request,
    create_greeting_response,
    create_socks5_response,
    parse_socks5_greeting,
    parse_socks5_request,
)
from tests.conftest import build_socks5_greeting, build_socks5_request


# ---------------------------------------------------------------------------
# parse_socks5_greeting
# ---------------------------------------------------------------------------


class TestParseSocks5Greeting:
    def test_valid_no_auth(self):
        data = build_socks5_greeting([0x00])
        greeting = parse_socks5_greeting(data)
        assert greeting.version == SOCKS_VERSION
        assert 0x00 in greeting.auth_methods

    def test_multiple_methods(self):
        data = build_socks5_greeting([0x00, 0x02])
        greeting = parse_socks5_greeting(data)
        assert greeting.auth_methods == [0x00, 0x02]

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_socks5_greeting(b"\x05")

    def test_wrong_version_raises(self):
        data = bytes([0x04, 0x01, 0x00])
        with pytest.raises(ValueError, match="Unsupported SOCKS version"):
            parse_socks5_greeting(data)

    def test_truncated_methods_raises(self):
        # Claims 3 methods but only provides 1
        data = bytes([SOCKS_VERSION, 0x03, 0x00])
        with pytest.raises(ValueError, match="truncated"):
            parse_socks5_greeting(data)

    def test_returns_greeting_dataclass(self):
        data = build_socks5_greeting()
        result = parse_socks5_greeting(data)
        assert isinstance(result, Socks5Greeting)


# ---------------------------------------------------------------------------
# parse_socks5_request
# ---------------------------------------------------------------------------


class TestParseSocks5Request:
    def test_valid_ipv4_connect(self):
        data = build_socks5_request(Command.CONNECT, "10.0.0.1", 80, AddressType.IPV4)
        req = parse_socks5_request(data)
        assert req.version == SOCKS_VERSION
        assert req.command == Command.CONNECT
        assert req.address_type == AddressType.IPV4
        assert req.dest_addr == "10.0.0.1"
        assert req.dest_port == 80

    def test_valid_domain_connect(self):
        data = build_socks5_request(
            Command.CONNECT, "example.com", 443, AddressType.DOMAIN
        )
        req = parse_socks5_request(data)
        assert req.dest_addr == "example.com"
        assert req.dest_port == 443
        assert req.address_type == AddressType.DOMAIN

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_socks5_request(b"\x05\x01\x00")

    def test_wrong_version_raises(self):
        data = (
            bytes([0x04, 0x01, 0x00, 0x01])
            + b"\x7f\x00\x00\x01"
            + struct.pack("!H", 80)
        )
        with pytest.raises(ValueError, match="Unsupported SOCKS version"):
            parse_socks5_request(data)

    def test_returns_request_dataclass(self):
        data = build_socks5_request()
        result = parse_socks5_request(data)
        assert isinstance(result, Socks5Request)

    def test_high_port(self):
        data = build_socks5_request(
            Command.CONNECT, "10.0.0.1", 65535, AddressType.IPV4
        )
        req = parse_socks5_request(data)
        assert req.dest_port == 65535


# ---------------------------------------------------------------------------
# create_greeting_response
# ---------------------------------------------------------------------------


class TestCreateGreetingResponse:
    def test_no_auth_response(self):
        resp = create_greeting_response(AuthMethod.NO_AUTH)
        assert resp == bytes([SOCKS_VERSION, AuthMethod.NO_AUTH])

    def test_no_acceptable_response(self):
        resp = create_greeting_response(AuthMethod.NO_ACCEPTABLE)
        assert resp == bytes([SOCKS_VERSION, AuthMethod.NO_ACCEPTABLE])

    def test_default_is_no_auth(self):
        resp = create_greeting_response()
        assert resp[1] == AuthMethod.NO_AUTH

    def test_length(self):
        resp = create_greeting_response()
        assert len(resp) == 2


# ---------------------------------------------------------------------------
# create_socks5_response
# ---------------------------------------------------------------------------


class TestCreateSocks5Response:
    def test_success_response(self):
        resp = create_socks5_response(ReplyCode.SUCCEEDED)
        assert len(resp) == 10  # VER+REP+RSV+ATYP+4(addr)+2(port)
        assert resp[0] == SOCKS_VERSION
        assert resp[1] == ReplyCode.SUCCEEDED

    def test_failure_response(self):
        resp = create_socks5_response(ReplyCode.GENERAL_FAILURE)
        assert resp[1] == ReplyCode.GENERAL_FAILURE

    def test_command_not_supported(self):
        resp = create_socks5_response(ReplyCode.COMMAND_NOT_SUPPORTED)
        assert resp[1] == ReplyCode.COMMAND_NOT_SUPPORTED


# ---------------------------------------------------------------------------
# ProxyServer lifecycle
# ---------------------------------------------------------------------------


class TestProxyServerLifecycle:
    def test_initial_state(self):
        proxy = ProxyServer()
        assert proxy.is_running is False
        assert proxy.active_connections == 0
        assert proxy.bytes_relayed == 0

    def test_start(self):
        proxy = ProxyServer()
        proxy.start()
        assert proxy.is_running is True

    def test_stop(self):
        proxy = ProxyServer()
        proxy.start()
        proxy.stop()
        assert proxy.is_running is False

    def test_double_start_raises(self):
        proxy = ProxyServer()
        proxy.start()
        with pytest.raises(RuntimeError, match="already running"):
            proxy.start()

    def test_stop_when_not_running_raises(self):
        proxy = ProxyServer()
        with pytest.raises(RuntimeError, match="not running"):
            proxy.stop()

    def test_endpoint(self):
        proxy = ProxyServer(listen_addr="127.0.0.1", listen_port=1080)
        assert proxy.endpoint == "127.0.0.1:1080"

    def test_record_bytes(self):
        proxy = ProxyServer()
        proxy.start()
        proxy.record_bytes(1024)
        proxy.record_bytes(512)
        assert proxy.bytes_relayed == 1536

    def test_record_connection(self):
        proxy = ProxyServer()
        proxy.start()
        proxy.record_connection()
        proxy.record_connection()
        assert proxy.active_connections == 2

    def test_stop_resets_connections(self):
        proxy = ProxyServer()
        proxy.start()
        proxy.record_connection()
        proxy.stop()
        assert proxy.active_connections == 0


# ---------------------------------------------------------------------------
# ProxyServer.process_greeting
# ---------------------------------------------------------------------------


class TestProxyServerProcessGreeting:
    def test_no_auth_accepted(self):
        proxy = ProxyServer(auth_required=False)
        proxy.start()
        data = build_socks5_greeting([AuthMethod.NO_AUTH])
        greeting, response = proxy.process_greeting(data)
        assert response[1] == AuthMethod.NO_AUTH

    def test_auth_required_no_password_method_rejected(self):
        proxy = ProxyServer(auth_required=True)
        proxy.start()
        data = build_socks5_greeting([AuthMethod.NO_AUTH])
        _greeting, response = proxy.process_greeting(data)
        assert response[1] == AuthMethod.NO_ACCEPTABLE

    def test_auth_required_no_auth_method_not_offered_rejected(self):
        # Implementation only accepts NO_AUTH or USERNAME_PASSWORD when NO_AUTH is included.
        # When auth_required=True and client offers only USERNAME_PASSWORD (no NO_AUTH),
        # the else branch fires and rejects with NO_ACCEPTABLE.
        proxy = ProxyServer(auth_required=True)
        proxy.start()
        data = build_socks5_greeting([AuthMethod.USERNAME_PASSWORD])
        _greeting, response = proxy.process_greeting(data)
        assert response[1] == AuthMethod.NO_ACCEPTABLE


# ---------------------------------------------------------------------------
# ProxyServer.process_request
# ---------------------------------------------------------------------------


class TestProxyServerProcessRequest:
    def test_connect_returns_none_response(self):
        proxy = ProxyServer()
        proxy.start()
        data = build_socks5_request(Command.CONNECT, "10.0.0.1", 80, AddressType.IPV4)
        request, response = proxy.process_request(data)
        assert request.command == Command.CONNECT
        assert response is None

    def test_bind_returns_unsupported_response(self):
        proxy = ProxyServer()
        proxy.start()
        data = build_socks5_request(Command.BIND, "10.0.0.1", 80, AddressType.IPV4)
        _request, response = proxy.process_request(data)
        assert response is not None
        assert response[1] == ReplyCode.COMMAND_NOT_SUPPORTED

    def test_udp_associate_returns_unsupported_response(self):
        proxy = ProxyServer()
        proxy.start()
        data = build_socks5_request(
            Command.UDP_ASSOCIATE, "10.0.0.1", 80, AddressType.IPV4
        )
        _request, response = proxy.process_request(data)
        assert response is not None
        assert response[1] == ReplyCode.COMMAND_NOT_SUPPORTED
