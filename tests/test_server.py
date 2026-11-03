"""
Consolidated server tests.
Combines: test_server.py, test_server_extra.py
"""
import asyncio
import os
import signal
import ssl
import types
import pytest
from aiohttp import web
from unittest.mock import AsyncMock, MagicMock
import dns.message

from dosev.server import run_server, run_server_sync, reload_resolver, ResolverHolder, UDPResolverProtocol, _handle_doh_request, _drop_dns_privileges, _tcp_handler
from dosev.resolver import DNSResolver


# ---------- Helpers ----------
class FakeUDPTransport:
    def close(self):
        pass


class FakeTCPServer:
    def __init__(self):
        self.served = False
        self.closed = False

    async def serve_forever(self):
        self.served = True
        while True:
            await asyncio.sleep(0.1)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_udp_client_payload_is_clamped_to_512_bytes():
    resolver = DNSResolver()
    resolver.forward_dns_query = AsyncMock(return_value=b"x" * 513)
    resolver._set_tc_bit = MagicMock(return_value=b"truncated")
    protocol = UDPResolverProtocol(ResolverHolder(resolver))
    protocol.transport = MagicMock()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1)

    await protocol._handle(query.to_wire(), ("127.0.0.1", 53000))

    resolver._set_tc_bit.assert_called_once_with(b"x" * 513, 512)


@pytest.mark.asyncio
async def test_tcp_handler_serves_multiple_queries_per_connection():
    query = dns.message.make_query("example.com", "A").to_wire()
    frames = iter([
        len(query).to_bytes(2, "big"), query,
        len(query).to_bytes(2, "big"), query,
    ])

    class Reader:
        async def readexactly(self, size):
            try:
                return next(frames)
            except StopIteration:
                raise asyncio.IncompleteReadError(b"", size)

    class Writer:
        def __init__(self):
            self.writes = []

        def get_extra_info(self, name):
            return ("192.0.2.1", 53000) if name == "peername" else None

        def write(self, data):
            self.writes.append(data)

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    resolver = DNSResolver()
    resolver._check_rate_limit = AsyncMock(return_value=True)
    resolver.is_blocked = AsyncMock(return_value=False)
    resolver.forward_dns_query = AsyncMock(
        side_effect=lambda data, **kwargs: dns.message.make_response(
            dns.message.from_wire(data)
        ).to_wire()
    )
    writer = Writer()

    await _tcp_handler(Reader(), writer, ResolverHolder(resolver))

    assert resolver.forward_dns_query.await_count == 2
    assert resolver._check_rate_limit.await_count == 2
    assert len(writer.writes) == 2


@pytest.mark.asyncio
async def test_udp_response_is_truncated_to_client_payload():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=512)
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text(
        "example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A,
        *[f"192.0.2.{index}" for index in range(1, 100)],
    ))
    resolver.forward_dns_query = AsyncMock(return_value=response.to_wire(max_size=4096))

    class Transport:
        def __init__(self):
            self.sent = None

        def sendto(self, data, addr):
            self.sent = data

    protocol = UDPResolverProtocol(ResolverHolder(resolver))
    protocol.transport = Transport()
    await protocol._handle(query.to_wire(), ("192.0.2.10", 53000))

    sent = protocol.transport.sent
    parsed = dns.message.from_wire(sent)
    assert len(sent) <= 512
    assert parsed.flags & dns.flags.TC
    assert parsed.question == query.question


# ---------- Server run tests ----------
@pytest.mark.asyncio
async def test_run_server_starts_udp_and_tcp_listeners(monkeypatch):
    called = {}

    async def fake_create_datagram_endpoint(protocol_factory, local_addr):
        called['udp_started'] = True
        return FakeUDPTransport(), None

    async def fake_start_server(handler, host, port, **kwargs):
        if kwargs.get('ssl') is not None:
            called['dot_started'] = True
        else:
            called['tcp_started'] = True
        return FakeTCPServer()

    async def fake_start_doh_server(holder, listen_ip, listen_port, doh_path, ssl_context):
        called['doh_started'] = True
        class FakeDohRunner:
            async def cleanup(self):
                pass
        return FakeDohRunner()

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)
    monkeypatch.setattr(loop, "add_signal_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr("asyncio.start_server", fake_start_server)
    monkeypatch.setattr("dosev.server._start_doh_server", fake_start_doh_server)
    monkeypatch.setattr("dosev.server._create_ssl_context", lambda cert, key: ssl.create_default_context(ssl.Purpose.CLIENT_AUTH))
    monkeypatch.setattr("dosev.server._drop_dns_privileges", lambda *args, **kwargs: None)

    task = asyncio.create_task(run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dns_enable_dot=True,
        dns_dot_cert_file="/tmp/cert.pem",
        dns_dot_key_file="/tmp/key.pem",
        dns_enable_doh=True,
        dns_doh_cert_file="/tmp/cert.pem",
        dns_doh_key_file="/tmp/key.pem",
        dns_doh_path="/dns-query"
    ))

    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert called.get('udp_started') is True
    assert called.get('tcp_started') is True
    assert called.get('dot_started') is True
    assert called.get('doh_started') is True


@pytest.mark.asyncio
async def test_run_server_graceful_shutdown_on_signal(monkeypatch):
    shutdown_called = False

    class FakeTCPServerShutdown:
        async def serve_forever(self):
            await asyncio.sleep(3600)

        def close(self):
            nonlocal shutdown_called
            shutdown_called = True

        async def wait_closed(self):
            pass

    async def fake_start_server(handler, host, port, **kwargs):
        if kwargs.get('ssl') is not None:
            return FakeTCPServerShutdown()
        return FakeTCPServerShutdown()

    async def fake_create_datagram_endpoint(protocol_factory, local_addr):
        return FakeUDPTransport(), None

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", fake_create_datagram_endpoint)
    monkeypatch.setattr(loop, "add_signal_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr("asyncio.start_server", fake_start_server)
    monkeypatch.setattr("dosev.server._drop_dns_privileges", lambda *args, **kwargs: None)

    task = asyncio.create_task(run_server(
        listen_ip="127.0.0.1",
        listen_port=5353,
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}]
    ))

    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert shutdown_called is True


def test_run_server_sync_uses_asyncio_run(monkeypatch):
    called = {}

    def fake_run_server(*args, **kwargs):
        async def _coroutine():
            return None
        return _coroutine()

    def fake_asyncio_run(coro):
        called['coro'] = coro
        if hasattr(coro, 'close'):
            coro.close()
        return None

    monkeypatch.setattr("dosev.server.run_server", fake_run_server)
    monkeypatch.setattr(asyncio, "run", fake_asyncio_run)

    run_server_sync(
        listen_ip="1.2.3.4",
        listen_port=9999,
        upstreams=[{"address": "8.8.8.8", "protocol": "tls", "ip": "8.8.8.8"}],
        verbose=True
    )
    assert called['coro'] is not None


# ---------- Privilege drop ----------
def test_drop_dns_privileges_does_nothing_when_not_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    called = {}

    def fake_setgid(gid):
        called['setgid'] = gid

    def fake_setuid(uid):
        called['setuid'] = uid

    def fake_chroot(path):
        called['chroot'] = path

    monkeypatch.setattr(os, "setgid", fake_setgid, raising=False)
    monkeypatch.setattr(os, "setuid", fake_setuid, raising=False)
    monkeypatch.setattr(os, "chroot", fake_chroot, raising=False)

    _drop_dns_privileges("nobody", "nogroup", "/var/empty")
    assert called == {}


def test_drop_dns_privileges_drops_privs_when_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

    import importlib.util
    import sys
    if importlib.util.find_spec("pwd") is None:
        pwd = types.SimpleNamespace()
        sys.modules["pwd"] = pwd
    else:
        import pwd
    if importlib.util.find_spec("grp") is None:
        grp = types.SimpleNamespace()
        sys.modules["grp"] = grp
    else:
        import grp

    class FakePw:
        pw_gid = 999
        pw_uid = 999

    class FakeGrp:
        gr_gid = 999

    monkeypatch.setattr(pwd, "getpwnam", lambda name: FakePw(), raising=False)
    monkeypatch.setattr(grp, "getgrnam", lambda name: FakeGrp(), raising=False)

    called = {}

    def fake_setgid(gid):
        called['setgid'] = gid
        called.setdefault('order', []).append('setgid')

    def fake_setuid(uid):
        called['setuid'] = uid
        called.setdefault('order', []).append('setuid')

    def fake_setgroups(groups):
        called['setgroups'] = groups
        called.setdefault('order', []).append('setgroups')

    def fake_chroot(path):
        called['chroot'] = path

    monkeypatch.setattr(os, "setgid", fake_setgid, raising=False)
    monkeypatch.setattr(os, "setuid", fake_setuid, raising=False)
    monkeypatch.setattr(os, "setgroups", fake_setgroups, raising=False)
    monkeypatch.setattr(os, "chroot", fake_chroot, raising=False)

    _drop_dns_privileges("nobody", "nogroup", "/var/empty")

    assert called.get('setgid') == 999
    assert called.get('setuid') == 999
    assert called.get('setgroups') == []
    assert called.get('order') == ['setgroups', 'setgid', 'setuid']
    assert called.get('chroot') == '/var/empty'


def test_drop_dns_privileges_raises_when_user_resolution_fails(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

    import sys
    try:
        import pwd
    except ImportError:
        pwd = types.SimpleNamespace()
        sys.modules["pwd"] = pwd
    try:
        import grp
    except ImportError:
        grp = types.SimpleNamespace()
        sys.modules["grp"] = grp

    monkeypatch.setattr(pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError("no such user")), raising=False)
    monkeypatch.setattr(grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=999), raising=False)

    with pytest.raises(KeyError):
        _drop_dns_privileges("missinguser", "nogroup", None)


# ---------- Reload resolver ----------
@pytest.mark.asyncio
async def test_reload_resolver_updates_max_edns_payload(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    async def fake_fetch_blocklists(urls, destination_dir):
        return None

    monkeypatch.setattr("dosev.server.fetch_blocklists", fake_fetch_blocklists)

    config = {
        'upstreams': [{"address": "9.9.9.9", "protocol": "udp", "ip": "9.9.9.9"}],
        'dns_max_payload': 1232,
    }

    await reload_resolver(holder, config, resolver, None)

    assert resolver.max_edns_payload == 1232


@pytest.mark.asyncio
async def test_reload_resolver_reloads_blocklists(monkeypatch, tmp_path):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    blocklist_dir = tmp_path / "blocklists"
    blocklist_dir.mkdir()
    (blocklist_dir / "test.txt").write_text("blocked.domain\n.badsuffix\n")

    blocklists_config = {
        'action': 'REFUSED',
        'urls': [],
        'local_blocklist_dir': str(blocklist_dir),
    }

    reload_called = False
    async def fake_fetch_blocklists(urls, destination_dir):
        nonlocal reload_called
        reload_called = True

    monkeypatch.setattr("dosev.server.fetch_blocklists", fake_fetch_blocklists)

    config = {
        'upstreams': [{"address": "9.9.9.9", "protocol": "tls", "ip": "9.9.9.9"}],
        'verbose': True,
        'disable_ipv6': True,
        'upstream_udp_timeout': 3.0,
        'upstream_tcp_timeout': 4.0,
        'upstream_doh_timeout': 6.0,
        'upstream_retries': 3,
        'dns_pinned_certs': {},
        'dnssec_enabled': True,
        'trust_anchors_file': '',
        'metrics_enabled': False,
        'metrics_port': 8000,
        'rate_limit_rps': 1.0,
        'rate_limit_burst': 2.0,
        'optimistic_cache_enabled': True,
        'optimistic_stale_max_age': 100,
        'optimistic_stale_response_ttl': 10,
        'dns_rebind_protection': True,
        'dns_rebind_action': 'block',
        'pool_max_size': 10,
        'pool_idle_timeout': 30.0,
        'doh_version': '2',
        'doh_auto_cache_ttl': 2000,
        'bootstrap': {'servers': ['1.1.1.1:53'], 'timeout': 1.0, 'retries': 1},
    }

    await reload_resolver(holder, config, resolver, blocklists_config)

    assert resolver.upstreams[0]["address"] == "9.9.9.9"
    assert resolver.verbose is True
    assert resolver.disable_ipv6 is True
    assert resolver.udp_timeout == 3.0
    assert resolver.tcp_timeout == 4.0
    assert resolver.doh_timeout == 6.0
    assert resolver.retries == 3
    assert resolver.dnssec_enabled is True

    assert await resolver.is_blocked('blocked.domain') is True
    assert await resolver.is_blocked('sub.badsuffix') is True
    assert await resolver.is_blocked('allowed.domain') is False
    assert resolver.get_block_action() == 'REFUSED'


# ---------- DoH handler ----------
@pytest.mark.asyncio
async def test_handle_doh_request_returns_bad_request_for_missing_dns(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    class FakeRequest:
        method = 'GET'
        rel_url = types.SimpleNamespace(query={})
        remote = '203.0.113.7'
        content_type = None

        async def read(self):
            return b''

    response = await _handle_doh_request(FakeRequest(), holder)
    assert response.status == 400
    assert 'Missing dns parameter' in response.text


# ---------- Regression test for trust_anchors_file bug ----------
@pytest.mark.asyncio
async def test_trust_anchors_file_passed_correctly(tmp_path):
    """
    Regression test for: {'file': path} in _load_trust_anchors is broken.
    
    When trust_anchors_file is set, server.py should pass the file path as a string
    directly to the resolver, not wrapped in a {'file': path} dict.
    """
    # Create a temporary trust anchors file
    anchors_file = tmp_path / "trust_anchors.txt"
    anchors_file.write_text(
        ". 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0=\n"
    )
    
    # This should not raise AttributeError: 'str' object has no attribute 'name'
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        trust_anchors=str(anchors_file)
    )
    
    # Verify the trust anchor was loaded correctly
    assert resolver._dnssec_raw_anchors is not None
    import dns.name
    assert dns.name.root in resolver._dnssec_raw_anchors


@pytest.mark.asyncio
async def test_trust_anchors_file_passed_via_config(tmp_path):
    """
    Test that trust_anchors_file works correctly when passed via config dict
    in reload_resolver.
    """
    # Create a temporary trust anchors file
    anchors_file = tmp_path / "trust_anchors.txt"
    anchors_file.write_text(
        ". 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0=\n"
    )
    
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True
    )
    holder = ResolverHolder(resolver)
    
    config = {
        'dnssec_enabled': True,
        'trust_anchors_file': str(anchors_file),
    }
    
    # This should not raise AttributeError
    await reload_resolver(holder, config, resolver)
    
    # Verify the trust anchor was loaded correctly
    assert resolver._dnssec_raw_anchors is not None
    import dns.name
    assert dns.name.root in resolver._dnssec_raw_anchors