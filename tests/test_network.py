"""
Consolidated network and pooling tests.
Combines: test_connection_pool.py, test_pool.py, test_http3.py, test_resolver_doq.py, test_tcp_fallback.py
"""
import asyncio
import base64
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
from aioquic.h3.events import DataReceived, HeadersReceived

from dosev.resolver import ConnectionPool, ClientPool, DNSResolver
from dosev.server import Http3ServerProtocol, ResolverHolder


# ---------- ConnectionPool tests ----------
@pytest.mark.asyncio
async def test_connection_pool_get_put():
    pool = ConnectionPool(max_size=2)
    key = ("host", 53)
    reader, writer = MagicMock(), MagicMock()
    writer.is_closing.return_value = False

    await pool.put(key, reader, writer)
    result = await pool.get(key)
    assert result is not None
    r, w = result
    assert r is reader
    assert w is writer


@pytest.mark.asyncio
async def test_connection_pool_max_size():
    pool = ConnectionPool(max_size=1)
    key = ("host", 53)
    writer1, writer2 = MagicMock(), MagicMock()
    writer1.is_closing.return_value = False
    writer2.is_closing.return_value = False

    await pool.put(key, MagicMock(), writer1)
    await pool.put(key, MagicMock(), writer2)
    writer1.close.assert_called_once()
    writer2.close.assert_not_called()


@pytest.mark.asyncio
async def test_connection_pool_closed_connection_dropped():
    pool = ConnectionPool()
    key = ("host", 53)
    reader, writer = MagicMock(), MagicMock()
    writer.is_closing.return_value = True

    await pool.put(key, reader, writer)
    result = await pool.get(key)
    assert result is None


@pytest.mark.asyncio
async def test_connection_pool_cleanup():
    pool = ConnectionPool(max_size=2, idle_timeout=0.1)
    key = ("host", 53)
    reader, writer = MagicMock(), MagicMock()
    writer.is_closing.return_value = False

    await pool.put(key, reader, writer)
    await pool.start_cleanup()
    await asyncio.sleep(0.2)

    result = await pool.get(key)
    assert result is None
    await pool.stop()


@pytest.mark.asyncio
async def test_connection_pool_stop_closes_all():
    pool = ConnectionPool(max_size=2)
    key1 = ("host1", 53)
    key2 = ("host2", 853)
    writer1, writer2 = MagicMock(), MagicMock()
    writer1.is_closing.return_value = False
    writer2.is_closing.return_value = False

    await pool.put(key1, MagicMock(), writer1)
    await pool.put(key2, MagicMock(), writer2)

    await pool.stop()
    writer1.close.assert_called_once()
    writer2.close.assert_called_once()
    assert len(pool._pools) == 0


# ---------- ClientPool tests ----------
@pytest.mark.asyncio
async def test_client_pool_basic():
    pool = ClientPool(max_size=2)
    key = ("host", 443)
    client = MagicMock()

    await pool.put(key, client)
    result = await pool.get(key)
    assert result is client


@pytest.mark.asyncio
async def test_client_pool_close_on_eviction():
    pool = ClientPool(max_size=1)
    key = ("host", 443)
    client1, client2 = MagicMock(), MagicMock()
    client1.aclose = AsyncMock()
    client2.aclose = AsyncMock()

    await pool.put(key, client1)
    await pool.put(key, client2)
    client1.aclose.assert_awaited_once()
    client2.aclose.assert_not_called()


@pytest.mark.asyncio
async def test_client_pool_cleanup():
    pool = ClientPool(idle_timeout=0.1)
    key = ("host", 443)
    client = MagicMock()
    client.aclose = AsyncMock()

    await pool.put(key, client)
    await pool.start_cleanup()
    await asyncio.sleep(0.2)

    result = await pool.get(key)
    assert result is None
    client.aclose.assert_awaited_once()
    await pool.stop()


@pytest.mark.asyncio
async def test_client_pool_stop_closes_all():
    pool = ClientPool()
    client1 = MagicMock()
    client1.aclose = AsyncMock()
    client2 = MagicMock()
    client2.close = MagicMock()

    await pool.put(("host1", 443), client1)
    await pool.put(("host2", 853), client2)

    await pool.stop()
    client1.aclose.assert_awaited_once()
    assert len(pool._pools) == 0


# ---------- HTTP/3 server tests ----------
@pytest.mark.asyncio
async def test_http3_protocol_handles_get_request():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    with patch.object(resolver, "forward_dns_query", new=AsyncMock(return_value=b"dummy_response")):
        quic = MagicMock()
        protocol = Http3ServerProtocol(quic=quic)
        protocol.set_holder(holder)

        send_responses = []
        async def fake_send_response(stream_id, status, body, content_type="text/plain"):
            send_responses.append((status, body, content_type))
        protocol._send_response = fake_send_response

        protocol._client_ip = "1.2.3.4"
        query = dns.message.make_query("example.com", "A").to_wire()
        b64 = base64.urlsafe_b64encode(query).decode()
        headers = {
            ":method": "GET",
            ":path": f"/dns-query?dns={b64}",
            ":scheme": "https",
            ":authority": "localhost",
        }
        stream_id = 0
        protocol._request_headers[stream_id] = headers
        protocol._request_data[stream_id] = bytearray()

        await protocol._handle_request(stream_id)

        assert len(send_responses) == 1
        status, body, content_type = send_responses[0]
        assert status == 200
        assert content_type == "application/dns-message"


@pytest.mark.asyncio
async def test_http3_protocol_handles_post_request():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    holder = ResolverHolder(resolver)

    with patch.object(resolver, "forward_dns_query", new=AsyncMock(return_value=b"dummy_response")):
        quic = MagicMock()
        protocol = Http3ServerProtocol(quic=quic)
        protocol.set_holder(holder)

        send_responses = []
        async def fake_send_response(stream_id, status, body, content_type="text/plain"):
            send_responses.append((status, body, content_type))
        protocol._send_response = fake_send_response

        protocol._client_ip = "1.2.3.4"
        query = dns.message.make_query("example.com", "A").to_wire()
        headers = {
            ":method": "POST",
            ":path": "/dns-query",
            ":scheme": "https",
            ":authority": "localhost",
            "content-type": "application/dns-message",
        }
        stream_id = 0
        protocol._request_headers[stream_id] = headers
        protocol._request_data[stream_id] = bytearray(query)

        await protocol._handle_request(stream_id)

        assert len(send_responses) == 1
        status, body, content_type = send_responses[0]
        assert status == 200
        assert content_type == "application/dns-message"


@pytest.mark.asyncio
async def test_http3_dispatches_get_when_headers_end_stream():
    resolver = DNSResolver()
    holder = ResolverHolder(resolver)
    query = dns.message.make_query("example.com", "A").to_wire()
    encoded_query = base64.urlsafe_b64encode(query).decode()
    headers = [
        (b":method", b"GET"),
        (b":path", f"/dns-query?dns={encoded_query}".encode()),
        (b"content-type", b"application/dns-message"),
    ]
    event = HeadersReceived(headers=headers, stream_id=0, stream_ended=True)
    protocol = Http3ServerProtocol(quic=MagicMock())
    protocol.set_holder(holder)
    protocol._client_ip = "192.0.2.10"
    protocol._http.handle_event = MagicMock(return_value=[event])
    protocol._send_response = AsyncMock()

    with patch.object(resolver, "forward_dns_query", new=AsyncMock(return_value=b"response")) as forward:
        protocol.quic_event_received(MagicMock())
        await asyncio.gather(*protocol._request_tasks.values())

    forward.assert_awaited_once_with(
        query, client_ip="192.0.2.10", rate_limit_checked=True
    )
    protocol._send_response.assert_awaited_once()


@pytest.mark.asyncio
async def test_http3_rejects_dns_bodies_over_wire_limit():
    protocol = Http3ServerProtocol(quic=MagicMock())
    protocol._http.handle_event = MagicMock(return_value=[
        DataReceived(stream_id=0, data=b"x" * 65536, stream_ended=True, push_id=None)
    ])
    protocol._send_response_now = MagicMock()

    protocol.quic_event_received(MagicMock())

    protocol._send_response_now.assert_called_once_with(
        0, 413, b"DNS message too large"
    )


# ---------- DoQ tests ----------
class MockQuicClient:
    def __init__(self, closed=False):
        self._quic = MagicMock()
        self._quic.closed = closed
        self._quic.get_next_available_stream_id = MagicMock(return_value=0)
        self._quic.send_stream_data = MagicMock()
        self.transmit = MagicMock()
        self._pending = {}
        self._connected = True
        self._cm = None

    async def wait_connected(self):
        if not self._connected:
            raise ConnectionError("Connection failed")
        return True


@pytest.mark.asyncio
async def test_doq_connection_pool_reuse():
    resolver = DNSResolver(upstreams=[{"address": "example.com", "protocol": "quic", "port": 853}])
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock(return_value=None)

    # Mock the connect function to return a context manager
    def mock_connect_func(*args, **kwargs):
        class CM:
            async def __aenter__(self):
                return mock_client
            async def __aexit__(self, *args):
                pass
        return CM()

    with patch("aioquic.asyncio.connect", side_effect=mock_connect_func) as mock_connect:
        # Create a proper query and matching response
        query = dns.message.make_query("example.com", "A")
        query_wire = query.to_wire()
        query_id = query_wire[:2]

        resp = dns.message.make_response(query)
        rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        resp.answer.append(rr)
        response_wire = resp.to_wire()
        # Ensure response has same ID as query
        response_wire = query_id + response_wire[2:]
        response_data = len(response_wire).to_bytes(2, 'big') + response_wire

        with patch("asyncio.wait_for", new=AsyncMock(return_value=response_data)):
            upstream = resolver.upstreams[0]
            result1 = await resolver._forward_quic(query_wire, upstream)
            assert result1 == response_wire
            assert mock_connect.call_count == 1

            result2 = await resolver._forward_quic(query_wire, upstream)
            assert result2 == response_wire
            assert mock_connect.call_count == 1


@pytest.mark.asyncio
async def test_doq_connection_pool_closed_connection():
    resolver = DNSResolver(upstreams=[{"address": "example.com", "protocol": "quic", "port": 853}])

    # Mock connect to return different clients
    connect_call_count = 0
    def mock_connect_func(*args, **kwargs):
        nonlocal connect_call_count
        connect_call_count += 1
        if connect_call_count == 1:
            client = MockQuicClient(closed=False)
            client.wait_connected = AsyncMock(return_value=None)
        else:
            client = MockQuicClient(closed=True)
            client.wait_connected = AsyncMock(return_value=None)

        class CM:
            async def __aenter__(self):
                return client
            async def __aexit__(self, *args):
                pass
        return CM()

    with patch("aioquic.asyncio.connect", side_effect=mock_connect_func) as mock_connect:
        with patch.object(resolver._quic_pool, "get") as mock_pool_get:
            mock_pool_get.side_effect = [None, MockQuicClient(closed=True)]

            # Create matching query/response
            query = dns.message.make_query("example.com", "A")
            query_wire = query.to_wire()
            query_id = query_wire[:2]

            resp = dns.message.make_response(query)
            resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
            response_wire = resp.to_wire()
            response_wire = query_id + response_wire[2:]
            response_data = len(response_wire).to_bytes(2, 'big') + response_wire

            with patch("asyncio.wait_for", new=AsyncMock(return_value=response_data)):
                upstream = resolver.upstreams[0]
                result1 = await resolver._forward_quic(query_wire, upstream)
                assert result1 == response_wire
                assert mock_connect.call_count == 1

                result2 = await resolver._forward_quic(query_wire, upstream)
                assert result2 == response_wire
                assert mock_connect.call_count == 2


@pytest.mark.asyncio
async def test_doq_connection_pool_handles_timeout():
    resolver = DNSResolver(upstreams=[{"address": "example.com", "protocol": "quic", "port": 853}])
    mock_client = MockQuicClient(closed=False)
    mock_client.wait_connected = AsyncMock(return_value=None)

    def mock_connect_func(*args, **kwargs):
        class CM:
            async def __aenter__(self):
                return mock_client
            async def __aexit__(self, *args):
                pass
        return CM()

    with patch("aioquic.asyncio.connect", side_effect=mock_connect_func) as mock_connect:
        with patch("asyncio.wait_for", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            query = dns.message.make_query("example.com", "A").to_wire()
            upstream = resolver.upstreams[0]

            with patch.object(resolver._quic_pool, "put") as mock_put:
                with pytest.raises(TimeoutError):
                    await resolver._forward_quic(query, upstream)
                mock_put.assert_not_called()


@pytest.mark.asyncio
async def test_doq_pool_handles_connection_error_during_handshake():
    resolver = DNSResolver(upstreams=[{"address": "example.com", "protocol": "quic", "port": 853}])
    mock_client = MockQuicClient()
    mock_client._connected = False
    mock_client.wait_connected = AsyncMock(side_effect=ConnectionError("Connection failed"))

    def mock_connect_func(*args, **kwargs):
        class CM:
            async def __aenter__(self):
                return mock_client
            async def __aexit__(self, *args):
                pass
        return CM()

    with patch("aioquic.asyncio.connect", side_effect=mock_connect_func) as mock_connect:
        query = dns.message.make_query("example.com", "A").to_wire()
        upstream = resolver.upstreams[0]

        with patch.object(resolver._quic_pool, "put") as mock_put:
            with pytest.raises(ConnectionError):
                await resolver._forward_quic(query, upstream)
            mock_put.assert_not_called()    


# ---------- TCP fallback tests (already in resolver, but keep separate for clarity) ----------
@pytest.fixture
def tcp_resolver():
    return DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        tcp_fallback_enabled=True,
    )


@pytest.mark.asyncio
async def test_tcp_fallback_on_truncation(tcp_resolver):
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(data, upstream):
        return truncated_wire
    tcp_resolver._forward_udp = fake_forward_udp

    tcp_response = b'success_over_tcp'
    async def fake_forward_tcp(data, upstream):
        return tcp_response
    tcp_resolver._forward_tcp = fake_forward_tcp

    query_data = query.to_wire()
    result = await tcp_resolver._try_upstream(tcp_resolver.upstreams[0], query_data)
    assert result == tcp_response


@pytest.mark.asyncio
async def test_tcp_fallback_disabled_network(tcp_resolver):
    tcp_resolver.tcp_fallback_enabled = False
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(data, upstream):
        return truncated_wire
    tcp_resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(data, upstream):
        nonlocal tcp_called
        tcp_called = True
        return b'tcp'
    tcp_resolver._forward_tcp = fake_forward_tcp

    query_data = query.to_wire()
    result = await tcp_resolver._try_upstream(tcp_resolver.upstreams[0], query_data)
    assert result == truncated_wire
    assert tcp_called is False


@pytest.mark.asyncio
async def test_tcp_fallback_does_not_trigger_on_non_truncated(tcp_resolver):
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    normal_wire = resp.to_wire()

    async def fake_forward_udp(data, upstream):
        return normal_wire
    tcp_resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(data, upstream):
        nonlocal tcp_called
        tcp_called = True
        return b'tcp'
    tcp_resolver._forward_tcp = fake_forward_tcp

    query_data = query.to_wire()
    result = await tcp_resolver._try_upstream(tcp_resolver.upstreams[0], query_data)
    assert result == normal_wire
    assert tcp_called is False


@pytest.mark.asyncio
async def test_tcp_fallback_uses_same_upstream_with_tcp_protocol(tcp_resolver):
    captured_upstream = None
    async def fake_forward_udp(data, upstream):
        query = dns.message.from_wire(data)
        resp = dns.message.make_response(query)
        resp.flags |= dns.flags.TC
        return resp.to_wire()

    async def fake_forward_tcp(data, upstream):
        nonlocal captured_upstream
        captured_upstream = upstream
        return b'tcp_response'

    tcp_resolver._forward_udp = fake_forward_udp
    tcp_resolver._forward_tcp = fake_forward_tcp

    query_data = dns.message.make_query("example.com", "A").to_wire()
    result = await tcp_resolver._try_upstream(tcp_resolver.upstreams[0], query_data)

    assert result == b'tcp_response'
    assert captured_upstream is not None
    assert captured_upstream['protocol'] == 'tcp'
    assert captured_upstream['address'] == tcp_resolver.upstreams[0]['address']
    assert captured_upstream.get('port') == 53