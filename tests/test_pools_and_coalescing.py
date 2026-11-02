import asyncio
import time
import pytest

from dosev.resolver import ConnectionPool, ClientPool, DNSResolver


class DummyWriter:
    def __init__(self):
        self._closed = False
    def is_closing(self):
        return self._closed
    def close(self):
        self._closed = True


@pytest.mark.asyncio
async def test_connection_pool_stop_cleans_up():
    pool = ConnectionPool(max_size=2, idle_timeout=0.1)
    key = ('localhost', 80)
    # create dummy reader/writer pairs
    r1, w1 = object(), DummyWriter()
    r2, w2 = object(), DummyWriter()
    await pool.put(key, r1, w1)
    await pool.put(key, r2, w2)
    # stop should close writers and clear pools
    await pool.stop()
    assert not pool._pools


@pytest.mark.asyncio
async def test_client_pool_stop_closes_clients(monkeypatch):
    pool = ClientPool(max_size=2, idle_timeout=0.1)
    key = ('upstream', 443)
    class DummyClient:
        def __init__(self):
            self.closed = False
        def close(self):
            self.closed = True
    c1 = DummyClient()
    await pool.put(key, c1)
    await pool.stop()
    assert not pool._pools


import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rrset

@pytest.mark.asyncio
async def test_flight_coalescing(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{'address':'1.1.1.1','protocol':'udp','port':53,'ip':'1.1.1.1'}],
        cache_ttl=0,  # Disable caching
        negative_cache_ttl=0
    )
    call_count = 0
    lock = asyncio.Lock()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        nonlocal call_count
        async with lock:
            call_count += 1
        await asyncio.sleep(0.5)  # Extended wait to guarantee concurrency overlapping
        query_msg = dns.message.from_wire(data)
        resp = dns.message.make_response(query_msg)
        rr = dns.rrset.from_text("example.com.", 0, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")  # TTL=0
        resp.answer.append(rr)
        return resp.to_wire()

    monkeypatch.setattr(resolver, '_try_upstream', fake_try_upstream)

    q = dns.message.make_query("example.com", "A").to_wire()

    async def invoke():
        return await resolver.forward_dns_query(q)

    # Run concurrent queries
    results = await asyncio.gather(invoke(), invoke(), invoke())
    assert call_count == 1, f"Expected 1 call, got {call_count}"
    assert all(r == results[0] for r in results)


@pytest.mark.asyncio
async def test_cancelled_flight_leader_releases_waiter(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{'address': '127.0.0.1', 'protocol': 'udp', 'ip': '127.0.0.1'}],
    )
    upstream_started = asyncio.Event()
    call_count = 0

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            upstream_started.set()
            await asyncio.Event().wait()
        query_msg = dns.message.from_wire(data)
        response = dns.message.make_response(query_msg)
        response.answer.append(dns.rrset.from_text(
            'example.com.', 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'
        ))
        return response.to_wire()

    monkeypatch.setattr(resolver, '_try_upstream', fake_try_upstream)
    query = dns.message.make_query('example.com', 'A').to_wire()

    leader = asyncio.create_task(resolver.forward_dns_query(query))
    await upstream_started.wait()
    waiter = asyncio.create_task(resolver.forward_dns_query(query))
    await asyncio.sleep(0)
    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader

    response = await asyncio.wait_for(waiter, timeout=1.0)
    assert dns.message.from_wire(response).answer
    assert call_count == 2
    