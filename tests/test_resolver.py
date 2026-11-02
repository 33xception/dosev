"""
Consolidated resolver core tests.
Combines: test_resolver.py, test_resolver_advanced.py, test_resolver_edge_cases.py,
test_resolver_extra.py, test_resolver_upstreams.py, test_ipv6_stripping.py,
test_load_balancing.py, test_ns_scrub.py
"""
import asyncio
import os
import tempfile
import time
import socket
import random
import pytest
import ssl
from typing import List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rcode
import dns.name
from dns.rdtypes.ANY.RRSIG import RRSIG

from dosev.resolver import DNSResolver, RateLimiter, AsyncTTLCache, ConnectionPool

def make_matching_response(query_data: bytes, rcode: int = dns.rcode.NOERROR, 
                         answers: Optional[List[dns.rrset.RRset]] = None,
                         authority: Optional[List[dns.rrset.RRset]] = None) -> bytes:
    """Create a DNS response that matches the query's transaction ID."""
    query_msg = dns.message.from_wire(query_data)
    resp = dns.message.make_response(query_msg)
    resp.set_rcode(rcode)
    if answers:
        for rrset in answers:
            resp.answer.append(rrset)
    if authority:
        for rrset in authority:
            resp.authority.append(rrset)
    return resp.to_wire()
# ---------- Fixtures ----------
@pytest.fixture
def resolver():
    """Basic resolver with a default upstream."""
    return DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])


@pytest.fixture
def resolver_with_scrub():
    """Resolver with NS scrubbing enabled."""
    return DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        scrub_unsolicited_ns=True,
    )

# ---------- Helpers ----------
def make_a_response(qname: str, ip: str = "192.0.2.1", ttl: int = 60) -> bytes:
    if not qname.endswith('.'):
        qname = qname + '.'
    query = dns.message.make_query(qname, "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, ip)
    resp.answer.append(rr)
    return resp.to_wire()


def make_rrsig(covered_type: int, name: str) -> dns.rrset.RRset:
    if not name.endswith('.'):
        name = name + '.'
    covered_text = dns.rdatatype.to_text(covered_type)
    rrsig_text = f"{covered_text} 8 2 300 20350101000000 20250101000000 12345 example.com. AAAA"
    return dns.rrset.from_text(name, 300, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrsig_text)


@pytest.mark.asyncio
async def test_async_ttl_cache_updates_and_evicts_in_constant_order():
    cache = AsyncTTLCache(maxsize=2, ttl=60)
    await cache.set("first", 1)
    await cache.set("second", 2)
    await cache.set("first", 10)
    await cache.set("third", 3)

    assert await cache.get("first") == 10
    assert await cache.get("second") is None
    assert await cache.get("third") == 3


# ---------- Basic Resolver Tests ----------
@pytest.mark.asyncio
async def test_is_blocked_exact_and_suffix():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    await resolver.set_blocklist(["example.com", ".bad"])

    assert await resolver.is_blocked("example.com") is True
    assert await resolver.is_blocked("sub.bad") is True
    assert await resolver.is_blocked("good.com") is False


def test_build_block_response_nxdomain():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver.build_block_response(query, action="NXDOMAIN")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NXDOMAIN


def test_build_nxdomain_response_preserves_opt_section():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A")
    ecs_opt = dns.edns.ECSOption("192.0.2.0", 24, 0)
    query.use_edns(options=[ecs_opt])
    response = resolver._make_nxdomain_response(query.to_wire())
    msg = dns.message.from_wire(response)

    assert msg.rcode() == dns.rcode.NXDOMAIN
    assert msg.opt is not None
    assert len(msg.options) == 1
    assert isinstance(msg.options[0], dns.edns.ECSOption)
    assert msg.options[0].address == "192.0.2.0"
    assert msg.options[0].srclen == 24


@pytest.mark.asyncio
async def test_forward_preserves_edns_payload(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=8192)
    query_wire = query.to_wire()

    captured = {}
    async def fake_try_upstream(upstream, data):
        captured['wire'] = data
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response = await resolver.forward_dns_query(query_wire)
    assert captured['wire'] is not None
    sent_msg = dns.message.from_wire(captured['wire'])
    assert sent_msg.opt is not None
    assert sent_msg.payload == 8192
    assert response is not None


@pytest.mark.asyncio
async def test_make_local_a_response_with_hosts_map():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    await resolver.set_hosts_map({"example.com": ("203.0.113.1",)})
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].to_text().endswith("203.0.113.1")


@pytest.mark.asyncio
async def test_forward_dns_query_negative_responses_are_cached(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        negative_cache_ttl=5
    )
    query = dns.message.make_query("does-not-exist.example", "A").to_wire()
    calls = 0

    async def fake_try_upstream(upstream, data):
        nonlocal calls
        calls += 1
        req = dns.message.from_wire(data)
        resp = dns.message.make_response(req)
        resp.set_rcode(dns.rcode.NXDOMAIN)
        resp.authority.append(dns.rrset.from_text(
            "example.", 30, "IN", "SOA",
            "ns.example. hostmaster.example. 1 3600 600 86400 60"
        ))
        return resp.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response1 = await resolver.forward_dns_query(query)
    response2 = await resolver.forward_dns_query(query)

    assert calls == 1
    assert dns.message.from_wire(response1).rcode() == dns.rcode.NXDOMAIN
    assert dns.message.from_wire(response2).rcode() == dns.rcode.NXDOMAIN


@pytest.mark.asyncio
async def test_forward_dns_query_does_not_cache_servfail(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}]
    )
    query = dns.message.make_query("temporary-failure.example", "A").to_wire()
    calls = 0

    async def failing_upstream(upstream, data):
        nonlocal calls
        calls += 1
        response = dns.message.make_response(dns.message.from_wire(data))
        response.set_rcode(dns.rcode.SERVFAIL)
        return response.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", failing_upstream)

    first = await resolver.forward_dns_query(query)
    second = await resolver.forward_dns_query(query)

    assert calls == 2
    assert dns.message.from_wire(first).rcode() == dns.rcode.SERVFAIL
    assert dns.message.from_wire(second).rcode() == dns.rcode.SERVFAIL


@pytest.mark.asyncio
async def test_negative_cache_decrements_ttl_and_uses_soa_bounds():
    resolver = DNSResolver(negative_cache_ttl=60)
    query = dns.message.make_query("example.com", "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NXDOMAIN)
    response.authority.append(dns.rrset.from_text(
        "example.com.", 90, "IN", "SOA",
        "ns.example.com. hostmaster.example.com. 1 3600 600 86400 60"
    ))
    key = ("example.com.", dns.rdatatype.A, "global")

    assert resolver._extract_soa_minimum(response.to_wire()) == 60
    with patch("time.time", return_value=1000):
        await resolver._negative_cache_set(key, response.to_wire(), ttl=60)
    with patch("time.time", return_value=1007):
        cached = await resolver._negative_cache_get(key)

    assert cached is not None
    assert dns.message.from_wire(cached).authority[0].ttl == 53


@pytest.mark.asyncio
async def test_negative_response_without_soa_is_not_cached(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "127.0.0.1", "protocol": "udp", "ip": "127.0.0.1"}])
    query = dns.message.make_query("missing.example", "A").to_wire()
    calls = 0

    async def fake_try_upstream(upstream, data):
        nonlocal calls
        calls += 1
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)
    await resolver.forward_dns_query(query)
    await resolver.forward_dns_query(query)
    assert calls == 2


@pytest.mark.asyncio
async def test_forward_dns_query_cache_expires(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        cache_ttl=1
    )
    query = dns.message.make_query("example.com", "A").to_wire()

    async def fake_try_upstream(upstream, data):
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response1 = await resolver.forward_dns_query(query)
    response2 = await resolver.forward_dns_query(query)
    assert response1 == response2

    await asyncio.sleep(1.1)
    response3 = await resolver.forward_dns_query(query)
    assert response3 == response1


@pytest.mark.asyncio
async def test_cached_answer_uses_remaining_ttl_and_client_edns(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}]
    )

    class Clock:
        now = 1000.0

        def time(self):
            return self.now

    clock = Clock()
    monkeypatch.setattr("dosev.resolver.time", clock)
    calls = 0

    async def fake_upstream(upstream, data):
        nonlocal calls
        calls += 1
        response = dns.message.make_response(dns.message.from_wire(data))
        response.answer.append(dns.rrset.from_text(
            "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"
        ))
        response.use_edns(payload=4096, ednsflags=dns.flags.DO)
        return response.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_upstream)
    query = dns.message.make_query("example.com", "A")
    first = await resolver.forward_dns_query(query.to_wire())
    assert dns.message.from_wire(first).edns == -1
    clock.now += 2.0

    edns_query = dns.message.make_query("example.com", "A")
    edns_query.use_edns(payload=1232)
    second = await resolver.forward_dns_query(edns_query.to_wire())
    cached = dns.message.from_wire(second)

    assert calls == 1
    assert cached.opt is not None
    assert cached.payload == 1232
    assert not (cached.ednsflags & dns.flags.DO)
    assert cached.answer[0].ttl == 298


@pytest.mark.asyncio
async def test_forward_dns_query_strips_ecs_when_disabled(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        ecs_enabled=False
    )
    query = dns.message.make_query("example.com", "A")
    ecs_opt = dns.edns.ECSOption("192.0.2.0", 24, 0)
    query.use_edns(options=[ecs_opt])
    qwire = query.to_wire()

    called = {}
    async def fake_try_upstream(upstream, data):
        called['data'] = data
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)

    response = await resolver.forward_dns_query(qwire)
    assert response is not None
    assert 'data' in called
    called_msg = dns.message.from_wire(called['data'])
    assert called_msg.opt is not None
    assert called_msg.options == ()


@pytest.mark.asyncio
async def test_get_auto_doh_version_prefers_http3_then_http2(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "https", "ip": "1.1.1.1"}], doh_timeout=1.0)

    async def fake_https3(data, hostname, port, host, path, ip_override):
        return b'response'

    async def fake_https2(data, hostname, port, host, path, ip_override):
        return b'response2'

    monkeypatch.setattr(resolver, '_forward_https3', fake_https3)
    monkeypatch.setattr(resolver, '_forward_https2', fake_https2)

    version = await resolver._get_auto_doh_version('example.com', 443, 'example.com', '/dns-query')
    assert version == '3'


@pytest.mark.asyncio
async def test_rate_limiter():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        rate_limit_rps=1.0,
        rate_limit_burst=1.0
    )
    limiter = resolver.rate_limiter
    assert limiter is not None
    assert await limiter.is_allowed("1.2.3.4") is True
    assert await limiter.is_allowed("1.2.3.4") is False
    await asyncio.sleep(1.1)
    assert await limiter.is_allowed("1.2.3.4") is True


# ---------- EDNS0 Tests ----------
@pytest.mark.asyncio
async def test_forward_preserves_edns_payload_advanced(resolver):
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1232, options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    qwire = query.to_wire()

    captured = {}

    async def fake_upstream(upstream, data):
        captured["data"] = data  # Actually capture the data
        msg = dns.message.from_wire(data)
        resp = dns.message.make_response(msg)
        resp.use_edns(payload=1232)
        return resp.to_wire()

    resolver._try_upstream = fake_upstream

    response = await resolver.forward_dns_query(qwire)
    assert "data" in captured
    sent = dns.message.from_wire(captured["data"])
    assert sent.opt is not None
    assert sent.payload == 1232
    assert response is not None


@pytest.mark.asyncio
async def test_forward_strips_ecs_when_disabled_advanced(resolver):
    resolver.ecs_enabled = False
    query = dns.message.make_query("example.com", "A")
    query.use_edns(options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    qwire = query.to_wire()

    captured = {}

    async def fake_upstream(upstream, data):
        captured["data"] = data
        msg = dns.message.from_wire(data)
        resp = dns.message.make_response(msg)
        return resp.to_wire()

    resolver._try_upstream = fake_upstream

    response = await resolver.forward_dns_query(qwire)
    sent = dns.message.from_wire(captured["data"])
    assert sent.opt is not None
    assert sent.options == ()


def test_doh_age_decrements_dns_ttls_without_changing_opt_ttl():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text("example.com.", 60, "IN", "A", "192.0.2.1"))
    response.authority.append(dns.rrset.from_text(
        "example.com.", 90, "IN", "SOA",
        "ns.example.com. hostmaster.example.com. 1 3600 600 86400 60"
    ))
    response.use_edns(payload=1232)

    aged = dns.message.from_wire(resolver._apply_doh_age(response.to_wire(), 25))
    assert aged.answer[0].ttl == 35
    assert aged.authority[0].ttl == 65
    assert aged.opt.ttl == response.opt.ttl


def test_normalized_badvers_keeps_upstream_edns_version():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(edns=1, payload=1232)
    response = dns.message.make_response(query)
    response.use_edns(edns=0, payload=1232)
    response.set_rcode(dns.rcode.BADVERS)

    normalized = dns.message.from_wire(
        resolver._normalize_response_edns(response.to_wire(), query, False)
    )
    assert normalized.edns == 0
    assert normalized.rcode() == dns.rcode.BADVERS


@pytest.mark.asyncio
async def test_edns_option_queries_bypass_response_cache(monkeypatch):
    resolver = DNSResolver(upstreams=[{"address": "127.0.0.1", "protocol": "udp", "ip": "127.0.0.1"}])
    query = dns.message.make_query("example.com", "A")
    query.use_edns(options=[dns.edns.GenericOption(65001, b"request")])
    calls = 0

    async def fake_try_upstream(upstream, data):
        nonlocal calls
        calls += 1
        request = dns.message.from_wire(data)
        response = dns.message.make_response(request)
        response.use_edns(options=[dns.edns.GenericOption(65001, b"response")])
        return response.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_try_upstream)
    await resolver.forward_dns_query(query.to_wire())
    await resolver.forward_dns_query(query.to_wire())
    assert calls == 2


def test_cache_safe_response_drops_opt_and_rejects_other_options():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    response = dns.message.make_response(query)
    response.use_edns(payload=1232)
    safe = resolver._cache_safe_response(response.to_wire())
    assert safe is not None
    assert dns.message.from_wire(safe).edns == -1

    response.use_edns(options=[dns.edns.GenericOption(65001, b"response")])
    assert resolver._cache_safe_response(response.to_wire()) is None


# ---------- DNSSEC Tests (basic) ----------
@pytest.mark.asyncio
async def test_dnssec_unsigned_domain_is_insecure(resolver):
    resolver.dnssec_enabled = True
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}
    resolver._is_proven_insecure_name = AsyncMock(return_value=True)

    qname = "example.com"
    msg = dns.message.make_response(dns.message.make_query(qname, "A"))
    rr = dns.rrset.from_text(qname + ".", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    msg.answer.append(rr)
    wire = msg.to_wire()

    secure, insecure = await resolver._dnssec_validate(qname, wire, dnssec_requested=True)
    assert secure is False
    assert insecure is True


@pytest.mark.asyncio
async def test_dnssec_validates_when_client_does_not_set_do(resolver, monkeypatch):
    resolver.dnssec_enabled = True
    query = dns.message.make_query("example.com", "A")
    captured = {}

    async def fake_upstream(upstream, data):
        forwarded = dns.message.from_wire(data)
        captured["do"] = bool(forwarded.ednsflags & dns.flags.DO)
        response = dns.message.make_response(forwarded)
        response.answer.append(dns.rrset.from_text(
            "example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"
        ))
        response.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))
        return response.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_upstream)
    validation = AsyncMock(return_value=(True, False))
    monkeypatch.setattr(resolver, "_dnssec_validate", validation)

    response_wire = await resolver.forward_dns_query(query.to_wire())
    response = dns.message.from_wire(response_wire)

    assert captured["do"] is True
    validation.assert_awaited_once()
    assert response.edns == -1
    assert [rrset.rdtype for rrset in response.answer] == [dns.rdatatype.A]


@pytest.mark.asyncio
async def test_dnssec_bogus_raises(resolver):
    resolver.dnssec_enabled = True
    with patch.object(resolver, "_dnssec_validate", side_effect=dns.dnssec.ValidationFailure("bad")):
        with pytest.raises(dns.dnssec.ValidationFailure):
            await resolver._dnssec_validate("example.com", b"", dnssec_requested=True)


@pytest.mark.asyncio
async def test_process_upstream_response_returns_servfail_on_dnssec_exception(resolver):
    resolver.dnssec_enabled = True
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
    resp_wire = resp.to_wire()

    resolver._try_upstream = AsyncMock(return_value=resp_wire)
    with patch.object(resolver, "_dnssec_validate", new=AsyncMock(side_effect=dns.dnssec.ValidationFailure("bad"))):
        result = await resolver._process_upstream_response(
            {"protocol": "udp", "address": "1.1.1.1"},
            resp_wire,
            "example.com",
            True,
            ("example.com", 1, "global"),
            0,
        )

    msg = dns.message.from_wire(result)
    assert msg.rcode() == dns.rcode.SERVFAIL


@pytest.mark.asyncio
async def test_process_upstream_response_returns_servfail_on_bogus_dnssec_result(resolver):
    resolver.dnssec_enabled = True
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
    resp_wire = resp.to_wire()

    resolver._try_upstream = AsyncMock(return_value=resp_wire)
    with patch.object(resolver, "_dnssec_validate", new=AsyncMock(return_value=(False, False))):
        result = await resolver._process_upstream_response(
            {"protocol": "udp", "address": "1.1.1.1"},
            resp_wire,
            "example.com",
            True,
            ("example.com", 1, "global"),
            0,
        )

    msg = dns.message.from_wire(result)
    assert msg.rcode() == dns.rcode.SERVFAIL


# ---------- Negative Caching ----------
@pytest.mark.asyncio
async def test_negative_cache_uses_soa_minimum(resolver):
    resolver.negative_cache_ttl = 5
    query = dns.message.make_query("nxdomain.example", "A")
    qwire = query.to_wire()

    soa_rr = dns.rrset.from_text(
        "example.com.", 3600, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns1.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )

    async def fake_upstream(upstream, data):
        req = dns.message.from_wire(data)
        resp = dns.message.make_response(req)
        resp.set_rcode(dns.rcode.NXDOMAIN)
        resp.authority.append(soa_rr)
        return resp.to_wire()

    resolver._try_upstream = fake_upstream

    # First query - should call upstream and cache
    response1 = await resolver.forward_dns_query(qwire)
    msg1 = dns.message.from_wire(response1)
    assert msg1.rcode() == dns.rcode.NXDOMAIN

    # Check cache was populated with trailing dot matching `resolver.py` cache logic
    qname = "nxdomain.example."
    qtype = dns.rdatatype.A
    key = (qname.lower(), qtype, "global")
    entry = await resolver._negative_cache_get(key)
    assert entry is not None, "Negative cache entry should exist"

    # Second query - should use cache
    response2 = await resolver.forward_dns_query(qwire)
    msg2 = dns.message.from_wire(response2)
    assert msg2.rcode() == dns.rcode.NXDOMAIN


# ---------- Optimistic Caching ----------
@pytest.mark.asyncio
async def test_optimistic_cache_serves_stale(resolver):
    resolver.optimistic_cache_enabled = True
    resolver.stale_max_age = 3600
    resolver.stale_response_ttl = 30

    query = dns.message.make_query("stale.example.com", "A")
    qwire = query.to_wire()
    qname = str(query.question[0].name).rstrip('.')
    qtype = query.question[0].rdtype

    # Create a response
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("stale.example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    wire = resp.to_wire()

    now = time.time()
    expiry = now - 10  # Already expired
    stale_until = now + 3600
    key = ("stale.example.com.", qtype, "global")
    entry = (wire, expiry, qwire, stale_until, False)
    await resolver._wire_cache_set(key, entry)

    # Mock to verify refresh is called
    async def fake_refresh(k, qd):
        pass
    resolver._maybe_refresh_stale = fake_refresh

    response = await resolver.forward_dns_query(qwire)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) > 0
    # The TTL should be rewritten to stale_response_ttl
    assert msg.answer[0].ttl == 30


# ---------- Blocklist Actions ----------
def test_build_block_response_refused(resolver):
    query = dns.message.make_query("blocked.com", "A").to_wire()
    resp_wire = resolver.build_block_response(query, action="REFUSED")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.REFUSED


def test_build_block_response_zeroip_a(resolver):
    query = dns.message.make_query("blocked.com", "A").to_wire()
    resp_wire = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "0.0.0.0"


def test_build_block_response_zeroip_aaaa_disabled(resolver):
    resolver.disable_ipv6 = True
    query = dns.message.make_query("blocked.com", "AAAA").to_wire()
    resp_wire = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.NXDOMAIN


def test_build_block_response_zeroip_any(resolver):
    query = dns.message.make_query("blocked.com", "ANY").to_wire()
    resp_wire = resolver.build_block_response(query, action="ZEROIP")
    msg = dns.message.from_wire(resp_wire)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 2
    types = {rr.rdtype for rr in msg.answer}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA in types


# ---------- Hosts Override ----------
@pytest.mark.asyncio
async def test_hosts_override_a(resolver):
    await resolver.set_hosts_map({"example.com": ("192.0.2.1",)})
    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"


@pytest.mark.asyncio
async def test_hosts_override_aaaa(resolver):
    await resolver.set_hosts_map({"example.com": ("2001:db8::1",)})
    query = dns.message.make_query("example.com", "AAAA").to_wire()
    async def fake_upstream(upstream, data):
        return make_matching_response(data)
    resolver._try_upstream = fake_upstream
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.AAAA


# ---------- Rebinding Protection ----------
def test_rebind_protection_strips_private(resolver):
    resolver.rebind_protection_enabled = True
    resolver.rebind_action = "strip"
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8"))
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    wire = resp.to_wire()
    result = resolver._apply_rebind_protection(wire)
    msg = dns.message.from_wire(result)
    ips = [rr.to_text().split()[-1] for rr in msg.answer if rr.rdtype == dns.rdatatype.A]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips


def test_rebind_protection_blocks_all_private(resolver):
    resolver.rebind_protection_enabled = True
    resolver.rebind_action = "block"
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1"))
    wire = resp.to_wire()
    result = resolver._apply_rebind_protection(wire)
    assert result is None


# ---------- Upstream Failover ----------
@pytest.mark.asyncio
async def test_upstream_failover(resolver):
    resolver.upstreams = [
        {"address": "1.1.1.1", "port": 53, "protocol": "udp", "ip": "1.1.1.1"},
        {"address": "8.8.8.8", "port": 53, "protocol": "udp", "ip": "8.8.8.8"},
    ]
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream['address'])
        if upstream['address'] == "1.1.1.1":
            raise Exception("fail")
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert calls == ["1.1.1.1", "8.8.8.8"]


# ---------- Connection Pool (basic) ----------
@pytest.mark.asyncio
async def test_connection_pool_get_put():
    pool = ConnectionPool(max_size=1, idle_timeout=1.0)
    key = ("host", 53)
    reader = MagicMock()
    writer = MagicMock()
    writer.is_closing.return_value = False
    await pool.put(key, reader, writer)
    result = await pool.get(key)
    assert result is not None
    r, w = result
    assert r is reader
    assert w is writer
    result2 = await pool.get(key)
    assert result2 is None


# ---------- Trust Anchor Loading ----------
def test_load_trust_anchors_from_file(resolver):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(". 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0=")
        fname = f.name
    resolver.dnssec_enabled = True
    resolver.trust_anchors = fname
    resolver._load_trust_anchors()
    assert resolver._dnssec_raw_anchors is not None
    assert dns.name.root in resolver._dnssec_raw_anchors
    os.unlink(fname)


def test_load_trust_anchors_default(resolver):
    resolver.dnssec_enabled = True
    resolver.trust_anchors = None
    resolver._load_trust_anchors()
    assert resolver._dnssec_raw_anchors is not None
    assert dns.name.root in resolver._dnssec_raw_anchors


# ---------- Config Update ----------
@pytest.mark.asyncio
async def test_update_config_changes_edns_payload(resolver):
    assert resolver.max_edns_payload == 4096
    await resolver.update_config(max_edns_payload=1232)
    assert resolver.max_edns_payload == 1232


@pytest.mark.asyncio
async def test_dnssec_background_tasks_follow_runtime_config(resolver):
    await resolver.start()
    assert resolver._trust_anchor_updater_task is None

    await resolver.update_config(dnssec_enabled=True, auto_update_trust_anchor=False)
    assert resolver._insecure_cleanup_task is not None
    assert resolver._trust_anchor_updater_task is None

    cleanup_task = resolver._insecure_cleanup_task
    await resolver.update_config(dnssec_enabled=False)
    assert resolver._insecure_cleanup_task is None
    assert cleanup_task.cancelled()
    await resolver.shutdown()


@pytest.mark.asyncio
async def test_update_config_changes_rate_limiter(resolver):
    assert resolver.rate_limiter is None
    await resolver.update_config(rate_limit_rps=10.0, rate_limit_burst=5.0)
    assert resolver.rate_limiter is not None
    assert resolver.rate_limit_rps == 10.0
    assert resolver.rate_limit_burst == 5.0


# ---------- Rate Limiter (standalone) ----------
@pytest.mark.asyncio
async def test_rate_limiter_token_bucket():
    limiter = RateLimiter(rate=1.0, burst=2.0)
    assert await limiter.is_allowed("ip") is True
    assert await limiter.is_allowed("ip") is True
    assert await limiter.is_allowed("ip") is False
    await asyncio.sleep(1.1)
    assert await limiter.is_allowed("ip") is True


# ---------- TC bit ----------
def test_set_tc_bit(resolver):
    msg = dns.message.make_query("example.com", "A")
    wire = msg.to_wire()
    new_wire = resolver._set_tc_bit(wire)
    flags = int.from_bytes(new_wire[2:4], 'big')
    assert flags & 0x0200 != 0


# ---------- EDNS0 in NXDOMAIN ----------
def test_make_nxdomain_response_preserves_edns(resolver):
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1232, options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    wire = query.to_wire()
    nx = resolver._make_nxdomain_response(wire)
    msg = dns.message.from_wire(nx)
    assert msg.opt is not None
    assert msg.payload == 1232
    assert len(msg.options) == 1
    assert isinstance(msg.options[0], dns.edns.ECSOption)


# ---------- Forward UDP Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_udp_timeout():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        udp_timeout=0.01
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    loop = asyncio.get_running_loop()

    # Mock sock_recvfrom to raise TimeoutError
    async def mock_recvfrom(sock, bufsize):
        await asyncio.sleep(0.1)  # Longer than timeout
        raise asyncio.TimeoutError()

    with patch.object(loop, "sock_sendall", new=AsyncMock()):
        with patch.object(loop, "sock_recvfrom", new=mock_recvfrom):
            with patch.object(resolver, "_get_udp_socket", new=AsyncMock(return_value=MagicMock())):
                with pytest.raises(asyncio.TimeoutError):
                    await resolver._forward_udp(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_udp_connection_lost():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    loop = asyncio.get_running_loop()
    with patch.object(loop, "sock_sendto", new=AsyncMock(side_effect=ConnectionError("Lost"))):
        with patch.object(resolver, "_get_udp_socket", new=AsyncMock(return_value=MagicMock())):
            with pytest.raises(ConnectionError, match="Lost"):
                await resolver._forward_udp(data, resolver.upstreams[0])


# ---------- Forward TCP Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_tcp_pool_reuse():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")
    resp = data[:2] + resp[2:]

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        def readexactly_side_effect(n):
            if n == 2:
                return len(resp).to_bytes(2, "big")
            else:
                return resp
        reader.readexactly = AsyncMock(side_effect=readexactly_side_effect)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch.object(resolver, "_open_tcp_connection", side_effect=fake_connect):
        result = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result == resp

        result2 = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result2 == resp


@pytest.mark.asyncio
async def test_open_tcp_connection_enables_fastopen_before_connect(monkeypatch):
    fastopen_option = 30
    monkeypatch.setattr(socket, "TCP_FASTOPEN_CONNECT", fastopen_option, raising=False)
    resolver = DNSResolver(tcp_timeout=3.0)
    calls = []

    class FakeSocket:
        def setsockopt(self, level, option, value):
            calls.append(("setsockopt", level, option, value))

        def settimeout(self, timeout):
            calls.append(("settimeout", timeout))

        def connect(self, address):
            calls.append(("connect", address))

        def setblocking(self, enabled):
            calls.append(("setblocking", enabled))

        def close(self):
            calls.append(("close",))

    fake_socket = FakeSocket()
    monkeypatch.setattr(socket, "socket", lambda *args: fake_socket)

    async def fake_to_thread(function, *args):
        function(*args)

    reader, writer = object(), object()

    async def fake_open_connection(*args, **kwargs):
        assert kwargs == {"sock": fake_socket}
        return reader, writer

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    assert await resolver._open_tcp_connection("192.0.2.1", 53) == (reader, writer)
    assert calls[:3] == [
        ("setsockopt", socket.IPPROTO_TCP, fastopen_option, 1),
        ("settimeout", 3.0),
        ("connect", ("192.0.2.1", 53)),
    ]
    assert calls[3] == ("setblocking", False)


@pytest.mark.asyncio
async def test_open_tcp_connection_can_disable_fastopen(monkeypatch):
    resolver = DNSResolver(tcp_fastopen_enabled=False)
    reader, writer = object(), object()
    open_connection = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    assert await resolver._open_tcp_connection("192.0.2.1", 53) == (reader, writer)
    open_connection.assert_awaited_once_with("192.0.2.1", 53)


@pytest.mark.asyncio
async def test_open_tcp_connection_falls_back_without_fastopen_cookie(monkeypatch):
    monkeypatch.setattr(socket, "TCP_FASTOPEN_CONNECT", 30, raising=False)
    resolver = DNSResolver()

    class FakeSocket:
        def setsockopt(self, level, option, value):
            pass

        def settimeout(self, timeout):
            pass

        def connect(self, address):
            raise BlockingIOError

        def close(self):
            pass

    fake_socket = FakeSocket()
    monkeypatch.setattr(socket, "socket", lambda *args: fake_socket)

    async def fake_to_thread(function, *args):
        function(*args)

    reader, writer = object(), object()
    open_connection = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)
    monkeypatch.setattr(asyncio, "open_connection", open_connection)

    assert await resolver._open_tcp_connection("192.0.2.1", 53) == (reader, writer)
    open_connection.assert_awaited_once_with("192.0.2.1", 53)


@pytest.mark.asyncio
async def test_forward_tcp_closes_new_connection_after_timeout(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tcp", "port": 53, "ip": "127.0.0.1"}]
    )
    query = dns.message.make_query("example.com", "A").to_wire()
    reader = MagicMock()
    reader.readexactly = AsyncMock(side_effect=asyncio.TimeoutError)
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    monkeypatch.setattr(resolver._tcp_pool, "get", AsyncMock(return_value=None))
    monkeypatch.setattr(resolver, "_resolve_upstream_ip", AsyncMock(return_value="127.0.0.1"))
    monkeypatch.setattr(resolver, "_open_tcp_connection", AsyncMock(return_value=(reader, writer)))

    with pytest.raises(asyncio.TimeoutError):
        await resolver._forward_tcp(query, resolver.upstreams[0])

    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()


@pytest.mark.asyncio
async def test_forward_tcp_closed_connection_creates_new():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    query_id = data[:2]

    # Create matching response
    query_msg = dns.message.from_wire(data)
    resp = dns.message.make_response(query_msg)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
    resp_wire = resp.to_wire()
    # Ensure response has same ID
    resp_wire = query_id + resp_wire[2:]

    connect_count = 0

    async def fake_connect(*args, **kwargs):
        nonlocal connect_count
        connect_count += 1
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[
            len(resp_wire).to_bytes(2, 'big'),
            resp_wire
        ])
        writer = MagicMock()
        if connect_count == 1:
            writer.is_closing = MagicMock(return_value=True)
            writer.close = MagicMock()
        else:
            writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    mock_get_calls = 0
    async def mock_get(key):
        nonlocal mock_get_calls
        mock_get_calls += 1
        if mock_get_calls == 1:
            return None
        else:
            closed_reader = AsyncMock()
            closed_writer = MagicMock()
            closed_writer.is_closing = MagicMock(return_value=True)
            closed_writer.close = MagicMock()
            return (closed_reader, closed_writer)

    resolver._tcp_pool.get = mock_get
    resolver._tcp_pool.put = AsyncMock()

    with patch.object(resolver, "_open_tcp_connection", side_effect=fake_connect):
        result = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result == resp_wire
        assert connect_count == 1

        result2 = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert result2 == resp_wire
        assert connect_count == 2


@pytest.mark.asyncio
async def test_forward_tcp_timeout():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "tcp", "port": 53, "ip": "1.1.1.1"}],
        tcp_timeout=0.01
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=asyncio.TimeoutError)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch.object(resolver, "_open_tcp_connection", side_effect=fake_connect):
        with pytest.raises(asyncio.TimeoutError):
            await resolver._forward_tcp(data, resolver.upstreams[0])


# ---------- Forward TLS Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_tls_cert_verification_error():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    with patch("asyncio.open_connection", new=AsyncMock(side_effect=ssl.SSLCertVerificationError("Invalid cert"))):
        with pytest.raises(ssl.SSLCertVerificationError):
            await resolver._forward_tls(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_tls_cert_pin_mismatch():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853, "hostname": "example.com"}],
        pinned_certs={"example.com": "abcdef1234567890"}
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        def readexactly_side_effect(n):
            if n == 2:
                return len(resp).to_bytes(2, "big")
            else:
                return resp
        reader.readexactly = AsyncMock(side_effect=readexactly_side_effect)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        ssl_obj = MagicMock()
        ssl_obj.getpeercert.return_value = b"different_cert"
        writer.get_extra_info = MagicMock(return_value=ssl_obj)
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        with patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "different_hash"
            with pytest.raises(Exception, match="Pinned certificate mismatch"):
                await resolver._forward_tls(data, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_tls_ssl_zero_return():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "tls", "port": 853}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    with patch("asyncio.open_connection", new=AsyncMock(side_effect=ssl.SSLZeroReturnError("Connection closed"))):
        with pytest.raises(ssl.SSLZeroReturnError):
            await resolver._forward_tls(data, resolver.upstreams[0])


# ---------- Forward HTTPS Edge Cases ----------
@pytest.mark.asyncio
async def test_forward_https1_chunked_response():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    lines = [
        b"HTTP/1.1 200 OK\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Type: application/dns-message\r\n",
        b"Age: 20\r\n",
        b"\r\n",
        b"2\r\n",
        str(len(resp) - 2).encode() + b"\r\n",
        b"0\r\n",
        b"\r\n",
    ]

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        remaining_lines = lines.copy()

        async def readline_side_effect():
            if remaining_lines:
                return remaining_lines.pop(0)
            return b""

        reader.readline = AsyncMock(side_effect=readline_side_effect)

        readexactly_responses = [
            resp[:2],
            b"\r\n",
            resp[2:],
            b"\r\n",
            b"\r\n",
        ]
        remaining_readexactly = readexactly_responses.copy()

        async def readexactly_side_effect(n):
            if remaining_readexactly:
                return remaining_readexactly.pop(0)
            return b""

        reader.readexactly = AsyncMock(side_effect=readexactly_side_effect)
        reader.readuntil = AsyncMock(return_value=b"\r\n")
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        result = await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query", None)
        assert dns.message.from_wire(result).answer[0].ttl == 40


@pytest.mark.asyncio
async def test_forward_https1_missing_content_length():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}]
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    lines = [
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: application/dns-message\r\n",
        b"\r\n",
    ]

    async def fake_connect(*args, **kwargs):
        reader = AsyncMock()
        remaining_lines = lines.copy()
        async def readline_side_effect():
            if remaining_lines:
                return remaining_lines.pop(0)
            return b""
        reader.readline = AsyncMock(side_effect=readline_side_effect)
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()
        return reader, writer

    with patch("asyncio.open_connection", side_effect=fake_connect):
        with pytest.raises(Exception, match="missing Content-Length and not chunked"):
            await resolver._forward_https1(data, "example.com", 443, "example.com", "/dns-query", None)


@pytest.mark.asyncio
async def test_forward_https2_pool_reuse():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}],
        doh_timeout=1.0
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(
        status_code=200, content=resp, headers={"age": "20"}
    ))
    mock_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await resolver._forward_https2(data, "example.com", 443, "example.com", "/dns-query", None)
        assert dns.message.from_wire(result).answer[0].ttl == 40

        with patch.object(resolver._h2_pool, "get", new=AsyncMock(return_value=mock_client)):
            result2 = await resolver._forward_https2(data, "example.com", 443, "example.com", "/dns-query", None)
            assert dns.message.from_wire(result2).answer[0].ttl == 40


# ---------- DNSSEC Validation Edge Cases ----------
@pytest.mark.asyncio
async def test_dnssec_validation_bogus_signature():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=10,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    async def fake_get_key(zone):
        return dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", "256 3 8 deadbeef")
    resolver._get_validated_dnskey = fake_get_key

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    with patch("dns.dnssec.validate_rrsig", side_effect=dns.dnssec.ValidationFailure("bogus")):
        with patch('time.time', return_value=1893456000):
            with pytest.raises(dns.dnssec.ValidationFailure):
                await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)


@pytest.mark.asyncio
async def test_dnssec_validation_limit_exceeded():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=1,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    async def fake_get_key(zone):
        return dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", "256 3 8 deadbeef")
    resolver._get_validated_dnskey = fake_get_key

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr1)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    rr2 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1")
    resp.answer.append(rr2)
    resp.answer.append(make_rrsig(dns.rdatatype.AAAA, "example.com"))

    with patch("dns.dnssec.validate_rrsig", return_value=None):
        with patch('time.time', return_value=1893456000):
            secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
            assert secure is False
            assert insecure is False


@pytest.mark.asyncio
async def test_dnssec_validation_timeout():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_validation_timeout=0.01,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    async def fake_get_key(zone):
        return dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", "256 3 8 deadbeef")
    resolver._get_validated_dnskey = fake_get_key

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    def slow_validate_rrsig(*args, **kwargs):
        import time
        time.sleep(0.1)
        return None

    with patch("dns.dnssec.validate_rrsig", side_effect=slow_validate_rrsig):
        with patch('time.time', return_value=1893456000):
            secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
            assert secure is False
            assert insecure is False


@pytest.mark.asyncio
async def test_dnssec_no_validation_when_disabled():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=False,
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.answer.append(make_rrsig(dns.rdatatype.A, "example.com"))

    secure, insecure = await resolver._dnssec_validate("example.com", resp.to_wire(), dnssec_requested=True)
    assert secure is False
    assert insecure is True


# ---------- Optimistic Caching Edge Cases ----------
@pytest.mark.asyncio
async def test_optimistic_cache_serves_stale_edge():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        optimistic_cache_enabled=True,
        optimistic_stale_max_age=3600,
        optimistic_stale_response_ttl=30,
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com", ttl=60)
    key = resolver._build_cache_key(data)

    expiry = time.time() - 10
    stale_until = time.time() + 3600
    val = (resp, expiry, data, stale_until, False)
    await resolver._wire_cache_set(key, val)

    refresh_called = False
    async def fake_refresh(k, qd):
        nonlocal refresh_called
        refresh_called = True
    resolver._maybe_refresh_stale = fake_refresh

    result = await resolver._wire_cache_get_valid(key)
    assert result is not None
    cached_resp, dnssec_ok = result
    msg = dns.message.from_wire(cached_resp)
    assert msg.answer[0].ttl == 30

    await asyncio.sleep(0.1)
    assert refresh_called is True


@pytest.mark.asyncio
async def test_optimistic_cache_expires_completely():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        optimistic_cache_enabled=True,
        optimistic_stale_max_age=1,
        optimistic_stale_response_ttl=30,
    )
    data = dns.message.make_query("example.com", "A").to_wire()
    resp = make_a_response("example.com")
    key = resolver._build_cache_key(data)

    expiry = time.time() - 10
    stale_until = time.time() - 5
    val = (resp, expiry, data, stale_until, False)
    await resolver._wire_cache_set(key, val)

    result = await resolver._wire_cache_get_valid(key)
    assert result is None


# ---------- TCP Fallback ----------
@pytest.mark.asyncio
async def test_tcp_fallback_on_truncated_response():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        tcp_fallback_enabled=True,
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(*args, **kwargs):
        return truncated_wire
    resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(data, upstream):
        nonlocal tcp_called
        tcp_called = True
        return make_a_response("example.com")
    resolver._forward_tcp = fake_forward_tcp

    result = await resolver._try_upstream(resolver.upstreams[0], data)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == dns.rcode.NOERROR
    assert len(msg.answer) == 1
    assert tcp_called is True


@pytest.mark.asyncio
async def test_tcp_fallback_disabled_edge():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"}],
        tcp_fallback_enabled=False,
    )
    data = dns.message.make_query("example.com", "A").to_wire()

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.flags |= dns.flags.TC
    truncated_wire = resp.to_wire()

    async def fake_forward_udp(*args, **kwargs):
        return truncated_wire
    resolver._forward_udp = fake_forward_udp

    tcp_called = False
    async def fake_forward_tcp(*args, **kwargs):
        nonlocal tcp_called
        tcp_called = True
        return make_a_response("example.com")
    resolver._forward_tcp = fake_forward_tcp

    result = await resolver._try_upstream(resolver.upstreams[0], data)
    assert result == truncated_wire
    assert tcp_called is False


# ---------- _set_tc_bit (duplicate kept) ----------
def test_set_tc_bit_duplicate():
    resolver = DNSResolver()
    response = make_a_response("example.com")
    modified = resolver._set_tc_bit(response)
    flags = int.from_bytes(modified[2:4], 'big')
    assert flags & 0x0200 != 0


# ---------- _dnssec_requested ----------
def test_dnssec_requested_detects_do_flag():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(edns=0, payload=1232)
    query.ednsflags = dns.flags.DO
    assert resolver._dnssec_requested(query.to_wire()) is True


def test_dnssec_requested_no_edns():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    assert resolver._dnssec_requested(query.to_wire()) is False


# ---------- _extract_soa_minimum ----------
def test_extract_soa_minimum():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    soa = dns.rrset.from_text(
        "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa)

    minimum = resolver._extract_soa_minimum(resp.to_wire())
    assert minimum == 60


def test_extract_soa_minimum_no_soa():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)

    minimum = resolver._extract_soa_minimum(resp.to_wire())
    assert minimum is None


# ---------- _extract_min_ttl ----------
def test_extract_min_ttl():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    rr2 = dns.rrset.from_text("example.com.", 120, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1")
    resp.answer.append(rr1)
    resp.answer.append(rr2)

    min_ttl = resolver._extract_min_ttl(resp.to_wire())
    assert min_ttl == 60


# ---------- Rebinding Protection (duplicate) ----------
def test_apply_rebind_protection_strips_private_duplicate():
    resolver = DNSResolver(
        rebind_protection_enabled=True,
        rebind_action="strip",
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr1 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "8.8.8.8")
    rr2 = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1")
    resp.answer.append(rr1)
    resp.answer.append(rr2)

    result = resolver._apply_rebind_protection(resp.to_wire())
    msg = dns.message.from_wire(result)
    ips = [rr.to_text().split()[-1] for rr in msg.answer if rr.rdtype == dns.rdatatype.A]
    assert "8.8.8.8" in ips
    assert "192.168.1.1" not in ips


def test_apply_rebind_protection_blocks_all_private_duplicate():
    resolver = DNSResolver(
        rebind_protection_enabled=True,
        rebind_action="block",
    )
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.168.1.1")
    resp.answer.append(rr)

    result = resolver._apply_rebind_protection(resp.to_wire())
    assert result is None


# ---------- _is_private_ip ----------
def test_is_private_ip():
    resolver = DNSResolver()
    assert resolver._is_private_ip("10.0.0.1") is True
    assert resolver._is_private_ip("192.168.1.1") is True
    assert resolver._is_private_ip("172.16.0.1") is True
    assert resolver._is_private_ip("127.0.0.1") is True
    assert resolver._is_private_ip("8.8.8.8") is False
    assert resolver._is_private_ip("::1") is True
    assert resolver._is_private_ip("2001:4860:4860::8888") is False
    assert resolver._is_private_ip("fe80::1") is True


# ---------- _split_hostport ----------
def test_split_hostport():
    resolver = DNSResolver()
    host, port = resolver._split_hostport("[2001:db8::1]:853")
    assert host == "2001:db8::1"
    assert port == 853

    host, port = resolver._split_hostport("example.com:443")
    assert host == "example.com"
    assert port == 443

    host, port = resolver._split_hostport("example.com")
    assert host == "example.com"
    assert port == 53


# ---------- Get Block Action ----------
def test_set_block_action():
    resolver = DNSResolver()
    resolver.set_block_action("REFUSED")
    assert resolver.get_block_action() == "REFUSED"

    resolver.set_block_action(None)
    assert resolver.get_block_action() == "NXDOMAIN"


# ---------- Build Local A Response ----------
def test_build_local_A_response():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A").to_wire()
    response = resolver._build_local_A_response(query, "192.0.2.1")
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"


# ---------- Make NXDOMAIN Response ----------
def test_make_nxdomain_response_preserves_edns_duplicate():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=1232, options=[dns.edns.ECSOption("192.0.2.0", 24, 0)])
    qwire = query.to_wire()

    response = resolver._make_nxdomain_response(qwire)
    msg = dns.message.from_wire(response)
    assert msg.opt is not None
    assert msg.payload == 1232
    assert len(msg.options) == 1


def test_make_nxdomain_response_no_query():
    resolver = DNSResolver()
    response = resolver._make_nxdomain_response(b"")
    assert len(response) >= 12


# ---------- Is Negative Response ----------
def test_is_negative_response_nxdomain():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    assert resolver._is_negative_response(resp.to_wire()) is True


def test_is_negative_response_noanswer():
    resolver = DNSResolver()
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    assert resolver._is_negative_response(resp.to_wire()) is True


def test_is_negative_response_referral_is_not_negative():
    resolver = DNSResolver()
    response = dns.message.make_response(dns.message.make_query("child.example", "A"))
    response.authority.append(dns.rrset.from_text(
        "example.", 300, "IN", "NS", "ns1.example."
    ))
    assert resolver._is_negative_response(response.to_wire()) is False


def test_is_negative_response_with_answer():
    resolver = DNSResolver()
    resp = make_a_response("example.com")
    assert resolver._is_negative_response(resp) is False


def test_is_negative_response_malformed():
    resolver = DNSResolver()
    assert resolver._is_negative_response(b"") is False
    assert resolver._is_negative_response(b"short") is False


# ---------- Make Response from Hosts (already covered) ----------
@pytest.mark.asyncio
async def test_hosts_map_response_edge():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}]
    )
    await resolver.set_hosts_map({"example.com": ("192.0.2.1",)})

    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    msg = dns.message.from_wire(response)
    assert len(msg.answer) == 1
    assert msg.answer[0].rdtype == dns.rdatatype.A
    assert msg.answer[0][0].address == "192.0.2.1"


# ---------- IPv6 Stripping ----------
def test_strip_ipv6_records():
    resolver = DNSResolver(strip_ipv6_records=True)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1"))
    wire = resp.to_wire()
    stripped = resolver._strip_ipv6_records(wire)
    msg = dns.message.from_wire(stripped)
    aaaa_rrs = [rr for rr in msg.answer if rr.rdtype == dns.rdatatype.AAAA]
    assert len(aaaa_rrs) == 0
    a_rrs = [rr for rr in msg.answer if rr.rdtype == dns.rdatatype.A]
    assert len(a_rrs) == 1


def test_strip_ipv6_records_disabled():
    resolver = DNSResolver(strip_ipv6_records=False)
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
    resp.answer.append(dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.AAAA, "2001:db8::1"))
    wire = resp.to_wire()
    stripped = resolver._strip_ipv6_records(wire)
    assert stripped == wire


# ---------- Load Balancing ----------
@pytest.mark.asyncio
async def test_load_balancing_failover():
    resolver = DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
            {"address": "upstream3", "protocol": "udp", "port": 53, "ip": "9.9.9.9"},
        ],
        load_balancing="failover",
    )
    call_order = []
    async def fake_try_upstream(upstream, data):
        call_order.append(upstream["address"])
        if upstream["address"] == "upstream1":
            raise Exception("fail")
        return make_a_response("example.com")
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert len(response) > 0
    assert call_order == ["upstream1", "upstream2"]


@pytest.mark.asyncio
async def test_load_balancing_parallel():
    resolver = DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
            {"address": "upstream3", "protocol": "udp", "port": 53, "ip": "9.9.9.9"},
        ],
        load_balancing="parallel",
    )
    call_order = []
    async def fake_try_upstream(upstream, data):
        call_order.append(upstream["address"])
        if upstream["address"] == "upstream1":
            return make_a_response("example.com")
        await asyncio.sleep(0.1)
        return make_a_response("example.com")
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert len(response) > 0
    assert set(call_order) == {"upstream1", "upstream2", "upstream3"}


@pytest.mark.asyncio
async def test_load_balancing_parallel_all_fail():
    resolver = DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
        ],
        load_balancing="parallel",
    )
    async def fake_try_upstream(upstream, data):
        raise Exception(f"fail {upstream['address']}")
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A").to_wire()
    with pytest.raises(Exception) as exc:
        await resolver.forward_dns_query(query)
    assert "fail" in str(exc.value)


@pytest.mark.asyncio
async def test_load_balancing_random():
    resolver = DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
            {"address": "upstream3", "protocol": "udp", "port": 53, "ip": "9.9.9.9"},
        ],
        load_balancing="random",
    )
    original_choice = random.choice
    try:
        choices = resolver.upstreams.copy()
        def mock_choice(seq):
            return choices.pop(0)
        random.choice = mock_choice

        used = []
        async def fake_try_upstream(upstream, data):
            used.append(upstream["address"])
            return make_a_response("example.com")
        resolver._try_upstream = fake_try_upstream

        query1 = dns.message.make_query("example1.com", "A").to_wire()
        query2 = dns.message.make_query("example2.com", "A").to_wire()

        response = await resolver.forward_dns_query(query1)
        assert response is not None
        assert used == ["upstream1"]

        response = await resolver.forward_dns_query(query2)
        assert response is not None
        assert used == ["upstream1", "upstream2"]
    finally:
        random.choice = original_choice


@pytest.mark.asyncio
async def test_load_balancing_roundrobin():
    resolver = DNSResolver(
        upstreams=[
            {"address": "upstream1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
            {"address": "upstream2", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
            {"address": "upstream3", "protocol": "udp", "port": 53, "ip": "9.9.9.9"},
        ],
        load_balancing="roundrobin",
    )
    used = []
    async def fake_try_upstream(upstream, data):
        used.append(upstream["address"])
        return make_a_response("example.com")
    resolver._try_upstream = fake_try_upstream

    query1 = dns.message.make_query("example.com", "A").to_wire()
    query2 = dns.message.make_query("example.org", "A").to_wire()
    query3 = dns.message.make_query("example.net", "A").to_wire()
    query4 = dns.message.make_query("example.info", "A").to_wire()

    response = await resolver.forward_dns_query(query1)
    assert response is not None
    assert used == ["upstream1"]

    response = await resolver.forward_dns_query(query2)
    assert used == ["upstream1", "upstream2"]

    response = await resolver.forward_dns_query(query3)
    assert used == ["upstream1", "upstream2", "upstream3"]

    response = await resolver.forward_dns_query(query4)
    assert used == ["upstream1", "upstream2", "upstream3", "upstream1"]


# ---------- NS Scrubbing ----------
@pytest.fixture
def resolver_with_scrub_fixture():
    return DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        scrub_unsolicited_ns=True,
    )


def test_scrub_unsolicited_ns_removes_foreign_ns(resolver_with_scrub):
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns_rrset)

    soa_rrset = dns.rrset.from_text(
        "example.com.", 300, dns.rdataclass.IN, dns.rdatatype.SOA,
        "ns.example.com. admin.example.com. 20250101 3600 1800 604800 60"
    )
    resp.authority.append(soa_rrset)

    wire = resp.to_wire()
    scrubbed = resolver_with_scrub._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 0
    soa_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.SOA]
    assert len(soa_records) == 1


def test_scrub_keeps_valid_ns_exact_match(resolver_with_scrub):
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.example.com.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver_with_scrub._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_keeps_valid_ns_parent_zone(resolver_with_scrub):
    query = dns.message.make_query("www.example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.example.com.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver_with_scrub._scrub_authority_section(wire, "www.example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_keeps_root_ns(resolver_with_scrub):
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text(".", 300, dns.rdataclass.IN, dns.rdatatype.NS, "a.root-servers.net.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver_with_scrub._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_disabled_advanced(resolver_with_scrub):
    resolver_with_scrub.scrub_unsolicited_ns = False
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    ns_rrset = dns.rrset.from_text("other.com.", 300, dns.rdataclass.IN, dns.rdatatype.NS, "ns.other.com.")
    resp.authority.append(ns_rrset)

    wire = resp.to_wire()
    scrubbed = resolver_with_scrub._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    ns_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.NS]
    assert len(ns_records) == 1


def test_scrub_keeps_non_ns_records(resolver_with_scrub):
    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    rrsig_rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdataclass.IN, dns.rdatatype.RRSIG)
    rrsig_rrset.ttl = 300
    rrsig = RRSIG(
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,
        8,
        1,
        300,
        2000000000,
        1000000000,
        12345,
        dns.name.from_text("example.com."),
        b"dummy"
    )
    rrsig_rrset.add(rrsig)
    resp.authority.append(rrsig_rrset)

    wire = resp.to_wire()
    scrubbed = resolver_with_scrub._scrub_authority_section(wire, "example.com")
    msg = dns.message.from_wire(scrubbed)

    rrsig_records = [rr for rr in msg.authority if rr.rdtype == dns.rdatatype.RRSIG]
    assert len(rrsig_records) == 1


# ---------- Upstream Resolution ----------
@pytest.mark.asyncio
async def test_constructor_accepts_upstreams_and_bootstrap():
    upstreams = [{"address": "1.1.1.1", "protocol": "udp", "port": 53}]
    bootstrap = {"servers": ["9.9.9.9:53"], "timeout": 3.0, "retries": 1}
    resolver = DNSResolver(upstreams=upstreams, bootstrap=bootstrap)
    assert resolver.upstreams == upstreams
    assert resolver.bootstrap_servers == ["9.9.9.9:53"]
    assert resolver.bootstrap_timeout == 3.0
    assert resolver.bootstrap_retries == 1


@pytest.mark.asyncio
async def test_default_upstream_when_none_provided():
    resolver = DNSResolver()
    assert len(resolver.upstreams) == 0
    query = dns.message.make_query("example.com", "A").to_wire()
    async def fake_try_upstream(upstream, data):
        return dns.message.make_response(dns.message.from_wire(data)).to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None


@pytest.mark.asyncio
async def test_resolve_upstream_ip_uses_ip_override():
    resolver = DNSResolver()
    result = await resolver._resolve_upstream_ip("example.com", ip_override="192.0.2.1")
    assert result == "192.0.2.1"

    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value=None)):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=[(None, None, None, None, ("203.0.113.1", 0))])):
            with patch.object(resolver, "_cache_set", new=AsyncMock()):
                result = await resolver._resolve_upstream_ip("example.com", ip_override="invalid")
                assert result == "203.0.113.1"


@pytest.mark.asyncio
async def test_resolve_upstream_ip_uses_bootstrap_when_no_ip():
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53", "8.8.8.8:53"]
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=AsyncMock(return_value="203.0.113.1")):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com")
            assert result == "203.0.113.1"


@pytest.mark.asyncio
async def test_forward_udp_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "udp",
        "port": 10053,
        "ip": "192.0.2.1"
    }
    data = dns.message.make_query("test.com", "A").to_wire()
    orig_id = int.from_bytes(data[:2], 'big')
    query_msg = dns.message.from_wire(data)

    with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
        mock_resolve.return_value = "192.0.2.1"

        resp = dns.message.make_response(query_msg)
        rr = dns.rrset.from_text("test.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
        resp.answer.append(rr)
        resp_wire = resp.to_wire()

        loop = asyncio.get_running_loop()
        with patch.object(loop, "sock_sendall", new=AsyncMock()):
            with patch.object(loop, "sock_recvfrom", new=AsyncMock(return_value=(resp_wire, ("192.0.2.1", 10053)))):
                with patch.object(resolver, "_get_udp_socket", new=AsyncMock(return_value=MagicMock())):
                    result = await resolver._forward_udp(data, upstream)
                    assert result == resp_wire


@pytest.mark.asyncio
async def test_forward_udp_rejects_mismatched_question_section():
    resolver = DNSResolver()
    upstream = {"address": "example.com", "protocol": "udp", "port": 53, "ip": "192.0.2.1"}

    query = dns.message.make_query("example.com", "A")
    qwire = query.to_wire()

    forged = dns.message.make_response(query)
    forged.question = dns.message.make_query("evil.example", "A").question
    resp_wire = forged.to_wire()

    with patch.object(resolver, "_resolve_upstream_ip", AsyncMock(return_value="192.0.2.1")):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "sock_recvfrom", new=AsyncMock(return_value=(resp_wire, ("192.0.2.1", 53)))):
            with patch.object(loop, "sock_sendto", new=AsyncMock()):
                with patch.object(resolver, "_get_udp_socket", new=AsyncMock(return_value=MagicMock())):
                    with pytest.raises(OSError, match="Response question mismatch"):
                        await resolver._forward_udp(qwire, upstream)


@pytest.mark.asyncio
async def test_forward_tcp_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "tcp",
        "port": 5353,
        "ip": "192.0.2.1"
    }
    data = dns.message.make_query("test.com", "A").to_wire()
    query_id = data[:2]

    with patch.object(resolver, "_tcp_pool") as mock_pool:
        mock_pool.get = AsyncMock(return_value=None)
        mock_pool.put = AsyncMock()

        query_msg = dns.message.from_wire(data)
        resp = dns.message.make_response(query_msg)
        resp.answer.append(dns.rrset.from_text("test.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
        resp_wire = resp.to_wire()
        resp_wire = query_id + resp_wire[2:]

        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[
            len(resp_wire).to_bytes(2, 'big'),
            resp_wire
        ])
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.write = MagicMock()
        writer.is_closing = MagicMock(return_value=False)

        with patch.object(resolver, "_open_tcp_connection", new=AsyncMock(return_value=(reader, writer))) as mock_connect:
            with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
                mock_resolve.return_value = "192.0.2.1"
                result = await resolver._forward_tcp(data, upstream)
                assert result == resp_wire
            mock_connect.assert_awaited_once_with("192.0.2.1", 5353)


@pytest.mark.asyncio
async def test_forward_quic_uses_ip_override():
    resolver = DNSResolver()
    upstream = {
        "address": "example.com",
        "protocol": "quic",
        "port": 853,
        "ip": "192.0.2.1",
        "hostname": "example.com"
    }
    data = dns.message.make_query("test.com", "A").to_wire()
    query_id = data[:2]

    # Create a proper async context manager
    class MockAsyncCM:
        async def __aenter__(self):
            client = MagicMock()
            client._quic = MagicMock()
            client._quic.closed = False
            client._quic.get_next_available_stream_id = MagicMock(return_value=0)
            client._quic.send_stream_data = MagicMock()
            client.transmit = MagicMock()
            client.wait_connected = AsyncMock()
            return client
        async def __aexit__(self, *args):
            pass

    with patch.object(resolver, "_resolve_upstream_ip") as mock_resolve:
        mock_resolve.return_value = "192.0.2.1"
        with patch("aioquic.asyncio.connect") as mock_connect:  # FIXED: was aioquic.asyncio.client.connect
            # Return the context manager, not a coroutine
            mock_connect.return_value = MockAsyncCM()

            query_msg = dns.message.from_wire(data)
            resp = dns.message.make_response(query_msg)
            resp.id = 0
            resp.answer.append(dns.rrset.from_text("test.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
            resp_wire = resp.to_wire()
            response_data = len(resp_wire).to_bytes(2, 'big') + resp_wire

            with patch("asyncio.wait_for", new=AsyncMock(return_value=response_data)):
                result = await resolver._forward_quic(data, upstream)
                assert result == query_id + resp_wire[2:]


@pytest.mark.asyncio
async def test_forward_dns_query_uses_upstreams_list():
    resolver = DNSResolver()
    upstreams = [
        {"address": "1.1.1.1", "protocol": "udp", "port": 53, "ip": "1.1.1.1"},
        {"address": "8.8.8.8", "protocol": "udp", "port": 53, "ip": "8.8.8.8"},
    ]
    resolver.upstreams = upstreams
    query = dns.message.make_query("example.com", "A").to_wire()
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream["address"])
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert calls[0] == "1.1.1.1"


@pytest.mark.asyncio
async def test_forward_dns_query_fallback_default_upstream():
    resolver = DNSResolver(upstreams=[])
    query = dns.message.make_query("example.com", "A").to_wire()
    calls = []
    async def fake_try_upstream(upstream, data):
        calls.append(upstream.get("address", "default"))
        resp = dns.message.make_response(dns.message.from_wire(data))
        return resp.to_wire()
    resolver._try_upstream = fake_try_upstream
    response = await resolver.forward_dns_query(query)
    assert response is not None
    assert len(calls) == 1
    assert calls[0] == "1.1.1.1"


@pytest.mark.asyncio
async def test_bootstrap_servers_used_for_resolution():
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53", "8.8.8.8:53"]
    mock_udp = AsyncMock(return_value="203.0.113.1")
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=mock_udp):
        with patch.object(resolver, "_cache_set", new=AsyncMock()):
            result = await resolver._resolve_upstream_ip("example.com")
            assert result == "203.0.113.1"
            mock_udp.assert_called()


@pytest.mark.asyncio
async def test_resolve_upstream_ip_falls_back_to_system_resolver():
    resolver = DNSResolver()
    resolver.bootstrap_servers = ["1.1.1.1:53"]
    mock_udp = AsyncMock(return_value=None)
    with patch.object(resolver, "_udp_query_a_or_aaaa", new=mock_udp):
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(None, None, None, None, ("203.0.113.1", 0))]
            with patch.object(resolver, "_cache_set", new=AsyncMock()):
                result = await resolver._resolve_upstream_ip("example.com")
                assert result == "203.0.113.1"
                mock_getaddrinfo.assert_called()
                
                
# ---------- TCP Length Validation ----------
@pytest.mark.asyncio
async def test_tcp_length_validation_zero():
    """Test that length=0 raises ValueError."""
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tcp", "port": 12345, "ip": "127.0.0.1"}],
        tcp_timeout=2.0,
    )

    resolver._tcp_pool.get = AsyncMock(return_value=None)
    resolver._tcp_pool.put = AsyncMock()

    async def mock_connect_zero(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[b'\x00\x00'])  # length 0
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch.object(resolver, "_open_tcp_connection", side_effect=mock_connect_zero):
        with pytest.raises(ValueError, match="TCP message length 0 is less than required DNS header size"):
            await resolver._forward_tcp(b"test", resolver.upstreams[0])


@pytest.mark.asyncio
async def test_tcp_length_validation_valid():
    """Test that a valid length (>=12) succeeds."""
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tcp", "port": 12345, "ip": "127.0.0.1"}],
        tcp_timeout=2.0,
    )

    resolver._tcp_pool.get = AsyncMock(return_value=None)
    resolver._tcp_pool.put = AsyncMock()

    # Create a valid DNS response (minimum 12 bytes)
    data = dns.message.make_query("example.com", "A").to_wire()
    query_msg = dns.message.from_wire(data)
    resp = dns.message.make_response(query_msg)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
    resp_wire = resp.to_wire()

    async def mock_connect_valid(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[
            len(resp_wire).to_bytes(2, 'big'),  # Valid length >= 12
            resp_wire
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch.object(resolver, "_open_tcp_connection", side_effect=mock_connect_valid):
        resp = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert resp == resp_wire


@pytest.mark.asyncio
async def test_tcp_length_validation_max():
    """Test that a response at or under the max length succeeds."""
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tcp", "port": 12345, "ip": "127.0.0.1"}],
        tcp_timeout=2.0,
    )

    resolver._tcp_pool.get = AsyncMock(return_value=None)
    resolver._tcp_pool.put = AsyncMock()

    data = dns.message.make_query("example.com", "A").to_wire()
    query_msg = dns.message.from_wire(data)
    resp = dns.message.make_response(query_msg)
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
    resp_wire = resp.to_wire()

    async def mock_connect_max(*args, **kwargs):
        reader = AsyncMock()
        reader.readexactly = AsyncMock(side_effect=[
            len(resp_wire).to_bytes(2, 'big'),
            resp_wire
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    with patch.object(resolver, "_open_tcp_connection", side_effect=mock_connect_max):
        resp = await resolver._forward_tcp(data, resolver.upstreams[0])
        assert resp == resp_wire


@pytest.mark.asyncio
async def test_tcp_length_validation_exceeds_limit():
    """Test that a length > MAX_TCP_RESPONSE_SIZE raises ValueError.
       To test this without patching the constant, we use a smaller constant for the test.
    """
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tcp", "port": 12345, "ip": "127.0.0.1"}],
        tcp_timeout=2.0,
    )

    resolver._tcp_pool.get = AsyncMock(return_value=None)
    resolver._tcp_pool.put = AsyncMock()

    # Patch the constant to a small value for this test
    with patch("dosev.resolver.MAX_TCP_RESPONSE_SIZE", 100):
        async def mock_connect_too_large(*args, **kwargs):
            reader = AsyncMock()
            reader.readexactly = AsyncMock(side_effect=[
                b'\x00\x65',  # length 101 (> 100)
            ])
            writer = MagicMock()
            writer.is_closing = MagicMock(return_value=False)
            writer.write = MagicMock()
            writer.drain = AsyncMock()
            return reader, writer

        with patch.object(resolver, "_open_tcp_connection", side_effect=mock_connect_too_large):
            with pytest.raises(ValueError, match="TCP message length 101 exceeds maximum 100"):
                await resolver._forward_tcp(b"test", resolver.upstreams[0])
                
# ---------- TXID Validation for TCP/TLS/DoQ ----------
@pytest.mark.asyncio
async def test_forward_tcp_txid_validation():
    """TCP forward should reject response with mismatched transaction ID."""
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tcp", "port": 12345, "ip": "127.0.0.1"}],
        tcp_timeout=1.0,
    )

    # Mock the connection to return a response with mismatched ID
    async def mock_open_connection(*args, **kwargs):
        reader = AsyncMock()
        # Length prefix + response with different ID
        # Query ID is 0x1234, response ID 0x5678
        length = 12
        response = b'\x56\x78' + b'\x81\x80' + b'\x00' * 10
        reader.readexactly = AsyncMock(side_effect=[
            length.to_bytes(2, 'big'),  # length
            response  # payload
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        return reader, writer

    # Force a new connection (bypass pool)
    resolver._tcp_pool.get = AsyncMock(return_value=None)
    resolver._tcp_pool.put = AsyncMock()

    query = dns.message.make_query("example.com", "A")
    query.id = 0x1234
    qwire = query.to_wire()

    with patch.object(resolver, "_open_tcp_connection", side_effect=mock_open_connection):
        with pytest.raises(OSError, match="TCP Response ID mismatch"):
            await resolver._forward_tcp(qwire, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_tls_txid_validation():
    """TLS forward should reject response with mismatched transaction ID."""
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "tls", "port": 853, "hostname": "example.com"}],
        tcp_timeout=1.0,
    )

    async def mock_open_connection(*args, **kwargs):
        reader = AsyncMock()
        length = 12
        response = b'\x56\x78' + b'\x81\x80' + b'\x00' * 10
        reader.readexactly = AsyncMock(side_effect=[
            length.to_bytes(2, 'big'),
            response
        ])
        writer = MagicMock()
        writer.is_closing = MagicMock(return_value=False)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.get_extra_info = MagicMock(return_value=None)
        return reader, writer

    resolver._tcp_pool.get = AsyncMock(return_value=None)
    resolver._tcp_pool.put = AsyncMock()

    query = dns.message.make_query("example.com", "A")
    query.id = 0x1234
    qwire = query.to_wire()

    with patch("asyncio.open_connection", side_effect=mock_open_connection):
        with pytest.raises(OSError, match="TLS Response ID mismatch"):
            await resolver._forward_tls(qwire, resolver.upstreams[0])


@pytest.mark.asyncio
async def test_forward_quic_rejects_nonzero_response_id():
    """DoQ must reject every upstream response whose DNS Message ID is nonzero."""
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "quic", "port": 853, "hostname": "example.com"}],
        doh_timeout=1.0,
    )

    # Create a proper mock client with context manager
    class MockQuicClient:
        def __init__(self):
            self._quic = MagicMock()
            self._quic.closed = False
            self._quic.get_next_available_stream_id = MagicMock(return_value=0)
            self._quic.send_stream_data = MagicMock()
            self.transmit = MagicMock()
            self._pending = {}
            self._fragments = {}

        async def wait_connected(self):
            return True

    client = MockQuicClient()

    class MockAsyncCM:
        async def __aenter__(self):
            return client
        async def __aexit__(self, *args):
            pass

    # Create a query with known ID
    query = dns.message.make_query("example.com", "A")
    query.id = 0x1234
    qwire = query.to_wire()

    # A nonzero response ID is a DoQ protocol error, regardless of the query ID.
    resp = dns.message.make_response(query)
    resp.id = 0x5678  # Different ID
    resp.answer.append(dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1"))
    resp_wire = resp.to_wire()
    response_data = len(resp_wire).to_bytes(2, 'big') + resp_wire

    with patch("aioquic.asyncio.connect", return_value=MockAsyncCM()):
        with patch.object(resolver._quic_pool, "get", new=AsyncMock(return_value=None)):
            with patch("asyncio.wait_for", new=AsyncMock(return_value=response_data)):
                with pytest.raises(OSError, match="DoQ response DNS Message ID must be zero"):
                    await resolver._forward_quic(qwire, resolver.upstreams[0])

    client._quic.close.assert_called_once_with(
        error_code=0x2, reason_phrase="DoQ DNS Message ID is not zero"
    )


@pytest.mark.asyncio
async def test_forward_https3_applies_age_to_dns_ttl():
    resolver = DNSResolver(
        upstreams=[{"address": "127.0.0.1", "protocol": "https", "port": 443, "hostname": "example.com", "ip": "127.0.0.1"}]
    )
    query = dns.message.make_query("example.com", "A").to_wire()
    response = make_a_response("example.com")

    class MockH3Client:
        async def send_request(self, data, hostname, path):
            return response, 20

    class MockAsyncCM:
        async def __aenter__(self):
            return MockH3Client()

        async def __aexit__(self, *args):
            return None

    with patch("dosev.resolver.connect", return_value=MockAsyncCM()):
        with patch.object(resolver._h3_pool, "get", new=AsyncMock(return_value=None)):
            with patch.object(resolver._h3_pool, "put", new=AsyncMock()):
                result = await resolver._forward_https3(
                    query, "example.com", 443, "example.com", "/dns-query", "127.0.0.1"
                )

    assert dns.message.from_wire(result).answer[0].ttl == 40


@pytest.mark.asyncio
async def test_forward_https3_closes_connection_on_question_mismatch():
    resolver = DNSResolver(
        upstreams=[{"address": "example.com", "protocol": "https", "port": 443, "hostname": "example.com"}],
        doh_timeout=1.0,
    )

    query = dns.message.make_query("example.com", "A")
    qwire = query.to_wire()

    bad_resp = dns.message.make_response(query)
    bad_resp.question = dns.message.make_query("evil.example", "A").question
    bad_wire = bad_resp.to_wire()

    class MockH3Client:
        async def send_request(self, data, hostname, path):
            return bad_wire

    cleanup_called = False

    class MockAsyncCM:
        async def __aenter__(self):
            return MockH3Client()

        async def __aexit__(self, *args):
            nonlocal cleanup_called
            cleanup_called = True

    cm = MockAsyncCM()

    with patch("dosev.resolver.connect", return_value=cm):
        with patch.object(resolver._h3_pool, "get", new=AsyncMock(return_value=None)):
            with patch.object(resolver._h3_pool, "put", new=AsyncMock()) as put_mock:
                with pytest.raises(OSError, match="Response question mismatch"):
                    await resolver._forward_https3(qwire, "example.com", 443, "example.com", "/dns-query", None)
                assert cleanup_called is True
                put_mock.assert_not_called()

# ---------- EDNS0 Multiple OPT Records ----------
@pytest.mark.asyncio
async def test_multiple_opt_records_return_formerr():
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])

    # Build a query with two OPT records
    query = dns.message.make_query("example.com", "A")
    
    # Create first OPT record (payload 4096)
    opt1 = dns.rrset.RRset(dns.name.root, dns.rdataclass.IN, dns.rdatatype.OPT)
    opt1.ttl = 4096
    opt1.add(dns.rdtypes.ANY.OPT.OPT(dns.rdataclass.IN, dns.rdatatype.OPT, []))
    query.additional.append(opt1)

    # Create second OPT record (payload 1232)
    opt2 = dns.rrset.RRset(dns.name.root, dns.rdataclass.IN, dns.rdatatype.OPT)
    opt2.ttl = 1232
    opt2.add(dns.rdtypes.ANY.OPT.OPT(dns.rdataclass.IN, dns.rdatatype.OPT, []))
    query.additional.append(opt2)

    qwire = query.to_wire()

    # The resolver should detect multiple OPT and return FORMERR
    result = await resolver.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == dns.rcode.FORMERR


@pytest.mark.asyncio
async def test_single_opt_record_is_accepted():
    """Query with exactly one OPT record should pass through."""
    resolver = DNSResolver(upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}])
    # Mock upstream to return a response quickly
    async def fake_try_upstream(*args, **kwargs):
        return dns.message.make_response(dns.message.make_query("example.com", "A")).to_wire()
    resolver._try_upstream = fake_try_upstream

    query = dns.message.make_query("example.com", "A")
    query.use_edns(payload=4096)
    qwire = query.to_wire()

    response = await resolver.forward_dns_query(qwire, client_ip="192.0.2.1")
    msg = dns.message.from_wire(response)
    assert msg.rcode() == dns.rcode.NOERROR
    
# ---------- ECS Scope-Aware Caching ----------
@pytest.mark.asyncio
async def test_explicit_ecs_requests_bypass_response_cache():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        ecs_enabled=True,
    )

    # Track cache keys
    cache_keys = []
    original_set = resolver._wire_cache_set

    async def mock_set(key, value):
        cache_keys.append(key)
        await original_set(key, value)

    resolver._wire_cache_set = mock_set

    # Build query with ECS
    query = dns.message.make_query("example.com", "A")
    ecs_opt = dns.edns.ECSOption(address="192.0.2.0", srclen=24, scopelen=24)
    query.use_edns(options=[ecs_opt])
    qwire = query.to_wire()

    # Build response with ECS in authority section
    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(rr)
    resp.use_edns(options=[ecs_opt])
    wire = resp.to_wire()

    async def fake_upstream(upstream, data):
        return wire

    resolver._try_upstream = fake_upstream

    await resolver.forward_dns_query(qwire)

    assert cache_keys == []


@pytest.mark.asyncio
async def test_client_subnets_do_not_share_ecs_cached_answers(monkeypatch):
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        ecs_enabled=True,
    )
    query = dns.message.make_query("geo.example", "A").to_wire()
    upstream_subnets = []

    async def fake_upstream(upstream, data):
        request = dns.message.from_wire(data)
        ecs = next(option for option in request.options
                   if isinstance(option, dns.edns.ECSOption))
        upstream_subnets.append((ecs.address, ecs.srclen))
        response = dns.message.make_response(request)
        answer_ip = "192.0.2.1" if ecs.address == "198.51.100.0" else "192.0.2.2"
        response.answer.append(dns.rrset.from_text(
            "geo.example.", 60, dns.rdataclass.IN, dns.rdatatype.A, answer_ip
        ))
        response.use_edns(options=[dns.edns.ECSOption(
            address=ecs.address, srclen=ecs.srclen, scopelen=ecs.srclen
        )])
        return response.to_wire()

    monkeypatch.setattr(resolver, "_try_upstream", fake_upstream)

    first = await resolver.forward_dns_query(
        query, client_ip="198.51.100.10", rate_limit_checked=True
    )
    second = await resolver.forward_dns_query(
        query, client_ip="198.51.101.10", rate_limit_checked=True
    )

    assert upstream_subnets == [("198.51.100.0", 24), ("198.51.101.0", 24)]
    assert dns.message.from_wire(first).answer[0][0].address == "192.0.2.1"
    assert dns.message.from_wire(second).answer[0][0].address == "192.0.2.2"