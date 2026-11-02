"""
Consolidated DNSSEC tests.
Combines: test_dnssec_cd.py, test_dnssec_chain.py, test_dnssec_keytrap.py
"""
import asyncio
import hashlib
import time
import tempfile
import os
import base64
import pytest
from unittest.mock import AsyncMock, patch

import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.name
import dns.dnssec
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rdtypes.ANY.NSEC3

from dosev.resolver import DNSResolver


# ---------- Helpers for chain tests ----------
def make_dnskey_rrset(owner: str, flags: int, protocol: int, algorithm: int, key: bytes) -> dns.rrset.RRset:
    rr = dns.rrset.from_text(owner, 3600, "IN", "DNSKEY", f"{flags} {protocol} {algorithm} {key.hex()}")
    return rr


def make_ds_rrset(owner: str, key_tag: int, algorithm: int, digest_type: int, digest: bytes) -> dns.rrset.RRset:
    ds_text = f"{key_tag} {algorithm} {digest_type} {digest.hex()}"
    return dns.rrset.from_text(owner, 3600, "IN", "DS", ds_text)


# ---------- CD flag tests ----------
@pytest.fixture
def resolver_with_dnssec():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}
    return resolver


def test_nsec3_hash_uses_module_limit_constant():
    resolver = DNSResolver()
    result = resolver._nsec3_hash("example.com.", b"salt", 0, 1)
    assert result is not None
    assert isinstance(result, str)
    expected = hashlib.sha1(
        dns.name.from_text("example.com.").to_wire() + b"salt"
    ).digest()
    assert result == base64.b32hexencode(expected).decode().lower().rstrip("=")


@pytest.mark.asyncio
async def test_cd_flag_skips_validation(resolver_with_dnssec):
    query = dns.message.make_query("example.com", "A")
    query.flags |= 0x0010
    qwire = query.to_wire()

    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    resp_wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return resp_wire
    resolver_with_dnssec._try_upstream = fake_try_upstream

    validate_called = False
    async def fake_validate(qname, wire, requested):
        nonlocal validate_called
        validate_called = True
        return False, True
    resolver_with_dnssec._dnssec_validate = fake_validate

    result = await resolver_with_dnssec.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == 0
    assert len(msg.answer) == 1
    assert validate_called is False


@pytest.mark.asyncio
async def test_no_cd_flag_triggers_validation(resolver_with_dnssec):
    def fake_dnssec_requested(data):
        return True
    resolver_with_dnssec._dnssec_requested = fake_dnssec_requested

    query = dns.message.make_query("example.com", "A")
    query.flags &= ~0x0010
    query.use_edns(edns=0, payload=1232, options=[])
    query.ednsflags = dns.flags.DO  # <-- add this
    qwire = query.to_wire()

    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    resp_wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return resp_wire
    resolver_with_dnssec._try_upstream = fake_try_upstream

    validate_called = False
    async def fake_validate(qname, wire, requested):
        nonlocal validate_called
        validate_called = True
        return False, True
    resolver_with_dnssec._dnssec_validate = fake_validate

    result = await resolver_with_dnssec.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == 0
    assert len(msg.answer) == 1
    assert validate_called is True


@pytest.mark.asyncio
async def test_cd_flag_passthrough_ignores_bogus(resolver_with_dnssec):
    query = dns.message.make_query("example.com", "A")
    query.flags |= 0x0010
    qwire = query.to_wire()

    resp = dns.message.make_response(query)
    rr = dns.rrset.from_text("example.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34")
    resp.answer.append(rr)
    resp_wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return resp_wire
    resolver_with_dnssec._try_upstream = fake_try_upstream

    async def fake_validate(*args, **kwargs):
        raise Exception("Should not be called")
    resolver_with_dnssec._dnssec_validate = fake_validate

    result = await resolver_with_dnssec.forward_dns_query(qwire)
    msg = dns.message.from_wire(result)
    assert msg.rcode() == 0
    assert len(msg.answer) == 1


# ---------- Chain validation tests ----------
class TestDNSSECChain:
    @pytest.mark.asyncio
    async def test_ds_rrset_is_verified_with_parent_key(self):
        resolver = DNSResolver(dnssec_enabled=True, dnssec_chain_validation=True)
        parent_key = make_dnskey_rrset(".", 257, 3, 8, b"parent-key")
        ds_rrset = dns.rrset.from_text(
            "example.com.", 3600, "IN", "DS", f"12345 8 2 {'aa' * 32}"
        )
        ds_sig = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "DS 8 2 3600 20350101000000 20300101000000 12345 . deadbeef"
        )
        response = dns.message.Message()
        response.answer.extend((ds_rrset, ds_sig))
        resolver._dnssec_lookup = AsyncMock(return_value=response)

        with patch("dns.dnssec.validate", return_value=None) as validate:
            result = await resolver._get_ds_for_zone(
                "example.com", ".", parent_key=parent_key
            )

        assert result is ds_rrset
        validate.assert_called_once()
        assert validate.call_args.args[0] is ds_rrset
        assert validate.call_args.args[2] == {dns.name.root: parent_key}

    @pytest.mark.asyncio
    async def test_dnskey_rrset_is_verified_with_ds_matched_key(self):
        resolver = DNSResolver(dnssec_enabled=True, dnssec_chain_validation=True)
        parent_key = dns.rrset.from_text(
            "com.", 3600, "IN", "DNSKEY",
            f"257 3 8 {base64.b64encode(b'parent-key').decode()}"
        )
        child_keys = dns.rrset.from_text(
            "example.com.", 3600, "IN", "DNSKEY",
            f"257 3 8 {base64.b64encode(b'child-key').decode()}"
        )
        ds = dns.dnssec.make_ds("example.com.", child_keys[0], "SHA256")
        ds_rrset = dns.rrset.RRset(
            dns.name.from_text("example.com."), dns.rdataclass.IN, dns.rdatatype.DS
        )
        ds_rrset.ttl = 3600
        ds_rrset.add(ds)
        dnskey_sig = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "DNSKEY 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        response = dns.message.Message()
        response.answer.extend((child_keys, dnskey_sig))

        resolver._dnssec_key_cache["com"] = (parent_key, time.time() + 3600)
        resolver._get_ds_for_zone = AsyncMock(return_value=ds_rrset)
        resolver._fetch_dnskey_response = AsyncMock(return_value=(child_keys, response))

        with patch("dns.dnssec.validate", return_value=None) as validate:
            result = await resolver._get_validated_dnskey("example.com")

        assert result is child_keys
        validate.assert_called_once()
        assert validate.call_args.args[0] is child_keys
        assert validate.call_args.args[2] == {
            dns.name.from_text("example.com."): child_keys
        }

    @pytest.mark.asyncio
    async def test_chain_validation_valid(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )
        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        with patch('dns.dnssec.validate_rrsig', return_value=None) as mock_validate:
            async def fake_get_key(zone):
                if zone == "example.com":
                    return dnskey_rrset
                return None
            resolver._get_validated_dnskey = fake_get_key

            msg = dns.message.make_query("example.com.", dns.rdatatype.A)
            a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
            msg.answer.append(a_rr)
            rrsig_rr = dns.rrset.from_text(
                "example.com.", 3600, "IN", "RRSIG",
                "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
            )
            msg.answer.append(rrsig_rr)
            response_wire = msg.to_wire()

            with patch('time.time', return_value=1893456000):
                secure, insecure = await resolver._dnssec_validate_chain("example.com", response_wire, dnssec_requested=True)
                assert secure
                assert not insecure
                mock_validate.assert_called()

    @pytest.mark.asyncio
    async def test_chain_validation_insecure_delegation_nsec3_optout(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        def fake_hash(name, salt, iterations, algorithm):
            return "0" * 32
        resolver._nsec3_hash = fake_hash

        nsec3 = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0x01,
            iterations=0,
            salt=b'',
            next=base64.b32hexdecode("1" * 32),
            windows=[]
        )
        nsec3_rrset = dns.rrset.RRset(dns.name.from_text(f'{"0" * 32}.com.'), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_rrset.ttl = 3600
        nsec3_rrset.add(nsec3)
        nsec3_sig = dns.rrset.from_text(
            str(nsec3_rrset.name), 3600, "IN", "RRSIG",
            "NSEC3 8 1 3600 20350101000000 20300101000000 12345 . deadbeef"
        )
        ns_rrset = dns.rrset.from_text(
            "example.com.", 3600, "IN", "NS", "ns.example.com."
        )

        async def fake_lookup(qname, rdtype, dnssec_ok=False):
            if rdtype == dns.rdatatype.DS and qname == "example.com":
                msg = dns.message.Message()
                msg.authority.append(ns_rrset)
                msg.authority.append(nsec3_rrset)
                msg.authority.append(nsec3_sig)
                return msg
            return None

        resolver._dnssec_lookup = fake_lookup

        with patch("dns.dnssec.validate", return_value=None):
            result = await resolver._prove_insecure_delegation("example.com", ".")
        assert result is True

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nxdomain_full_proof(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        # Build an NXDOMAIN response for foo.example.com with NSEC3 proof.
        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NXDOMAIN)

        hash_map = {
            "example.com.": "22222222222222222222222222222222",
            "*.example.com.": "44444444444444444444444444444444",
            "foo.example.com.": "33333333333333333333333333333333",
            "*.foo.example.com.": "55555555555555555555555555555555",
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "77777777777777777777777777777777")
        resolver._nsec3_hash = fake_hash

        next_example = base64.b32decode("44444444444444444444444444444444")
        next_wildcard = base64.b32decode("66666666666666666666666666666666")

        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=next_example,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        nsec3_wildcard = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=next_wildcard,
            windows=[],
        )
        nsec3_wildcard_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['*.example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_wildcard_rrset.ttl = 3600
        nsec3_wildcard_rrset.add(nsec3_wildcard)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        rrsig_wildcard = dns.rrset.from_text(
            f"{hash_map['*.example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)
        resp.authority.append(nsec3_wildcard_rrset)
        resp.authority.append(rrsig_wildcard)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nxdomain_closest_encloser_wildcard_candidate(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))
        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        hash_map = {
            "www.foo.example.com.": "33333333333333333333333333333333",
            "foo.example.com.": "55555555555555555555555555555555",
            "example.com.": "22222222222222222222222222222222",
            "*.example.com.": "66666666666666666666666666666666",
        }
        hashed_names = []
        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            hashed_names.append(name)
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        msg = dns.message.make_query("www.foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NXDOMAIN)

        next_example = base64.b32decode(hash_map["*.example.com."])
        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=next_example,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        wrap_example = base64.b32decode(hash_map["example.com."])
        nsec3_wildcard = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=wrap_example,
            windows=[],
        )
        nsec3_wildcard_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['*.example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_wildcard_rrset.ttl = 3600
        nsec3_wildcard_rrset.add(nsec3_wildcard)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        rrsig_wildcard = dns.rrset.from_text(
            f"{hash_map['*.example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)
        resp.authority.append(nsec3_wildcard_rrset)
        resp.authority.append(rrsig_wildcard)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            assert await resolver._validate_nsec3_negative("www.foo.example.com.", resp) is True
        assert "*.example.com." in hashed_names
        assert "*.foo.example.com." not in hashed_names

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nodata_exact_hash_type_bitmap(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NOERROR)

        qname_hash = b"\x11" * 20
        hash_map = {
            "foo.example.com.": base64.b32encode(qname_hash).decode().lower().rstrip("="),
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        nsec3 = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x22" * 20,
            windows=[],
        )
        nsec3_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['foo.example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_rrset.ttl = 3600
        nsec3_rrset.add(nsec3)

        rrsig = dns.rrset.from_text(
            f"{hash_map['foo.example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_rrset)
        resp.authority.append(rrsig)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nxdomain_wildcard_absent(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NXDOMAIN)

        hash_map = {
            "example.com.": base64.b32encode(b"\x22" * 20).decode().lower().rstrip("="),
            "foo.example.com.": base64.b32encode(b"\x55" * 20).decode().lower().rstrip("="),
            "*.example.com.": base64.b32encode(b"\x33" * 20).decode().lower().rstrip("="),
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x66" * 20,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nxdomain_wraparound_with_wildcard_and_multiple_rrsets(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NXDOMAIN)

        hash_map = {
            "example.com.": base64.b32encode(b"\x22" * 20).decode().lower().rstrip("="),
            "*.example.com.": base64.b32encode(b"\x33" * 20).decode().lower().rstrip("="),
            "foo.example.com.": base64.b32encode(b"\x55" * 20).decode().lower().rstrip("="),
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x33" * 20,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        nsec3_wildcard = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x22" * 20,
            windows=[],
        )
        nsec3_wildcard_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['*.example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_wildcard_rrset.ttl = 3600
        nsec3_wildcard_rrset.add(nsec3_wildcard)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        rrsig_wildcard = dns.rrset.from_text(
            f"{hash_map['*.example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)
        resp.authority.append(nsec3_wildcard_rrset)
        resp.authority.append(rrsig_wildcard)

        validate_entries = []
        def fake_validate_rrsig(rrset, rrsig, keys, origin=None, now=None, policy=None):
            validate_entries.append(str(rrset.name))
            return None

        with patch('dns.dnssec.validate_rrsig', side_effect=fake_validate_rrsig):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False
            assert validate_entries == [
                str(nsec3_example_rrset.name),
                str(nsec3_wildcard_rrset.name),
            ]

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nxdomain_wildcard_interval_separate_proofs(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NXDOMAIN)

        hash_map = {
            "example.com.": base64.b32hexencode(b"\x22" * 20).decode().lower().rstrip("="),
            "foo.example.com.": base64.b32hexencode(b"\x33" * 20).decode().lower().rstrip("="),
            "*.example.com.": base64.b32hexencode(b"\x44" * 20).decode().lower().rstrip("="),
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x55" * 20,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        nsec3_wildcard = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x66" * 20,
            windows=[],
        )
        nsec3_wildcard_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['*.example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_wildcard_rrset.ttl = 3600
        nsec3_wildcard_rrset.add(nsec3_wildcard)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        rrsig_wildcard = dns.rrset.from_text(
            f"{hash_map['*.example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)
        resp.authority.append(nsec3_wildcard_rrset)
        resp.authority.append(rrsig_wildcard)

        validated_rrsets = []
        def fake_validate_rrsig(rrset, rrsig, keys, origin=None, now=None, policy=None):
            validated_rrsets.append(str(rrset.name))
            return None

        with patch('dns.dnssec.validate_rrsig', side_effect=fake_validate_rrsig):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False
            assert validated_rrsets == [
                str(nsec3_example_rrset.name),
                str(nsec3_wildcard_rrset.name),
            ]

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nodata_wildcard_nonexistence(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NOERROR)

        hash_map = {
            "example.com.": base64.b32encode(b"\x22" * 20).decode().lower().rstrip("="),
            "foo.example.com.": base64.b32encode(b"\x55" * 20).decode().lower().rstrip("="),
            "*.example.com.": base64.b32encode(b"\x33" * 20).decode().lower().rstrip("="),
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x66" * 20,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False

    @pytest.mark.asyncio
    async def test_chain_validation_nsec3_nxdomain_wildcard_exists(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        dnskey_rrset = make_dnskey_rrset("example.com.", 256, 3, 8, bytes.fromhex("deadbeef"))

        async def fake_get_key(zone):
            if zone == "example.com":
                return dnskey_rrset
            return None
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("foo.example.com.", dns.rdatatype.A)
        resp = dns.message.make_response(msg)
        resp.set_rcode(dns.rcode.NXDOMAIN)

        hash_map = {
            "example.com.": base64.b32encode(b"\x22" * 20).decode().lower().rstrip("="),
            "*.example.com.": base64.b32encode(b"\x33" * 20).decode().lower().rstrip("="),
            "foo.example.com.": base64.b32encode(b"\x55" * 20).decode().lower().rstrip("="),
        }

        def fake_hash(name: str, salt: bytes, iterations: int, algorithm: int) -> str:
            return hash_map.get(name, "ffffffffffffffffffffffffffffffff")
        resolver._nsec3_hash = fake_hash

        nsec3_example = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x66" * 20,
            windows=[],
        )
        nsec3_example_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_example_rrset.ttl = 3600
        nsec3_example_rrset.add(nsec3_example)

        nsec3_wildcard = dns.rdtypes.ANY.NSEC3.NSEC3(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.NSEC3,
            algorithm=1,
            flags=0,
            iterations=0,
            salt=b'',
            next=b"\x77" * 20,
            windows=[],
        )
        nsec3_wildcard_rrset = dns.rrset.RRset(dns.name.from_text(f"{hash_map['*.example.com.']}.example.com."), dns.rdataclass.IN, dns.rdatatype.NSEC3)
        nsec3_wildcard_rrset.ttl = 3600
        nsec3_wildcard_rrset.add(nsec3_wildcard)

        rrsig_example = dns.rrset.from_text(
            f"{hash_map['example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        rrsig_wildcard = dns.rrset.from_text(
            f"{hash_map['*.example.com.']}.example.com.",
            3600,
            "IN",
            "RRSIG",
            "NSEC3 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )

        resp.authority.append(nsec3_example_rrset)
        resp.authority.append(rrsig_example)
        resp.authority.append(nsec3_wildcard_rrset)
        resp.authority.append(rrsig_wildcard)

        validate_entries = []
        def fake_validate_rrsig(rrset, rrsig, keys, origin=None, now=None, policy=None):
            validate_entries.append((str(rrset.name), str(rrsig.signer)))
            assert str(rrset.name).endswith("example.com.")
            return None

        with patch('dns.dnssec.validate_rrsig', side_effect=fake_validate_rrsig):
            secure, insecure = await resolver._dnssec_validate_chain("foo.example.com.", resp.to_wire(), dnssec_requested=True)
            assert secure is True
            assert insecure is False
            assert validate_entries == [
                (str(nsec3_example_rrset.name), str(rrsig_example[0].signer)),
                (str(nsec3_wildcard_rrset.name), str(rrsig_wildcard[0].signer)),
            ]

    @pytest.mark.asyncio
    async def test_chain_validation_fails_on_bogus_signature(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        with patch('dns.dnssec.validate_rrsig', side_effect=dns.dnssec.ValidationFailure("Bogus")):
            async def fake_get_key(zone):
                if zone == "example.com":
                    return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
                return None
            resolver._get_validated_dnskey = fake_get_key

            msg = dns.message.make_query("example.com.", dns.rdatatype.A)
            a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
            msg.answer.append(a_rr)
            rrsig = dns.rrset.from_text(
                "example.com.", 3600, "IN", "RRSIG",
                "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
            )
            msg.answer.append(rrsig)

            with patch('time.time', return_value=1893456000):
                with pytest.raises(dns.dnssec.ValidationFailure):
                    await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)

    @pytest.mark.asyncio
    async def test_chain_validation_limits_keytrap(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=1,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        async def fake_get_key(zone):
            return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
        resolver._get_validated_dnskey = fake_get_key

        msg = dns.message.make_query("example.com.", dns.rdatatype.A)
        a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
        msg.answer.append(a_rr)
        rrsig_a = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig_a)

        mx_rr = dns.rrset.from_text("example.com.", 3600, "IN", "MX", "10 mail.example.com.")
        msg.answer.append(mx_rr)
        rrsig_mx = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "MX 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig_mx)

        with patch('dns.dnssec.validate_rrsig', return_value=None):
            with patch('time.time', return_value=1893456000):
                secure, insecure = await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)
                assert not secure
                assert not insecure

    @pytest.mark.asyncio
    async def test_chain_validation_fallback_to_legacy(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=False,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=2.0,
            trust_anchors=None,
        )

        with patch.object(resolver, '_dnssec_validate_old', new_callable=AsyncMock) as mock_old:
            mock_old.return_value = (True, False)
            await resolver._dnssec_validate("example.com", b"dummy", dnssec_requested=True)
            mock_old.assert_called_once()

    @pytest.mark.asyncio
    async def test_chain_validation_timeout(self):
        resolver = DNSResolver(
            dnssec_enabled=True,
            dnssec_chain_validation=True,
            dnssec_max_validations=10,
            dnssec_max_dnskey_records=5,
            dnssec_validation_timeout=0.1,
            trust_anchors=None,
        )

        async def slow_get_key(zone):
            await asyncio.sleep(0.5)
            return make_dnskey_rrset("example.com.", 256, 3, 8, b"deadbeef")
        resolver._get_validated_dnskey = slow_get_key

        msg = dns.message.make_query("example.com.", dns.rdatatype.A)
        a_rr = dns.rrset.from_text("example.com.", 3600, "IN", "A", "1.2.3.4")
        msg.answer.append(a_rr)
        rrsig = dns.rrset.from_text(
            "example.com.", 3600, "IN", "RRSIG",
            "A 8 2 3600 20350101000000 20300101000000 12345 example.com. deadbeef"
        )
        msg.answer.append(rrsig)

        with patch('time.time', return_value=1893456000):
            secure, insecure = await resolver._dnssec_validate_chain("example.com", msg.to_wire(), dnssec_requested=True)
            assert not secure
            assert not insecure


# ---------- KeyTrap tests ----------
@pytest.fixture
def keytrap_resolver():
    return DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
        dnssec_max_validations=2,
        dnssec_max_dnskey_records=1,
        dnssec_validation_timeout=0.1,
        trust_anchors=None,
    )


def create_rrsig(covered_type: int, name: str) -> dns.rrset.RRset:
    covered_text = dns.rdatatype.to_text(covered_type)
    rrsig_text = f"{covered_text} 8 1 300 20350101000000 20300101000000 12345 {name} deadbeef"
    return dns.rrset.from_text(name, 300, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrsig_text)


@pytest.mark.asyncio
async def test_dnssec_max_validations_limit(keytrap_resolver):
    async def fake_get_key(zone):
        return dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", "256 3 8 deadbeef")
    keytrap_resolver._get_validated_dnskey = fake_get_key

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    for i in range(3):
        name = f"example{i}.com."
        a_rrset = dns.rrset.from_text(name, 300, dns.rdataclass.IN, dns.rdatatype.A, f"192.0.2.{i+1}")
        resp.answer.append(a_rrset)
        resp.answer.append(create_rrsig(dns.rdatatype.A, name))

    validate_calls = 0
    def fake_validate_rrsig(rrset, rrsig, keys, origin=None, now=None, policy=None):
        nonlocal validate_calls
        validate_calls += 1
        return

    wire = resp.to_wire()
    qname = "example.com"

    with patch('dns.dnssec.validate_rrsig', side_effect=fake_validate_rrsig):
        with patch('time.time', return_value=1893456000):
            secure, insecure = await keytrap_resolver._dnssec_validate(qname, wire, dnssec_requested=True)
            assert secure is False
            assert insecure is False
            assert validate_calls == 2


@pytest.mark.asyncio
async def test_dnssec_keytrap_dnskey_limit():
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(""". 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0=\n""")
        f.write(""". 3600 IN DNSKEY 257 3 8 AwEAAdummy1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n""")
        f.write(""". 3600 IN DNSKEY 257 3 8 AwEAAdummy2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n""")
        fname = f.name

    try:
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
            dnssec_enabled=True,
            auto_update_trust_anchor=False,
            dnssec_max_dnskey_records=1,
            trust_anchors=fname,
        )
        resolver._load_trust_anchors()
        assert resolver._dnssec_raw_anchors is not None
        root_anchor = resolver._dnssec_raw_anchors.get(dns.name.root)
        assert root_anchor is not None
        assert len(root_anchor) == 1
    finally:
        os.unlink(fname)


@pytest.mark.asyncio
async def test_dnssec_keytrap_validation_timeout(keytrap_resolver):
    async def fake_get_key(zone):
        return dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", "256 3 8 deadbeef")
    keytrap_resolver._get_validated_dnskey = fake_get_key

    query = dns.message.make_query("example.com", "A")
    resp = dns.message.make_response(query)

    a_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(a_rrset)
    resp.answer.append(create_rrsig(dns.rdatatype.A, "example.com."))

    wire = resp.to_wire()
    qname = "example.com"

    def slow_validate_rrsig(rrset, rrsig, keys, origin=None, now=None, policy=None):
        time.sleep(0.5)
        return

    with patch('dns.dnssec.validate_rrsig', side_effect=slow_validate_rrsig):
        with patch('time.time', side_effect=[1893456000, 1893456000, 1893456005, 1893456005]):
            secure, insecure = await keytrap_resolver._dnssec_validate(qname, wire, dnssec_requested=True)
            assert secure is False


@pytest.mark.asyncio
async def test_dnssec_no_validation_when_cd_flag_set_keytrap():
    resolver = DNSResolver(
        upstreams=[{"address": "1.1.1.1", "protocol": "udp", "ip": "1.1.1.1"}],
        dnssec_enabled=True,
        auto_update_trust_anchor=False,
    )
    resolver._dnssec_raw_anchors = {dns.name.root: b"dummy"}

    query = dns.message.make_query("example.com", "A")
    query.flags |= 0x0010
    qwire = query.to_wire()

    validate_called = False
    def fake_validate_rrsig(*args, **kwargs):
        nonlocal validate_called
        validate_called = True
        return

    resp = dns.message.make_response(query)
    a_rrset = dns.rrset.from_text("example.com.", 300, dns.rdataclass.IN, dns.rdatatype.A, "192.0.2.1")
    resp.answer.append(a_rrset)
    resp.answer.append(create_rrsig(dns.rdatatype.A, "example.com."))
    wire = resp.to_wire()

    async def fake_try_upstream(upstream, data, _health_check=False, _no_retry=False):
        return wire
    resolver._try_upstream = fake_try_upstream

    with patch('dns.dnssec.validate_rrsig', side_effect=fake_validate_rrsig):
        result = await resolver.forward_dns_query(qwire)
        assert validate_called is False
        msg = dns.message.from_wire(result)
        assert msg.rcode() == 0