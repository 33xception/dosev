import asyncio
import logging
import socket
import ssl
import struct
import time
import threading
import hashlib
import ipaddress
import os
import random
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional, Tuple, Any, Set, Dict, Union, List, Callable, Coroutine, Iterable
from urllib.parse import urlparse
import base64
from concurrent.futures import ThreadPoolExecutor
from collections import deque
import ipaddress

DEFAULT_LOG_DIR = os.path.join(os.getenv('LOCALAPPDATA') or os.path.expanduser('~'), 'dosev', 'logs') if os.name == 'nt' else '/var/log/dosev'

try:
    from cachetools import TTLCache
    _HAS_CACHETOOLS = True
except Exception:
    _HAS_CACHETOOLS = False
    TTLCache = None

try:
    import aioquic.asyncio
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived, H3Event
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import QuicEvent
    from aioquic.quic.events import StreamDataReceived
    _HAS_AIOQUIC = True
except Exception:
    aioquic = None
    connect = None
    QuicConnectionProtocol = None
    H3Connection = None
    DataReceived = None
    HeadersReceived = None
    H3Event = None
    QuicConfiguration = None
    QuicConnection = None
    QuicEvent = None
    _HAS_AIOQUIC = False

try:
    from prometheus_client import Counter, Histogram
    _HAS_PROM = True
except Exception:
    Counter = None
    Histogram = None
    _HAS_PROM = False

try:
    import dns.message
    import dns.dnssec
    import dns.name
    import dns.flags
    import dns.resolver
    import dns.rdatatype
    import dns.rrset
    import dns.rdataclass
    import dns.rcode
    import dns.rdtypes.ANY.NSEC3
    import dns.rdtypes.ANY.DS
    import dns.rdtypes.ANY.DNSKEY
    import dns.exception
    from dns.rdtypes.ANY.NSEC3 import NSEC3
    from dns.rdtypes.ANY.DS import DS
    from dns.rdtypes.ANY.DNSKEY import DNSKEY
    _HAS_DNSPY = True
except Exception:
    dns = None
    _HAS_DNSPY = False

try:
    import uvloop
    _HAS_UVLOOP = True
except Exception:
    uvloop = None
    _HAS_UVLOOP = False

MAX_UDP_PAYLOAD = 4096
DEFAULT_DNSSEC_KEY_CACHE_SIZE = 1000
DEFAULT_DNSSEC_DS_CACHE_SIZE = 1000
INSECURE_CACHE_TTL = 3600

# ---------- Default DNSSEC trust anchor (root KSK) ----------
DEFAULT_ROOT_DNSKEY = (
    ". 172800 IN DNSKEY 257 3 8 "
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0="
)
DEFAULT_ROOT_DS = "19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"

# ---------- NSEC3 constants ----------
NSEC3_OPT_OUT = 0x01

# Global executor for CPU‑bound crypto tasks
_CRYPTO_EXECUTOR = ThreadPoolExecutor(max_workers=4)

# Maximum allowed TCP message size (RFC 1035 allows up to 65535, but we enforce a cap)
MAX_TCP_RESPONSE_SIZE = 65535

MAX_NSEC3_ITERATIONS = 100  # RFC 9276 recommended limit to prevent CPU exhaustion DoS

class AsyncTTLCache:
    """Async-capable TTL cache with optional size limit and per-item TTL."""
    def __init__(self, maxsize: int = 1024, ttl: int = 300) -> None:
        self._data: Dict[Any, Tuple[Any, float]] = {}
        self._default_ttl: int = ttl
        self._max: int = max(1, maxsize)
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get(self, key: Any) -> Optional[Any]:
        async with self._lock:
            v = self._data.get(key)
            if v is None:
                return None
            value, expire = v
            if time.time() >= expire:
                del self._data[key]
                return None
            return value

    async def set(self, key: Any, value: Any, ttl: Optional[int] = None) -> None:
        async with self._lock:
            if key in self._data:
                del self._data[key]
            elif len(self._data) >= self._max:
                del self._data[next(iter(self._data))]
            expiry = time.time() + (ttl if ttl is not None else self._default_ttl)
            self._data[key] = (value, expiry)

    async def delete(self, key: Any) -> None:
        async with self._lock:
            try:
                if key in self._data:
                    del self._data[key]
            except Exception:
                pass


class RateLimiter:
    """Token-bucket rate limiter for DNS queries (per IP)."""
    def __init__(self, rate: float, burst: float) -> None:
        # clamp values to safe ranges
        self.rate: float = max(0.0, float(rate))
        self.burst: float = max(1.0, float(burst) if burst is not None else 1.0)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start_cleanup(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return
        async def _cleanup():
            while True:
                await asyncio.sleep(60)
                now = time.time()
                async with self._lock:
                    for key, (_, last) in list(self._buckets.items()):
                        if now - last > 300:
                            del self._buckets[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop_cleanup(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def is_allowed(self, key: str) -> bool:
        async with self._lock:
            now = time.time()
            tokens, last = self._buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return True
            self._buckets[key] = (tokens, now)
            return False


class ConnectionPool:
    """A simple connection pool for TCP and TLS connections."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        async with self._lock:
            if key in self._pools:
                while self._pools[key]:
                    reader, writer, _ = self._pools[key].pop()
                    if not writer.is_closing():
                        return reader, writer
                    try:
                        writer.close()
                    except Exception:
                        pass
        return None

    async def put(self, key: Tuple, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._lock:
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                return
            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) >= self.max_size:
                _, oldest_writer, _ = self._pools[key].pop(0)
                try:
                    oldest_writer.close()
                except Exception:
                    pass
            self._pools[key].append((reader, writer, time.time()))

    async def start_cleanup(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    keys_to_purge = []
                    for key in list(self._pools.keys()):
                        keep = []
                        for reader, writer, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout or writer.is_closing():
                                try:
                                    writer.close()
                                except Exception:
                                    pass
                            else:
                                keep.append((reader, writer, last_used))
                        if keep:
                            self._pools[key] = keep
                        else:
                            keys_to_purge.append(key)
                    for key in keys_to_purge:
                        del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        async with self._lock:
            for pool_key, connections in list(self._pools.items()):
                for _, writer, _ in connections:
                    try:
                        writer.close()
                    except Exception:
                        pass
                del self._pools[pool_key]
            self._pools.clear()


class ClientPool:
    """A pool that holds arbitrary client objects (httpx clients, QUIC connections, etc.)."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[Any, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[Any]:
        async with self._lock:
            if key in self._pools and self._pools[key]:
                client, _ = self._pools[key].pop()
                return client
        return None

    async def put(self, key: Tuple, client: Any) -> None:
        async with self._lock:
            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) >= self.max_size:
                old_client, _ = self._pools[key].pop(0)
                await self._close_client(old_client)
            self._pools[key].append((client, time.time()))

    async def start_cleanup(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    for key in list(self._pools.keys()):
                        keep = []
                        for client, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout:
                                await self._close_client(client)
                            else:
                                keep.append((client, last_used))
                        self._pools[key] = keep
                        if not self._pools[key]:
                            del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        async with self._lock:
            for pool_key, clients in list(self._pools.items()):
                for client, _ in clients:
                    await self._close_client(client)
                del self._pools[pool_key]
            self._pools.clear()

    async def _close_client(self, client: Any) -> None:
        try:
            if isinstance(client, tuple) and len(client) == 2:
                conn, _ = client
                if hasattr(conn, 'close'):
                    conn.close()
                return
            if hasattr(client, '_quic') and hasattr(client._quic, 'close'):
                client._quic.close()
            if hasattr(client, '_cm'):
                try:
                    await client._cm.__aexit__(None, None, None)
                except Exception:
                    pass
            if hasattr(client, 'aclose'):
                await client.aclose()
            elif hasattr(client, 'close'):
                client.close()
        except Exception:
            pass


# ---------- H3 DoH Protocol with proper pooling support ----------
class H3DohProtocol(QuicConnectionProtocol):
    """HTTP/3 protocol handler for DoH that supports connection pooling."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http: Optional[H3Connection] = None
        self._request_events: Dict[int, deque] = {}
        self._request_waiter: Dict[int, asyncio.Future] = {}
        self._loop = asyncio.get_running_loop()

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self._http_event_received(http_event)

    def _http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) or isinstance(event, DataReceived):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                self._request_events[stream_id].append(event)
                if event.stream_ended:
                    waiter = self._request_waiter.pop(stream_id, None)
                    if waiter and not waiter.done():
                        waiter.set_result(self._request_events.pop(stream_id, deque()))

    async def send_request(self, data: bytes, hostname: str, path: str = "/dns-query") -> Tuple[bytes, int]:
        if self._http is None:
            self._http = H3Connection(self._quic)

        stream_id = self._quic.get_next_available_stream_id()
        self._request_events[stream_id] = deque()
        waiter = self._loop.create_future()
        self._request_waiter[stream_id] = waiter

        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", hostname.encode()),
                (b":path", path.encode()),
                (b"content-type", b"application/dns-message"),
                (b"accept", b"application/dns-message"),
                (b"content-length", str(len(data)).encode()),
            ],
            end_stream=False,
        )

        self._http.send_data(stream_id=stream_id, data=data, end_stream=True)
        self.transmit()

        try:
            events = await asyncio.wait_for(waiter, timeout=30.0)
        finally:
            self._request_events.pop(stream_id, None)
            self._request_waiter.pop(stream_id, None)

        body = bytearray()
        age = 0
        for event in events:
            if isinstance(event, DataReceived):
                body.extend(event.data)
            elif isinstance(event, HeadersReceived):
                for name, value in event.headers:
                    if name.lower() == b"age":
                        age = self._parse_http_age(value.decode("ascii", errors="ignore"))
        return bytes(body), age

    def close(self) -> None:
        if self._quic:
            self._quic.close()
            self.transmit()


class H3ConnectionPool:
    """Pool of persistent HTTP/3 connections for DoH upstreams."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[H3DohProtocol, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[H3DohProtocol]:
        async with self._lock:
            if key not in self._pools or not self._pools[key]:
                return None
            client, _ = self._pools[key].pop()
            # Check if the connection is still alive
            try:
                if client._quic is None:
                    return None
                # Try to get a stream ID – raises if connection is closed
                client._quic.get_next_available_stream_id()
                return client
            except Exception:
                # Connection is dead, close it and discard
                try:
                    client.close()
                except Exception:
                    pass
                return None

    async def put(self, key: Tuple, client: H3DohProtocol) -> None:
        async with self._lock:
            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) >= self.max_size:
                old_client, _ = self._pools[key].pop(0)
                try:
                    old_client.close()
                except Exception:
                    pass
            self._pools[key].append((client, time.time()))

    async def start_cleanup(self) -> None:
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    for key in list(self._pools.keys()):
                        keep = []
                        for client, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout:
                                try:
                                    client.close()
                                except Exception:
                                    pass
                            else:
                                keep.append((client, last_used))
                        if keep:
                            self._pools[key] = keep
                        else:
                            del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        async with self._lock:
            for key in list(self._pools.keys()):
                for client, _ in self._pools[key]:
                    try:
                        client.close()
                    except Exception:
                        pass
                del self._pools[key]


class DNSResolver:
    
    # Reserved / Private IP Subnets per RFC 6890, RFC 1918, RFC 4291
    PRIVATE_SUBNETS = [
        ipaddress.ip_network("127.0.0.0/8"),       # Loopback
        ipaddress.ip_network("10.0.0.0/8"),         # Private
        ipaddress.ip_network("172.16.0.0/12"),      # Private
        ipaddress.ip_network("192.168.0.0/16"),     # Private
        ipaddress.ip_network("100.64.0.0/10"),      # CGNAT (RFC 6598)
        ipaddress.ip_network("169.254.0.0/16"),     # Link-local
        ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
        ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
        ipaddress.ip_network("224.0.0.0/4"),        # Multicast
        ipaddress.ip_network("240.0.0.0/4"),        # Reserved
        ipaddress.ip_network("::1/128"),            # IPv6 Loopback
        ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local (ULA)
        ipaddress.ip_network("fe80::/10"),          # IPv6 Link-local
        ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ]
    
    def __init__(self,
                  upstreams: Optional[List[Dict[str, Any]]] = None,
                  verbose: bool = False,
                  disable_ipv6: bool = False,
                  strip_ipv6_records: bool = False,
                  cache_ttl: int = 300,
                  cache_max_size: int = 2048,
                  negative_cache_ttl: int = 5,
                  doh_timeout: float = 5.0,
                  udp_timeout: float = 2.0,
                  tcp_timeout: float = 5.0,
                  retries: int = 1,
                  initial_backoff: float = 0.1,
                  dns_logging_enabled: bool = False,
                  dns_log_dir: str = DEFAULT_LOG_DIR,
                  dns_log_prefix: str = "dns-requests",
                  dns_log_retention_days: int = 7,
                  pinned_certs: Optional[Dict[str, str]] = None,
                  dnssec_enabled: bool = False,
                  trust_anchors: Optional[Union[Dict[str, str], str]] = None,
                  auto_update_trust_anchor: bool = True,
                  dnssec_max_validations: int = 32,
                  dnssec_max_dnskey_records: int = 8,
                  dnssec_validation_timeout: float = 2.0,
                  dnssec_chain_validation: bool = True,
                  dnssec_max_iterations: int = 100,
                  scrub_unsolicited_ns: bool = True,
                  metrics_enabled: bool = False,
                  metrics_port: int = 8000,
                  uvloop_enable: bool = False,
                  rate_limit_rps: float = 0.0,
                  rate_limit_burst: float = 0.0,
                  optimistic_cache_enabled: bool = False,
                  optimistic_stale_max_age: int = 86400,
                  optimistic_stale_response_ttl: int = 30,
                  rebind_protection_enabled: bool = False,
                  rebind_action: str = 'strip',
                  ecs_enabled: bool = True,
                  max_edns_payload: int = MAX_UDP_PAYLOAD,
                  pool_max_size: int = 5,
                  pool_idle_timeout: float = 60.0,
                  doh_version: str = 'auto',
                  doh_auto_cache_ttl: int = 3600,
                  load_balancing: str = 'failover',
                  bootstrap: Optional[Dict[str, Any]] = None,
                  tcp_fallback_enabled: bool = True,
                  tcp_fastopen_enabled: bool = True,
                  health_config: Optional[Dict[str, Any]] = None) -> None:

        self.upstreams: List[Dict[str, Any]] = upstreams or []
        if bootstrap is None:
            bootstrap = {}
        self.bootstrap_servers: List[str] = bootstrap.get('servers', [])
        self.bootstrap_timeout: float = bootstrap.get('timeout', 2.0)
        self.bootstrap_retries: int = bootstrap.get('retries', 2)

        self.disable_ipv6: bool = bool(disable_ipv6)
        self.strip_ipv6_records: bool = bool(strip_ipv6_records)
        self.verbose: bool = bool(verbose)
        self.logger: logging.Logger = logging.getLogger("dosev.DNSResolver")
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.logger.addHandler(h)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        self._cache_ttl = cache_ttl
        self._cache_max_size = cache_max_size
        self._init_caches(cache_ttl, cache_max_size, negative_cache_ttl)

        self.negative_cache_ttl: int = max(1, int(negative_cache_ttl))

        self._lock: asyncio.Lock = asyncio.Lock()
        self._cache_lock: asyncio.Lock = asyncio.Lock()
        self._flight_lock: asyncio.Lock = asyncio.Lock()
        self._config_lock: asyncio.Lock = asyncio.Lock()
        self._trust_anchor_lock: asyncio.Lock = asyncio.Lock()
        self._blocklist_lock: asyncio.Lock = asyncio.Lock()
        self._dnssec_cache_lock: asyncio.Lock = asyncio.Lock()

        self.doh_timeout: float = doh_timeout
        self.udp_timeout: float = udp_timeout
        self.tcp_timeout: float = tcp_timeout
        self.retries: int = max(1, int(retries))
        self.initial_backoff: float = initial_backoff

        self.dns_logging_enabled: bool = dns_logging_enabled
        self._file_logger: Optional[logging.Logger] = None
        if dns_logging_enabled:
            dns_log_dir = dns_log_dir or DEFAULT_LOG_DIR
            try:
                from logging.handlers import TimedRotatingFileHandler
                os.makedirs(dns_log_dir, exist_ok=True)
                fh = TimedRotatingFileHandler(
                    os.path.join(dns_log_dir, f"{dns_log_prefix}.log"),
                    when='midnight',
                    backupCount=dns_log_retention_days
                )
                fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
                flog = logging.getLogger("dosev.DNSRequests")
                flog.setLevel(logging.INFO)
                if not any(isinstance(h, TimedRotatingFileHandler) for h in flog.handlers):
                    flog.addHandler(fh)
                self._file_logger = flog
            except Exception as e:
                self.logger.warning("Failed to init file logger: %s", e)

        self.pinned_certs: Dict[str, str] = pinned_certs or {}
        self.dnssec_enabled: bool = bool(dnssec_enabled)
        self.auto_update_trust_anchor: bool = auto_update_trust_anchor
        self.trust_anchors: Any = trust_anchors
        self._dnssec_raw_anchors: Optional[Any] = None
        self._dnssec_keyring: Optional[Any] = None
        self._trust_anchor_updater_task: Optional[asyncio.Task] = None

        self.dnssec_chain_validation: bool = dnssec_chain_validation
        self.dnssec_max_iterations: int = dnssec_max_iterations
        self.dnssec_max_validations: int = dnssec_max_validations
        self.dnssec_max_dnskey_records: int = dnssec_max_dnskey_records
        self.dnssec_validation_timeout: float = dnssec_validation_timeout

        self._dnssec_key_cache: Dict[str, Tuple[dns.rrset.RRset, float]] = {}
        self._dnssec_key_cache_maxsize = DEFAULT_DNSSEC_KEY_CACHE_SIZE
        self._dnssec_ds_cache: Dict[str, Tuple[dns.rrset.RRset, float]] = {}
        self._dnssec_ds_cache_maxsize = DEFAULT_DNSSEC_DS_CACHE_SIZE
        self._dnssec_insecure_cache: Dict[str, float] = {}
        self._dnssec_insecure_cache_ttl = INSECURE_CACHE_TTL
        self._dnssec_cache_lock: asyncio.Lock = asyncio.Lock()
        self._insecure_cleanup_task: Optional[asyncio.Task] = None

        self.metrics_enabled: bool = bool(metrics_enabled) and _HAS_PROM
        self._metrics: Optional[Dict[str, Any]] = None
        # Prometheus metrics server is started in a controllable WSGI server so
        # tests and consumers can shut it down cleanly. Only start when the
        # prometheus client is available and metrics are enabled.
        if self.metrics_enabled:
            try:
                self._metrics = {
                    'requests_total': Counter('dosev_dns_requests_total', 'Total DNS upstream requests', ['proto']),
                    'requests_errors': Counter('dosev_dns_request_errors_total', 'Failed DNS upstream requests', ['proto']),
                    'request_latency_seconds': Histogram('dosev_dns_request_latency_seconds', 'Upstream request latency seconds', ['proto'])
                }
                try:
                    # Use make_wsgi_app for a stoppable server.
                    from prometheus_client import make_wsgi_app
                    from wsgiref.simple_server import make_server, WSGIRequestHandler

                    class _SilentHandler(WSGIRequestHandler):
                        def log_message(self, format, *args):
                            return

                    app = make_wsgi_app()
                    server = make_server('', int(metrics_port), app, handler_class=_SilentHandler)
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    self._prometheus_server = server
                    self._prometheus_thread = thread
                    self._prometheus_started = True
                    self.logger.info("Prometheus metrics server started on :%s", metrics_port)
                except Exception as e:
                    self.logger.debug("Could not start prometheus http server: %s", e)
                    self._prometheus_server = None
                    self._prometheus_thread = None
                    self._prometheus_started = False
            except Exception:
                self._metrics = None
                self._prometheus_server = None
                self._prometheus_thread = None
                self._prometheus_started = False

        if uvloop_enable and _HAS_UVLOOP:
            try:
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                self.logger.info("uvloop enabled")
            except Exception as e:
                self.logger.warning("Failed to enable uvloop: %s", e)

        self._blocklist_exact: Set[str] = set()
        self._blocklist_suffix: Set[str] = set()
        self._hosts_map: Dict[str, Tuple[str, ...]] = {}
        self._block_action: str = 'NXDOMAIN'

        self.rate_limit_rps: float = rate_limit_rps
        self.rate_limit_burst: float = rate_limit_burst
        if rate_limit_rps > 0:
            effective_burst = max(1.0, rate_limit_burst)
            self.rate_limiter: Optional[RateLimiter] = RateLimiter(rate_limit_rps, effective_burst)
        else:
            self.rate_limiter = None

        self.optimistic_cache_enabled: bool = optimistic_cache_enabled
        self.stale_max_age: int = optimistic_stale_max_age
        self.stale_response_ttl: int = optimistic_stale_response_ttl
        self._stale_refresh_pending: Set[str] = set()
        self._stale_refresh_lock: asyncio.Lock = asyncio.Lock()

        self.rebind_protection_enabled: bool = rebind_protection_enabled
        self.rebind_action: str = rebind_action
        self.ecs_enabled: bool = bool(ecs_enabled)
        self.max_edns_payload: int = max(512, int(max_edns_payload))

        self._tcp_pool: ConnectionPool = ConnectionPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._h2_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._h3_pool: H3ConnectionPool = H3ConnectionPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._quic_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)

        self._udp_sockets: Dict[Tuple[str, int], socket.socket] = {}
        self._udp_locks: Dict[Tuple[str, int], asyncio.Lock] = {}
        self._udp_sockets_lock: asyncio.Lock = asyncio.Lock()

        self.doh_version: str = doh_version
        self.doh_auto_cache_ttl: int = doh_auto_cache_ttl
        # Auto-DoH version cache with bounded size to avoid unbounded growth
        self._doh_auto_cache: Dict[str, Tuple[str, float]] = {}
        self._doh_auto_cache_maxsize: int = max(256, int(cache_max_size) // 8 if cache_max_size else 256)
        self._doh_auto_lock: asyncio.Lock = asyncio.Lock()

        self.load_balancing: str = load_balancing
        self._rr_index: int = 0

        self.tcp_fallback_enabled: bool = tcp_fallback_enabled
        self.tcp_fastopen_enabled: bool = bool(tcp_fastopen_enabled)

        self._health_config: Dict[str, Any] = health_config or {}
        self._health_enabled: bool = self._health_config.get('enabled', False)
        self._health_interval: int = self._health_config.get('interval', 30)
        self._health_timeout: float = self._health_config.get('timeout', 2.0)
        self._health_unhealthy_threshold: int = self._health_config.get('unhealthy_threshold', 3)
        self._health_healthy_threshold: int = self._health_config.get('healthy_threshold', 2)
        self._health_cooldown: int = self._health_config.get('cooldown', 60)
        self._health_domain: str = self._health_config.get('domain', '.')

        self._upstream_health: Dict[str, Dict[str, Any]] = {}
        self._health_lock: asyncio.Lock = asyncio.Lock()
        self._health_task: Optional[asyncio.Task] = None

        self.scrub_unsolicited_ns: bool = scrub_unsolicited_ns

        self._flights: Dict[Tuple[str, int, bool], asyncio.Future] = {}
        self._flight_lock: asyncio.Lock = asyncio.Lock()
        self._background_tasks: Set[asyncio.Task] = set()
        self._started: bool = False

        # Load trust anchors synchronously (safe)
        if self.dnssec_enabled:
            self._load_trust_anchors()    

    def _init_caches(self, cache_ttl: int, cache_max_size: int, negative_cache_ttl: int) -> None:
        if _HAS_CACHETOOLS:
            self._dns_cache: Any = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache: Any = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._negative_cache: Any = TTLCache(maxsize=cache_max_size, ttl=negative_cache_ttl)
            self._cache_is_sync: bool = True
        else:
            self._dns_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._negative_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=negative_cache_ttl)
            self._cache_is_sync: bool = False
            
    def _is_in_bailiwick(self, record_name: dns.name.Name, query_name: dns.name.Name) -> bool:
        """
        Validates whether a record name falls within the bailiwick (zone of authority)
        of the queried name per RFC 5452 §3.
        """
        # Record name must be equal to or a subdomain of the queried name's apex/zone
        return record_name.is_subdomain(query_name) or record_name == query_name
    
    # -------------------------------------------------------------------------
    # ECS Privacy & Scoping Helpers (RFC 7871)
    # -------------------------------------------------------------------------
    def _truncate_ecs_ip(self, client_ip_str: str) -> Tuple[str, int]:
        """Truncate client IP to privacy-safe prefix lengths (RFC 7871 §11.3)."""
        if not client_ip_str:
            return "", 0
        try:
            ip = ipaddress.ip_address(client_ip_str)
            if ip.version == 4:
                net = ipaddress.ip_network(f"{client_ip_str}/24", strict=False)
                return str(net.network_address), 24
            else:
                net = ipaddress.ip_network(f"{client_ip_str}/56", strict=False)
                return str(net.network_address), 56
        except ValueError:
            return client_ip_str, 0

    def _build_ecs_cache_key(self, qname: str, qtype: int, client_ip: Optional[str] = None, scope_prefix: int = 0) -> Tuple:
        """Build cache key respecting EDNS Client Subnet scope (RFC 7871 §7.1.2)."""
        if scope_prefix > 0 and client_ip:
            masked_ip, _ = self._truncate_ecs_ip(client_ip)
            return (qname.lower(), qtype, f"{masked_ip}/{scope_prefix}")
        return (qname.lower(), qtype, "global")

    def _attach_ecs_option(self, query_data: bytes, client_ip: str) -> bytes:
        """Attach truncated EDNS Client Subnet option to wire query data."""
        if not getattr(self, 'ecs_enabled', True) or not client_ip:
            return query_data

        try:
            msg = dns.message.from_wire(query_data)
            masked_ip, source_prefix = self._truncate_ecs_ip(client_ip)
            if source_prefix > 0:
                ecs_opt = dns.edns.ECSOption(address=masked_ip, srclen=source_prefix)
                opts = [o for o in msg.options if o.otype != dns.edns.ECS]
                opts.append(ecs_opt)
                msg.use_edns(payload=self.max_edns_payload, options=opts)
                return msg.to_wire()
        except Exception as e:
            self.logger.debug("Failed to attach ECS option: %s", e)
        return query_data

    def _extract_ecs_scope(self, response_bytes: bytes) -> int:
        """Extract EDNS Client Subnet scope prefix length from response."""
        try:
            msg = dns.message.from_wire(response_bytes)
            for opt in msg.options:
                if opt.otype == dns.edns.ECS:
                    return getattr(opt, 'scope', 0)
        except Exception:
            pass
        return 0

    # -------------------------------------------------------------------------
    # Bailiwick Scrubbing Helper (RFC 5452 §3 / RFC 2181 §5.4.1)
    # -------------------------------------------------------------------------
    def _scrub_unsolicited_sections(self, response_bytes: bytes, qname_str: str) -> bytes:
        """Filter out-of-bailiwick records from Authority and Additional sections."""
        if not getattr(self, 'scrub_unsolicited_ns', True):
            return response_bytes

        try:
            msg = dns.message.from_wire(response_bytes)
            qname = dns.name.from_text(qname_str)

            def is_in_bailiwick(name: dns.name.Name) -> bool:
                return name.is_subdomain(qname) or name == qname

            # Clean Authority section
            msg.authority = [rrset for rrset in msg.authority if is_in_bailiwick(rrset.name)]
            
            # Clean Additional section (keep OPT pseudo-records)
            msg.additional = [
                rrset for rrset in msg.additional 
                if rrset.rdtype == dns.rdatatype.OPT or is_in_bailiwick(rrset.name)
            ]
            return msg.to_wire()
        except Exception as e:
            self.logger.debug("Bailiwick scrubbing failed: %s", e)
            return response_bytes
        
    def _has_multiple_opt_records(self, msg: dns.message.Message) -> bool:
        """
        RFC 6891 §6.1.1: A DNS message MUST NOT contain more than one OPT RR.
        """
        opt_count = 0
        for rrset in msg.additional:
            if rrset.rdtype == dns.rdatatype.OPT:
                opt_count += len(rrset)  # Accurately count RData instances in RRset
                if opt_count > 1:
                    return True
        return False

    def _make_rcode_response(self, original_data: bytes, rcode: int) -> bytes:
        """Construct an error response (FORMERR, REFUSED, SERVFAIL) retaining query ID."""
        try:
            msg = dns.message.from_wire(original_data)
            resp = dns.message.make_response(msg)
            resp.set_rcode(rcode)
            return resp.to_wire()
        except Exception:
            # Fallback: build minimal 12-byte header response
            orig_id = original_data[:2] if len(original_data) >= 2 else b'\x00\x00'
            # Set QR bit (0x8000) + RCODE
            flags = (0x8000 | (rcode & 0x0F)).to_bytes(2, 'big')
            # Header: ID, flags, QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
            return orig_id + flags + (b'\x00\x00' * 4)

    async def start(self) -> None:
        if self._started:
            return
        self._started = True

        if self.dnssec_enabled and self.auto_update_trust_anchor and self._trust_anchor_updater_task is None:
            self._trust_anchor_updater_task = asyncio.create_task(self._background_trust_anchor_updater())
            self._background_tasks.add(self._trust_anchor_updater_task)

        if self.rate_limiter:
            task = asyncio.create_task(self.rate_limiter.start_cleanup())
            self._background_tasks.add(task)

        if self.dnssec_enabled:
            self._insecure_cleanup_task = asyncio.create_task(self._cleanup_insecure_cache())
            self._background_tasks.add(self._insecure_cleanup_task)

        await self.start_pool_cleanups()

        # Health checks
        if self._health_enabled and self.upstreams and self._health_task is None:
            self._health_task = asyncio.create_task(self._health_check_loop())
            self._background_tasks.add(self._health_task)

        self.logger.info("Background tasks started")

    # ---------- Health check methods ----------
    def _get_upstream_key(self, upstream: Dict[str, Any]) -> str:
        addr = upstream.get('address', '')
        proto = upstream.get('protocol', 'udp')
        port = upstream.get('port', 53)
        return f"{addr}:{proto}:{port}"

    async def _do_health_check(self, upstream: Dict[str, Any]) -> bool:
        try:
            qname = self._health_domain
            query = dns.message.make_query(qname, dns.rdatatype.SOA)
            data = query.to_wire()
            result = await asyncio.wait_for(
                self._try_upstream(upstream, data, _health_check=True, _no_retry=True),
                timeout=self._health_timeout
            )
            return True
        except Exception as e:
            self.logger.debug("Health check failed for %s: %s", upstream.get('address'), e)
            return False

    async def _health_check_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._health_interval)
                async with self._health_lock:
                    for upstream in self.upstreams:
                        key = self._get_upstream_key(upstream)
                        state = self._upstream_health.get(key, {})
                        now = time.time()
                        if state.get('next_retry', 0) > now:
                            continue
                        healthy = await self._do_health_check(upstream)
                        if healthy:
                            state['successes'] = state.get('successes', 0) + 1
                            state['failures'] = 0
                            if state['successes'] >= self._health_healthy_threshold:
                                state['healthy'] = True
                                state['successes'] = 0
                                self.logger.info("Upstream %s is now healthy", upstream.get('address'))
                        else:
                            state['failures'] = state.get('failures', 0) + 1
                            state['successes'] = 0
                            if state['failures'] >= self._health_unhealthy_threshold:
                                state['healthy'] = False
                                state['next_retry'] = time.time() + self._health_cooldown
                                self.logger.warning("Upstream %s marked unhealthy (failures=%d)",
                                                    upstream.get('address'), state['failures'])
                        state['last_check'] = time.time()
                        self._upstream_health[key] = state
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.warning("Health check loop error: %s", e)

    async def start_health_checks(self) -> None:
        await self.start()

    async def start_background_tasks(self) -> None:
        await self.start()

    async def _get_healthy_upstreams(self, upstreams: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self._health_enabled:
            return upstreams
        healthy = []
        async with self._health_lock:
            for up in upstreams:
                key = self._get_upstream_key(up)
                state = self._upstream_health.get(key, {})
                if not state:
                    self._upstream_health[key] = {'healthy': True, 'failures': 0, 'successes': 0,
                                                  'last_check': 0, 'next_retry': 0}
                    healthy.append(up)
                elif state.get('healthy', True):
                    healthy.append(up)
        if not healthy:
            self.logger.warning("All upstreams are unhealthy, falling back to all")
            return upstreams
        return healthy

    # ---------- Pool management ----------
    async def start_pool_cleanups(self) -> None:
        await self._tcp_pool.start_cleanup()
        await self._h2_pool.start_cleanup()
        await self._h3_pool.start_cleanup()
        await self._quic_pool.start_cleanup()

    async def stop_pool_cleanups(self) -> None:
        await self._tcp_pool.stop()
        await self._h2_pool.stop()
        await self._h3_pool.stop()
        await self._quic_pool.stop()
        async with self._udp_sockets_lock:
            for sock in self._udp_sockets.values():
                try:
                    sock.close()
                except Exception:
                    pass
            self._udp_sockets.clear()
            self._udp_locks.clear()

    async def stop_background_tasks(self) -> None:
        for task in list(self._background_tasks):
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._background_tasks.clear()
        if self.rate_limiter:
            await self.rate_limiter.stop_cleanup()

    async def shutdown(self, shutdown_executor: bool = False, stop_prometheus: bool = False) -> None:
        """Gracefully shutdown background tasks, pools and executors.

        Args:
            shutdown_executor: if True, call shutdown() on module-level
                `_CRYPTO_EXECUTOR` to stop worker threads.
            stop_prometheus: if True, stop the internally started Prometheus
                WSGI server (if present).
        """
        try:
            await self.stop_background_tasks()
        except Exception:
            pass

        try:
            await self.stop_pool_cleanups()
        except Exception:
            pass

        if shutdown_executor:
            try:
                _CRYPTO_EXECUTOR.shutdown(wait=False)
            except Exception:
                pass

        if stop_prometheus and getattr(self, '_prometheus_server', None):
            try:
                try:
                    self._prometheus_server.shutdown()
                except Exception:
                    pass
                try:
                    self._prometheus_server.server_close()
                except Exception:
                    pass
                thr = getattr(self, '_prometheus_thread', None)
                if thr and thr.is_alive():
                    try:
                        thr.join(timeout=1.0)
                    except Exception:
                        pass
            except Exception:
                pass
        self._started = False

    # ---------- blocklist helpers ----------
    async def set_blocklist(self, domains: Iterable[str]) -> None:
        async with self._blocklist_lock:
            self._blocklist_exact.clear()
            self._blocklist_suffix.clear()
            for d in domains:
                d = d.strip().lower().rstrip('.')
                if not d:
                    continue
                if d.startswith("."):
                    self._blocklist_suffix.add(d.lstrip("."))
                else:
                    self._blocklist_exact.add(d)

    async def set_hosts_map(self, hosts_map: Dict[str, Tuple[str, ...]]) -> None:
        async with self._blocklist_lock:
            self._hosts_map = {k.lower().rstrip('.'): tuple(v) for k, v in (hosts_map or {}).items()}

    async def get_host_for(self, qname: str) -> Optional[Tuple[str, ...]]:
        if not qname:
            return None
        async with self._blocklist_lock:
            return self._hosts_map.get(qname.lower().rstrip('.'))

    async def is_blocked(self, qname: Optional[str]) -> bool:
        if not qname:
            return False
        q = qname.lower().rstrip('.')
        async with self._blocklist_lock:
            if q in self._blocklist_exact:
                return True
            labels = q.split('.')
            for i in range(len(labels)):
                suffix = '.'.join(labels[i:])
                if suffix in self._blocklist_suffix:
                    return True
        return False

    @staticmethod
    def load_blocklists_from_dir(directory: str) -> Tuple[Set[str], Set[str], Dict[str, Tuple[str, ...]]]:
        exact_set: Set[str] = set()
        suffix_set: Set[str] = set()
        hosts_map: Dict[str, Tuple[str, ...]] = {}
        if not os.path.isdir(directory):
            return exact_set, suffix_set, hosts_map
        for fname in os.listdir(directory):
            path = os.path.join(directory, fname)
            if not os.path.isfile(path):
                continue
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.split('#', 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) == 0:
                        continue
                    if len(parts) >= 2 and (parts[0].count('.') == 3 or ':' in parts[0]):
                        ip = parts[0]
                        domain = parts[1].lower().rstrip('.')
                        hosts_map[domain] = (ip,)
                        continue
                    domain = parts[0].lower().rstrip('.')
                    if domain.startswith('.'):
                        suffix_set.add(domain.lstrip('.'))
                    else:
                        exact_set.add(domain)
        return exact_set, suffix_set, hosts_map

    # ---------- Cache helpers ----------
    async def _wire_cache_get(self, key: Tuple[str, int, str]) -> Optional[Tuple[bytes, float, bytes, float, bool]]:
        try:
            if self._cache_is_sync:
                val = self._wire_cache.get(key)
                if val is None:
                    return None
                if isinstance(val, tuple):
                    if len(val) == 4:
                        a, b, c, d = val
                        return (a, b, c, d, False)
                    elif len(val) == 5:
                        return val
                return None
            else:
                val = await self._wire_cache.get(key)
                if val is None:
                    return None
                if isinstance(val, tuple):
                    if len(val) == 4:
                        a, b, c, d = val
                        return (a, b, c, d, False)
                    elif len(val) == 5:
                        return val
                return None
        except Exception as e:
            self.logger.debug("wire cache get error %s: %s", key, e)
            return None

    async def _wire_cache_set(self, key: Tuple[str, int, str],
                              value: Tuple[bytes, float, bytes, float, bool]) -> None:
        try:
            if self._cache_is_sync:
                self._wire_cache[key] = value
            else:
                await self._wire_cache.set(key, value)
        except Exception as e:
            self.logger.debug("wire cache set error %s: %s", key, e)

    async def _wire_cache_delete(self, key: Tuple[str, int, str]) -> None:
        try:
            if self._cache_is_sync:
                if key in self._wire_cache:
                    del self._wire_cache[key]
            else:
                await self._wire_cache.delete(key)
        except Exception:
            pass

    async def _wire_cache_get_valid(self, key: Tuple[str, int, str]) -> Optional[Tuple[bytes, bool]]:
        async with self._cache_lock:
            entry = await self._wire_cache_get(key)
            if entry is None:
                return None
            resp_bytes, expiry, query_data, stale_until, dnssec_validated = entry
            now = time.time()
            if now < expiry:
                return self._set_response_ttl(resp_bytes, max(0, int(expiry - now))), dnssec_validated
            if self.optimistic_cache_enabled and now < stale_until:
                self.logger.debug("serving stale response for %s (age=%.1fs)", key, now - expiry)
                stale_resp = self._set_response_ttl(resp_bytes, self.stale_response_ttl)
                asyncio.create_task(self._maybe_refresh_stale(key, query_data))
                return stale_resp, dnssec_validated
            await self._wire_cache_delete(key)
            return None

    async def _cache_get(self, key: Tuple[str, int, str]) -> Optional[str]:
        try:
            if self._cache_is_sync:
                return self._dns_cache.get(key)
            else:
                return await self._dns_cache.get(key)
        except Exception:
            return None

    async def _cache_set(self, key: Tuple[str, int, str], value: str) -> None:
        try:
            if self._cache_is_sync:
                self._dns_cache[key] = value
            else:
                await self._dns_cache.set(key, value)
        except Exception:
            pass

    async def _negative_cache_get(self, key: Tuple[str, int, str]) -> Optional[bytes]:
        try:
            if self._cache_is_sync:
                value = self._negative_cache.get(key)
            else:
                value = await self._negative_cache.get(key)
            if isinstance(value, tuple) and len(value) == 2:
                response, stored_at = value
                return self._decrement_response_ttls(response, max(0, int(time.time() - stored_at)))
            return value
        except Exception:
            return None

    async def _negative_cache_set(self, key: Tuple[str, int, str], value: bytes, ttl: Optional[int] = None) -> None:
        try:
            effective_ttl = self.negative_cache_ttl if ttl is None else int(ttl)
            if effective_ttl <= 0:
                return
            cache_value = (self._set_response_ttl(value, effective_ttl), time.time())
            if self._cache_is_sync:
                self._negative_cache[key] = cache_value
            else:
                await self._negative_cache.set(key, cache_value, ttl=effective_ttl)
        except Exception:
            pass

    async def _negative_cache_delete(self, key: Tuple[str, int, str]) -> None:
        try:
            if self._cache_is_sync:
                if key in self._negative_cache:
                    del self._negative_cache[key]
            else:
                await self._negative_cache.delete(key)
        except Exception:
            pass

    @staticmethod
    def _is_negative_response(response_bytes: bytes) -> bool:
        try:
            if not response_bytes or len(response_bytes) < 12 or not _HAS_DNSPY:
                return False
            msg = dns.message.from_wire(response_bytes)
            if msg.rcode() == dns.rcode.NXDOMAIN:
                return True
            if msg.rcode() != dns.rcode.NOERROR or msg.answer:
                return False
            has_soa = any(rrset.rdtype == dns.rdatatype.SOA for rrset in msg.authority)
            has_ns = any(rrset.rdtype == dns.rdatatype.NS for rrset in msg.authority)
            return has_soa or not has_ns
        except Exception:
            return False

    # ---------- stale refresh ----------
    async def _maybe_refresh_stale(self, key: Tuple[str, int, str], query_data: bytes) -> None:
        async with self._stale_refresh_lock:
            if key in self._stale_refresh_pending:
                return
            self._stale_refresh_pending.add(key)
        task = asyncio.create_task(self._background_refresh(key, query_data))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _background_refresh(self, key: Tuple[str, int, str], query_data: bytes) -> None:
        try:
            upstream_list = self.upstreams
            if not upstream_list:
                upstream_list = [{
                    'address': '1.1.1.1', 'protocol': 'udp', 'port': 53,
                    'hostname': '1.1.1.1', 'ip': '1.1.1.1'
                }]
            last_exc = None
            for upstream in upstream_list:
                try:
                    resp = await self._try_upstream(upstream, query_data)
                    dnssec_ok = False
                    if self.dnssec_enabled:
                        qname = key[0] if key[0] else None
                        if qname:
                            try:
                                secure, insecure = await self._dnssec_validate_chain(qname, resp)
                                if secure:
                                    dnssec_ok = True
                            except Exception as e:
                                self.logger.warning("DNSSEC validation failed for stale refresh %s: %s", key, e)
                                continue
                    ttl = self._extract_min_ttl(resp)
                    if ttl <= 0:
                        return
                    safe_response = self._cache_safe_response(resp)
                    if safe_response is None:
                        return
                    expiry = time.time() + ttl
                    stale_until = expiry + self.stale_max_age if self.optimistic_cache_enabled else expiry
                    val = (safe_response, expiry, query_data, stale_until, dnssec_ok)
                    async with self._cache_lock:
                        await self._wire_cache_set(key, val)
                    self.logger.debug("stale refresh succeeded for %s from %s", key, upstream['address'])
                    return
                except Exception as e:
                    last_exc = e
                    self.logger.debug("stale refresh upstream %s failed: %s", upstream['address'], e)
            self.logger.warning("stale refresh failed for %s: %s", key, last_exc)
        finally:
            async with self._stale_refresh_lock:
                self._stale_refresh_pending.discard(key)

    def _set_response_ttl(self, response_bytes: bytes, ttl: int) -> bytes:
        if _HAS_DNSPY:
            try:
                msg = dns.message.from_wire(response_bytes)
                def _replace_ttl(rrset_list):
                    new_list = []
                    for rrset in rrset_list:
                        if rrset.rdtype == dns.rdatatype.OPT:
                            new_list.append(rrset)
                            continue
                        new_rr = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                        new_rr.ttl = ttl
                        for rd in rrset:
                            new_rr.add(rd)
                        new_list.append(new_rr)
                    return new_list
                msg.answer = _replace_ttl(msg.answer)
                msg.authority = _replace_ttl(msg.authority)
                msg.additional = _replace_ttl(msg.additional)
                return msg.to_wire()
            except Exception as e:
                self.logger.debug("_set_response_ttl failed: %s", e)
        return response_bytes

    @staticmethod
    def _set_query_id(response_bytes: bytes, new_id: int) -> bytes:
        if len(response_bytes) < 2:
            return response_bytes
        return new_id.to_bytes(2, 'big') + response_bytes[2:]

    # ---------- IPv6 stripping ----------
    def _strip_ipv6_records(self, response_bytes: bytes) -> bytes:
        if not self.strip_ipv6_records:
            return response_bytes
        try:
            msg = dns.message.from_wire(response_bytes)
            msg.answer = [rrset for rrset in msg.answer if rrset.rdtype != dns.rdatatype.AAAA]
            msg.additional = [rrset for rrset in msg.additional if rrset.rdtype != dns.rdatatype.AAAA]
            return msg.to_wire()
        except Exception:
            return response_bytes

    def _strip_dnssec_records(self, response_bytes: bytes, qname: Any,
                              qtype: int) -> bytes:
        try:
            message = dns.message.from_wire(response_bytes)
            dnssec_types = {
                dns.rdatatype.DS, dns.rdatatype.RRSIG, dns.rdatatype.NSEC,
                dns.rdatatype.DNSKEY, dns.rdatatype.NSEC3, dns.rdatatype.DLV,
                dns.rdatatype.CDS, dns.rdatatype.CDNSKEY,
            }

            def filter_section(section):
                return [rrset for rrset in section
                        if rrset.rdtype not in dnssec_types
                        or (rrset.name == qname and rrset.rdtype == qtype)]

            message.answer = filter_section(message.answer)
            message.authority = filter_section(message.authority)
            message.additional = filter_section(message.additional)
            if message.edns >= 0:
                message.ednsflags &= ~dns.flags.DO
            return message.to_wire()
        except Exception as e:
            self.logger.debug("DNSSEC record filtering failed: %s", e)
            return response_bytes

    def _normalize_response_edns(self, response_bytes: bytes,
                                 request: Any,
                                 client_requested_do: bool) -> bytes:
        try:
            response = dns.message.from_wire(response_bytes)
            if request.edns < 0:
                response.use_edns(edns=None)
                return response.to_wire()

            request_used_ecs = any(
                option.otype == dns.edns.ECS for option in request.options
            )
            options = [
                option for option in response.options
                if request_used_ecs or option.otype != dns.edns.ECS
            ]
            ednsflags = response.ednsflags
            response_rcode = response.rcode()
            if client_requested_do:
                ednsflags |= dns.flags.DO
            else:
                ednsflags &= ~dns.flags.DO
            response_edns = response.edns if response.edns >= 0 else 0
            response.use_edns(
                edns=response_edns,
                ednsflags=ednsflags,
                payload=request.payload,
                options=options,
            )
            response.set_rcode(response_rcode)
            return response.to_wire()
        except Exception as e:
            self.logger.debug("Response EDNS normalization failed: %s", e)
            return response_bytes

    @staticmethod
    def _parse_http_age(value: Any) -> int:
        if isinstance(value, bytes):
            value = value.decode("ascii", errors="ignore")
        if not isinstance(value, str):
            return 0
        value = value.strip()
        if not value.isascii() or not value.isdigit():
            return 0
        return int(value)

    def _apply_doh_age(self, response_bytes: bytes, age: int) -> bytes:
        return self._decrement_response_ttls(response_bytes, age)

    def _decrement_response_ttls(self, response_bytes: bytes, elapsed: int) -> bytes:
        if elapsed <= 0:
            return response_bytes
        try:
            message = dns.message.from_wire(response_bytes)
            for section in (message.answer, message.authority, message.additional):
                for rrset in section:
                    if rrset.rdtype != dns.rdatatype.OPT:
                        rrset.ttl = max(0, rrset.ttl - elapsed)
            return message.to_wire()
        except Exception as exc:
            self.logger.debug("Could not decrement DNS TTLs: %s", exc)
            return response_bytes

    def _cache_safe_response(self, response_bytes: bytes) -> Optional[bytes]:
        try:
            message = dns.message.from_wire(response_bytes)
            if any(option.otype != dns.edns.ECS for option in message.options):
                return None
            if message.edns >= 0:
                message.use_edns(edns=None)
            return message.to_wire()
        except Exception:
            return None

    # ---------- parsing helpers ----------
    @staticmethod
    def _parse_dns_name(packet: bytes, offset: int, max_depth: int = 20, _depth: int = 0) -> Tuple[str, int]:
        labels = []
        while True:
            if offset >= len(packet):
                raise ValueError("Out of bounds while parsing DNS name")
            length = packet[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(packet):
                    raise ValueError("Truncated pointer")
                pointer = ((length & 0x3F) << 8) | packet[offset + 1]
                if pointer >= len(packet):
                    raise ValueError("Pointer out of bounds")
                if _depth >= max_depth:
                    raise ValueError("Pointer loop detected")
                recursive_label, _ = DNSResolver._parse_dns_name(packet, pointer, max_depth, _depth + 1)
                labels.append(recursive_label)
                offset += 2
                break
            if offset + 1 + length > len(packet):
                raise ValueError("Label extends past packet")
            labels.append(packet[offset + 1:offset + 1 + length].decode('ascii', errors='ignore'))
            offset += 1 + length
        name = '.'.join(labels)
        return name, offset

    def _extract_qname_from_wire(self, data: bytes) -> Optional[str]:
        try:
            if not data or len(data) < 12:
                return None
            qname, _ = self._parse_dns_name(data, 12)
            return qname
        except Exception:
            return None

    def _extract_qtype_from_wire(self, data: bytes) -> Optional[int]:
        try:
            if not data or len(data) < 12:
                return None
            _, off = self._parse_dns_name(data, 12)
            if off + 4 > len(data):
                return None
            qtype = (data[off] << 8) | data[off+1]
            return qtype
        except Exception:
            return None

    def _extract_question_section(self, packet: bytes) -> Tuple[bytes, int, int]:
        if not packet or len(packet) < 12:
            return b'', 0, 12
        qdcount = (packet[4] << 8) | packet[5]
        offset = 12
        for _ in range(qdcount):
            _, offset = self._parse_dns_name(packet, offset)
            offset += 4
            if offset > len(packet):
                raise ValueError("Truncated question section")
        return packet[12:offset], qdcount, offset

    def _extract_additional_section(self, packet: bytes, question_end: int) -> Tuple[bytes, int]:
        if not packet or len(packet) < 12 or question_end > len(packet):
            return b'', 0
        arcount = (packet[10] << 8) | packet[11]
        if arcount == 0:
            return b'', 0
        return packet[question_end:], arcount

    def _build_cache_key(self, data: bytes) -> Tuple[str, int, str, bytes]:
        qname = self._extract_qname_from_wire(data) or ""
        qtype = self._extract_qtype_from_wire(data) or 1
        try:
            _, _, question_end = self._extract_question_section(data)
            opt_bytes = data[question_end:]
        except Exception:
            opt_bytes = b''
        return (qname, qtype, 'unknown', opt_bytes)

    def _strip_ecs(self, data: bytes) -> bytes:
        try:
            if not _HAS_DNSPY:
                return data
            msg = dns.message.from_wire(data)
            if msg.opt is None:
                return data
            options = [opt for opt in msg.options if not isinstance(opt, dns.edns.ECSOption)]
            if len(options) == len(msg.options):
                return data
            msg.use_edns(edns=msg.edns, payload=msg.payload, options=options)
            return msg.to_wire()
        except Exception:
            return data

    def _normalize_query_for_forward(self, data: bytes) -> bytes:
        if not self.ecs_enabled:
            data = self._strip_ecs(data)
        return data

    def _make_servfail_response(self, query_data: bytes) -> bytes:
        try:
            msg = dns.message.from_wire(query_data)
            resp = dns.message.make_response(msg)
            resp.set_rcode(dns.rcode.SERVFAIL)
            return resp.to_wire()
        except Exception:
            try:
                qid = 0
                if isinstance(query_data, (bytes, bytearray)) and len(query_data) >= 2:
                    qid = (query_data[0] << 8) | query_data[1]
                resp = dns.message.Message(id=qid)
                resp.set_rcode(dns.rcode.SERVFAIL)
                return resp.to_wire()
            except Exception:
                return b""

    # ---------- Trust anchor management ----------
    def _fetch_root_trust_anchor_from_iana(self) -> Optional[str]:
        try:
            with urllib.request.urlopen("https://data.iana.org/root-anchors/root-anchors.xml", timeout=10) as response:
                xml_data = response.read()
            root = ET.fromstring(xml_data)
            for child in root:
                if child.tag == "KeyDigest":
                    key_tag = child.attrib.get("keyTag")
                    algo = child.attrib.get("algorithm")
                    digest_type = child.attrib.get("digestType")
                    digest = child.text.strip()
                    if key_tag and algo and digest_type and digest:
                        return f"{key_tag} {algo} {digest_type} {digest}"
            return None
        except Exception as e:
            self.logger.warning("Failed to fetch root trust anchor from IANA: %s", e)
            return None

    def _load_trust_anchors(self) -> None:
        if not self.dnssec_enabled:
            return
        anchors: Dict[dns.name.Name, dns.rrset.RRset] = {}

        if self.trust_anchors is None:
            try:
                parts = DEFAULT_ROOT_DNSKEY.split()
                name = parts[0]
                ttl = int(parts[1])
                rdclass = parts[2]
                rdtype = parts[3]
                rdata = ' '.join(parts[4:])
                rr = dns.rrset.from_text(name, ttl, rdclass, rdtype, rdata)
                if self.dnssec_max_dnskey_records == 0:
                    self.logger.warning("dnssec_max_dnskey_records is 0, not loading any DNSKEYs")
                    anchors = {}
                else:
                    count = 0
                    limited_rr = dns.rrset.RRset(rr.name, rr.rdclass, rr.rdtype)
                    limited_rr.ttl = rr.ttl
                    for r in rr:
                        if count >= self.dnssec_max_dnskey_records:
                            self.logger.warning("DNSKEY limit (%d) reached for built-in root anchor, truncating",
                                                self.dnssec_max_dnskey_records)
                            break
                        limited_rr.add(r)
                        count += 1
                    anchors[dns.name.root] = limited_rr
                self.logger.info("Using bundled default root trust anchor (limited to %d DNSKEYs)",
                                 self.dnssec_max_dnskey_records)
            except Exception as e:
                self.logger.error("Failed to parse default root trust anchor: %s", e)
                return

        elif isinstance(self.trust_anchors, str):
            path = self.trust_anchors
            try:
                with open(path, 'r') as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or line.startswith('#') or line.startswith(';'):
                            continue
                        parts = line.split()
                        if len(parts) < 5:
                            self.logger.debug("skipping malformed anchor line: %s", line)
                            continue
                        try:
                            idx = parts.index('DNSKEY')
                        except ValueError:
                            try:
                                idx = parts.index('dnskey')
                            except ValueError:
                                self.logger.debug("no DNSKEY token in line: %s", line)
                                continue
                        if idx < 1:
                            self.logger.debug("unexpected DNSKEY line format: %s", line)
                            continue
                        name_text = parts[0]
                        ttl_text = parts[1] if idx >= 2 else '3600'
                        try:
                            ttl = int(ttl_text)
                        except Exception:
                            ttl = 3600
                        rdata_text = ' '.join(parts[idx+1:])
                        try:
                            rr = dns.rrset.from_text(name_text, ttl, 'IN', 'DNSKEY', rdata_text)
                            name_obj = dns.name.from_text(name_text)
                            if self.dnssec_max_dnskey_records == 0:
                                self.logger.debug("Skipping DNSKEY for %s due to limit 0", name_text)
                                continue
                            if name_obj in anchors:
                                current_count = len(anchors[name_obj])
                                for r in rr:
                                    if current_count >= self.dnssec_max_dnskey_records:
                                        self.logger.warning("DNSKEY limit (%d) reached for %s, truncating",
                                                            self.dnssec_max_dnskey_records, name_text)
                                        break
                                    anchors[name_obj].add(r)
                                    current_count += 1
                            else:
                                new_rr = dns.rrset.RRset(name_obj, rr.rdclass, rr.rdtype)
                                new_rr.ttl = rr.ttl
                                count = 0
                                for r in rr:
                                    if count >= self.dnssec_max_dnskey_records:
                                        self.logger.warning("DNSKEY limit (%d) reached for %s, truncating",
                                                            self.dnssec_max_dnskey_records, name_text)
                                        break
                                    new_rr.add(r)
                                    count += 1
                                anchors[name_obj] = new_rr
                        except Exception as e:
                            self.logger.debug("failed to parse anchor line '%s': %s", line, e)
                            continue
                self.logger.info("Loaded trust anchors from file: %s (limited to %d DNSKEYs per domain)",
                                 path, self.dnssec_max_dnskey_records)
            except Exception as e:
                self.logger.warning("failed to load trust anchors from %s: %s", path, e)
                return

        elif isinstance(self.trust_anchors, dict):
            anchors = self.trust_anchors
            if self.dnssec_max_dnskey_records == 0:
                self.logger.warning("dnssec_max_dnskey_records is 0, not using any trust anchors")
                anchors = {}
            else:
                for name, rrset in list(anchors.items()):
                    if len(rrset) > self.dnssec_max_dnskey_records:
                        new_rr = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                        new_rr.ttl = rrset.ttl
                        count = 0
                        for r in rrset:
                            if count >= self.dnssec_max_dnskey_records:
                                break
                            new_rr.add(r)
                            count += 1
                        anchors[name] = new_rr
                        self.logger.debug("Truncated DNSKEY RRset for %s to %d records",
                                          name, self.dnssec_max_dnskey_records)
            self.logger.info("Using provided trust anchors dict (limited to %d DNSKEYs per domain)",
                             self.dnssec_max_dnskey_records)

        else:
            self.logger.warning("Unsupported trust_anchors type: %s", type(self.trust_anchors))
            return

        self._dnssec_raw_anchors = anchors
        self._dnssec_keyring = None

    async def _update_trust_anchor_from_iana(self) -> bool:
        if not self.dnssec_enabled:
            return False
        async with self._trust_anchor_lock:
            ds_text = await asyncio.get_running_loop().run_in_executor(None, self._fetch_root_trust_anchor_from_iana)
            if ds_text is None:
                return False
            try:
                ds_rrset = dns.rrset.from_text(".", 0, "IN", "DS", ds_text)
                root_dnskey_msg = await self._dnssec_lookup(".", dns.rdatatype.DNSKEY, dnssec_ok=True)
                if root_dnskey_msg is None:
                    self.logger.warning("Failed to fetch root DNSKEY from DNS during trust-anchor update")
                    return False
                dnskey_rrset = None
                for rrset in root_dnskey_msg.answer:
                    if rrset.rdtype == dns.rdatatype.DNSKEY:
                        dnskey_rrset = rrset
                        break
                if dnskey_rrset is None:
                    self.logger.warning("No DNSKEY RRset in root response during trust-anchor update")
                    return False
                try:
                    dns.dnssec.validate_keys(dnskey_rrset, ds_rrset)
                except dns.dnssec.ValidationFailure as e:
                    self.logger.warning("DNSKEY validation against new DS failed: %s", e)
                    return False
                if self.dnssec_max_dnskey_records > 0:
                    limited_rrset = dns.rrset.RRset(dnskey_rrset.name, dnskey_rrset.rdclass, dnskey_rrset.rdtype)
                    limited_rrset.ttl = dnskey_rrset.ttl
                    count = 0
                    for r in dnskey_rrset:
                        if count >= self.dnssec_max_dnskey_records:
                            break
                        limited_rrset.add(r)
                        count += 1
                    dnskey_rrset = limited_rrset
                self._dnssec_raw_anchors = {dns.name.root: dnskey_rrset}
                self._dnssec_keyring = None
                self.logger.info("Updated root trust anchor from IANA: validated %d DNSKEY records",
                                 len(dnskey_rrset))
                return True
            except Exception as e:
                self.logger.warning("Failed to update trust anchor from IANA: %s", e)
                return False

    async def _background_trust_anchor_updater(self) -> None:
        await asyncio.sleep(random.randint(300, 900))
        while True:
            try:
                updated = await self._update_trust_anchor_from_iana()
                if updated:
                    self.logger.info("Trust anchor updated from IANA")
            except Exception as e:
                self.logger.warning("Background trust anchor update failed: %s", e)
            await asyncio.sleep(86400)

    # ---------- Insecure cache cleanup ----------
    async def _cleanup_insecure_cache(self) -> None:
        while True:
            await asyncio.sleep(self._dnssec_insecure_cache_ttl / 2)
            now = time.time()
            async with self._dnssec_cache_lock:
                for zone, expiry in list(self._dnssec_insecure_cache.items()):
                    if now >= expiry:
                        del self._dnssec_insecure_cache[zone]

    # ---------- DNSSEC chain validation core ----------
    async def _dnssec_lookup(self, qname: str, rdtype: int, dnssec_ok: bool = False) -> Optional[dns.message.Message]:
        data = dns.message.make_query(qname, rdtype, want_dnssec=dnssec_ok).to_wire()
        upstream_list = list(self.upstreams) if self.upstreams else []
        if not upstream_list:
            upstream_list = [{'address': '1.1.1.1', 'protocol': 'udp', 'port': 53, 'hostname': '1.1.1.1', 'ip': '1.1.1.1'}]
        for upstream in upstream_list:
            try:
                resp_bytes = await self._try_upstream(upstream, data, _health_check=False, _no_retry=True)
                try:
                    return dns.message.from_wire(resp_bytes)
                except Exception:
                    self.logger.debug("Malformed upstream response during DNSSEC lookup for %s from %s", qname, upstream.get('address'))
                    continue
            except Exception:
                continue
        return None


    def _nsec3_hash(self, name: str, salt: bytes, iterations: int, algorithm: int) -> Optional[str]:
        """Return base32-encoded NSEC3 hash (lowercase, no padding)."""
        if algorithm != 1:
            self.logger.warning("Unsupported NSEC3 algorithm: %d", algorithm)
            return None
        if iterations > MAX_NSEC3_ITERATIONS:
            self.logger.warning("NSEC3 iterations (%d) exceed safe limit", iterations)
            return None
        try:
            name_wire = dns.name.from_text(name).to_wire()
        except Exception:
            name_wire = name.lower().encode('utf-8')
        digest = hashlib.sha1(name_wire + salt).digest()
        for _ in range(iterations):
            digest = hashlib.sha1(digest + salt).digest()
        # base32 encode without padding, lowercase
        b32 = base64.b32hexencode(digest).decode().lower().rstrip('=')
        return b32

    @staticmethod
    def _nsec3_bitmap_contains(windows: Tuple[Tuple[int, bytes], ...], rdtype: int) -> bool:
        for window, bitmap in windows:
            if window == rdtype >> 8:
                offset = rdtype & 0xFF
                byte_idx = offset >> 3
                bit_mask = 1 << (offset & 0x07)
                if byte_idx < len(bitmap):
                    if bitmap[byte_idx] & bit_mask:
                        return True
        return False

    @staticmethod
    def _rrsig_for(rrset: dns.rrset.RRset, sections: Iterable[Iterable[dns.rrset.RRset]]) -> Optional[dns.rrset.RRset]:
        signatures = dns.rrset.RRset(rrset.name, rrset.rdclass, dns.rdatatype.RRSIG)
        found = False
        for section in sections:
            for candidate in section:
                if candidate.rdtype != dns.rdatatype.RRSIG or candidate.name != rrset.name:
                    continue
                for signature in candidate:
                    if signature.type_covered == rrset.rdtype:
                        signatures.add(signature)
                        found = True
        return signatures if found else None

    @staticmethod
    def _cache_insecure_delegation(cache: Dict[str, float], zone: str) -> bool:
        expiry = cache.get(zone)
        return expiry is not None and time.time() < expiry

    async def _is_proven_insecure_name(self, qname: str) -> bool:
        name = dns.name.from_text(qname)
        for offset in range(len(name.labels) - 1):
            candidate = dns.name.Name(name.labels[offset:]).to_text().rstrip('.')
            await self._get_validated_dnskey(candidate)
            if self._cache_insecure_delegation(self._dnssec_insecure_cache, candidate):
                return True
        return False

    async def _get_validated_dnskey(self, zone: str, _depth: int = 0) -> Optional[dns.rrset.RRset]:
        if _depth > self.dnssec_max_iterations:
            self.logger.warning("DNSSEC chain depth exceeded limit (%d) for zone %s", self.dnssec_max_iterations, zone)
            return None

        cache_key = zone
        async with self._dnssec_cache_lock:
            if cache_key in self._dnssec_key_cache:
                key_rrset, expiry = self._dnssec_key_cache[cache_key]
                if time.time() < expiry:
                    return key_rrset
                else:
                    del self._dnssec_key_cache[cache_key]

        if zone == "." or zone == "":
            if self._dnssec_raw_anchors and dns.name.root in self._dnssec_raw_anchors:
                return self._dnssec_raw_anchors[dns.name.root]
            return None

        parent_zone = ".".join(zone.split(".")[1:]) or "."
        parent_key = await self._get_validated_dnskey(parent_zone, _depth + 1)
        if parent_key is None:
            if self._cache_insecure_delegation(self._dnssec_insecure_cache, parent_zone):
                async with self._dnssec_cache_lock:
                    self._dnssec_insecure_cache[zone] = time.time() + self._dnssec_insecure_cache_ttl
            return None

        parent_ds = await self._get_ds_for_zone(zone, parent_zone, _depth + 1, parent_key)
        if parent_ds is None:
            return None

        dnskey_result = await self._fetch_dnskey_response(zone)
        if dnskey_result is None:
            return None
        child_dnskey, dnskey_msg = dnskey_result

        matched_keys = dns.rrset.RRset(child_dnskey.name, child_dnskey.rdclass, child_dnskey.rdtype)
        matched_keys.ttl = child_dnskey.ttl
        zone_name = dns.name.from_text(zone)
        for ds_rr in parent_ds:
            for key_rr in child_dnskey:
                if not key_rr.flags & 0x0100 or ds_rr.algorithm != key_rr.algorithm:
                    continue
                if ds_rr.key_tag != dns.dnssec.key_id(key_rr):
                    continue
                try:
                    candidate = dns.dnssec.make_ds(zone_name, key_rr, ds_rr.digest_type)
                except Exception:
                    continue
                if candidate.digest == ds_rr.digest:
                    matched_keys.add(key_rr)

        if not len(matched_keys):
            self.logger.debug("DS mismatch for zone %s", zone)
            return None

        signatures = self._rrsig_for(
            child_dnskey,
            (dnskey_msg.answer, dnskey_msg.authority, dnskey_msg.additional),
        )
        if signatures is None:
            return None
        try:
            dns.dnssec.validate(child_dnskey, signatures, {zone_name: matched_keys})
        except Exception as exc:
            self.logger.warning("DNSKEY RRset validation failed for %s: %s", zone, exc)
            return None

        ttl = min(child_dnskey.ttl, parent_ds.ttl)
        async with self._dnssec_cache_lock:
            if len(self._dnssec_key_cache) >= self._dnssec_key_cache_maxsize:
                oldest = min(self._dnssec_key_cache.items(), key=lambda kv: kv[1][1])[0]
                del self._dnssec_key_cache[oldest]
            self._dnssec_key_cache[zone] = (child_dnskey, time.time() + ttl)
        return child_dnskey

    async def _get_ds_for_zone(self, zone: str, parent_zone: str, _depth: int = 0,
                               parent_key: Optional[dns.rrset.RRset] = None) -> Optional[dns.rrset.RRset]:
        if _depth > self.dnssec_max_iterations:
            self.logger.warning("DNSSEC chain depth exceeded limit (%d) for DS zone %s", self.dnssec_max_iterations, zone)
            return None

        cache_key = f"DS:{zone}"
        async with self._dnssec_cache_lock:
            if cache_key in self._dnssec_ds_cache:
                ds_rrset, expiry = self._dnssec_ds_cache[cache_key]
                if time.time() < expiry:
                    return ds_rrset
                else:
                    del self._dnssec_ds_cache[cache_key]

        msg = await self._dnssec_lookup(zone, dns.rdatatype.DS, dnssec_ok=True)
        if msg is None:
            return None

        ds_rrset = None
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.DS:
                ds_rrset = rrset
                break

        if ds_rrset is None:
            if parent_key is not None and await self._prove_insecure_delegation(
                zone, parent_zone, msg, parent_key
            ):
                async with self._dnssec_cache_lock:
                    self._dnssec_insecure_cache[zone] = time.time() + self._dnssec_insecure_cache_ttl
            return None

        if parent_key is None:
            parent_key = await self._get_validated_dnskey(parent_zone, _depth + 1)
        signatures = self._rrsig_for(ds_rrset, (msg.answer, msg.authority, msg.additional))
        if parent_key is None or signatures is None:
            return None
        try:
            dns.dnssec.validate(
                ds_rrset,
                signatures,
                {dns.name.from_text(parent_zone): parent_key},
            )
        except Exception as exc:
            self.logger.warning("DS RRset validation failed for %s: %s", zone, exc)
            return None

        ttl = ds_rrset.ttl if ds_rrset else 300
        async with self._dnssec_cache_lock:
            if len(self._dnssec_ds_cache) >= self._dnssec_ds_cache_maxsize:
                oldest = min(self._dnssec_ds_cache.items(), key=lambda kv: kv[1][1])[0]
                del self._dnssec_ds_cache[oldest]
            self._dnssec_ds_cache[cache_key] = (ds_rrset, time.time() + ttl)
        return ds_rrset

    async def _fetch_dnskey_response(self, zone: str) -> Optional[Tuple[dns.rrset.RRset, dns.message.Message]]:
        msg = await self._dnssec_lookup(zone, dns.rdatatype.DNSKEY, dnssec_ok=True)
        if msg is None:
            return None
        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                if self.dnssec_max_dnskey_records > 0 and len(rrset) > self.dnssec_max_dnskey_records:
                    self.logger.warning("DNSKEY RRset for %s exceeds configured limit", zone)
                    return None
                return rrset, msg
        return None

    async def _fetch_dnskey(self, zone: str) -> Optional[dns.rrset.RRset]:
        result = await self._fetch_dnskey_response(zone)
        return result[0] if result is not None else None

    async def _prove_insecure_delegation(self, zone: str, parent_zone: str,
                                         msg: Optional[dns.message.Message] = None,
                                         parent_key: Optional[dns.rrset.RRset] = None) -> bool:
        if self._cache_insecure_delegation(self._dnssec_insecure_cache, zone):
            return True
        if msg is None:
            msg = await self._dnssec_lookup(zone, dns.rdatatype.DS, dnssec_ok=True)
        if msg is None:
            return False

        delegation_ns = any(
            rrset.rdtype == dns.rdatatype.NS and rrset.name == dns.name.from_text(zone)
            for section in (msg.answer, msg.authority)
            for rrset in section
        )
        if not delegation_ns:
            return False
        if parent_key is None:
            parent_key = await self._get_validated_dnskey(parent_zone)
        if parent_key is None:
            return False

        sections = (msg.answer, msg.authority, msg.additional)
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.NSEC and rrset.name == dns.name.from_text(zone):
                signatures = self._rrsig_for(rrset, sections)
                if signatures is None:
                    continue
                try:
                    dns.dnssec.validate(rrset, signatures, {dns.name.from_text(parent_zone): parent_key})
                except Exception:
                    continue
                if (self._nsec3_bitmap_contains(rrset[0].windows, dns.rdatatype.NS)
                    and not self._nsec3_bitmap_contains(rrset[0].windows, dns.rdatatype.DS)):
                    return True

        nsec3_rrsets = []
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.NSEC3:
                nsec3_rrsets.append(rrset)

        if not nsec3_rrsets:
            return False

        for rrset in nsec3_rrsets:
            signatures = self._rrsig_for(rrset, sections)
            if signatures is None:
                return False
            try:
                dns.dnssec.validate(rrset, signatures, {dns.name.from_text(parent_zone): parent_key})
            except Exception:
                return False

        nsec3_rrsets.sort(key=lambda rrset: str(rrset.name).lower())

        first_rrset = nsec3_rrsets[0]
        first_rr = first_rrset[0]
        salt = first_rr.salt
        iterations = first_rr.iterations
        algorithm = first_rr.algorithm

        zone_hash = self._nsec3_hash(zone, salt, iterations, algorithm)
        if zone_hash is None:
            return False

        for idx, rrset in enumerate(nsec3_rrsets):
            for rr in rrset:
                rr_name = str(rrset.name).lower().rstrip('.')
                hash_part = rr_name.split('.')[0]
                next_hash = base64.b32hexencode(rr.next).decode().lower().rstrip('=')

                if hash_part <= zone_hash < next_hash:
                    if rr.flags & NSEC3_OPT_OUT:
                        if not self._nsec3_bitmap_contains(rr.windows, dns.rdatatype.DS):
                            return True
                    return False

                if idx == len(nsec3_rrsets) - 1:
                    first_hash = str(nsec3_rrsets[0].name).lower().split('.')[0]
                    if zone_hash >= hash_part and zone_hash < first_hash:
                        if rr.flags & NSEC3_OPT_OUT:
                            if not self._nsec3_bitmap_contains(rr.windows, dns.rdatatype.DS):
                                return True
                        return False

        return False

    # ---------- Full NSEC3 negative validation (RFC 5155) ----------
    async def _validate_nsec3_negative(self, qname: str, msg: dns.message.Message) -> bool:
        """
        Validate a negative answer (NXDOMAIN or NODATA) using NSEC3 records.
        Implements closest-encloser, next-closer, and type-bitmap check per RFC 5155.
        """
        if msg.rcode() != dns.rcode.NXDOMAIN and not (msg.rcode() == dns.rcode.NOERROR and not msg.answer):
            return False

        # Find NSEC3 RRsets and their RRSIGs in authority
        nsec3_rrsets = []
        nsec3_sigs: Dict[dns.name.Name, dns.rrset.RRset] = {}
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.NSEC3:
                nsec3_rrsets.append(rrset)
            elif rrset.rdtype == dns.rdatatype.RRSIG and any(r.type_covered == dns.rdatatype.NSEC3 for r in rrset):
                existing = nsec3_sigs.get(rrset.name)
                if existing is None:
                    nsec3_sigs[rrset.name] = rrset
                else:
                    for r in rrset:
                        existing.add(r)
        if not nsec3_rrsets or not nsec3_sigs:
            return False

        # Validate signatures for each NSEC3 RRset by owner name
        try:
            for rrset in nsec3_rrsets:
                sig_rrset = nsec3_sigs.get(rrset.name)
                if sig_rrset is None:
                    return False

                validated = False
                last_exc = None
                for sig in sig_rrset:
                    if sig.type_covered != dns.rdatatype.NSEC3:
                        continue

                    signer = str(sig.signer).lower().rstrip('.')
                    signer_name_obj = dns.name.from_text(signer)
                    key_rrset = await self._get_validated_dnskey(signer)
                    if key_rrset is None:
                        if signer in ('.', '') and self._dnssec_raw_anchors and dns.name.root in self._dnssec_raw_anchors:
                            key_rrset = self._dnssec_raw_anchors[dns.name.root]
                    if key_rrset is None:
                        continue

                    try:
                        dns.dnssec.validate_rrsig(rrset, sig, {signer_name_obj: key_rrset})
                        validated = True
                        break
                    except dns.dnssec.ValidationFailure as exc:
                        last_exc = exc
                        continue

                if not validated:
                    if last_exc is not None:
                        raise last_exc
                    return False
        except dns.dnssec.ValidationFailure:
            return False

        first_rr = nsec3_rrsets[0][0]
        salt = first_rr.salt
        iterations = first_rr.iterations
        algorithm = first_rr.algorithm

        qname_obj = dns.name.from_text(qname)
        qname_hash = self._nsec3_hash(str(qname_obj), salt, iterations, algorithm)
        if qname_hash is None:
            return False

        # Sort NSEC3 RRsets by hash order and index exact hashes.
        sorted_nsec3 = []
        hash_to_rr: Dict[str, Tuple[str, str, dns.rdtypes.ANY.NSEC3.NSEC3, dns.rrset.RRset]] = {}
        for rrset in nsec3_rrsets:
            for rr in rrset:
                rr_name = str(rrset.name).lower().rstrip('.')
                hash_part = rr_name.split('.')[0]
                next_hash = base64.b32hexencode(rr.next).decode().lower().rstrip('=')
                entry = (hash_part, next_hash, rr, rrset)
                sorted_nsec3.append(entry)
                hash_to_rr[hash_part] = entry
        sorted_nsec3.sort(key=lambda x: x[0])

        def find_cover(hash_value: str):
            if not sorted_nsec3:
                return None
            for idx, (hash_part, next_hash, rr, rrset) in enumerate(sorted_nsec3):
                if hash_part <= hash_value < next_hash:
                    return hash_part, next_hash, rr, rrset
                if idx == len(sorted_nsec3) - 1:
                    first_hash = sorted_nsec3[0][0]
                    if hash_part <= hash_value or hash_value < first_hash:
                        return hash_part, next_hash, rr, rrset
            return None

        def find_closest_encloser():
            labels = qname_obj.labels
            for i in range(1, len(labels)):
                candidate = dns.name.Name(labels[i:])
                candidate_hash = self._nsec3_hash(str(candidate), salt, iterations, algorithm)
                exact = hash_to_rr.get(candidate_hash)
                if exact is not None:
                    return candidate, exact
            return None, None

        def next_closer_name(closest_encloser: dns.name.Name) -> Optional[dns.name.Name]:
            ce_len = len(closest_encloser.labels)
            q_len = len(qname_obj.labels)
            if ce_len >= q_len:
                return None
            cut = q_len - ce_len - 1
            return dns.name.Name(qname_obj.labels[cut:])

        def wildcard_name_for_closest_encloser(closest_encloser: dns.name.Name) -> dns.name.Name:
            return dns.name.Name([b'*'] + list(closest_encloser.labels))

        def validate_wildcard_nonexistence():
            closest_encloser, closest_rr = find_closest_encloser()
            if closest_encloser is None or closest_rr is None:
                return False
            next_closer = next_closer_name(closest_encloser)
            if next_closer is None:
                return False
            next_closer_hash = self._nsec3_hash(str(next_closer), salt, iterations, algorithm)
            if find_cover(next_closer_hash) is None:
                return False
            wildcard_name = wildcard_name_for_closest_encloser(closest_encloser)
            wildcard_hash = self._nsec3_hash(str(wildcard_name), salt, iterations, algorithm)
            if find_cover(wildcard_hash) is None:
                return False
            return True

        if msg.rcode() == dns.rcode.NXDOMAIN:
            # qname itself must not exist.
            if qname_hash in hash_to_rr:
                return False

            return validate_wildcard_nonexistence()

        exact_match = hash_to_rr.get(qname_hash)
        if exact_match is None:
            if msg.rcode() == dns.rcode.NOERROR and not msg.answer:
                return validate_wildcard_nonexistence()
            return False
        if exact_match is None:
            return False

        if not msg.question:
            return False
        qtype = msg.question[0].rdtype
        if self._nsec3_bitmap_contains(exact_match[2].windows, qtype):
            return False
        return True

    async def _dnssec_validate_chain(self, qname: str, response_wire: bytes, dnssec_requested: bool = True) -> Tuple[bool, bool]:
        if not self.dnssec_enabled:
            return False, True
        if not _HAS_DNSPY:
            raise RuntimeError("dnspython required")
        if not dnssec_requested:
            return False, True

        if self._dnssec_raw_anchors is None:
            self._load_trust_anchors()
        if not self._dnssec_raw_anchors:
            raise Exception("DNSSEC trust anchors missing")

        try:
            return await asyncio.wait_for(
                self._dnssec_validate_chain_internal(qname, response_wire, dnssec_requested),
                timeout=self.dnssec_validation_timeout
            )
        except asyncio.TimeoutError:
            self.logger.warning("DNSSEC chain validation timeout for %s after %.1fs", qname, self.dnssec_validation_timeout)
            return False, False

    async def _dnssec_validate_chain_internal(self, qname: str, response_wire: bytes, dnssec_requested: bool = True) -> Tuple[bool, bool]:
        try:
            msg = dns.message.from_wire(response_wire)
        except Exception as e:
            self.logger.warning("Malformed DNS response during DNSSEC validation for %s: %s", qname, e)
            return False, False
        # Check if this is a negative answer (NXDOMAIN or NODATA)
        is_negative = (msg.rcode() == dns.rcode.NXDOMAIN or
                       (msg.rcode() == dns.rcode.NOERROR and not msg.answer))

        if is_negative:
            if await self._validate_nsec3_negative(qname, msg):
                self.logger.debug("NSEC3 negative validation passed for %s", qname)
                return True, False
            return False, await self._is_proven_insecure_name(qname)

        # Positive answer: validate signatures
        has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in msg.answer)
        if not has_rrsig:
            return False, await self._is_proven_insecure_name(qname)

        validation_counter = 0
        max_validations = self.dnssec_max_validations if self.dnssec_max_validations > 0 else 999999
        loop = asyncio.get_running_loop()

        for rrset in msg.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue

            sig_rdata = None
            for rr in msg.answer:
                if rr.rdtype == dns.rdatatype.RRSIG and rr.name == rrset.name:
                    for r in rr:
                        if r.type_covered == rrset.rdtype:
                            sig_rdata = r
                            break
                    if sig_rdata:
                        break

            if sig_rdata is None:
                raise dns.dnssec.ValidationFailure(f"No RRSIG for rrset {rrset.name}")

            signer_name = str(sig_rdata.signer).lower().rstrip('.')
            signer_name_obj = dns.name.from_text(signer_name)

            key_rrset = await self._get_validated_dnskey(signer_name)
            if key_rrset is None:
                if signer_name == "." or signer_name == "":
                    if self._dnssec_raw_anchors and dns.name.root in self._dnssec_raw_anchors:
                        key_rrset = self._dnssec_raw_anchors[dns.name.root]
                    else:
                        self.logger.debug("No root key for signer %s", signer_name)
                        return False, await self._is_proven_insecure_name(qname)
                else:
                    self.logger.debug("No validated key for signer %s", signer_name)
                    return False, await self._is_proven_insecure_name(qname)

            validation_counter += 1
            if validation_counter > max_validations:
                self.logger.warning("DNSSEC validation limit (%d) exceeded for %s; refusing to validate",
                                    max_validations, qname)
                return False, False

            try:
                await loop.run_in_executor(
                    _CRYPTO_EXECUTOR,
                    lambda: dns.dnssec.validate_rrsig(rrset, sig_rdata, {signer_name_obj: key_rrset})
                )
            except dns.dnssec.ValidationFailure as e:
                # If signer is root, try validating with configured anchors; otherwise propagate the failure.
                if (signer_name == "." or signer_name == "") and self._dnssec_raw_anchors:
                    try:
                        await loop.run_in_executor(
                            _CRYPTO_EXECUTOR,
                            lambda: dns.dnssec.validate_rrsig(rrset, sig_rdata, self._dnssec_raw_anchors)
                        )
                    except dns.dnssec.ValidationFailure:
                        self.logger.warning("RRSIG validation against root anchors failed for %s", rrset.name)
                        raise
                else:
                    self.logger.warning("RRSIG validation failed for %s, signer=%s", rrset.name, signer_name)
                    raise

        return True, False

    async def _dnssec_validate(self, qname: str, response_wire: bytes, dnssec_requested: bool = True) -> Tuple[bool, bool]:
        if self.dnssec_chain_validation:
            return await self._dnssec_validate_chain(qname, response_wire, dnssec_requested)
        else:
            return await self._dnssec_validate_old(qname, response_wire, dnssec_requested)

    async def _dnssec_validate_old(self, qname: str, response_wire: bytes, dnssec_requested: bool = True) -> Tuple[bool, bool]:
        if not self.dnssec_enabled:
            return False, True
        if not _HAS_DNSPY:
            raise RuntimeError("dnspython required")
        if not dnssec_requested:
            return False, True

        if self._dnssec_raw_anchors is None:
            self._load_trust_anchors()
        if not self._dnssec_raw_anchors:
            raise Exception("DNSSEC trust anchors missing")

        try:
            message = dns.message.from_wire(response_wire)
        except Exception as exc:
            self.logger.warning("Malformed DNS response during DNSSEC validation for %s: %s", qname, exc)
            return False, False
        if not any(rr.rdtype == dns.rdatatype.RRSIG for rr in message.answer):
            return False, await self._is_proven_insecure_name(qname)

        validation_counter = 0
        max_validations = self.dnssec_max_validations if self.dnssec_max_validations > 0 else 999999

        def _validate() -> Tuple[bool, bool]:
            nonlocal validation_counter
            msg = dns.message.from_wire(response_wire)
            has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in msg.answer)
            if not has_rrsig:
                return False, False

            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                sig = None
                for rr in msg.answer:
                    if rr.rdtype == dns.rdatatype.RRSIG and rr.name == rrset.name:
                        for r in rr:
                            if r.type_covered == rrset.rdtype:
                                sig = rr
                                break
                        if sig:
                            break
                if sig is None:
                    raise dns.dnssec.ValidationFailure(f"No RRSIG for rrset {rrset.name}")

                validation_counter += 1
                if validation_counter > max_validations:
                    self.logger.warning("DNSSEC validation limit (%d) exceeded for %s; refusing to validate",
                                        max_validations, qname)
                    return False, False

                dns.dnssec.validate(rrset, sig, self._dnssec_raw_anchors)

            return True, False

        try:
            secure, insecure = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, _validate),
                timeout=self.dnssec_validation_timeout
            )
            if secure:
                self.logger.debug("DNSSEC validation passed for %s (validations=%d)", qname, validation_counter)
            else:
                self.logger.debug("DNSSEC validation: insecure (unsigned) for %s", qname)
            return secure, insecure
        except asyncio.TimeoutError:
            self.logger.warning("DNSSEC validation timeout for %s after %.1fs", qname, self.dnssec_validation_timeout)
            return False, False
        except dns.dnssec.ValidationFailure as e:
            self.logger.warning("DNSSEC validation bogus for %s: %s", qname, e)
            raise
        except Exception as e:
            self.logger.warning("DNSSEC validation error for %s: %s", qname, e)
            raise

    # ---------- Rate limiting helper ----------
    async def _check_rate_limit(self, client_ip: str) -> bool:
        if self.rate_limiter is None:
            return True
        return await self.rate_limiter.is_allowed(client_ip)

    def _is_quic_connection_alive(self, client: Any) -> bool:
        if client is None:
            return False
        quic = getattr(client, '_quic', None)
        if quic is None:
            return False
        if hasattr(quic, 'closed') and quic.closed:
            return False
        if hasattr(quic, 'is_closing'):
            maybe_closed = quic.is_closing
            if callable(maybe_closed):
                try:
                    closed = maybe_closed()
                except Exception:
                    closed = False
                if isinstance(closed, bool) and closed:
                    return False
        try:
            quic.get_next_available_stream_id()
            return True
        except Exception:
            return False

    # ---------- upstream resolution ----------
    async def _resolve_upstream_ip(self, hostname: str, ip_override: Optional[str] = None) -> str:
        if ip_override:
            try:
                ipaddress.ip_address(ip_override)
                self.logger.debug("using fixed IP for upstream: %s", ip_override)
                return ip_override
            except ValueError:
                self.logger.warning("ip_override '%s' is not a valid IP address, falling back to resolution", ip_override)

        try:
            ipaddress.ip_address(hostname)
            self.logger.debug("hostname %s is already an IP address, skipping resolution", hostname)
            return hostname
        except ValueError:
            pass

        key = (hostname, bool(self.disable_ipv6))
        async with self._cache_lock:
            cached = await self._cache_get(key)
            if cached:
                self.logger.debug("resolved %s from cache -> %s", hostname, cached)
                return cached

        self.logger.debug("resolving upstream hostname: %s", hostname)

        if self.bootstrap_servers:
            for bs in self.bootstrap_servers:
                try:
                    ip, port = self._split_hostport(bs, default_port=53)
                    addr = await self._udp_query_a_or_aaaa(ip, port, hostname, qtype=1)
                    if not addr:
                        addr = await self._udp_query_a_or_aaaa(ip, port, hostname, qtype=28)
                    if addr:
                        async with self._cache_lock:
                            await self._cache_set(key, addr)
                        self.logger.debug("bootstrap server %s returned %s for %s", bs, addr, hostname)
                        return addr
                except Exception as e:
                    self.logger.debug("bootstrap server %s failed: %s", bs, e)
                    continue

        try:
            family = socket.AF_INET if self.disable_ipv6 else 0
            infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr:
                    async with self._cache_lock:
                        await self._cache_set(key, addr)
                    self.logger.debug("system resolver returned %s for %s", addr, hostname)
                    return addr
        except Exception as e:
            self.logger.debug("system resolver failed for %s: %s", hostname, e)

        self.logger.error("unable to resolve upstream hostname: %s", hostname)
        raise Exception(f"Unable to resolve upstream hostname: {hostname}")

    async def _udp_query_a_or_aaaa(self, resolver_ip: str, resolver_port: int, qname: str, qtype: int = 1) -> Optional[str]:
        self.logger.debug("udp lookup of %s via %s:%d", qname, resolver_ip, resolver_port)
        loop = asyncio.get_running_loop()
        try:
            ip_obj = ipaddress.ip_address(resolver_ip)
            fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        except Exception:
            fam = socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            tid = int(time.time() * 1000) & 0xFFFF
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split("."))
            q += b"\x00" + struct.pack(">HH", int(qtype), 1)
            query = header + q
            addr_tuple = (resolver_ip, resolver_port) if fam == socket.AF_INET else (resolver_ip, resolver_port, 0, 0)
            await loop.sock_sendto(sock, query, addr_tuple)
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=self.udp_timeout)
            except asyncio.TimeoutError:
                self.logger.debug("udp lookup timed out for %s (qtype=%s)", qname, qtype)
                return None

            if len(data) < 12:
                raise Exception("short DNS response")
            qdcount = (data[4] << 8) | data[5]
            ancount = (data[6] << 8) | data[7]
            i = 12
            for _ in range(qdcount):
                _, i = self._parse_dns_name(data, i)
                i += 4
            a_addr: Optional[str] = None
            aaaa_addr: Optional[str] = None
            for _ in range(ancount):
                _, i = self._parse_dns_name(data, i)
                if i + 10 > len(data):
                    raise Exception("truncated answer header")
                rtype = (data[i] << 8) | data[i+1]
                ttl = struct.unpack(">I", data[i+4:i+8])[0]
                rdlen = (data[i+8] << 8) | data[i+9]
                if i + 10 + rdlen > len(data):
                    raise Exception("truncated rdata")
                rdata = data[i+10:i+10+rdlen]
                i += 10 + rdlen
                if rtype == 1 and rdlen == 4:
                    a_addr = ".".join(str(b) for b in rdata)
                elif rtype == 28 and rdlen == 16:
                    try:
                        aaaa_addr = socket.inet_ntop(socket.AF_INET6, bytes(rdata))
                    except Exception:
                        aaaa_addr = ":".join("{:02x}{:02x}".format(rdata[j], rdata[j+1]) for j in range(0, 16, 2))
            if qtype == 1:
                return a_addr
            if qtype == 28:
                return aaaa_addr
            return a_addr or aaaa_addr
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ---------- _try_upstream with health checks and TCP fallback ----------
    async def _try_upstream(self, upstream: Dict[str, Any], data: bytes, _health_check: bool = False, _no_retry: bool = False) -> bytes:
        proto = upstream.get('protocol', 'udp')
        if proto == 'udp':
            try:
                response = await self._with_retries(
                    lambda d: self._forward_udp(d, upstream), data, timeout=self.udp_timeout, no_retry=_no_retry)
                if self.tcp_fallback_enabled and not _health_check:
                    if len(response) >= 4:
                        flags = int.from_bytes(response[2:4], 'big')
                        if flags & 0x0200:
                            self.logger.debug("UDP response truncated (TC=1), falling back to TCP for %s",
                                              upstream.get('address'))
                            tcp_upstream = upstream.copy()
                            tcp_upstream['protocol'] = 'tcp'
                            if 'port' not in tcp_upstream:
                                tcp_upstream['port'] = 53
                            return await self._with_retries(
                                lambda d: self._forward_tcp(d, tcp_upstream), data, timeout=self.tcp_timeout, no_retry=_no_retry)
                return response
            except Exception as e:
                raise
        elif proto == 'tcp':
            return await self._with_retries(
                lambda d: self._forward_tcp(d, upstream), data, timeout=self.tcp_timeout, no_retry=_no_retry)
        elif proto == 'tls':
            return await self._with_retries(
                lambda d: self._forward_tls(d, upstream), data, timeout=self.tcp_timeout, no_retry=_no_retry)
        elif proto == 'https':
            return await self._with_retries(
                lambda d: self._forward_https(d, upstream), data, timeout=self.doh_timeout, no_retry=_no_retry)
        elif proto == 'quic':
            if not _HAS_AIOQUIC:
                raise RuntimeError("aioquic not available for DoQ")
            return await self._with_retries(
                lambda d: self._forward_quic(d, upstream), data, timeout=self.doh_timeout, no_retry=_no_retry)
        else:
            raise ValueError(f"Unsupported upstream protocol: {proto}")

    # ---------- NS scrubbing ----------
    def _scrub_authority_section(self, response_bytes: bytes, qname: str) -> bytes:
        """Remove unsolicited NS records from Authority and out‑of‑bailiwick records from Additional."""
        if not self.scrub_unsolicited_ns or not _HAS_DNSPY:
            return response_bytes

        try:
            msg = dns.message.from_wire(response_bytes)
            if not msg.authority and not msg.additional:
                return response_bytes

            qname_obj = dns.name.from_text(qname.lower().rstrip('.'))

            # ---- Scrub Authority (NS records) ----
            filtered_authority = []
            for rrset in msg.authority:
                if rrset.rdtype != dns.rdatatype.NS:
                    filtered_authority.append(rrset)
                    continue
                # Always keep root NS
                if rrset.name == dns.name.root:
                    filtered_authority.append(rrset)
                    continue
                # Keep if within bailiwick – allow exact match or superdomain
                if rrset.name == qname_obj or qname_obj.is_subdomain(rrset.name):
                    filtered_authority.append(rrset)
                else:
                    self.logger.debug("Scrubbed unsolicited NS record: %s (qname=%s)",
                                    rrset.name.to_text(), qname)

            # ---- Scrub Additional (glue, etc.) ----
            filtered_additional = []
            for rrset in msg.additional:
                # Always keep OPT (EDNS0) records
                if rrset.rdtype == dns.rdatatype.OPT:
                    filtered_additional.append(rrset)
                    continue
                # Keep if within bailiwick
                if self._is_in_bailiwick(rrset.name, qname_obj):
                    filtered_additional.append(rrset)
                else:
                    self.logger.debug("Scrubbed out‑of‑bailiwick Additional record: %s (qname=%s)",
                                    rrset.name.to_text(), qname)

            msg.authority = filtered_authority
            msg.additional = filtered_additional
            return msg.to_wire()

        except Exception as e:
            self.logger.debug("NS scrubbing failed: %s", e)
            return response_bytes

    # ---------- forward_dns_query (fixed coalescing, rate limiting removed) ----------
    def _finalize_response(self, resp: bytes, orig_id: int, cd_flag: bool) -> bytes:
        """
        Stamp the response with the original transaction ID and copy CD bit.
        """
        result = self._set_query_id(resp, orig_id)
        if cd_flag and len(result) >= 4:
            flags = int.from_bytes(result[2:4], 'big')
            flags |= dns.flags.CD  # CORRECT: bit 13 (0x2000) per RFC 1035/4035
            result = result[:2] + flags.to_bytes(2, 'big') + result[4:]
        return result

    async def forward_dns_query(self, original_data: bytes, client_ip: Optional[str] = None,
                                rate_limit_checked: bool = False) -> bytes:
        """
        Forwards DNS query with rate-limiting, RFC 6891 OPT validation,
        blocklist checking, DNSSEC, ECS, scope-aware caching, rebind protection,
        out-of-bailiwick scrubbing, and IPv6 record stripping.
        """
        # 1. Rate Limiting (cheap, before parsing)
        if client_ip and self.rate_limiter and not rate_limit_checked:
            if not await self.rate_limiter.is_allowed(client_ip):
                self.logger.warning("Rate limit exceeded for %s", client_ip)
                return self._make_rcode_response(original_data, dns.rcode.REFUSED)

        # 2. Wire Format & RFC 6891 Single-OPT Check
        if len(original_data) < 12:
            return self._make_rcode_response(original_data, dns.rcode.FORMERR)

        try:
            msg = dns.message.from_wire(original_data)
        except Exception:
            return self._make_rcode_response(original_data, dns.rcode.FORMERR)

        if not msg.question:
            reply = dns.message.make_response(msg)
            reply.set_rcode(dns.rcode.FORMERR)
            return reply.to_wire()

        # RFC 6891 §6.1.1: at most one OPT record
        opt_count = sum(1 for rrset in msg.additional if rrset.rdtype == dns.rdatatype.OPT)
        if opt_count > 1:
            self.logger.warning("Rejecting query with %d OPT records (RFC 6891 FORMERR)", opt_count)
            reply = dns.message.make_response(msg)
            reply.set_rcode(dns.rcode.FORMERR)
            return reply.to_wire()

        qname = msg.question[0].name.to_text()
        qtype = msg.question[0].rdtype
        orig_id = msg.id
        cd_flag = bool(msg.flags & dns.flags.CD)
        do_flag = bool(msg.ednsflags & dns.flags.DO) if msg.edns is not None else False
        cacheable_request = not msg.options

        # 3. Hosts override (local A/AAAA)
        host_entry = await self.get_host_for(qname)
        if host_entry:
            if qtype in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.ANY):
                try:
                    resp = dns.message.make_response(msg)
                    ttl = 60
                    for ip in host_entry:
                        if qtype == dns.rdatatype.A and ':' not in ip:
                            rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, ip)
                            resp.answer.append(rr)
                        elif qtype == dns.rdatatype.AAAA and ':' in ip:
                            rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, ip)
                            resp.answer.append(rr)
                        elif qtype == dns.rdatatype.ANY:
                            if ':' not in ip:
                                rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.A, ip)
                                resp.answer.append(rr)
                            else:
                                rr = dns.rrset.from_text(qname, ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, ip)
                                resp.answer.append(rr)
                    self._log_event("Hosts override", qname, client_ip)
                    return resp.to_wire()
                except Exception as e:
                    self.logger.warning("Failed to synthesise hosts response for %s: %s", qname, e)

        # 4. Blocklist Check
        if await self.is_blocked(qname):
            self.logger.info("Blocked query for %s", qname)
            return self.build_block_response(original_data)

        # 5. Prepare forward message with EDNS0 ECS
        forward_msg = dns.message.from_wire(original_data)
        if not self.ecs_enabled and forward_msg.options:
            # Remove ECS option by creating a new options list
            filtered = [opt for opt in forward_msg.options if opt.otype != 8]
            forward_msg.use_edns(
                edns=forward_msg.edns,
                payload=forward_msg.payload,
                options=filtered,
            )

        client_subnet_prefix = 0
        client_subnet_key = "global"
        if client_ip and self.ecs_enabled:
            try:
                ip_obj = ipaddress.ip_address(client_ip)
                if ip_obj.version == 4:
                    prefix_len = 24
                    net = ipaddress.IPv4Network(f"{client_ip}/24", strict=False)
                    subnet_bytes = net.network_address.packed[:3]
                    family = 1
                else:
                    prefix_len = 56
                    net = ipaddress.IPv6Network(f"{client_ip}/56", strict=False)
                    subnet_bytes = net.network_address.packed[:7]
                    family = 2
                client_subnet_prefix = prefix_len
                client_subnet_key = f"{net.network_address}/{prefix_len}"
                ecs_data = struct.pack("!HBB", family, prefix_len, 0) + subnet_bytes
                ecs_option = dns.edns.GenericOption(8, ecs_data)
                options = [opt for opt in (forward_msg.options or []) if opt.otype != 8]
                options.append(ecs_option)
                forward_msg.use_edns(edns=0, payload=self.max_edns_payload, options=options)
            except Exception as e:
                self.logger.debug("Failed to attach ECS: %s", e)

        if self.ecs_enabled and client_subnet_prefix == 0:
            for option in forward_msg.options or ():
                if isinstance(option, dns.edns.ECSOption) and option.srclen:
                    try:
                        subnet = ipaddress.ip_network(
                            f"{option.address}/{option.srclen}", strict=False
                        )
                        client_subnet_prefix = option.srclen
                        client_subnet_key = f"{subnet.network_address}/{option.srclen}"
                    except ValueError:
                        pass
                    break

        validate_dnssec = self.dnssec_enabled and not cd_flag
        if validate_dnssec:
            forward_msg.use_edns(
                edns=0,
                ednsflags=forward_msg.ednsflags | dns.flags.DO,
                payload=self.max_edns_payload,
                options=list(forward_msg.options or ()),
            )

        default_query_context = (
            msg.question[0].rdclass == dns.rdataclass.IN
            and not do_flag and not cd_flag and not validate_dnssec
            and msg.opcode() == 0
            and bool(msg.flags & dns.flags.RD)
            and not bool(msg.flags & dns.flags.AD)
        )
        cache_context = "" if default_query_context else (
            f"{msg.question[0].rdclass}:{int(do_flag)}:{int(cd_flag)}:"
            f"{msg.opcode()}:{int(bool(msg.flags & dns.flags.RD))}:"
            f"{int(bool(msg.flags & dns.flags.AD))}:{int(validate_dnssec)}:"
        )
        cache_scope = f"{cache_context}{client_subnet_key}"
        cache_key = (qname.lower(), qtype, cache_scope)
        global_cache_key = (qname.lower(), qtype, f"{cache_context}global")

        # 6. Negative cache lookup
        neg_entry = await self._negative_cache_get(cache_key) if cacheable_request else None
        if neg_entry is not None:
            self.logger.debug("Negative-cache hit for %s", qname)
            normalized = self._normalize_response_edns(neg_entry, msg, do_flag)
            return self._set_query_id(normalized, orig_id)

        forward_data = forward_msg.to_wire()

        # 8. Scope-aware wire cache lookup (positive)
        cached_entry = await self._wire_cache_get_valid(cache_key) if cacheable_request else None
        if cacheable_request and cached_entry is None and cache_key != global_cache_key:
            cached_entry = await self._wire_cache_get_valid(global_cache_key)

        if cached_entry is not None:
            resp_bytes, _ = cached_entry
            self.logger.debug("Wire-cache hit for %s", qname)
            normalized = self._normalize_response_edns(resp_bytes, msg, do_flag)
            return self._set_query_id(normalized, orig_id)

        # 9. Flight coalescing (in-flight query deduplication)
        flight_key = (
            qname.lower(), qtype, msg.question[0].rdclass, msg.opcode(),
            bool(msg.flags & dns.flags.RD), bool(msg.flags & dns.flags.AD),
            do_flag, cd_flag, validate_dnssec, client_subnet_key,
        )
        
        future = None
        if cacheable_request:
            while True:
                existing_future = None

                async with self._flight_lock:
                    existing_future = self._flights.get(flight_key)
                    if existing_future and not existing_future.done():
                        self.logger.debug("Coalescing flight for %s", qname)
                    else:
                        existing_future = None
                        future = asyncio.get_running_loop().create_future()
                        future.add_done_callback(
                            lambda completed: completed.exception()
                            if not completed.cancelled() else None
                        )
                        self._flights[flight_key] = future

                if existing_future:
                    try:
                        resp = await asyncio.shield(existing_future)
                        normalized = self._normalize_response_edns(resp, msg, do_flag)
                        return self._set_query_id(normalized, orig_id)
                    except Exception as e:
                        self.logger.debug("Coalesced flight failed: %s", e)
                        continue

                break

        # At this point, we are the "leader" – we must set the future result/exception.
        try:
            # 10. Select upstream(s) and execute load-balancing strategy
            upstream_list = self.upstreams or []
            if not upstream_list:
                upstream_list = [{
                    'address': '1.1.1.1',
                    'protocol': 'udp',
                    'port': 53,
                    'hostname': '1.1.1.1',
                    'ip': '1.1.1.1'
                }]
                self.logger.warning("No upstreams defined; using default 1.1.1.1 over UDP")

            if self._health_enabled:
                upstream_list = await self._get_healthy_upstreams(upstream_list)

            response = await self._execute_strategy(
                self.load_balancing,
                upstream_list,
                forward_data,
                qname,
                validate_dnssec,
                cache_key,
                orig_id,
                cacheable_request=cacheable_request,
            )

            returned_scope = 0
            try:
                upstream_response = dns.message.from_wire(response)
                for option in upstream_response.options:
                    if isinstance(option, dns.edns.ECSOption):
                        returned_scope = option.scopelen
                        break
                    if option.otype == dns.edns.ECS and len(getattr(option, "data", b"")) >= 4:
                        returned_scope = option.data[3]
                        break
            except Exception:
                pass

            if not do_flag:
                response = self._strip_dnssec_records(
                    response, msg.question[0].name, qtype
                )
            response = self._normalize_response_edns(response, msg, do_flag)

            # 12. Rebind protection
            if self.rebind_protection_enabled:
                response = self._apply_rebind_protection(response)
                if response is None:
                    response = self._make_rcode_response(original_data, dns.rcode.REFUSED)

            # 13. NS scrubbing
            if self.scrub_unsolicited_ns:
                response = self._scrub_authority_section(response, qname)

            # 14. IPv6 stripping
            if self.strip_ipv6_records:
                response = self._strip_ipv6_records(response)

            # 15. Cache the response (positive or negative)
            if cacheable_request and self._is_negative_response(response):
                ttl = self._extract_soa_minimum(response)
                safe_response = self._cache_safe_response(response)
                if ttl is not None and safe_response is not None:
                    await self._negative_cache_set(
                        cache_key, safe_response, ttl=min(ttl, self.negative_cache_ttl)
                    )
            elif cacheable_request and dns.message.from_wire(response).rcode() == dns.rcode.NOERROR:
                try:
                    safe_response = self._cache_safe_response(response)
                    if safe_response is None:
                        raise ValueError("response contains uncacheable EDNS options")
                    resp_msg = dns.message.from_wire(safe_response)
                    min_ttl = min(
                        (rr.ttl for sec in (resp_msg.answer, resp_msg.authority, resp_msg.additional)
                        for rr in sec if rr.rdtype != dns.rdatatype.OPT),
                        default=300
                    )
                    final_key = global_cache_key if returned_scope == 0 else cache_key
                    if min_ttl > 0:
                        expiry = time.time() + min_ttl
                        stale_until = expiry + self.stale_max_age if self.optimistic_cache_enabled else expiry
                        val = (safe_response, expiry, forward_data, stale_until, validate_dnssec)
                        await self._wire_cache_set(final_key, val)
                except Exception as e:
                    self.logger.debug("Cache set error: %s", e)

            # 16. Set the future result (for any concurrent waiters) and return
            if future is not None and not future.done():
                future.set_result(response)
            return response

        except asyncio.CancelledError:
            if future is not None and not future.done():
                future.set_exception(RuntimeError("DNS query leader was cancelled"))
            raise
        except Exception as e:
            # Set the future exception before raising
            if future is not None and not future.done():
                future.set_exception(e)
            raise
        finally:
            # Remove the future from the dict, but only if it's still the same one.
            # This prevents removing a future that was replaced by a new leader.
            if future is not None:
                async with self._flight_lock:
                    if self._flights.get(flight_key) is future:
                        self._flights.pop(flight_key, None)
    # ---------- Helper methods ----------
    async def _check_hosts_and_blocklists(self, qname: str, qtype: int, original_data: bytes) -> Optional[bytes]:
        if qname:
            host_values = await self.get_host_for(qname)
            if host_values:
                if qtype == 1 and len(host_values) > 0:
                    ip = host_values[0]
                    try:
                        if _HAS_DNSPY:
                            absolute_qname = qname if qname.endswith('.') else f"{qname}."
                            resp = dns.message.make_response(dns.message.from_wire(original_data) if original_data else None)
                            rr = dns.rrset.from_text(absolute_qname, 60, dns.rdataclass.IN, dns.rdatatype.A, ip)
                            resp.answer = [rr]
                            return resp.to_wire()
                        else:
                            return self._build_local_A_response(original_data, ip)
                    except Exception:
                        self.logger.exception("failed to synthesize hosts map response for %s", qname)
            if await self.is_blocked(qname):
                self._log_event("Blocked (internal)", qname, None, "blocklist")
                try:
                    return self.build_block_response(original_data)
                except Exception:
                    return self._make_nxdomain_response(original_data)
        return None

    async def _check_caches(self, key, qname: str, original_data: bytes, dnssec_requested: bool) -> Optional[bytes]:
        cached_negative = await self._negative_cache_get(key)
        if cached_negative is not None:
            self.logger.debug("negative-cache hit %s", key)
            return cached_negative

        cached = await self._wire_cache_get_valid(key)
        if cached is not None:
            resp_bytes, dnssec_validated = cached
            self.logger.debug("wire-cache hit %s", key)

            if self.dnssec_enabled and not dnssec_validated:
                self.logger.debug("cache entry lacks DNSSEC validation, revalidating...")
                try:
                    secure, insecure = await self._dnssec_validate(qname, resp_bytes, dnssec_requested)
                    if secure or insecure:
                        async with self._cache_lock:
                            entry = await self._wire_cache_get(key)
                            if entry is not None:
                                _, expiry, query_data, stale_until, _ = entry
                                new_val = (resp_bytes, expiry, query_data, stale_until, True)
                                await self._wire_cache_set(key, new_val)
                        dnssec_validated = True
                except Exception as e:
                    self.logger.warning("DNSSEC revalidation failed for %s, treating as cache miss", key)
                    async with self._cache_lock:
                        await self._wire_cache_delete(key)
                    return None

            if self.rebind_protection_enabled:
                resp_bytes = self._apply_rebind_protection(resp_bytes)
                if resp_bytes is None:
                    return self._make_nxdomain_response(original_data)
            return resp_bytes
        return None

    # ---------- Fixed parallel strategy ----------
    async def _execute_strategy(self, strategy: str, upstream_list: List[Dict[str, Any]],
                                data: bytes, qname: str, dnssec_requested: bool,
                                key, orig_id: int, cacheable_request: bool = True) -> bytes:
        last_exc = None
        if strategy == 'failover':
            for upstream in upstream_list:
                try:
                    return await self._process_upstream_response(
                        upstream, data, qname, dnssec_requested, key, orig_id, cacheable_request
                    )
                except Exception as e:
                    last_exc = e
                    self.logger.debug("upstream %s failed: %s", upstream.get('address'), e)
                    continue
            raise last_exc or Exception("All upstreams failed")

        elif strategy == 'parallel':
            semaphore = asyncio.Semaphore(5)
            async def bounded_task(upstream):
                async with semaphore:
                    return await self._process_upstream_response(
                        upstream, data, qname, dnssec_requested, key, orig_id, cacheable_request
                    )
            tasks = [asyncio.create_task(bounded_task(upstream)) for upstream in upstream_list]
            pending = set(tasks)
            try:
                while pending:
                    done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        if not task.cancelled():
                            try:
                                result = task.result()
                                for p in pending:
                                    p.cancel()
                                if pending:
                                    await asyncio.gather(*pending, return_exceptions=True)
                                return result
                            except Exception as e:
                                last_exc = e
                                continue
                raise last_exc or Exception("All upstreams failed in parallel")
            except Exception as e:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                if any(not t.done() for t in tasks):
                    await asyncio.gather(*tasks, return_exceptions=True)
                raise e

        elif strategy == 'random':
            import random
            upstream = random.choice(upstream_list)
            try:
                return await self._process_upstream_response(
                    upstream, data, qname, dnssec_requested, key, orig_id, cacheable_request
                )
            except Exception as e:
                last_exc = e
                self.logger.debug("random upstream %s failed: %s", upstream.get('address'), e)
                raise last_exc

        elif strategy == 'roundrobin':
            idx = self._rr_index % len(upstream_list)
            upstream = upstream_list[idx]
            self._rr_index += 1
            try:
                return await self._process_upstream_response(
                    upstream, data, qname, dnssec_requested, key, orig_id, cacheable_request
                )
            except Exception as e:
                last_exc = e
                self.logger.debug("roundrobin upstream %s failed: %s", upstream.get('address'), e)
                raise last_exc
        else:
            raise ValueError(f"Unknown load balancing strategy: {strategy}")

    async def _process_upstream_response(self, upstream: Dict[str, Any], data: bytes,
                                         qname: str, dnssec_requested: bool,
                                         key, orig_id: int,
                                         cacheable_request: bool = True) -> bytes:
        resp = await self._try_upstream(upstream, data)

        if self.metrics_enabled and self._metrics:
            try:
                self._metrics['requests_total'].labels(proto=upstream['protocol']).inc()
            except Exception:
                pass

        if self.scrub_unsolicited_ns and qname:
            resp = self._scrub_authority_section(resp, qname)

        dnssec_ok = False
        if self.dnssec_enabled and qname and dnssec_requested:
            try:
                secure, insecure = await self._dnssec_validate(qname, resp, dnssec_requested)
                if secure:
                    dnssec_ok = True
                elif not insecure:
                    self.logger.warning("DNSSEC validation bogus for %s", qname)
                    return self._make_servfail_response(data)
            except Exception as e:
                self.logger.warning("DNSSEC validation failed for %s: %s", qname, e)
                return self._make_servfail_response(data)

        if self.rebind_protection_enabled:
            resp = self._apply_rebind_protection(resp)
            if resp is None:
                return self._make_nxdomain_response(data)

        if self.strip_ipv6_records:
            resp = self._strip_ipv6_records(resp)

        if self._is_negative_response(resp):
            ttl = self._extract_soa_minimum(resp)
            safe_response = self._cache_safe_response(resp) if cacheable_request else None
            async with self._cache_lock:
                await self._wire_cache_delete(key)
                if ttl is not None and safe_response is not None:
                    await self._negative_cache_set(
                        key, safe_response, ttl=min(ttl, self.negative_cache_ttl)
                    )
            return self._set_query_id(resp, orig_id)

        if dns.message.from_wire(resp).rcode() != dns.rcode.NOERROR:
            return self._set_query_id(resp, orig_id)

        ttl = self._extract_min_ttl(resp)
        if ttl <= 0:
            return self._set_query_id(resp, orig_id)
        expiry = time.time() + ttl
        stale_until = expiry + self.stale_max_age if self.optimistic_cache_enabled else expiry
        safe_response = self._cache_safe_response(resp) if cacheable_request else None
        if safe_response is not None:
            val = (safe_response, expiry, data, stale_until, dnssec_ok)
            async with self._cache_lock:
                await self._negative_cache_delete(key)
                await self._wire_cache_set(key, val)

        return self._set_query_id(resp, orig_id)

    # ---------- Forwarding implementations ----------
    async def _get_udp_socket(self, key: Tuple[str, int]) -> socket.socket:
        async with self._udp_sockets_lock:
            if key in self._udp_sockets:
                sock = self._udp_sockets[key]
                try:
                    sock.getpeername()
                    return sock
                except (OSError, socket.error):
                    del self._udp_sockets[key]
                    try:
                        sock.close()
                    except Exception:
                        pass

            resolved, port = key
            family = socket.AF_INET6 if self._is_ipv6_address(resolved) else socket.AF_INET
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")

            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)

            try:
                sock.connect((resolved, port))
            except Exception as e:
                sock.close()
                raise e

            self._udp_sockets[key] = sock
            return sock

    def _validate_response_question(self, query_data: bytes, response_data: bytes, prefix: str = "") -> None:
        if not query_data or not response_data:
            raise OSError(f"{prefix} Response question mismatch".strip())

        try:
            req_msg = dns.message.from_wire(query_data)
            resp_msg = dns.message.from_wire(response_data)
        except dns.exception.DNSException as e:
            self.logger.warning("Malformed DNS response during question validation%s: %s",
                                f" ({prefix})" if prefix else "", e)
            raise OSError(f"{prefix} Malformed DNS response".strip()) from e

        if req_msg.question != resp_msg.question:
            self.logger.warning(
                "%sresponse question mismatch: sent %s, got %s",
                f"{prefix} " if prefix else "",
                req_msg.question,
                resp_msg.question,
            )
            raise OSError(f"{prefix} Response question mismatch".strip())

    async def _forward_udp(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = int(upstream.get('port', 53))
        ip_override = upstream.get('ip')

        resolved = await self._resolve_upstream_ip(host, ip_override)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        # Determine address family
        family = socket.AF_INET6 if self._is_ipv6_address(resolved) else socket.AF_INET

        # Fresh ephemeral socket per query (RFC 5452 source-port randomization)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)

        loop = asyncio.get_running_loop()
        try:
            # Send query asynchronously without blocking loop
            await loop.sock_sendto(sock, data, (resolved, port))

            # Receive response asynchronously (pure asyncio, no executor needed)
            buf_size = getattr(self, 'max_edns_payload', 4096) or 4096
            response, addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock, buf_size),
                timeout=self.udp_timeout
            )

            # RFC 5452 §4.4: Verify response comes from expected upstream IP & port
            resp_ip, resp_port = addr[0], addr[1]
            if resp_ip != resolved or resp_port != port:
                self.logger.warning(
                    "Spoofed/unexpected UDP sender: expected %s:%d, got %s:%d",
                    resolved, port, resp_ip, resp_port
                )
                raise OSError("UDP response origin mismatch")

            # RFC 5452 §4.1: Validate Transaction ID (TXID)
            if len(response) >= 2:
                resp_id = int.from_bytes(response[:2], 'big')
                sent_id = int.from_bytes(data[:2], 'big')
                if resp_id != sent_id:
                    self.logger.warning("UDP response ID mismatch: sent %d, got %d", sent_id, resp_id)
                    raise OSError("Response ID mismatch")
            else:
                raise OSError("Truncated DNS response")

            self._validate_response_question(data, response)
            return response

        except (OSError, socket.error) as e:
            self.logger.warning("UDP forward error to %s:%d: %s", resolved, port, e)
            raise
        except asyncio.TimeoutError:
            self.logger.warning("UDP timeout to %s:%d", resolved, port)
            raise
        finally:
            sock.close()

    async def _forward_tcp(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 53)
        ip_override = upstream.get('ip')
        key = (host, port)
        pooled = await self._tcp_pool.get(key)

        if pooled:
            reader, writer = pooled
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                pooled = None

        if not pooled:
            resolved = await self._resolve_upstream_ip(host, ip_override)
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")
            reader, writer = await self._open_tcp_connection(resolved, int(port))

        reusable = False
        try:
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()

            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, 'big')

            # Validate TCP DNS payload length (RFC 1035 §4.1.1 requires at least a 12-byte header)
            if length < 12:
                raise ValueError(f"TCP message length {length} is less than required DNS header size (12 bytes)")
            if length > MAX_TCP_RESPONSE_SIZE:
                raise ValueError(f"TCP message length {length} exceeds maximum {MAX_TCP_RESPONSE_SIZE}")

            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)

            # RFC 7766: Validate Transaction ID matches query
            if len(resp) >= 2 and len(data) >= 2:
                resp_id = int.from_bytes(resp[:2], 'big')
                sent_id = int.from_bytes(data[:2], 'big')
                if resp_id != sent_id:
                    self.logger.warning("TCP response ID mismatch: sent %d, got %d", sent_id, resp_id)
                    raise OSError("TCP Response ID mismatch")

            self._validate_response_question(data, resp, "TCP")
            await self._tcp_pool.put(key, reader, writer)
            reusable = True
            return resp
        finally:
            if not reusable:
                try:
                    writer.close()
                    await writer.wait_closed()
                except (Exception, asyncio.CancelledError):
                    pass

    async def _open_tcp_connection(self, host: str, port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        fastopen_option = getattr(socket, 'TCP_FASTOPEN_CONNECT', None)
        if not self.tcp_fastopen_enabled or fastopen_option is None:
            return await asyncio.open_connection(host, port)

        family = socket.AF_INET6 if self._is_ipv6_address(host) else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, fastopen_option, 1)
            except OSError:
                sock.close()
                return await asyncio.open_connection(host, port)

            sock.settimeout(self.tcp_timeout)
            try:
                await asyncio.to_thread(sock.connect, (host, port))
            except BlockingIOError:
                sock.close()
                return await asyncio.open_connection(host, port)
            sock.setblocking(False)
            return await asyncio.open_connection(sock=sock)
        except BaseException:
            sock.close()
            raise

    async def _forward_tls(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 853)
        hostname = upstream.get('hostname', host)
        ip_override = upstream.get('ip')

        self.logger.debug("TLS forward to %s:%s (hostname=%s)", host, port, hostname)

        key = (host, port, hostname)
        pooled = await self._tcp_pool.get(key)
        if pooled:
            reader, writer = pooled
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                pooled = None

        if not pooled:
            resolved = await self._resolve_upstream_ip(host, ip_override)
            self.logger.debug("Resolved %s -> %s", host, resolved)
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")
            ssl_ctx = ssl.create_default_context()
            try:
                import certifi
                ssl_ctx = ssl.create_default_context(cafile=certifi.where())
                self.logger.debug("Using certifi CA bundle: %s", certifi.where())
            except ImportError:
                self.logger.debug("certifi not installed, using system CA bundle")

            self.logger.debug("Connecting to %s:%s (TLS)", resolved, port)
            try:
                conn_future = asyncio.open_connection(resolved, int(port), ssl=ssl_ctx, server_hostname=hostname)
                reader, writer = await asyncio.wait_for(conn_future, timeout=self.tcp_timeout)
                self.logger.debug("TLS connection established to %s:%s", host, port)
            except asyncio.TimeoutError:
                self.logger.error("TLS connection timeout to %s:%s (tcp_timeout=%s)", host, port, self.tcp_timeout)
                raise
            except ssl.SSLCertVerificationError as e:
                self.logger.error("TLS certificate verification failed for %s: %s", hostname, e)
                raise
            except ssl.SSLZeroReturnError as e:
                self.logger.error("TLS connection closed prematurely for %s: %s", hostname, e)
                raise
            except OSError as e:
                self.logger.error("OS error connecting to %s:%s: %s", host, port, e)
                raise

            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                await self._check_cert_pins(hostname, ssl_obj)

        try:
            self.logger.debug("Sending %d bytes to %s:%s", len(data), host, port)
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()

            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, "big")

            # Validate TCP DNS payload length (RFC 1035 §4.1.1 requires at least a 12-byte header)
            if length < 12:
                raise ValueError(f"TCP message length {length} is less than required DNS header size (12 bytes)")
            if length > MAX_TCP_RESPONSE_SIZE:
                raise ValueError(f"TCP message length {length} exceeds maximum {MAX_TCP_RESPONSE_SIZE}")

            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)

            # RFC 7858 / RFC 1035 §4.1.1: Validate Transaction ID matches query
            if len(resp) >= 2 and len(data) >= 2:
                resp_id = int.from_bytes(resp[:2], 'big')
                sent_id = int.from_bytes(data[:2], 'big')
                if resp_id != sent_id:
                    self.logger.warning("TLS response ID mismatch: sent %d, got %d", sent_id, resp_id)
                    raise OSError("TLS Response ID mismatch")

            self._validate_response_question(data, resp, "TLS")
            await self._tcp_pool.put(key, reader, writer)
            return resp
        except Exception:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            raise

    async def _forward_https(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 443)
        hostname = upstream.get('hostname', host)
        path = upstream.get('path', '')
        if not path:
            path = "/dns-query"
        version = upstream.get('doh_version', self.doh_version)
        ip_override = upstream.get('ip')

        if version == 'auto':
            resolved_ip = await self._resolve_upstream_ip(host, ip_override)
            version = await self._get_auto_doh_version(hostname, port, resolved_ip, path)

        if version == '3':
            return await self._with_retries(
                lambda d: self._forward_https3(d, hostname, port, host, path, ip_override), data, timeout=self.doh_timeout)
        elif version == '2':
            return await self._with_retries(
                lambda d: self._forward_https2(d, hostname, port, host, path, ip_override), data, timeout=self.doh_timeout)
        else:
            return await self._with_retries(
                lambda d: self._forward_https1(d, hostname, port, host, path, ip_override), data, timeout=self.doh_timeout)

    async def _get_auto_doh_version(self, hostname: str, port: int, host: str, path: str) -> str:
        now = time.time()
        async with self._doh_auto_lock:
            if hostname in self._doh_auto_cache:
                version, expiry = self._doh_auto_cache[hostname]
                if now < expiry and version != '_probing':
                    return version
            if hostname in self._doh_auto_cache:
                version, expiry = self._doh_auto_cache[hostname]
                if version == '_failed' and now < expiry:
                    return '1.1'
            # Evict oldest entries if cache exceeds maxsize
            try:
                if len(self._doh_auto_cache) >= self._doh_auto_cache_maxsize:
                    # remove the entry with the earliest expiry
                    oldest = min(self._doh_auto_cache.items(), key=lambda kv: kv[1][1])[0]
                    del self._doh_auto_cache[oldest]
            except Exception:
                pass
            self._doh_auto_cache[hostname] = ('_probing', now + 10)

        probe_data = dns.message.make_query('probe.invalid', 'A').to_wire()
        try:
            await asyncio.wait_for(
                self._forward_https3(probe_data, hostname, port, host, path, None),
                timeout=self.doh_timeout
            )
            version = '3'
        except Exception:
            try:
                await asyncio.wait_for(
                    self._forward_https2(probe_data, hostname, port, host, path, None),
                    timeout=self.doh_timeout
                )
                version = '2'
            except Exception:
                version = '1.1'

        async with self._doh_auto_lock:
            if self._doh_auto_cache.get(hostname, ('', 0))[0] == '_probing':
                # Before writing, keep cache bounded
                try:
                    if len(self._doh_auto_cache) >= self._doh_auto_cache_maxsize:
                        oldest = min(self._doh_auto_cache.items(), key=lambda kv: kv[1][1])[0]
                        del self._doh_auto_cache[oldest]
                except Exception:
                    pass
                self._doh_auto_cache[hostname] = (version, time.time() + self.doh_auto_cache_ttl)
            elif version == '1.1':
                self._doh_auto_cache[hostname] = ('_failed', time.time() + self.doh_auto_cache_ttl // 2)
        return version

    async def _forward_https1(self, data: bytes, hostname: str, port: int, host: str, path: str, ip_override: Optional[str]) -> bytes:
        resolved = await self._resolve_upstream_ip(host, ip_override)
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(resolved, port, ssl=ssl_ctx, server_hostname=hostname)

        try:
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                await self._check_cert_pins(hostname, ssl_obj)

            headers = [
                f"POST {path} HTTP/1.1", f"Host: {hostname}",
                "User-Agent: dosev/1.0", "Accept: application/dns-message",
                "Content-Type: application/dns-message", f"Content-Length: {len(data)}",
                "Connection: close", "", ""
            ]
            hdr = "\r\n".join(headers).encode("ascii")
            writer.write(hdr + data)
            await writer.drain()

            status_line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
            if not status_line:
                raise Exception("Empty response from DoH upstream")
            status_line = status_line.decode("ascii", errors="ignore").strip()
            if not status_line.startswith("HTTP/"):
                raise Exception(f"Invalid HTTP response start: {status_line}")
            try:
                parts = status_line.split(None, 2)
                status_code = int(parts[1]) if len(parts) > 1 else 0
            except Exception:
                status_code = 0
            if status_code < 200 or status_code >= 300:
                raise Exception(f"DoH upstream returned non-2xx status: {status_line}")

            content_length: Optional[int] = None
            chunked = False
            age = 0
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
                if not line:
                    break
                s = line.decode("ascii", errors="ignore").strip()
                if s == "":
                    break
                parts = s.split(":", 1)
                if len(parts) == 2:
                    k, v = parts[0].lower(), parts[1].strip()
                    if k == "content-length":
                        try:
                            content_length = int(v)
                        except Exception:
                            content_length = None
                    if k == "transfer-encoding" and "chunked" in v.lower():
                        chunked = True
                    if k == "age":
                        age = self._parse_http_age(v)

            if chunked:
                body = bytearray()
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
                    if not line:
                        break
                    hexlen = line.decode("ascii", errors="ignore").strip().split(";", 1)[0]
                    try:
                        ln = int(hexlen, 16)
                    except Exception:
                        raise Exception("Invalid chunk length")
                    if ln == 0:
                        await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=self.doh_timeout)
                        break
                    chunk = await asyncio.wait_for(reader.readexactly(ln), timeout=self.doh_timeout)
                    body.extend(chunk)
                    await asyncio.wait_for(reader.readexactly(2), timeout=self.doh_timeout)
                body_bytes = bytes(body)
                self._validate_response_question(data, body_bytes, "DoH")
                return self._apply_doh_age(body_bytes, age)
            else:
                if content_length is None:
                    raise Exception("DoH response missing Content-Length and not chunked")
                body_bytes = await asyncio.wait_for(reader.readexactly(content_length), timeout=self.doh_timeout)
                self._validate_response_question(data, body_bytes, "DoH")
                return self._apply_doh_age(body_bytes, age)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _forward_https2(self, data: bytes, hostname: str, port: int, host: str, path: str, ip_override: Optional[str]) -> bytes:
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required for HTTP/2 DoH (install with: pip install httpx[h2])")

        key = (hostname, port, path)
        client = await self._h2_pool.get(key)
        resolved = await self._resolve_upstream_ip(host, ip_override)

        if client is None:
            transport = httpx.AsyncHTTPTransport(http2=True, verify=ssl.create_default_context())
            client = httpx.AsyncClient(http2=True, transport=transport)

        url = f"https://{resolved}:{port}{path}"
        
        # Set SNI via extensions
        extensions = {"sni_hostname": hostname}  # <-- FIX: this is how httpx sets SNI

        try:
            resp = await client.post(
                url,
                headers={
                    "Host": hostname,
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
                content=data,
                timeout=self.doh_timeout,
                extensions=extensions,  # <-- pass it here
            )
            if resp.status_code < 200 or resp.status_code >= 300:
                raise Exception(f"HTTP/2 upstream returned status {resp.status_code}")
            result = resp.content
            self._validate_response_question(data, result, "DoH")
            result = self._apply_doh_age(result, self._parse_http_age(resp.headers.get("age")))
            await self._h2_pool.put(key, client)
            return result
        except Exception:
            try:
                await client.aclose()
            except Exception:
                pass
            raise

    # ---------- Corrected H3 DoH pooling ----------
    async def _forward_https3(self, data: bytes, hostname: str, port: int, host: str, path: str, ip_override: Optional[str]) -> bytes:
        if not _HAS_AIOQUIC:
            raise RuntimeError("aioquic is required for HTTP/3 DoH (install with: pip install aioquic)")

        resolved = await self._resolve_upstream_ip(host, ip_override)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        key = (hostname, port, path)

        # Try to get a pooled connection
        client = await self._h3_pool.get(key)

        if client is None:
            config = QuicConfiguration(
                is_client=True,
                alpn_protocols=["h3"],
                verify_mode=ssl.CERT_REQUIRED,
            )
            config.server_name = hostname

            cm = connect(resolved, port, configuration=config, create_protocol=H3DohProtocol)
            try:
                client = await cm.__aenter__()
                client._cm = cm
            except asyncio.CancelledError:
                # Clean up on cancellation during handshake
                await cm.__aexit__(None, None, None)
                raise
            except Exception:
                await cm.__aexit__(None, None, None)
                raise

        try:
            result = await client.send_request(data, hostname, path)
            if isinstance(result, tuple):
                response, age = result
            else:
                response, age = result, 0
            self._validate_response_question(data, response, "DoH")
            response = self._apply_doh_age(response, age)
            # Success: return connection to pool
            await self._h3_pool.put(key, client)
            return response
        except asyncio.CancelledError:
            # Clean up on cancellation (e.g., health‑check timeout)
            if hasattr(client, '_cm'):
                try:
                    await client._cm.__aexit__(None, None, None)
                except Exception:
                    pass
            else:
                try:
                    client.close()
                except Exception:
                    pass
            raise
        except Exception:
            # On other failures, close and don't pool
            if hasattr(client, '_cm'):
                try:
                    await client._cm.__aexit__(None, None, None)
                except Exception:
                    pass
            else:
                try:
                    client.close()
                except Exception:
                    pass
            raise

    # ---------- DOQ with connection pooling and fragmentation fix ----------
    def _close_doq_protocol_error(self, client: Any, reason: str) -> None:
        try:
            client._quic.close(error_code=0x2, reason_phrase=reason)
            client.transmit()
        except Exception as exc:
            self.logger.debug("Could not close DoQ connection with protocol error: %s", exc)

    async def _forward_quic(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        """Forward DNS query over QUIC (DoQ)."""
        if not _HAS_AIOQUIC:
            raise RuntimeError("aioquic not available for DoQ")

        from aioquic.asyncio import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived

        host = upstream['address']
        port = upstream.get('port', 853)
        hostname = upstream.get('hostname', host)
        ip_override = upstream.get('ip')
        if len(data) < 12:
            raise ValueError("DoQ query is shorter than a DNS header")
        original_id = int.from_bytes(data[:2], 'big')
        doq_query = b"\x00\x00" + data[2:]

        resolved = await self._resolve_upstream_ip(host, ip_override)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        key = (host, port, hostname, resolved)

        class DoQProtocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._pending: Dict[int, asyncio.Future[bytes]] = {}
                self._fragments: Dict[int, bytearray] = {}

            def quic_event_received(self, event):
                if isinstance(event, StreamDataReceived):
                    fut = self._pending.get(event.stream_id)
                    if fut and not fut.done():
                        self._fragments.setdefault(event.stream_id, bytearray()).extend(event.data)
                        if event.end_stream:
                            data = bytes(self._fragments.pop(event.stream_id))
                            fut.set_result(data)

        client = await self._quic_pool.get(key)
        if client is not None and not self._is_quic_connection_alive(client):
            client = None

        if client is None:
            config = QuicConfiguration(
                is_client=True,
                alpn_protocols=["doq"],
                verify_mode=ssl.CERT_REQUIRED,
                server_name=hostname,
            )
            try:
                import certifi
                config.load_verify_locations(certifi.where())
            except ImportError:
                pass

            cm = connect(resolved, port, configuration=config, create_protocol=DoQProtocol)
            try:
                client = await cm.__aenter__()
                client._cm = cm
                client._pending = {}
                client._fragments = {}
            except Exception:
                await cm.__aexit__(None, None, None)
                raise

        # Define future early to allow cancellation in all error paths
        future = None
        stream_id = None

        try:
            await client.wait_connected()

            stream_id = client._quic.get_next_available_stream_id()
            future = asyncio.get_running_loop().create_future()
            client._pending[stream_id] = future

            # DoQ format: 2-byte length prefix + DNS message
            client._quic.send_stream_data(
                stream_id,
                len(doq_query).to_bytes(2, 'big') + doq_query,
                end_stream=True
            )
            client.transmit()

            try:
                response_data = await asyncio.wait_for(future, timeout=self.doh_timeout)
            except asyncio.TimeoutError:
                # Clean up the pending future and close the stream
                client._pending.pop(stream_id, None)
                if future and not future.done():
                    future.cancel()
                if self._is_quic_connection_alive(client):
                    client._quic.close()
                raise TimeoutError(f"DoQ query to {host}:{port} timed out")
            except asyncio.CancelledError:
                # Explicitly cancel the future before re-raising
                if future and not future.done():
                    future.cancel()
                client._pending.pop(stream_id, None)
                raise
            except Exception:
                client._pending.pop(stream_id, None)
                if future and not future.done():
                    future.cancel()
                raise
            finally:
                if future and not future.done():
                    future.cancel()
                client._pending.pop(stream_id, None)
                client._fragments.pop(stream_id, None)

            if len(response_data) < 2:
                self._close_doq_protocol_error(client, "DoQ response missing length prefix")
                raise OSError("Invalid DoQ response (too short)")
            resp_len = int.from_bytes(response_data[:2], 'big')
            if resp_len + 2 != len(response_data) or resp_len < 12:
                self._close_doq_protocol_error(client, "Invalid DoQ response framing")
                raise OSError("Invalid DoQ response framing")
            resp = response_data[2:2+resp_len]

            if resp[:2] != b"\x00\x00":
                self._close_doq_protocol_error(client, "DoQ DNS Message ID is not zero")
                raise OSError("DoQ response DNS Message ID must be zero")

            try:
                self._validate_response_question(doq_query, resp, "DoQ")
            except OSError:
                self._close_doq_protocol_error(client, "DoQ response question mismatch")
                raise
            # Store in pool on success
            await self._quic_pool.put(key, client)
            return self._set_query_id(resp, original_id)

        except asyncio.CancelledError:
            # Clean up the connection on cancellation (e.g., health-check timeout)
            if client is not None and hasattr(client, '_cm'):
                try:
                    await client._cm.__aexit__(None, None, None)
                except Exception:
                    pass
            raise

        except Exception:
            # Don't pool failed connections
            if client is not None and hasattr(client, '_cm'):
                try:
                    await client._cm.__aexit__(None, None, None)
                except Exception:
                    pass
            raise

    # ---------- remainder of file ----------
    def _split_hostport(self, hostport: str, default_port: int = 53) -> Tuple[str, int]:
        if not hostport:
            return "", default_port
        host = hostport
        port = default_port
        if hostport.startswith("["):
            try:
                end = hostport.index("]")
                host = hostport[1:end]
                rest = hostport[end+1:]
                if rest.startswith(":"):
                    port = int(rest[1:])
            except Exception:
                host = hostport
        else:
            if hostport.count(":") == 1:
                h, p = hostport.rsplit(":", 1)
                try:
                    port = int(p)
                    host = h
                except Exception:
                    host = hostport
            else:
                host = hostport
        return host, int(port)

    def _is_ipv6_address(self, addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr).version == 6
        except Exception:
            return False

    def _dnssec_requested(self, query_data: bytes) -> bool:
        if not query_data or len(query_data) < 12 or not _HAS_DNSPY:
            return False
        try:
            msg = dns.message.from_wire(query_data)
            return bool(msg.ednsflags & dns.flags.DO)
        except Exception:
            return False

    def _make_nxdomain_response(self, query_data: bytes) -> bytes:
        extra = b''
        if not query_data or len(query_data) < 12:
            tid = 0
            qpart = b''
            qdcount = 0
            arcount = 0
            rd = 0
        else:
            tid = int.from_bytes(query_data[0:2], 'big')
            req_flags = int.from_bytes(query_data[2:4], 'big')
            try:
                qpart, qdcount, qend = self._extract_question_section(query_data)
                extra, arcount = self._extract_additional_section(query_data, qend)
            except Exception:
                qpart = query_data[12:]
                qdcount = 0
                arcount = 0
                extra = b''
            rd = req_flags & 0x0100

        flags = 0x8000 | rd | 0x0003
        header = (
            tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') +
            qdcount.to_bytes(2, 'big') + (0).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') + arcount.to_bytes(2, 'big')
        )
        return header + qpart + extra

    def _build_local_A_response(self, query_data: bytes, ip: str) -> bytes:
        if not query_data or len(query_data) < 12:
            return b''
        tid = int.from_bytes(query_data[0:2], 'big')
        try:
            qpart, qdcount, qend = self._extract_question_section(query_data)
            extra, arcount = self._extract_additional_section(query_data, qend)
        except Exception:
            qpart = query_data[12:]
            qdcount = 0
            arcount = 0
            extra = b''
        flags = 0x8000
        header = (
            tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') +
            qdcount.to_bytes(2, 'big') + (1).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') + arcount.to_bytes(2, 'big')
        )
        name_ptr = b'\xc0\x0c'
        rtype = (1).to_bytes(2, 'big')
        rclass = (1).to_bytes(2, 'big')
        ttl = (60).to_bytes(4, 'big')
        ip_parts = [int(x) for x in ip.split('.')]
        rdata = struct.pack('BBBB', *ip_parts)
        rdlen = (len(rdata)).to_bytes(2, 'big')
        answer = name_ptr + rtype + rclass + ttl + rdlen + rdata
        return header + qpart + answer + extra

    def _extract_min_ttl(self, response: bytes) -> int:
        try:
            if not response or len(response) < 12:
                return 0
            qdcount = (response[4] << 8) | response[5]
            ancount = (response[6] << 8) | response[7]
            offset = 12
            for _ in range(qdcount):
                _, offset = self._parse_dns_name(response, offset)
                offset += 4
            min_ttl: Optional[int] = None
            for _ in range(ancount):
                _, offset = self._parse_dns_name(response, offset)
                if offset + 10 > len(response):
                    raise Exception("truncated answer header")
                ttl = struct.unpack(">I", response[offset+4:offset+8])[0]
                rdlen = (response[offset+8] << 8) | response[offset+9]
                if offset + 10 + rdlen > len(response):
                    raise Exception("truncated rdata")
                offset += 10 + rdlen
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
            return min_ttl or 0
        except Exception:
            return 0

    def _extract_soa_minimum(self, response: bytes) -> Optional[int]:
        try:
            msg = dns.message.from_wire(response)
            ttl = None
            for rrset in msg.authority:
                if rrset.rdtype == dns.rdatatype.SOA:
                    for rr in rrset:
                        candidate = min(rrset.ttl, rr.minimum)
                        ttl = candidate if ttl is None else min(ttl, candidate)
            return ttl
        except Exception:
            pass
        return None

    def _apply_rebind_protection(self, response_bytes: bytes) -> Optional[bytes]:
        if not self.rebind_protection_enabled or not _HAS_DNSPY:
            return response_bytes
        try:
            msg = dns.message.from_wire(response_bytes)
            filtered_answer = []
            for rrset in msg.answer:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    new_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                    new_rrset.ttl = rrset.ttl
                    has_public = False
                    for rd in rrset:
                        ip_str = rd.to_text().strip()
                        if not self._is_private_ip(ip_str):
                            new_rrset.add(rd)
                            has_public = True
                    if has_public:
                        filtered_answer.append(new_rrset)
                else:
                    filtered_answer.append(rrset)
            msg.answer = filtered_answer
            if self.rebind_action == 'block' and not filtered_answer:
                return None
            return msg.to_wire()
        except Exception as e:
            self.logger.debug("rebind protection failed: %s", e)
            return response_bytes

    def _is_private_ip(self, ip_str: str) -> bool:
        """Checks whether an IP address belongs to a private/reserved range."""
        try:
            ip = ipaddress.ip_address(ip_str)
            # First, use ipaddress built-in checks (covers many common ranges)
            if (ip.is_private or ip.is_loopback or ip.is_link_local or 
                ip.is_multicast or ip.is_unspecified or ip.is_reserved):
                return True
            # Then check our explicit list for ranges not covered by ipaddress
            return any(ip in subnet for subnet in self.PRIVATE_SUBNETS)
        except ValueError:
            return False

    def _set_tc_bit(self, response_bytes: bytes, max_size: int = 512) -> bytes:
        try:
            message = dns.message.from_wire(response_bytes)
            message.flags |= dns.flags.TC
            return message.to_wire(max_size=max_size, prefer_truncation=True)
        except Exception:
            if len(response_bytes) < 4:
                return response_bytes
            header = bytearray(response_bytes)
            flags = int.from_bytes(header[2:4], 'big') | 0x0200
            header[2:4] = flags.to_bytes(2, 'big')
            return bytes(header)

    async def _with_retries(self, fn: Callable[[bytes], Coroutine[Any, Any, bytes]], data: bytes, timeout: float, no_retry: bool = False) -> bytes:
        if no_retry:
            try:
                return await asyncio.wait_for(fn(data), timeout=timeout)
            except Exception as e:
                raise e

        backoff = self.initial_backoff
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                self.logger.debug("attempt %d/%d for %s", attempt + 1, self.retries, fn.__name__)
                start = time.time()
                result = await asyncio.wait_for(fn(data), timeout=timeout)
                dur = time.time() - start
                self.logger.debug("success %s on attempt %d (%.3fs)", fn.__name__, attempt + 1, dur)
                if self.metrics_enabled and self._metrics:
                    try:
                        self._metrics['request_latency_seconds'].labels(proto="unknown").observe(dur)
                    except Exception:
                        pass
                return result
            except asyncio.TimeoutError as e:
                last_exc = e
                self.logger.warning("timeout on attempt %d for %s", attempt + 1, fn.__name__)
            except Exception as e:
                last_exc = e
                self.logger.debug("attempt %d failed for %s: %s", attempt + 1, fn.__name__, e)
            if attempt < self.retries - 1:
                await asyncio.sleep(backoff)
                self.logger.debug("backing off %.3fs before next attempt", backoff)
                backoff *= 2
        self.logger.error("all %d attempts failed for %s", self.retries, fn.__name__)
        if self.metrics_enabled and self._metrics:
            try:
                self._metrics['requests_errors'].labels(proto="unknown").inc()
            except Exception:
                pass
        raise last_exc or Exception("Unknown forward error")

    def _log_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None) -> None:
        msg = f"{status}\tqname={qname}\tclient={client}\t{details or ''}"
        if status.startswith("Blocked"):
            self.logger.info(msg)
        else:
            self.logger.debug(msg)
        if self._file_logger:
            try:
                self._file_logger.info(msg)
            except Exception:
                pass

    def log_dns_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None) -> None:
        self._log_event(status, qname, client, details)

    async def _check_cert_pins(self, hostname: str, ssl_obj: Any) -> None:
        if not self.pinned_certs:
            return
        self.logger.debug("checking certificate pin for %s", hostname)
        try:
            der = ssl_obj.getpeercert(binary_form=True)
            if not der:
                raise Exception("No peer cert available for pin-check")
            got = hashlib.sha256(der).hexdigest()
            expected = self.pinned_certs.get(hostname) or self.pinned_certs.get('*')
            if expected and got.lower() != expected.lower():
                self.logger.warning("certificate pin mismatch for %s: got %s expected %s", hostname, got, expected)
                raise Exception(f"Pinned certificate mismatch for {hostname}: got {got}, expected {expected}")
            self.logger.debug("certificate pin match for %s", hostname)
        except Exception:
            self.logger.exception("certificate pin check failed for %s", hostname)
            raise

    def set_block_action(self, action: Optional[str]) -> None:
        try:
            if action is None:
                action = 'NXDOMAIN'
            self._block_action = str(action).upper()
        except Exception:
            self._block_action = 'NXDOMAIN'

    def get_block_action(self) -> str:
        return getattr(self, '_block_action', 'NXDOMAIN')

    def build_block_response(self, request_data: bytes, action: Optional[str] = None) -> bytes:
        use_action = action or self.get_block_action()
        try:
            if _HAS_DNSPY:
                try:
                    request_msg = dns.message.from_wire(request_data)
                except Exception:
                    request_msg = None
                if request_msg is None and use_action != 'ZEROIP':
                    return self._make_nxdomain_response(request_data)
                if request_msg is None:
                    resp = dns.message.Message()
                    if use_action == 'REFUSED':
                        resp.set_rcode(dns.rcode.REFUSED)
                    else:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
                resp = dns.message.make_response(request_msg)
                resp.answer = []
                if use_action == 'REFUSED':
                    resp.set_rcode(dns.rcode.REFUSED)
                    return resp.to_wire()
                if use_action == 'NXDOMAIN':
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
                if use_action == 'ZEROIP':
                    if not request_msg.question:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                        return resp.to_wire()
                    q = request_msg.question[0]
                    qname = q.name
                    qtype = q.rdtype
                    ttl = 60
                    if qtype == dns.rdatatype.A:
                        rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
                        resp.answer.append(rrset)
                        return resp.to_wire()
                    elif qtype == dns.rdatatype.AAAA:
                        if self.disable_ipv6:
                            resp.set_rcode(dns.rcode.NXDOMAIN)
                            return resp.to_wire()
                        rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
                        resp.answer.append(rrset)
                        return resp.to_wire()
                    elif qtype == dns.rdatatype.ANY:
                        a = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
                        resp.answer.append(a)
                        if not self.disable_ipv6:
                            aaaa = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
                            resp.answer.append(aaaa)
                        return resp.to_wire()
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
            if use_action == 'REFUSED':
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        _, qend = self._parse_dns_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000 | 5
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                return header + qpart
            if use_action == 'NXDOMAIN':
                return self._make_nxdomain_response(request_data)
            if use_action == 'ZEROIP':
                qname = self._extract_qname_from_wire(request_data)
                qtype = self._extract_qtype_from_wire(request_data) or 1
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        _, qend = self._parse_dns_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000
                name_ptr = b'\xc0\x0c'
                if qtype == 1:
                    header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                    rtype = (1).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (4).to_bytes(2, 'big')
                    rdata = b'\x00\x00\x00\x00'
                    ans = name_ptr + rtype + rclass + ttl + rdlen + rdata
                    return header + qpart + ans
                elif qtype == 28:
                    if self.disable_ipv6:
                        return self._make_nxdomain_response(request_data)
                    header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                    rtype = (28).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (16).to_bytes(2, 'big')
                    rdata = b'\x00' * 16
                    ans = name_ptr + rtype + rclass + ttl + rdlen + rdata
                    return header + qpart + ans
                elif qtype == 255:
                    a_ans = name_ptr + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (60).to_bytes(4, 'big') + (4).to_bytes(2, 'big') + b'\x00\x00\x00\x00'
                    if self.disable_ipv6:
                        header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                        return header + qpart + a_ans
                    else:
                        aaaa_ans = name_ptr + (28).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (60).to_bytes(4, 'big') + (16).to_bytes(2, 'big') + (b'\x00' * 16)
                        header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (2).to_bytes(2, 'big') + (2).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                        return header + qpart + a_ans + aaaa_ans
                else:
                    return self._make_nxdomain_response(request_data)
        except Exception:
            return self._make_nxdomain_response(request_data)

    # ---------- update_config ----------
    async def update_config(self, *,
                            verbose: Optional[bool] = None,
                            disable_ipv6: Optional[bool] = None,
                            strip_ipv6_records: Optional[bool] = None,
                            cache_ttl: Optional[int] = None,
                            cache_max_size: Optional[int] = None,
                            negative_cache_ttl: Optional[int] = None,
                            doh_timeout: Optional[float] = None,
                            udp_timeout: Optional[float] = None,
                            tcp_timeout: Optional[float] = None,
                            retries: Optional[int] = None,
                            initial_backoff: Optional[float] = None,
                            dns_logging_enabled: Optional[bool] = None,
                            pinned_certs: Optional[Dict[str, str]] = None,
                            dnssec_enabled: Optional[bool] = None,
                            trust_anchors: Optional[Union[Dict[str, str], str]] = None,
                            auto_update_trust_anchor: Optional[bool] = None,
                            dnssec_max_validations: Optional[int] = None,
                            dnssec_max_dnskey_records: Optional[int] = None,
                            dnssec_validation_timeout: Optional[float] = None,
                            dnssec_chain_validation: Optional[bool] = None,
                            dnssec_max_iterations: Optional[int] = None,
                            scrub_unsolicited_ns: Optional[bool] = None,
                            metrics_enabled: Optional[bool] = None,
                            metrics_port: Optional[int] = None,
                            uvloop_enable: Optional[bool] = None,
                            rate_limit_rps: Optional[float] = None,
                            rate_limit_burst: Optional[float] = None,
                            upstreams: Optional[List[Dict[str, Any]]] = None,
                            optimistic_cache_enabled: Optional[bool] = None,
                            optimistic_stale_max_age: Optional[int] = None,
                            optimistic_stale_response_ttl: Optional[int] = None,
                            rebind_protection_enabled: Optional[bool] = None,
                            rebind_action: Optional[str] = None,
                            ecs_enabled: Optional[bool] = None,
                            max_edns_payload: Optional[int] = None,
                            pool_max_size: Optional[int] = None,
                            pool_idle_timeout: Optional[float] = None,
                            doh_version: Optional[str] = None,
                            doh_auto_cache_ttl: Optional[int] = None,
                            load_balancing: Optional[str] = None,
                            bootstrap: Optional[Dict[str, Any]] = None,
                            tcp_fallback_enabled: Optional[bool] = None,
                            tcp_fastopen_enabled: Optional[bool] = None,
                            health_config: Optional[Dict[str, Any]] = None) -> None:
        async with self._config_lock:
            if verbose is not None:
                self.verbose = bool(verbose)
                self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
            if disable_ipv6 is not None:
                self.disable_ipv6 = bool(disable_ipv6)
            if strip_ipv6_records is not None:
                self.strip_ipv6_records = bool(strip_ipv6_records)

            if cache_ttl is not None or cache_max_size is not None:
                new_ttl = cache_ttl if cache_ttl is not None else self._cache_ttl
                new_max = cache_max_size if cache_max_size is not None else self._cache_max_size
                self._cache_ttl = new_ttl
                self._cache_max_size = new_max
                self._init_caches(new_ttl, new_max, self.negative_cache_ttl)

            if negative_cache_ttl is not None:
                self.negative_cache_ttl = max(1, int(negative_cache_ttl))
            if doh_timeout is not None:
                self.doh_timeout = doh_timeout
            if udp_timeout is not None:
                self.udp_timeout = udp_timeout
            if tcp_timeout is not None:
                self.tcp_timeout = tcp_timeout
            if retries is not None:
                self.retries = max(1, int(retries))
            if initial_backoff is not None:
                self.initial_backoff = float(initial_backoff)
            if dns_logging_enabled is not None:
                self.dns_logging_enabled = dns_logging_enabled
                if self.dns_logging_enabled and self._file_logger is None:
                    pass
            if pinned_certs is not None:
                self.pinned_certs = pinned_certs
            if dnssec_enabled is not None:
                self.dnssec_enabled = bool(dnssec_enabled)
                if self.dnssec_enabled and self._dnssec_raw_anchors is None:
                    self._load_trust_anchors()
            if trust_anchors is not None:
                self.trust_anchors = trust_anchors
                if self.dnssec_enabled:
                    self._load_trust_anchors()
            if auto_update_trust_anchor is not None:
                self.auto_update_trust_anchor = auto_update_trust_anchor
            if dnssec_max_validations is not None:
                self.dnssec_max_validations = dnssec_max_validations
            if dnssec_max_dnskey_records is not None:
                self.dnssec_max_dnskey_records = dnssec_max_dnskey_records
            if dnssec_validation_timeout is not None:
                self.dnssec_validation_timeout = dnssec_validation_timeout
            if dnssec_chain_validation is not None:
                self.dnssec_chain_validation = dnssec_chain_validation
            if dnssec_max_iterations is not None:
                self.dnssec_max_iterations = dnssec_max_iterations
            if scrub_unsolicited_ns is not None:
                self.scrub_unsolicited_ns = scrub_unsolicited_ns
            if metrics_enabled is not None:
                self.metrics_enabled = bool(metrics_enabled) and _HAS_PROM
            if metrics_port is not None:
                self.metrics_port = int(metrics_port)
            if rate_limit_rps is not None:
                self.rate_limit_rps = rate_limit_rps
            if rate_limit_burst is not None:
                self.rate_limit_burst = rate_limit_burst
            if self.rate_limit_rps > 0:
                effective_burst = max(1.0, self.rate_limit_burst)
                if self.rate_limiter is None:
                    self.rate_limiter = RateLimiter(self.rate_limit_rps, effective_burst)
                    task = asyncio.create_task(self.rate_limiter.start_cleanup())
                    self._background_tasks.add(task)
                else:
                    self.rate_limiter.rate = self.rate_limit_rps
                    self.rate_limiter.burst = effective_burst
            else:
                if self.rate_limiter is not None:
                    await self.rate_limiter.stop_cleanup()
                    self.rate_limiter = None
            if upstreams is not None:
                self.upstreams = upstreams
            if optimistic_cache_enabled is not None:
                self.optimistic_cache_enabled = optimistic_cache_enabled
            if optimistic_stale_max_age is not None:
                self.stale_max_age = optimistic_stale_max_age
            if optimistic_stale_response_ttl is not None:
                self.stale_response_ttl = optimistic_stale_response_ttl
            if rebind_protection_enabled is not None:
                self.rebind_protection_enabled = rebind_protection_enabled
            if rebind_action is not None:
                self.rebind_action = rebind_action.lower()
            if ecs_enabled is not None:
                self.ecs_enabled = bool(ecs_enabled)
            if max_edns_payload is not None:
                self.max_edns_payload = max(512, int(max_edns_payload))
            if pool_max_size is not None:
                self._tcp_pool.max_size = pool_max_size
                self._h2_pool.max_size = pool_max_size
                self._h3_pool.max_size = pool_max_size
                self._quic_pool.max_size = pool_max_size
            if pool_idle_timeout is not None:
                self._tcp_pool.idle_timeout = pool_idle_timeout
                self._h2_pool.idle_timeout = pool_idle_timeout
                self._h3_pool.idle_timeout = pool_idle_timeout
                self._quic_pool.idle_timeout = pool_idle_timeout
            if doh_version is not None:
                self.doh_version = doh_version
            if doh_auto_cache_ttl is not None:
                self.doh_auto_cache_ttl = doh_auto_cache_ttl
            if load_balancing is not None:
                self.load_balancing = load_balancing.lower()
                if self.load_balancing not in ('failover', 'parallel', 'random', 'roundrobin'):
                    self.load_balancing = 'failover'
            if bootstrap is not None:
                self.bootstrap_servers = bootstrap.get('servers', [])
                self.bootstrap_timeout = bootstrap.get('timeout', 2.0)
                self.bootstrap_retries = bootstrap.get('retries', 2)
            if tcp_fallback_enabled is not None:
                self.tcp_fallback_enabled = tcp_fallback_enabled
            if tcp_fastopen_enabled is not None:
                self.tcp_fastopen_enabled = bool(tcp_fastopen_enabled)
            if health_config is not None:
                self._health_config = health_config
                self._health_enabled = health_config.get('enabled', False)
                self._health_interval = health_config.get('interval', 30)
                self._health_timeout = health_config.get('timeout', 2.0)
                self._health_unhealthy_threshold = health_config.get('unhealthy_threshold', 3)
                self._health_healthy_threshold = health_config.get('healthy_threshold', 2)
                self._health_cooldown = health_config.get('cooldown', 60)
                self._health_domain = health_config.get('domain', '.')
                if self._health_enabled and self._health_task is None and self.upstreams:
                    self._health_task = asyncio.create_task(self._health_check_loop())
                    self._background_tasks.add(self._health_task)
                elif not self._health_enabled and self._health_task is not None:
                    self._health_task.cancel()
                    try:
                        await self._health_task
                    except asyncio.CancelledError:
                        pass
                    self._health_task = None

            if self._started and self.dnssec_enabled:
                if self._insecure_cleanup_task is None or self._insecure_cleanup_task.done():
                    self._insecure_cleanup_task = asyncio.create_task(self._cleanup_insecure_cache())
                    self._background_tasks.add(self._insecure_cleanup_task)
                if self.auto_update_trust_anchor and (
                    self._trust_anchor_updater_task is None
                    or self._trust_anchor_updater_task.done()
                ):
                    self._trust_anchor_updater_task = asyncio.create_task(
                        self._background_trust_anchor_updater()
                    )
                    self._background_tasks.add(self._trust_anchor_updater_task)
            else:
                for task_name in ("_insecure_cleanup_task", "_trust_anchor_updater_task"):
                    task = getattr(self, task_name)
                    if task is not None:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                        self._background_tasks.discard(task)
                        setattr(self, task_name, None)

            self.logger.info("DNSResolver configuration updated: "
                             "disable_ipv6=%s, strip_ipv6_records=%s, verbose=%s, rate_limit=%s/%s, optimistic_cache=%s, "
                             "rebind_protection=%s/%s, doh_version=%s, load_balancing=%s, tcp_fallback=%s, health=%s, "
                             "dnssec_chain_validation=%s, dnssec_max_iterations=%s, scrub_unsolicited_ns=%s",
                             self.disable_ipv6, self.strip_ipv6_records, self.verbose,
                             self.rate_limit_rps, self.rate_limit_burst,
                             self.optimistic_cache_enabled,
                             self.rebind_protection_enabled, self.rebind_action,
                             self.doh_version, self.load_balancing, self.tcp_fallback_enabled,
                             self._health_enabled,
                             self.dnssec_chain_validation, self.dnssec_max_iterations,
                             self.scrub_unsolicited_ns)