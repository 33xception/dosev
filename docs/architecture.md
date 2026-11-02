# Architecture

This document describes the internal architecture of `dosev` – its components, data flow, and key design decisions.

---

## Overview

`dosev` is an asynchronous DNS resolver and server built on Python's `asyncio`. It is split into several logical layers:

1. **Configuration** – loading and validating settings from an INI file.
2. **Server** – listening for incoming DNS queries over multiple protocols (UDP, TCP, TLS, HTTPS).
3. **Resolver** – the core logic that processes queries, applies blocklists, handles caching, performs DNSSEC validation, and forwards to upstreams.
4. **Transports** – protocol-specific client implementations for upstream communication (UDP, TCP, TLS, HTTPS, QUIC).
5. **Utilities** – helpers for blocklist fetching, logging, and metrics.

All components are designed to be modular and testable.

---

## High-Level Data Flow

```
Client
   │
   ▼
Server (UDP / TCP / TLS / HTTPS)
   │
   ▼
Resolver.forward_dns_query()
   │
   ├── Hosts override?
   ├── Blocklist match?
   ├── Cache hit?
   │       └── (positive / negative / stale)
   ├── EDNS0 processing (ECS)
   ├── Upstream selection (configurable: failover, parallel, random, roundrobin)
   ├── Forward via transport (UDP/TCP/TLS/DoH/DoQ)
   ├── DNSSEC validation (with chain validation)
   ├── Bailiwick scrubbing
   ├── Cache response
   └── Return to client
```

---

## Core Components

### 1. `DNSResolver` (dosev/resolver.py)

The heart of the system. It manages:

- **Caches**: positive cache (TTL-based), negative cache (NXDOMAIN/NODATA), and stale-serve logic.
- **Blocklists & Hosts**: exact-match and suffix-based domain filtering; static A/AAAA overrides.
- **Upstream management**: supports `failover`, `parallel`, `random`, and `roundrobin` strategies; configured via `load_balancing` in the config. Also includes health checks (circuit breaker) and TCP fallback on truncated UDP responses.
- **DNSSEC**: validates responses using a trust anchor (bundled or IANA-fetched); caches validation results. Respects the client's CD (Checking Disabled) flag – if set, validation is skipped. Includes **KeyTrap mitigation** (CVE-2023-50387) with configurable limits on signature validations, DNSKEY records, and validation timeouts. **Chain validation** (enabled by default via `dnssec_chain_validation`) recursively fetches DS/DNSKEY records to build the full chain of trust, with crypto operations offloaded to a thread executor (`_CRYPTO_EXECUTOR`) to prevent event loop blocking.
- **Cache poisoning prevention**: scrubs unsolicited NS records from the authority section (RFC 2181 Section 5.4.1) to prevent injection attacks (CVE-2025-11411). Configurable via `dns_scrub_unsolicited_ns`.
- **EDNS0**: parses client subnet and forwards it to upstreams. **ECS support** (enabled by default via `dns_ecs_enabled`) truncates client IPs to privacy-safe prefixes (/24 for IPv4, /56 for IPv6 per RFC 7871) before forwarding to upstreams.
- **Rate limiting**: token-bucket per client IP, now **actually enforced** in all transport handlers via `_check_rate_limit()`.
- **Rebinding protection**: strips or blocks private IPs.
- **Metrics**: collects request counts, errors, and latency.
- **Request coalescing**: single-flight deduplication for concurrent identical queries, with per-caller ID/CD bit stamping.
- **Bailiwick verification**: `_is_in_bailiwick()` validates whether record names fall within the queried name's zone of authority (RFC 5452 §3).

#### Health Checks
The resolver periodically tests each upstream using a DNS query (default: SOA for root). If an upstream fails `unhealthy_threshold` consecutive checks, it is marked unhealthy and skipped during query routing. After `cooldown` seconds and `healthy_threshold` successful checks, it is restored. If all upstreams are unhealthy, the resolver uses all of them as a fallback.

#### TCP Fallback
If an upstream returns a UDP response with the TC (truncation) bit set, the resolver automatically retries the same query over TCP to that upstream, returning the full response.

New plain TCP upstream connections can use RFC 7413 TCP Fast Open (`tcp_fastopen_enabled`, enabled by default) to send the DNS query with the connection's initial data and reduce connection latency. It is best-effort: platforms or kernels without client Fast Open support use ordinary TCP connections. Reused pooled connections do not need Fast Open.

**Key Methods**:
- `forward_dns_query(data: bytes) -> bytes` – the main entry point for processing a raw DNS query.
- `_try_upstream(upstream, data) -> bytes` – sends a query to a single upstream, with retries.
- `_wire_cache_get_valid(key) -> Optional[bytes]` – fetches a cached response, with stale-serve logic.
- `_dnssec_validate(qname, response) -> None` – validates DNSSEC signatures with KeyTrap mitigation.
- `_scrub_unsolicited_sections(response, qname) -> bytes` – removes out-of-bailiwick NS records.
- `_attach_ecs_option(query_data, client_ip) -> bytes` – attaches ECS option to query.

### 2. Server Layer (dosev/server.py)

Provides listeners for:
- **UDP**: `asyncio.DatagramProtocol` with rate limiting.
- **TCP**: `asyncio.StreamReader` / `StreamWriter` with rate limiting.
- **TLS (DoT)**: TCP with SSL context on port 853.
- **HTTPS (DoH)**: HTTP/2 and HTTP/3 servers using `aiohttp` and `aioquic`.
- **HTTP/3**: `Http3ServerProtocol` for QUIC-based DoH.

Each listener accepts a query, passes it to the resolver, and sends back the response. All transports enforce rate limiting via `_check_rate_limit()`.

**Graceful Shutdown**: Signal handlers (SIGINT, SIGTERM) trigger a clean shutdown, closing all listeners, connection pools, and background tasks.

### 3. Transports (client-side)

Each transport implements the protocol-specific forwarding logic:
- `_forward_udp()`
- `_forward_tcp()`
- `_forward_tls()`
- `_forward_https1()`, `_forward_https2()`, `_forward_https3()`
- `_forward_quic()` – uses a connection pool (`_quic_pool`) to reuse QUIC connections across multiple queries, reducing handshake overhead.

These handle connection pooling, timeouts, retries, certificate pinning, and the `ip` field to skip DNS resolution.

**HTTP/3 DoH Pooling**: The new `H3DohProtocol` and `H3ConnectionPool` classes provide proper QUIC stream management and connection reuse for HTTP/3 DoH upstreams.

### 4. Caching

Two-layer cache:
- **DNS cache** (`_dns_cache`): stores parsed responses (used for upstream IP resolution).
- **Wire cache** (`_wire_cache`): stores raw wire-format responses for fast replay.

Both support TTL expiration and size limits. The wire cache includes a `dnssec_validated` flag. DNSSEC-specific caches (`_dnssec_key_cache`, `_dnssec_ds_cache`, `_dnssec_insecure_cache`) have bounded sizes and periodic cleanup.

### 5. Configuration (dosev/config.py)

Loads an INI file and returns a flat dictionary with sensible defaults. Supports all sections documented in the configuration reference.
On first run, a default configuration file is created in the OS-specific user config directory (`~/.config/dosev/`, `~/Library/Application Support/dosev/`, or `%APPDATA%\dosev\`).

### 6. Utilities (dosev/utils.py)

- `fetch_blocklists()` – downloads remote blocklists using streaming HTTP.
- Logging helpers.
- Metrics (Prometheus) integration.

---

## Concurrency Model

`dosev` uses `asyncio` for non-blocking I/O. Each client connection is handled in its own coroutine; the resolver is stateless, so multiple queries can be processed concurrently.

**Thread safety**: The resolver uses `asyncio.Lock` for mutable state (caches, blocklists, configuration). Connection pools also use locks. CPU-bound operations (DNSSEC crypto) are offloaded to a `ThreadPoolExecutor` (`_CRYPTO_EXECUTOR`).

**Background tasks**:
- Connection pool cleanup (TCP, TLS, HTTP/2, HTTP/3, DoQ).
- Blocklist refresh.
- DNSSEC trust anchor update.
- Health checks (circuit breaker).
- Rate limiter bucket cleanup.
- DNSSEC insecure cache cleanup.

All background tasks are tracked in `_background_tasks` for clean shutdown.

---

## Security Considerations

- **Privilege dropping**: After binding to privileged ports, the process drops to a non-root user/group (Linux/Unix).
- **Certificate pinning**: SHA-256 pinning for TLS connections.
- **Certificate verification**: DoQ now uses `CERT_REQUIRED` with proper CA bundle loading.
- **Rebinding protection**: Prevents DNS rebinding attacks by filtering private IPs.
- **Rate limiting**: Protects against DDoS.
- **DNSSEC**: Validates response authenticity with KeyTrap mitigation and chain validation.
- **Cache poisoning prevention**: Scrubs unsolicited NS records to prevent injection attacks.
- **UDP transaction-ID verification**: Prevents response spoofing by matching query IDs.
- **Bailiwick scrubbing**: Removes out-of-zone authority records.
- **chroot**: Optional jail for additional isolation.

---

## Post-Quantum Readiness

`dosev` includes foundational support for post-quantum cryptography, primarily focused on **transport security** (TLS) to mitigate the harvest-now-decrypt-later threat.

### Transport PQ Status

| Transport | PQ Status | Notes |
|-----------|-----------|-------|
| **DoT** (DNS-over-TLS) | classical only | Uses Python's `ssl` module. OpenSSL 3.5+ supports hybrid X25519MLKEM768 groups, but Python's `ssl` does not expose group selection APIs. Requires `OPENSSL_CONF` environment variable workaround. |
| **DoH 1.1/2** | classical only | Uses `aiohttp` which uses Python's `ssl`. Same limitation as DoT. |
| **DoH/3** (HTTP/3) | classical only | Uses `aioquic` library (v1.3.0). Currently has only classical groups: X25519, X448, SECP256R1, SECP384R1, SECP521R1, GREASE. No ML-KEM support. |
| **DoQ** (DNS-over-QUIC) | classical only | Uses `aioquic` library. Same limitation as DoH/3. |

### Configuration

The `[security]` section includes `pqc_mode`:
- `auto` (default): Logs a startup warning if OpenSSL < 3.5 or group control unavailable
- `off`: Disables PQ group preference

**Not hot-reloadable**: TLS context cannot be reinitialized after startup.

### Handshake Failure Monitoring

TLS handshake failures are tracked with the Prometheus metric:
- `dosev_upstream_handshake_failures_total` (labels: `upstream`, `reason`)

Rate-limited warnings (once per 5 minutes per upstream) help diagnose middlebox compatibility issues with oversized ClientHellos (hybrid groups add ~1216 bytes to the key share).

### DNSSEC Considerations

DNSSEC signature validation already handles unknown algorithms correctly per RFC 4035 Section 5.3.2: unsupported algorithms yield **insecure** (not bogus), allowing the response to be served. This prevents PQ algorithm deployment from breaking resolution.

DNSSEC signatures themselves are not currently vulnerable to harvest-now-decrypt-later because:
1. Validators choose the trust anchor
2. Signatures are ephemeral and expire
3. IETF PQ DNSSEC signature algorithms are still at draft stage

See [docs/pqc.md](pqc.md) for detailed configuration and troubleshooting.

---

## Performance Optimizations

- **Asynchronous I/O**: All network operations are non-blocking.
- **Connection pooling**: Reuses TCP/TLS/HTTP/2/HTTP/3/DoQ connections to reduce handshake overhead.
- **Caching**: Reduces upstream load and latency.
- **Optimistic caching**: Serves stale responses while refreshing in the background.
- **Request coalescing**: Deduplicates concurrent identical queries.
- **uvloop**: Optional faster event loop (Unix).
- **Thread executor**: Offloads CPU-bound crypto operations.

---
## Extensibility

The modular design makes it easy to add:
- New transport protocols (e.g., DNSCrypt, ODoH).
- Additional caching strategies.
- Custom load-balancing policies.
- New metrics or logging backends.

---
## Dependencies

| Library | Purpose |
|---------|---------|
| `dnspython` | DNS message parsing and construction. |
| `aiohttp` | HTTP/1.1 and HTTP/2 client & server. |
| `aioquic` | HTTP/3 and QUIC client & server. |
| `httpx` | HTTP/2 client (optional fallback). |
| `cachetools` | TTL cache (fallback to internal `AsyncTTLCache`). |
| `prometheus-client` | Metrics exposition. |
| `cryptography` | Certificate handling. |

---
## Testing

- **Unit tests**: cover all core logic with mocked network calls.
- **Integration tests**: test against real upstreams (using `dig` or stub servers).
- **CI**: runs on Linux, macOS, and Windows for Python 3.11–3.14.

---
## Future Directions

- Full RFC 5011 trust anchor management.
- DNSCrypt and ODoH client/server support.
- More advanced EDNS0 options.
- Enhanced load balancing (weighted, latency-based).
- Web-based status dashboard.