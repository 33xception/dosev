# Configuration Reference

`dosev` uses an INI-style configuration file. This document describes every available option.

---

## Global Sections

### `[server]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `listen_ip` | string | `0.0.0.0` | IP address to bind to. |
| `listen_port` | int | `53` | Port for UDP and TCP (plain DNS). |

---

### `[resolver]`

**Note:** `upstream_dns` and `protocol` are **deprecated** and have been removed.
All upstreams are now defined in the `[upstreams]` section (see below).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `verbose` | bool | `false` | Enable debug logging. |
| `disable_ipv6` | bool | `false` | Do not query AAAA records. |
| `strip_ipv6_records` | bool | `false` | Strip AAAA records from responses. |
| `dns_ecs_enabled` | bool | `true` | Enable EDNS Client Subnet. |
| `dns_max_payload` | int | `4096` | Maximum EDNS payload size (512–4096). |
| `dns_enable_dot` | bool | `false` | Enable DNS-over-TLS server listener. |
| `dns_dot_port` | int | `853` | Port for DoT server. |
| `dns_dot_cert_file` | string | `""` | Certificate file for DoT server. |
| `dns_dot_key_file` | string | `""` | Private key file for DoT server. |
| `dns_enable_doh` | bool | `false` | Enable DNS-over-HTTPS (HTTP/1.1 & HTTP/2) server listener. |
| `dns_enable_http3` | bool | `false` | Enable DNS-over-HTTPS (HTTP/3) server listener. Requires the same certificate and key files as DoH. |
| `dns_doh_port` | int | `443` | Port for DoH/HTTP/3 server. |
| `dns_doh_cert_file` | string | `""` | Certificate file for DoH/HTTP/3 server. |
| `dns_doh_key_file` | string | `""` | Private key file for DoH/HTTP/3 server. |
| `dns_doh_path` | string | `/dns-query` | URL path for DoH/HTTP/3 server. |

---
### `[cache]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ttl` | int | `300` | TTL (seconds) for positive cache entries. |
| `max_size` | int | `1024` | Maximum number of cache entries. |
| `negative_ttl` | int | `5` | TTL for negative (NXDOMAIN) cache entries (used when SOA MINIMUM is not available). |

---
### `[timeouts]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `udp` | float | `2.0` | UDP query timeout (seconds). |
| `tcp` | float | `5.0` | TCP/TLS query timeout. |
| `doh` | float | `5.0` | DoH/DoQ query timeout. |

---
### `[advanced]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `retries` | int | `2` | Number of retries per upstream. |
| `rate_limit_rps` | float | `0.0` | Request per second per client IP (0 = disabled). |
| `rate_limit_burst` | float | `0.0` | Max burst (must be ≥ `rate_limit_rps`). |
| `optimistic_cache_enabled` | bool | `false` | Serve stale responses while refreshing. |
| `optimistic_stale_max_age` | int | `86400` | Maximum age (seconds) for stale responses. |
| `optimistic_stale_response_ttl` | int | `30` | TTL to set on stale responses. |
| `pool_max_size` | int | `5` | Max connections per upstream pool. |
| `pool_idle_timeout` | float | `60.0` | Idle timeout (seconds) for pooled connections. |
| `doh_version` | string | `auto` | DoH version: `1.1`, `2`, `3`, or `auto`. |
| `doh_auto_cache_ttl` | int | `3600` | Cache TTL for auto-detected DoH versions. |
| `load_balancing` | string | `failover` | Upstream selection strategy: `failover` (try in order), `parallel` (query all, return first success), `random` (pick random), `roundrobin` (cycle through). |
| `tcp_fallback_enabled` | bool | `true` | Automatically retry truncated UDP responses over TCP. |
| `tcp_fastopen_enabled` | bool | `true` | Use RFC 7413 TCP Fast Open for new plain TCP upstream connections when supported. This can reduce connection latency for TCP fallback and TCP upstream queries; unsupported platforms or kernels use normal TCP connects. |
| `initial_backoff` | float | `0.1` | Initial backoff (seconds) before first retry, doubles each attempt. |

---
### `[health]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable periodic health checks for upstreams. |
| `interval` | int | `30` | Interval between health checks (seconds). |
| `timeout` | float | `2.0` | Timeout for each health check query. |
| `unhealthy_threshold` | int | `3` | Consecutive failures to mark upstream unhealthy. |
| `healthy_threshold` | int | `2` | Consecutive successes to mark upstream healthy again. |
| `cooldown` | int | `60` | Seconds to wait before retrying a failed upstream. |
| `domain` | string | `.` | Domain name to query for health checks (default: root SOA). |

**Note:** Health checks are performed using the same protocol as the upstream (UDP for UDP, TCP for TCP, etc.). If all upstreams are unhealthy, the resolver falls back to using all upstreams (to avoid complete service failure).

---
### `[security]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dnssec_enabled` | bool | `false` | Enable DNSSEC validation. |
| `auto_update_trust_anchor` | bool | `true` | Automatically fetch root trust anchor from IANA. |
| `trust_anchors_file` | string | `""` | Custom trust anchor file (overrides built-in). |
| `dnssec_max_validations` | int | `32` | Maximum number of signatures validated per response (KeyTrap mitigation, CVE-2023-50387). Set to `0` to disable limit. |
| `dnssec_max_dnskey_records` | int | `8` | Maximum number of DNSKEY records processed per domain (KeyTrap mitigation). |
| `dnssec_validation_timeout` | float | `2.0` | Timeout in seconds for DNSSEC validation operations. |
| `dnssec_chain_validation` | bool | `true` | Enable the recursive chain-of-trust validation (fetches DS/DNSKEY). If false, falls back to the legacy static validation using only the root anchor. |
| `dnssec_max_iterations` | int | `100` | Maximum number of iterations (validation steps) to prevent infinite loops (RFC 9276). |
| `dns_scrub_unsolicited_ns` | bool | `true` | Scrub unsolicited NS records from authority section to prevent cache poisoning (RFC 2181 Section 5.4.1, CVE-2025-11411). |
| `pqc_mode` | string | `auto` | Post-quantum cryptography mode. `auto`: use PQ groups when available (requires OpenSSL >= 3.5, logs warning if unavailable). `off`: disable PQ groups. **Not hot-reloadable**. |
| `pinned_certs` | string | `""` | Comma-separated `hostname=sha256` pins for TLS connections. |
| `rebind_protection` | bool | `false` | Enable rebinding protection. |
| `rebind_action` | string | `strip` | `strip` or `block` when private IPs are detected. |
| `dns_privilege_drop_user` | string | `""` | User to drop privileges to (Linux/Unix). |
| `dns_privilege_drop_group` | string | `""` | Group to drop privileges to. |
| `dns_chroot_dir` | string | `""` | chroot directory (Linux/Unix). |

**Note:** If the client sets the CD (Checking Disabled) flag in the query, validation is automatically bypassed, regardless of the `dnssec_enabled` setting.

---
### `[logging]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable request logging to file. |
| `log_dir` | string | `/var/log/dosev` or `%LOCALAPPDATA%/dosev/logs` | Directory for log files. |
| `retention_days` | int | `7` | Number of days to keep log files. |
| `log_prefix` | string | `dns-log` | Prefix for log filenames. |

**Note:** Only plain text logging is supported; JSON output is not implemented.

---
### `[metrics]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Prometheus metrics endpoint. |
| `port` | int | `8000` | Port for metrics server. |
| `uvloop_enable` | bool | `false` | Use uvloop (faster event loop on Unix). |

---
### `[bootstrap]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `servers` | string | `1.1.1.1:53,8.8.8.8:53` | Comma-separated list of bootstrap DNS servers (used to resolve upstream hostnames). |
| `timeout` | float | `2.0` | Timeout for bootstrap lookups. |
| `retries` | int | `2` | Number of retries for bootstrap. |

---
### `[upstreams]`

Define multiple upstream servers with custom settings.

```ini
[upstreams]
servers = primary,secondary

[upstreams.primary]
address = 1.1.1.1
protocol = udp
port = 53
# optional fixed IP – if provided, no DNS resolution is performed for this upstream
ip = 1.1.1.1

[upstreams.secondary]
address = dns.google
protocol = tls
port = 853
hostname = dns.google         # SNI (defaults to 'address')
```

Each upstream section supports:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `address` | string | **required** | IP or hostname of the upstream server. |
| `protocol` | string | `udp` | `udp`, `tcp`, `tls`, `https`, `quic`. |
| `port` | int | auto | Port number (defaults to standard port for the protocol: 53 for UDP/TCP, 853 for TLS/DoQ, 443 for HTTPS). |
| `hostname` | string | `address` | SNI for TLS/DoH/DoQ and HTTP Host header. |
| `path` | string | `/dns-query` | DoH URL path (only for `https` protocol). |
| `doh_version` | string | `auto` | `auto`, `1.1`, `2`, `3`. |
| `ip` | string | `""` | Optional fixed IP address. If set, DNS resolution is skipped entirely. |

**Upstream selection**: The `load_balancing` option in `[advanced]` controls the strategy:
- `failover` – try upstreams in the order they appear; fall back to the next on failure.
- `parallel` – send the query to **all** upstreams concurrently and return the first successful response.
- `random` – pick a random upstream for each query.
- `roundrobin` – cycle through the list in order.

---
### `[blocklists]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable blocklist filtering. |
| `urls` | string | `""` | Comma-separated list of URLs to fetch. |
| `interval_seconds` | int | `86400` | Refresh interval for remote lists. |
| `action` | string | `NXDOMAIN` | Action for blocked domains: `NXDOMAIN`, `REFUSED`, `ZEROIP`. |
| `local_blocklist_dir` | string | `blocklists` | Directory to store downloaded lists. |
| `reload_on_change` | bool | `true` | Automatically reload if files change. |

---
## Example Full Configuration

See the default configuration file created on first run for a complete example covering all sections.