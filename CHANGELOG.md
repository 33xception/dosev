# [1.10.1] – 2026-11-01

## Added

- **Persistent DNS/TCP client connections** – Serve multiple queries on a connection, with per-query rate limiting.
- **Bounded request handling** – Limit pending UDP queries, concurrent TCP/DoH/HTTP/3 work, and HTTP/3 DNS message sizes.

## Fixed

- **Client-aware ECS and cache isolation** – Forward the transport client's subnet and separate cached or coalesced answers by ECS scope and query semantics.
- **DNSSEC and EDNS behavior** – Validate when DNSSEC is enabled and CD is clear, regardless of client DO; normalize OPT and DNSSEC records for the client request.
- **UDP response truncation** – Truncate oversized responses to the client's advertised payload and set TC.
- **Cache correctness** – Do not cache SERVFAIL or zero-TTL answers; decrement TTLs on cache hits and preserve EDNS metadata.
- **Connection and task cleanup** – Close failed upstream TCP connections, stop pool and background cleanup tasks, and release HTTP/3 protocols at shutdown.
- **Privilege dropping** – Clear supplementary groups before changing GID and UID.
- **HTTP/3 GET handling** – Dispatch header-terminated GET requests and reject oversized request bodies.

## Performance

- **Fallback cache eviction** – Replace full-map expiry scans with constant-time bounded eviction.
- **Blocklist refresh I/O** – Move writes off the event loop and atomically replace files only after successful downloads.

# [1.9.7] – 2026-11-01

## Fixed

- **DNSSEC validation now fails closed** – Responses that fail validation or are determined to be bogus now return `SERVFAIL` instead of being served without successful validation.
- **Upstream response questions are validated** – Responses with malformed or mismatched question sections are rejected across UDP, TCP, TLS, DoH, HTTP/3, and DoQ transports.

# [1.9.6] – 2026-08-07

## Fixed

- **Config file encoding error on Windows (GBK systems)** – When configuration files contained non‑ASCII characters (e.g., curly quotes, em dashes), `configparser` would fail with `'gbk' codec can't decode byte...` because it used the system default encoding. The fix explicitly sets `encoding='utf-8'` when reading the config file, ensuring consistent behaviour across all platforms.
- **DoQ connection leaks and "Future exception was never retrieved" warnings** – When a DoQ connection was cancelled (e.g., during parallel load balancing or health‑check timeouts), the asyncio `Future` created for the response was not explicitly cancelled, leaving it pending. When garbage‑collected, this triggered `"Future exception was never retrieved"` warnings in the logs. The fix explicitly cancels the future in all error paths (timeout, cancellation, and general exceptions) before cleaning up the connection.
- **HTTP/3 connection leaks on cancellation** – Similar to the DoQ fix, HTTP/3 connections were not properly cleaned up when the operation was cancelled during the handshake or the request phase. The fix adds explicit `except asyncio.CancelledError` blocks to close the QUIC connection on cancellation, preventing resource leaks and suppressed warnings.
