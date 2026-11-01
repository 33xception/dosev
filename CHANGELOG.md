# [1.9.7] – 2026-11-01

## Fixed

- **DNSSEC validation now fails closed** – Responses that fail validation or are determined to be bogus now return `SERVFAIL` instead of being served without successful validation.
- **Upstream response questions are validated** – Responses with malformed or mismatched question sections are rejected across UDP, TCP, TLS, DoH, HTTP/3, and DoQ transports.

# [1.9.6] – 2026-08-07

## Fixed

- **Config file encoding error on Windows (GBK systems)** – When configuration files contained non‑ASCII characters (e.g., curly quotes, em dashes), `configparser` would fail with `'gbk' codec can't decode byte...` because it used the system default encoding. The fix explicitly sets `encoding='utf-8'` when reading the config file, ensuring consistent behaviour across all platforms.
- **DoQ connection leaks and "Future exception was never retrieved" warnings** – When a DoQ connection was cancelled (e.g., during parallel load balancing or health‑check timeouts), the asyncio `Future` created for the response was not explicitly cancelled, leaving it pending. When garbage‑collected, this triggered `"Future exception was never retrieved"` warnings in the logs. The fix explicitly cancels the future in all error paths (timeout, cancellation, and general exceptions) before cleaning up the connection.
- **HTTP/3 connection leaks on cancellation** – Similar to the DoQ fix, HTTP/3 connections were not properly cleaned up when the operation was cancelled during the handshake or the request phase. The fix adds explicit `except asyncio.CancelledError` blocks to close the QUIC connection on cancellation, preventing resource leaks and suppressed warnings.
