# Post-Quantum Cryptography (PQC) Readiness

This document describes dosev's post-quantum readiness for encrypted DNS transports and DNSSEC validation.

---

## Threat Model

### Transport Security (Harvest-Now-Decrypt-Later)

The primary post-quantum threat for DNS is **harvest-now-decrypt-later**: an adversary captures encrypted DNS traffic today and decrypts it later when quantum computers become capable of breaking classical ECDH/RSA key exchange.

**Priority: HIGH** – Transport encryption (TLS for DoT/DoH/DoQ) must use hybrid post-quantum key exchange to protect against this threat.

### DNSSEC Signatures

DNSSEC signatures use RSA/ECDSA/Ed25519 algorithms. These signatures **cannot be harvested** for later decryption because:
1. The validator chooses the trust anchor (root zone key)
2. Signatures are ephemeral and expire
3. The IETF is still drafting post-quantum DNSSEC signature algorithms

**Priority: LOW** – DNSSEC signatures are not currently vulnerable to harvest-now-decrypt-later. Future work will add PQ signature algorithms when standardized.

---

## Transport PQ Status

| Transport | PQ Status | Details |
|-----------|-----------|---------|
| **DoT** (DNS-over-TLS) | classical only | Uses Python's `ssl` module. OpenSSL 3.5+ supports hybrid X25519MLKEM768 groups, but Python's ssl does not expose group selection API. Requires `OPENSSL_CONF` workaround. |
| **DoH 1.1/2** (DNS-over-HTTPS) | classical only | Uses `aiohttp` which uses Python's `ssl`. Same as DoT. |
| **DoH/3** (HTTP/3) | classical only | Uses `aioquic` library. Version 1.3.0 has only classical groups: X25519, X448, SECP256R1, SECP384R1, SECP521R1, GREASE. No ML-KEM support. |
| **DoQ** (DNS-over-QUIC) | classical only | Uses `aioquic` library. Same as DoH/3. |

**Verification**: Run `dosev --crypto-info` to see the current PQ status for each transport in your environment.

---

## Configuration

### `pqc_mode` (in `[security]` section)

```ini
[security]
pqc_mode = auto
```

**Values**:
- `auto` (default): Automatically use PQ groups when available
- `off`: Disable PQ groups (use classical only)

**Current behavior**:
- When `auto` and OpenSSL >= 3.5, a **startup warning** is logged explaining that Python's ssl module does not expose group control APIs, and the `OPENSSL_CONF` workaround is required.
- When `off`, no warning is logged.
- The setting is **not hot-reloadable** (TLS context cannot be reinitialized after startup).

---

## OpenSSL 3.5+ Configuration

### Using `OPENSSL_CONF` Environment Variable

OpenSSL 3.5 introduces the ML-KEM hybrid key exchange groups. To enable them for DoT/DoH, you must configure OpenSSL via the `OPENSSL_CONF` environment variable:

```bash
# Set before starting dosev
export OPENSSL_CONF=/etc/ssl/openssl-pq.cnf
dosev
```

Or in a single command:
```bash
OPENSSL_CONF=/etc/ssl/openssl-pq.cnf dosev
```

### Example `openssl-pq.cnf`

Create `/etc/ssl/openssl-pq.cnf` with:

```ini
[openssl_init]
providers = provider_sect
algorithms = algorithm_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1

[algorithm_sect]
default_properties = default_sect

[default_sect]
# Enable ML-KEM hybrid groups for TLS 1.3
# X25519MLKEM768: X25519 + ML-KEM-768 hybrid
# This makes ClientHellos larger (~1216 bytes for the key share)
tls1_3_groups = X25519MLKEM768:X25519
```

**Note**: The exact group names may vary. Check your OpenSSL 3.5+ documentation for the correct syntax. The `tls1_3_groups` configuration restricts the groups offered in ClientHellos to only hybrid and classical X25519.

### Systemd Service

For systemd services, add the environment variable to your unit file:

```ini
[Service]
Environment=OPENSSL_CONF=/etc/ssl/openssl-pq.cnf
ExecStart=/usr/local/bin/dosev -c /etc/dosev/dosev.ini
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dosev
```

---

## Middlebox Compatibility

### ClientHello Size

The hybrid X25519MLKEM768 key share is **1216 bytes**, making ClientHellos significantly larger than with classical groups (~100-200 bytes). Some middleboxes and servers may:

- Reject oversized ClientHellos
- Drop connections without explanation
- Time out waiting for the handshake

### Symptoms

- TLS handshake failures to known-good servers
- `dosev_upstream_handshake_failures_total` metric increasing
- Log messages: `TLS handshake failed for upstream ...`

### Workarounds

1. **Verify OpenSSL version**: Run `dosev --crypto-info` to confirm OpenSSL >= 3.5
2. **Test with `openssl s_client`**: 
   ```bash
   openssl s_client -connect 1.1.1.1:853 -tls1_3 -groups X25519MLKEM768
   ```
3. **Check middlebox limits**: Some firewalls/load balancers have hard-coded ClientHello size limits
4. **Fallback to classical**: Set `pqc_mode = off` if middleboxes cannot handle hybrid groups

---

## Metrics and Monitoring

### Prometheus Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `dosev_upstream_handshake_failures_total` | `upstream`, `reason` | Count of TLS handshake failures. `reason` can be `timeout`, `refused`, `handshake_error`, `unknown`. |

### Log Messages

- **Start-up warning** (once per start, when `pqc_mode=auto` and OpenSSL < 3.5):
  ```
  WARNING: pqc_mode=auto requested but Python's ssl module is linked to OpenSSL < 3.5. 
  Hybrid X25519MLKEM768 groups are NOT available. 
  To use PQ groups, set OPENSSL_CONF environment variable before starting dosev.
  Example: OPENSSL_CONF=/etc/ssl/openssl-pq.cnf dosev
  ```

- **Handshake failure warning** (rate-limited: once per 5 minutes per upstream):
  ```
  WARNING: TLS handshake failed for upstream 1.1.1.1:853 (DoT). 
  Reason: handshake_error. 
  Possible cause: Oversized ClientHello with PQ groups. 
  If using OpenSSL >= 3.5 with pqc_mode=auto, verify OPENSSL_CONF is set.
  ```

---

## Verification

### Check Environment

```bash
# Run diagnostics
dosev --crypto-info

# Expected output (OpenSSL 3.5+):
# Python version: 3.x.x
# ssl.OPENSSL_VERSION: OpenSSL 3.5.x
# OpenSSL >= 3.5: YES
# aioquic Support: ML-KEM support: NO
# Transport PQ Status:
#   DoT: classical only
#   DoH 1.1: classical only
#   DoH 2: classical only
#   DoH/3: classical only
#   DoQ: classical only
```

### Test DoT with PQ Groups

```bash
# Verify OpenSSL supports hybrid groups
openssl s_server -accept 853 -cert server.crt -key server.key -tls1_3 -groups X25519MLKEM768 &

# In another terminal, use dosev with OPENSSL_CONF
OPENSSL_CONF=/etc/ssl/openssl-pq.cnf dosev -c test-pqc.ini

# Query via DoT (should succeed with hybrid groups)
dig @127.0.0.1 -p 853 example.com +tls +tls-ca=ca.crt
```

### Test aioquic PQ Support

```bash
# Check if aioquic has ML-KEM support (should show NO for v1.3.0)
python -c "from dosev.cryptoinfo import check_aioquic_pq_support; print(check_aioquic_pq_support())"
```

---

## Future Work

### DNSSEC Post-Quantum Signatures

The IETF is drafting post-quantum DNSSEC signature algorithms. When standardized, dosev will support them with:
- Configurable PQ signature validation
- Trust anchor updates
- Backward compatibility with classical signatures

### aioquic ML-KEM Support

Monitor [aioquic](https://github.com/aio-libs/aioquic) for ML-KEM support. When available:
- Update DoQ and DoH/3 to use hybrid groups
- Update transport PQ status table
- Add regression tests to detect when support lands

### Python ssl API

Monitor CPython for TLS 1.3 group control APIs. When available:
- Implement `pqc_mode` with in-process group selection
- Remove OPENSSL_CONF workaround requirement
- Update documentation

---

## References

- [RFC 8701: ML-KEM for TLS](https://datatracker.ietf.org/doc/html/rfc8701)
- [RFC 8998: Hybrid Key Exchange in TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8998)
- [OpenSSL 3.5 Release Notes](https://www.openssl.org/news/openssl-3.5-notes.html)
- [NIST PQC Standardization Process](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [IETF DNSSEC PQ Drafts](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-dnssec-pq-signatures)
