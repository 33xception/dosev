# dosev/config.py – configuration loading and default content
import os
import sys
import configparser
import warnings
from typing import Dict, Any, List, Optional

# ---------- Default configuration content with comments ----------
DEFAULT_CONFIG_CONTENT = """#
# dosev configuration file
# All paths can be absolute or relative to the working directory.
#
# ============================================================================
# SERVER – local listener settings
# ============================================================================
[server]
# IP address to listen on. Use 0.0.0.0 for all interfaces.
listen_ip = 0.0.0.0
# UDP and TCP port for DNS (standard is 53).
listen_port = 53

# ============================================================================
# RESOLVER – general resolver behaviour
# ============================================================================
[resolver]
# Enable verbose logging (debug level).
verbose = false
# If true, all IPv6 answers will be stripped (AAAA records removed).
disable_ipv6 = false
# Strip AAAA records from responses (applied after resolution).
strip_ipv6_records = false
# Enable EDNS Client Subnet (ECS) – helps CDNs but may reduce privacy.
dns_ecs_enabled = true
# Maximum EDNS payload size (512–4096).
dns_max_payload = 4096

# ---------- DNS over TLS (DoT) server listener ----------
dns_enable_dot = false
# dns_dot_port = 853
# dns_dot_cert_file = /path/to/cert.pem
# dns_dot_key_file = /path/to/key.pem

# ---------- DNS over HTTPS (DoH) server listener ----------
# HTTP/1.1 and HTTP/2 are provided by aiohttp.
dns_enable_doh = false
# dns_doh_port = 443
# dns_doh_cert_file = /path/to/cert.pem
# dns_doh_key_file = /path/to/key.pem
# dns_doh_path = /dns-query

# ---------- DNS over HTTPS (HTTP/3) server listener ----------
dns_enable_http3 = false

# ============================================================================
# CACHE – local caching settings
# ============================================================================
[cache]
# Positive cache TTL (seconds)
ttl = 300
# Maximum number of entries in the cache.
max_size = 1024
# Negative cache TTL (seconds) – used when SOA MINIMUM is not available.
negative_ttl = 5

# ============================================================================
# TIMEOUTS – upstream communication timeouts (seconds)
# ============================================================================
[timeouts]
udp = 2.0
tcp = 5.0
doh = 5.0

# ============================================================================
# ADVANCED – performance and experimental features
# ============================================================================
[advanced]
# Number of retries per upstream before failing over.
retries = 2
# Initial backoff (seconds) before first retry, doubles each attempt.
initial_backoff = 0.1
# Rate limiting (queries per second per client IP). 0 = unlimited.
rate_limit_rps = 0.0
# Burst size for rate limiter (token bucket).
rate_limit_burst = 0.0
# Serve stale responses (RFC 8767) when a fresh answer is unavailable.
optimistic_cache_enabled = false
# How long (seconds) a stale entry can be kept.
optimistic_stale_max_age = 86400
# TTL to set on stale responses (to prevent client caching).
optimistic_stale_response_ttl = 30
# Connection pooling for TCP/TLS/HTTP/2/HTTP/3/DoQ.
pool_max_size = 5
pool_idle_timeout = 60.0
# DoH version preference: auto, 1.1, 2, or 3.
doh_version = auto
# TTL for caching the DoH version auto‑detection result.
doh_auto_cache_ttl = 3600
# Upstream selection strategy: failover, parallel, random, roundrobin.
# - failover: try upstreams in order until one succeeds.
# - parallel: query all upstreams concurrently, return the first successful response.
# - random: pick a random upstream for each query.
# - roundrobin: cycle through upstreams in order.
load_balancing = failover
# Automatically retry a UDP query over TCP if the response has the TC (truncation) bit set.
tcp_fallback_enabled = true
# Use TCP Fast Open for new plain TCP upstream connections where supported.
tcp_fastopen_enabled = true

# ============================================================================
# HEALTH – upstream health checks (circuit breaker)
# ============================================================================
[health]
# Enable periodic health checks for upstream servers.
enabled = false
# Interval between health checks (seconds).
interval = 30
# Timeout for each health check query.
timeout = 2.0
# Number of consecutive failures before marking an upstream unhealthy.
unhealthy_threshold = 3
# Number of consecutive successes before marking an upstream healthy again.
healthy_threshold = 2
# Cooldown period (seconds) before retrying a previously unhealthy upstream.
cooldown = 60
# Optional custom domain to query for health checks (default: "." for root SOA).
# domain = .

# ============================================================================
# SECURITY – DNSSEC, certificate pinning, rebind protection, privilege drop
# ============================================================================
[security]
# Enable DNSSEC validation (requires trust anchors).
dnssec_enabled = false
# Automatically fetch the latest root trust anchor from IANA.
auto_update_trust_anchor = true
# Path to a file containing additional trust anchors (DNSKEY or DS records).
trust_anchors_file =
# DNSSEC KeyTrap mitigation (CVE-2023-50387):
# Limit the number of signatures validated per response.
# Set to 0 to disable limits (not recommended).
dnssec_max_validations = 32
# Limit the number of DNSKEY records processed per validation.
dnssec_max_dnskey_records = 8
# Timeout in seconds for DNSSEC validation operations.
dnssec_validation_timeout = 2.0
# Enable the new recursive chain‑of‑trust validation (fetches DS/DNSKEY).
# If false, falls back to the legacy static validation using only the root anchor.
dnssec_chain_validation = true
# Maximum number of iterations (validation steps) to prevent infinite loops.
dnssec_max_iterations = 100
# Scrub unsolicited NS records from authority section to prevent cache poisoning.
# See: CVE-2025-11411, RFC 2181 Section 5.4.1
dns_scrub_unsolicited_ns = true
# Certificate pinning: comma‑separated list of host=sha256(der) pairs.
pinned_certs =
# Rebinding protection: prevent responses containing private IPs.
rebind_protection = false
# Action: strip (remove private IPs) or block (return NXDOMAIN).
rebind_action = strip
# Privilege drop (only works on Unix when run as root).
dns_privilege_drop_user =
dns_privilege_drop_group =
dns_chroot_dir =

# ============================================================================
# LOGGING – DNS request logging (file rotation)
# ============================================================================
[logging]
enabled = false
retention_days = 7
# Directory to store log files. If empty, uses OS‑specific default.
log_dir =
log_prefix = dns-log

# ============================================================================
# METRICS – Prometheus metrics endpoint
# ============================================================================
[metrics]
enabled = false
port = 8000
# Use uvloop for better performance (requires uvloop installed).
uvloop_enable = false

# ============================================================================
# BOOTSTRAP – DNS servers used to resolve upstream hostnames
# ============================================================================
[bootstrap]
# Comma‑separated list of DNS servers (IP:port) to use for bootstrapping.
servers = 1.1.1.1:53,8.8.8.8:53
timeout = 2.0
retries = 2

# ============================================================================
# UPSTREAMS – define your DNS upstreams
# ============================================================================
#
# Each upstream is a named section under [upstreams].
# The list of active upstreams is defined in the "servers" option below.
#
# Fields:
#   address   – domain name or IP address (required)
#   protocol  – udp, tcp, tls, https, or quic (default: udp)
#   port      – optional, default depends on protocol
#   hostname  – SNI for TLS/DoH; defaults to address
#   path      – DoH URL path (default: /dns-query)
#   ip        – optional fixed IP address to avoid DNS resolution
#   doh_version – 1.1, 2, 3, or auto (default: auto)
#
# Example with fixed IP (no DNS resolution needed):
#   [upstreams.cloudflare]
#   address = cloudflare-dns.com
#   protocol = https
#   port = 443
#   ip = 1.1.1.1
#   doh_version = auto
#
# Example without fixed IP (uses bootstrap servers to resolve):
#   [upstreams.google]
#   address = dns.google
#   protocol = https
#   port = 443
#   doh_version = auto

[upstreams]
# List the active upstreams (comma‑separated names from sections above)
servers =

# ============================================================================
# BLOCKLISTS – domain filtering
# ============================================================================
#
# Blocklists can be loaded from local files or downloaded from URLs.
# The list is refreshed periodically.
#
[blocklists]
enabled = false
# Comma‑separated URLs of blocklist files (hosts‑format or domain‑per‑line).
urls =
interval_seconds = 86400
# Action: NXDOMAIN, REFUSED, or ZEROIP.
action = NXDOMAIN
# Local directory where blocklist files are stored.
local_blocklist_dir = blocklists
# Reload on change (inotify on Linux, periodic check on other OS).
reload_on_change = true
"""

# ---------- OS‑specific config directory ----------
def _default_log_dir() -> str:
    if os.name == 'nt':
        return os.path.join(os.getenv('LOCALAPPDATA') or os.path.expanduser('~'), 'dosev', 'logs')
    return '/var/log/dosev'

def get_user_config_dir() -> str:
    """Return the OS‑specific user configuration directory for dosev."""
    if os.name == 'nt':
        base = os.getenv('APPDATA')
        if not base:
            base = os.path.expanduser('~')
        return os.path.join(base, 'dosev')
    elif sys.platform == 'darwin':
        return os.path.join(os.path.expanduser('~/Library/Application Support'), 'dosev')
    else:
        return os.path.join(os.path.expanduser('~/.config'), 'dosev')

def get_default_config_path() -> str:
    """Return the full path to the default configuration file."""
    return os.path.join(get_user_config_dir(), 'dosev.conf')

def write_default_config(path: str) -> None:
    """Write the default configuration content to the given path."""
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(DEFAULT_CONFIG_CONTENT)

# ---------- Validation and loading ----------
def _validate_and_warn(config: Dict[str, Any]) -> None:
    listen_port = config.get('listen_port', 53)
    if not isinstance(listen_port, int) or not 1 <= listen_port <= 65535:
        raise ValueError('listen_port must be between 1 and 65535')

    dns_max_payload = config.get('dns_max_payload', 4096)
    if not isinstance(dns_max_payload, int) or not 512 <= dns_max_payload <= 4096:
        raise ValueError('dns_max_payload must be between 512 and 4096')

    if config.get('dns_enable_dot', False) and not (config.get('dns_dot_cert_file') and config.get('dns_dot_key_file')):
        raise ValueError('dns_enable_dot requires dns_dot_cert_file and dns_dot_key_file')

    if config.get('dns_enable_doh', False) and not (config.get('dns_doh_cert_file') and config.get('dns_doh_key_file')):
        raise ValueError('dns_enable_doh requires dns_doh_cert_file and dns_doh_key_file')

    if config.get('dns_enable_http3', False) and not (config.get('dns_doh_cert_file') and config.get('dns_doh_key_file')):
        raise ValueError('dns_enable_http3 requires dns_doh_cert_file and dns_doh_key_file')

    if config.get('dns_enable_dot', False) or config.get('dns_enable_doh', False) or config.get('dns_enable_http3', False):
        if config.get('protocol') == 'udp':
            warnings.warn(
                'Secure listeners are enabled while the main resolver protocol is udp; '
                'this is usually intentional but verify your upstream defaults.',
                RuntimeWarning
            )

    rate_limit_rps = config.get('rate_limit_rps', 0.0)
    if rate_limit_rps < 0:
        raise ValueError('rate_limit_rps must be non-negative')
    rate_limit_burst = config.get('rate_limit_burst', 0.0)
    if rate_limit_burst < 0:
        raise ValueError('rate_limit_burst must be non-negative')

    dns_cache_ttl = config.get('dns_cache_ttl', 300)
    if not isinstance(dns_cache_ttl, (int, float)) or dns_cache_ttl <= 0:
        raise ValueError('dns_cache_ttl must be positive')
    dns_cache_max_size = config.get('dns_cache_max_size', 1024)
    if not isinstance(dns_cache_max_size, int) or dns_cache_max_size <= 0:
        raise ValueError('dns_cache_max_size must be positive')
    dns_negative_cache_ttl = config.get('dns_negative_cache_ttl', 5)
    if not isinstance(dns_negative_cache_ttl, (int, float)) or dns_negative_cache_ttl <= 0:
        raise ValueError('dns_negative_cache_ttl must be positive')
    pool_max_size = config.get('pool_max_size', 5)
    if not isinstance(pool_max_size, int) or pool_max_size <= 0:
        raise ValueError('pool_max_size must be positive')

    if config.get('metrics_enabled', False) and config.get('metrics_port', 8000) == 53:
        warnings.warn('Metrics are enabled on port 53; this may conflict with DNS traffic.', RuntimeWarning)

    if config.get('doh_version', 'auto') not in {'auto', '1.1', '2', '3'}:
        raise ValueError('doh_version must be auto, 1.1, 2, or 3')

    load_balancing = config.get('load_balancing', 'failover')
    if load_balancing not in ('failover', 'parallel', 'random', 'roundrobin'):
        raise ValueError('load_balancing must be failover, parallel, random, or roundrobin')

    # Health checks
    health = config.get('health', {})
    if health.get('enabled', False):
        interval = health.get('interval', 30)
        if interval <= 0:
            raise ValueError('health.interval must be positive')
        timeout = health.get('timeout', 2.0)
        if timeout <= 0:
            raise ValueError('health.timeout must be positive')
        unhealthy_threshold = health.get('unhealthy_threshold', 3)
        if unhealthy_threshold <= 0:
            raise ValueError('health.unhealthy_threshold must be positive')
        healthy_threshold = health.get('healthy_threshold', 2)
        if healthy_threshold <= 0:
            raise ValueError('health.healthy_threshold must be positive')
        cooldown = health.get('cooldown', 60)
        if cooldown < 0:
            raise ValueError('health.cooldown must be non‑negative')

    # DNSSEC validation limits
    dnssec_max_validations = config.get('dnssec_max_validations', 32)
    if dnssec_max_validations < 0:
        raise ValueError('dnssec_max_validations must be non-negative')
    dnssec_max_dnskey_records = config.get('dnssec_max_dnskey_records', 8)
    if dnssec_max_dnskey_records < 0:
        raise ValueError('dnssec_max_dnskey_records must be non-negative')
    dnssec_validation_timeout = config.get('dnssec_validation_timeout', 2.0)
    if dnssec_validation_timeout <= 0:
        raise ValueError('dnssec_validation_timeout must be positive')
    dnssec_chain_validation = config.get('dnssec_chain_validation', True)
    if not isinstance(dnssec_chain_validation, bool):
        raise ValueError('dnssec_chain_validation must be boolean')
    dnssec_max_iterations = config.get('dnssec_max_iterations', 100)
    if dnssec_max_iterations < 0:
        raise ValueError('dnssec_max_iterations must be non-negative')

def load_config(path: str = 'config/dosev.conf') -> Dict[str, Any]:
    config = configparser.ConfigParser()

    if not os.path.exists(path):
        # Return defaults
        return {
            'listen_ip': '0.0.0.0',
            'listen_port': 53,
            'verbose': False,
            'disable_ipv6': False,
            'strip_ipv6_records': None,
            'dns_cache_ttl': 300,
            'dns_cache_max_size': 1024,
            'dns_negative_cache_ttl': 5,
            'dns_logging_enabled': False,
            'dns_log_retention_days': 7,
            'dns_log_dir': _default_log_dir(),
            'dns_log_prefix': 'dns-log',
            'dns_pinned_certs': {},
            'dns_ecs_enabled': True,
            'dns_max_payload': 4096,
            'dnssec_enabled': False,
            'auto_update_trust_anchor': True,
            'trust_anchors_file': '',
            'dnssec_max_validations': 32,
            'dnssec_max_dnskey_records': 8,
            'dnssec_validation_timeout': 2.0,
            'dnssec_chain_validation': True,
            'dnssec_max_iterations': 100,
            'dns_scrub_unsolicited_ns': True,
            'metrics_enabled': False,
            'metrics_port': 8000,
            'uvloop_enable': False,
            'upstream_retries': 2,
            'upstream_initial_backoff': 0.1,
            'upstream_udp_timeout': 2.0,
            'upstream_tcp_timeout': 5.0,
            'upstream_doh_timeout': 5.0,
            'rate_limit_rps': 0.0,
            'rate_limit_burst': 0.0,
            'upstreams': [],
            'optimistic_cache_enabled': False,
            'optimistic_stale_max_age': 86400,
            'optimistic_stale_response_ttl': 30,
            'dns_privilege_drop_user': '',
            'dns_privilege_drop_group': '',
            'dns_chroot_dir': '',
            'dns_rebind_protection': False,
            'dns_rebind_action': 'strip',
            'pool_max_size': 5,
            'pool_idle_timeout': 60.0,
            'doh_version': 'auto',
            'doh_auto_cache_ttl': 3600,
            'load_balancing': 'failover',
            'tcp_fallback_enabled': True,
            'tcp_fastopen_enabled': True,
            'bootstrap': {
                'servers': ['1.1.1.1:53', '8.8.8.8:53'],
                'timeout': 2.0,
                'retries': 2,
            },
            'blocklists': {
                'enabled': False,
                'urls': [],
                'interval_seconds': 86400,
                'action': 'NXDOMAIN',
                'local_blocklist_dir': 'blocklists',
                'reload_on_change': True,
            },
            'health': {
                'enabled': False,
                'interval': 30,
                'timeout': 2.0,
                'unhealthy_threshold': 3,
                'healthy_threshold': 2,
                'cooldown': 60,
                'domain': '.',
            },
        }

    config.read(path, encoding='utf-8')

    # Server
    listen_ip = config.get('server', 'listen_ip', fallback='0.0.0.0')
    listen_port = config.getint('server', 'listen_port', fallback=53)

    # Resolver
    verbose = config.getboolean('resolver', 'verbose', fallback=False)
    disable_ipv6 = config.getboolean('resolver', 'disable_ipv6', fallback=False)
    dns_ecs_enabled = config.getboolean('resolver', 'dns_ecs_enabled', fallback=True)
    dns_max_payload = config.getint('resolver', 'dns_max_payload', fallback=4096)
    dns_enable_dot = config.getboolean('resolver', 'dns_enable_dot', fallback=False)
    dns_dot_port = config.getint('resolver', 'dns_dot_port', fallback=853)
    dns_dot_cert_file = config.get('resolver', 'dns_dot_cert_file', fallback='')
    dns_dot_key_file = config.get('resolver', 'dns_dot_key_file', fallback='')
    dns_enable_doh = config.getboolean('resolver', 'dns_enable_doh', fallback=False)
    dns_doh_port = config.getint('resolver', 'dns_doh_port', fallback=443)
    dns_doh_cert_file = config.get('resolver', 'dns_doh_cert_file', fallback='')
    dns_doh_key_file = config.get('resolver', 'dns_doh_key_file', fallback='')
    dns_doh_path = config.get('resolver', 'dns_doh_path', fallback='/dns-query')
    dns_enable_http3 = config.getboolean('resolver', 'dns_enable_http3', fallback=False)

    strip_ipv6_records_raw = config.get('resolver', 'strip_ipv6_records', fallback=None)
    strip_ipv6_records = None if strip_ipv6_records_raw is None else config.getboolean('resolver', 'strip_ipv6_records', fallback=None)

    # Cache
    dns_cache_ttl = config.getint('cache', 'ttl', fallback=300)
    dns_cache_max_size = config.getint('cache', 'max_size', fallback=1024)
    dns_negative_cache_ttl = config.getint('cache', 'negative_ttl', fallback=5)

    # Timeouts
    upstream_udp_timeout = config.getfloat('timeouts', 'udp', fallback=2.0)
    upstream_tcp_timeout = config.getfloat('timeouts', 'tcp', fallback=5.0)
    upstream_doh_timeout = config.getfloat('timeouts', 'doh', fallback=5.0)
    upstream_initial_backoff = config.getfloat('advanced', 'initial_backoff', fallback=0.1)

    # Advanced
    upstream_retries = config.getint('advanced', 'retries', fallback=2)
    rate_limit_rps = config.getfloat('advanced', 'rate_limit_rps', fallback=0.0)
    rate_limit_burst = config.getfloat('advanced', 'rate_limit_burst', fallback=0.0)
    optimistic_cache_enabled = config.getboolean('advanced', 'optimistic_cache_enabled', fallback=False)
    optimistic_stale_max_age = config.getint('advanced', 'optimistic_stale_max_age', fallback=86400)
    optimistic_stale_response_ttl = config.getint('advanced', 'optimistic_stale_response_ttl', fallback=30)
    pool_max_size = config.getint('advanced', 'pool_max_size', fallback=5)
    pool_idle_timeout = config.getfloat('advanced', 'pool_idle_timeout', fallback=60.0)
    doh_version = config.get('advanced', 'doh_version', fallback='auto').lower()
    if doh_version not in ('auto', '1.1', '2', '3'):
        doh_version = 'auto'
    doh_auto_cache_ttl = config.getint('advanced', 'doh_auto_cache_ttl', fallback=3600)
    load_balancing = config.get('advanced', 'load_balancing', fallback='failover').lower()
    if load_balancing not in ('failover', 'parallel', 'random', 'roundrobin'):
        load_balancing = 'failover'
    tcp_fallback_enabled = config.getboolean('advanced', 'tcp_fallback_enabled', fallback=True)
    tcp_fastopen_enabled = config.getboolean('advanced', 'tcp_fastopen_enabled', fallback=True)

    # Security
    dnssec_enabled = config.getboolean('security', 'dnssec_enabled', fallback=False)
    auto_update_trust_anchor = config.getboolean('security', 'auto_update_trust_anchor', fallback=True)
    trust_anchors_file = config.get('security', 'trust_anchors_file', fallback='')
    dnssec_max_validations = config.getint('security', 'dnssec_max_validations', fallback=32)
    dnssec_max_dnskey_records = config.getint('security', 'dnssec_max_dnskey_records', fallback=8)
    dnssec_validation_timeout = config.getfloat('security', 'dnssec_validation_timeout', fallback=2.0)
    dnssec_chain_validation = config.getboolean('security', 'dnssec_chain_validation', fallback=True)
    dnssec_max_iterations = config.getint('security', 'dnssec_max_iterations', fallback=100)
    dns_scrub_unsolicited_ns = config.getboolean('security', 'dns_scrub_unsolicited_ns', fallback=True)

    pinned_raw = config.get('security', 'pinned_certs', fallback='')
    dns_pinned_certs = {}
    for item in [s.strip() for s in pinned_raw.split(',') if s.strip()]:
        if '=' in item:
            host, fp = item.split('=', 1)
            dns_pinned_certs[host.strip()] = fp.strip()

    dns_rebind_protection = config.getboolean('security', 'rebind_protection', fallback=False)
    dns_rebind_action = config.get('security', 'rebind_action', fallback='strip').lower()
    if dns_rebind_action not in ('strip', 'block'):
        dns_rebind_action = 'strip'

    dns_privilege_drop_user = config.get('security', 'dns_privilege_drop_user', fallback='')
    dns_privilege_drop_group = config.get('security', 'dns_privilege_drop_group', fallback='')
    dns_chroot_dir = config.get('security', 'dns_chroot_dir', fallback='')

    # Logging
    dns_logging_enabled = config.getboolean('logging', 'enabled', fallback=False)
    dns_log_dir = config.get('logging', 'log_dir', fallback=_default_log_dir())
    dns_log_retention_days = config.getint('logging', 'retention_days', fallback=7)
    dns_log_prefix = config.get('logging', 'log_prefix', fallback='dns-log')

    # Metrics
    metrics_enabled = config.getboolean('metrics', 'enabled', fallback=False)
    metrics_port = config.getint('metrics', 'port', fallback=8000)
    uvloop_enable = config.getboolean('metrics', 'uvloop_enable', fallback=False)

    # Bootstrap
    bootstrap_servers_raw = config.get('bootstrap', 'servers', fallback='')
    if bootstrap_servers_raw.strip():
        bootstrap_servers = [s.strip() for s in bootstrap_servers_raw.split(',') if s.strip()]
    else:
        bootstrap_servers = ['1.1.1.1:53', '8.8.8.8:53']
    bootstrap_timeout = config.getfloat('bootstrap', 'timeout', fallback=2.0)
    bootstrap_retries = config.getint('bootstrap', 'retries', fallback=2)
    bootstrap = {
        'servers': bootstrap_servers,
        'timeout': bootstrap_timeout,
        'retries': bootstrap_retries,
    }

    # Upstreams
    upstreams = []
    if config.has_section('upstreams') and config.has_option('upstreams', 'servers'):
        server_names = [s.strip() for s in config.get('upstreams', 'servers').split(',') if s.strip()]
        for name in server_names:
            section = f'upstreams.{name}'
            if not config.has_section(section):
                continue
            address = config.get(section, 'address', fallback='')
            if not address:
                continue
            proto = config.get(section, 'protocol', fallback='udp').lower()
            port_str = config.get(section, 'port', fallback=None)
            if port_str:
                try:
                    port = int(port_str)
                except ValueError:
                    port = None
            else:
                default_ports = {'tls': 853, 'https': 443, 'quic': 853, 'udp': 53, 'tcp': 53}
                port = default_ports.get(proto, 53)
            hostname = config.get(section, 'hostname', fallback='') or address
            path = config.get(section, 'path', fallback='')
            us_doh_version = config.get(section, 'doh_version', fallback=doh_version).lower()
            if us_doh_version not in ('auto', '1.1', '2', '3'):
                us_doh_version = doh_version
            ip = config.get(section, 'ip', fallback=None)
            upstreams.append({
                'address': address,
                'protocol': proto,
                'port': port,
                'hostname': hostname,
                'doh_version': us_doh_version,
                'path': path,
                'ip': ip,
            })

    # If no upstreams defined, use a default (1.1.1.1 over UDP)
    if not upstreams:
        upstreams.append({
            'address': '1.1.1.1',
            'protocol': 'udp',
            'port': 53,
            'hostname': '1.1.1.1',
            'doh_version': 'auto',
            'path': '',
            'ip': '1.1.1.1',
        })
        warnings.warn('No upstreams defined in [upstreams]; using default 1.1.1.1 over UDP.', RuntimeWarning)

    # Health checks
    health = {
        'enabled': config.getboolean('health', 'enabled', fallback=False),
        'interval': config.getint('health', 'interval', fallback=30),
        'timeout': config.getfloat('health', 'timeout', fallback=2.0),
        'unhealthy_threshold': config.getint('health', 'unhealthy_threshold', fallback=3),
        'healthy_threshold': config.getint('health', 'healthy_threshold', fallback=2),
        'cooldown': config.getint('health', 'cooldown', fallback=60),
        'domain': config.get('health', 'domain', fallback='.'),
    }

    # Blocklists
    blocklists = {
        'enabled': config.getboolean('blocklists', 'enabled', fallback=False),
        'urls': [u.strip() for u in config.get('blocklists', 'urls', fallback='').split(',') if u.strip()],
        'interval_seconds': config.getint('blocklists', 'interval_seconds', fallback=86400),
        'action': config.get('blocklists', 'action', fallback='NXDOMAIN').upper(),
        'local_blocklist_dir': config.get('blocklists', 'local_blocklist_dir', fallback='blocklists'),
        'reload_on_change': config.getboolean('blocklists', 'reload_on_change', fallback=True),
    }

    validated_config = {
        'listen_ip': listen_ip,
        'listen_port': listen_port,
        'dns_enable_dot': dns_enable_dot,
        'dns_dot_port': dns_dot_port,
        'dns_dot_cert_file': dns_dot_cert_file,
        'dns_dot_key_file': dns_dot_key_file,
        'dns_enable_doh': dns_enable_doh,
        'dns_doh_port': dns_doh_port,
        'dns_doh_cert_file': dns_doh_cert_file,
        'dns_doh_key_file': dns_doh_key_file,
        'dns_doh_path': dns_doh_path,
        'dns_enable_http3': dns_enable_http3,
        'verbose': verbose,
        'disable_ipv6': disable_ipv6,
        'strip_ipv6_records': strip_ipv6_records,
        'dns_cache_ttl': dns_cache_ttl,
        'dns_cache_max_size': dns_cache_max_size,
        'dns_negative_cache_ttl': dns_negative_cache_ttl,
        'dns_logging_enabled': dns_logging_enabled,
        'dns_log_retention_days': dns_log_retention_days,
        'dns_log_dir': dns_log_dir,
        'dns_log_prefix': dns_log_prefix,
        'dns_pinned_certs': dns_pinned_certs,
        'dns_ecs_enabled': dns_ecs_enabled,
        'dns_max_payload': dns_max_payload,
        'dnssec_enabled': dnssec_enabled,
        'auto_update_trust_anchor': auto_update_trust_anchor,
        'trust_anchors_file': trust_anchors_file,
        'dnssec_max_validations': dnssec_max_validations,
        'dnssec_max_dnskey_records': dnssec_max_dnskey_records,
        'dnssec_validation_timeout': dnssec_validation_timeout,
        'dnssec_chain_validation': dnssec_chain_validation,
        'dnssec_max_iterations': dnssec_max_iterations,
        'dns_scrub_unsolicited_ns': dns_scrub_unsolicited_ns,
        'metrics_enabled': metrics_enabled,
        'metrics_port': metrics_port,
        'uvloop_enable': uvloop_enable,
        'upstream_retries': upstream_retries,
        'upstream_initial_backoff': upstream_initial_backoff,
        'upstream_udp_timeout': upstream_udp_timeout,
        'upstream_tcp_timeout': upstream_tcp_timeout,
        'upstream_doh_timeout': upstream_doh_timeout,
        'rate_limit_rps': rate_limit_rps,
        'rate_limit_burst': rate_limit_burst,
        'upstreams': upstreams,
        'optimistic_cache_enabled': optimistic_cache_enabled,
        'optimistic_stale_max_age': optimistic_stale_max_age,
        'optimistic_stale_response_ttl': optimistic_stale_response_ttl,
        'dns_privilege_drop_user': dns_privilege_drop_user,
        'dns_privilege_drop_group': dns_privilege_drop_group,
        'dns_chroot_dir': dns_chroot_dir,
        'dns_rebind_protection': dns_rebind_protection,
        'dns_rebind_action': dns_rebind_action,
        'pool_max_size': pool_max_size,
        'pool_idle_timeout': pool_idle_timeout,
        'doh_version': doh_version,
        'doh_auto_cache_ttl': doh_auto_cache_ttl,
        'load_balancing': load_balancing,
        'tcp_fallback_enabled': tcp_fallback_enabled,
            'tcp_fastopen_enabled': tcp_fastopen_enabled,
        'bootstrap': bootstrap,
        'blocklists': blocklists,
        'health': health,
    }

    _validate_and_warn(validated_config)
    return validated_config