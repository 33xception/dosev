# dosev/cli.py – command‑line interface
import os
import sys
import argparse
from importlib.metadata import version

from .config import load_config, _default_log_dir, get_default_config_path, write_default_config
from .server import run_server_sync
from . import cryptoinfo

def main() -> None:
    default_config = get_default_config_path()
    parser = argparse.ArgumentParser(description="dosev DNS server")
    parser.add_argument("--config", "-c", default=default_config,
                        help=f"Path to configuration file (default: {default_config})")
    parser.add_argument("--check-config", action="store_true",
                        help="Validate the configuration and exit without starting the server")
    parser.add_argument("--version", action="store_true",
                        help="Show version and exit")
    parser.add_argument("--crypto-info", action="store_true",
                        help="Show crypto environment diagnostics and exit (no config file needed)")
    args = parser.parse_args()

    if args.version:
        try:
            ver = version("dosev")
        except Exception:
            ver = "unknown"
        print(f"dosev {ver}")
        return

    if args.crypto_info:
        info = cryptoinfo.get_crypto_info()
        print(cryptoinfo.format_crypto_info(info))
        return

    config_path = args.config
    if config_path == default_config and not os.path.exists(config_path):
        try:
            write_default_config(config_path)
            print(f"Default configuration file created at:\n {config_path}", file=sys.stderr)
            print("Please edit it to your needs and restart dosev.", file=sys.stderr)
            sys.exit(0)
        except Exception as e:
            print(f"Error creating default config: {e}", file=sys.stderr)
            print("Falling back to built‑in defaults.", file=sys.stderr)

    try:
        config = load_config(config_path)
    except Exception as e:
        print(f"Failed to load config: {e}", file=sys.stderr)
        sys.exit(1)

    if args.check_config:
        print("Configuration is valid.")
        return

    run_server_sync(
        listen_ip=config["listen_ip"],
        listen_port=config["listen_port"],
        verbose=config.get("verbose", False),
        blocklists=config.get("blocklists"),
        disable_ipv6=config.get("disable_ipv6", False),
        strip_ipv6_records=config.get("strip_ipv6_records", False),
        dns_cache_ttl=config.get("dns_cache_ttl", 300),
        dns_cache_max_size=config.get("dns_cache_max_size", 1024),
        dns_negative_cache_ttl=config.get("dns_negative_cache_ttl", 5),
        dns_logging_enabled=config.get("dns_logging_enabled", False),
        dns_log_retention_days=config.get("dns_log_retention_days", 7),
        dns_log_dir=config.get("dns_log_dir", _default_log_dir()),
        dns_log_prefix=config.get("dns_log_prefix", "dns-log"),
        dns_pinned_certs=config.get("dns_pinned_certs", {}),
        dnssec_enabled=config.get("dnssec_enabled", False),
        auto_update_trust_anchor=config.get("auto_update_trust_anchor", True),
        trust_anchors_file=config.get("trust_anchors_file", ""),
        dnssec_max_validations=config.get("dnssec_max_validations", 32),
        dnssec_max_dnskey_records=config.get("dnssec_max_dnskey_records", 8),
        dnssec_validation_timeout=config.get("dnssec_validation_timeout", 2.0),
        dnssec_chain_validation=config.get("dnssec_chain_validation", True),
        dnssec_max_iterations=config.get("dnssec_max_iterations", 100),
        dns_scrub_unsolicited_ns=config.get("dns_scrub_unsolicited_ns", True),
        metrics_enabled=config.get("metrics_enabled", False),
        metrics_port=config.get("metrics_port", 8000),
        uvloop_enable=config.get("uvloop_enable", False),
        upstream_retries=config.get("upstream_retries", 2),
        upstream_initial_backoff=config.get("upstream_initial_backoff", 0.1),
        upstream_udp_timeout=config.get("upstream_udp_timeout", 2.0),
        upstream_tcp_timeout=config.get("upstream_tcp_timeout", 5.0),
        upstream_doh_timeout=config.get("upstream_doh_timeout", 5.0),
        rate_limit_rps=config.get("rate_limit_rps", 0.0),
        rate_limit_burst=config.get("rate_limit_burst", 0.0),
        upstreams=config.get("upstreams", []),
        optimistic_cache_enabled=config.get("optimistic_cache_enabled", False),
        optimistic_stale_max_age=config.get("optimistic_stale_max_age", 86400),
        optimistic_stale_response_ttl=config.get("optimistic_stale_response_ttl", 30),
        dns_privilege_drop_user=config.get("dns_privilege_drop_user", ""),
        dns_privilege_drop_group=config.get("dns_privilege_drop_group", ""),
        dns_chroot_dir=config.get("dns_chroot_dir", ""),
        dns_rebind_protection=config.get("dns_rebind_protection", False),
        dns_rebind_action=config.get("dns_rebind_action", "strip"),
        dns_ecs_enabled=config.get("dns_ecs_enabled", True),
        dns_max_payload=config.get("dns_max_payload", 4096),
        dns_enable_dot=config.get("dns_enable_dot", False),
        dns_dot_port=config.get("dns_dot_port", 853),
        dns_dot_cert_file=config.get("dns_dot_cert_file", ""),
        dns_dot_key_file=config.get("dns_dot_key_file", ""),
        dns_enable_doh=config.get("dns_enable_doh", False),
        dns_doh_port=config.get("dns_doh_port", 443),
        dns_doh_cert_file=config.get("dns_doh_cert_file", ""),
        dns_doh_key_file=config.get("dns_doh_key_file", ""),
        dns_doh_path=config.get("dns_doh_path", "/dns-query"),
        dns_enable_http3=config.get("dns_enable_http3", False),
        pool_max_size=config.get("pool_max_size", 5),
        pool_idle_timeout=config.get("pool_idle_timeout", 60.0),
        doh_version=config.get("doh_version", "auto"),
        doh_auto_cache_ttl=config.get("doh_auto_cache_ttl", 3600),
        load_balancing=config.get("load_balancing", "failover"),
        bootstrap=config.get("bootstrap", {"servers": [], "timeout": 2.0, "retries": 2}),
        tcp_fallback_enabled=config.get("tcp_fallback_enabled", True),
        tcp_fastopen_enabled=config.get("tcp_fastopen_enabled", True),
        health_config=config.get("health", {}),
    )

if __name__ == "__main__":
    main()