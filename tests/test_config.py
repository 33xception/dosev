"""
Consolidated config tests.
Combines: test_config.py, test_config_edge_cases.py, test_config_extra.py
"""
import os
import tempfile
import configparser
import pytest
from dosev.config import load_config, write_default_config, _validate_and_warn


def test_load_config_defaults_nonexistent_file(tmp_path):
    config = load_config(str(tmp_path / "missing.conf"))
    assert config["listen_ip"] == "0.0.0.0"
    assert config["dns_cache_ttl"] == 300
    assert config["tcp_fastopen_enabled"] is True
    assert config["blocklists"]["enabled"] is False


def test_load_config_tcp_fastopen_setting(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg_path.write_text("[advanced]\ntcp_fastopen_enabled = false\n", encoding="utf-8")

    assert load_config(str(cfg_path))["tcp_fastopen_enabled"] is False


def test_load_config_from_file(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["server"] = {"listen_ip": "127.0.0.1", "listen_port": "5353"}
    cfg["cache"] = {"ttl": "100", "max_size": "256"}
    cfg["blocklists"] = {"enabled": "true", "urls": "https://example.com/bl.txt", "interval_seconds": "3600"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    config = load_config(str(cfg_path))
    assert config["listen_ip"] == "127.0.0.1"
    assert config["listen_port"] == 5353
    assert config["dns_cache_ttl"] == 100
    assert config["dns_cache_max_size"] == 256
    assert config["blocklists"]["enabled"] is True
    assert config["blocklists"]["interval_seconds"] == 3600


def test_load_config_missing_file():
    """load_config should return defaults when file doesn't exist."""
    config = load_config("/nonexistent/path/file.conf")
    assert config["listen_ip"] == "0.0.0.0"
    assert config["listen_port"] == 53
    assert config["dnssec_max_validations"] == 32


def test_load_config_with_custom_values():
    """load_config should read custom values from file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write("""
[server]
listen_ip = 127.0.0.1
listen_port = 5353

[security]
dnssec_max_validations = 64
dnssec_max_dnskey_records = 16
dnssec_validation_timeout = 5.0
dns_scrub_unsolicited_ns = false
""")
        path = f.name

    try:
        config = load_config(path)
        assert config["listen_ip"] == "127.0.0.1"
        assert config["listen_port"] == 5353
        assert config["dnssec_max_validations"] == 64
        assert config["dnssec_max_dnskey_records"] == 16
        assert config["dnssec_validation_timeout"] == 5.0
        assert config["dns_scrub_unsolicited_ns"] is False
    finally:
        os.unlink(path)


def test_write_default_config_creates_directory():
    """write_default_config should create directory if it doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "subdir", "dosev.conf")
        write_default_config(path)
        assert os.path.exists(path)
        with open(path, 'r') as f:
            content = f.read()
            assert "[server]" in content
            assert "[security]" in content
            assert "dnssec_max_validations" in content


def test_validate_invalid_port():
    """Validation should reject invalid port numbers."""
    with pytest.raises(ValueError, match="listen_port must be between 1 and 65535"):
        _validate_and_warn({"listen_port": 0})

    with pytest.raises(ValueError, match="listen_port must be between 1 and 65535"):
        _validate_and_warn({"listen_port": 65536})


def test_validate_invalid_dnssec_options():
    """Validation should reject invalid DNSSEC options."""
    with pytest.raises(ValueError, match="dnssec_max_validations must be non-negative"):
        _validate_and_warn({"dnssec_max_validations": -1})

    with pytest.raises(ValueError, match="dnssec_max_dnskey_records must be non-negative"):
        _validate_and_warn({"dnssec_max_dnskey_records": -1})


def test_validate_invalid_validation_timeout():
    """Validation should reject non-positive timeout."""
    with pytest.raises(ValueError, match="dnssec_validation_timeout must be positive"):
        _validate_and_warn({"dnssec_validation_timeout": 0})

    with pytest.raises(ValueError, match="dnssec_validation_timeout must be positive"):
        _validate_and_warn({"dnssec_validation_timeout": -1.0})


def test_validate_invalid_cache_and_pool_options():
    """Validation should reject invalid cache TTL/size and pool settings."""
    with pytest.raises(ValueError, match="dns_cache_ttl must be positive"):
        _validate_and_warn({"dns_cache_ttl": 0})

    with pytest.raises(ValueError, match="dns_cache_max_size must be positive"):
        _validate_and_warn({"dns_cache_max_size": 0})

    with pytest.raises(ValueError, match="dns_negative_cache_ttl must be positive"):
        _validate_and_warn({"dns_negative_cache_ttl": 0})

    with pytest.raises(ValueError, match="pool_max_size must be positive"):
        _validate_and_warn({"pool_max_size": 0})


def test_validate_http3_requires_cert_and_key():
    """Validation should require cert/key when HTTP/3 is enabled."""
    with pytest.raises(ValueError, match="dns_enable_http3 requires dns_doh_cert_file and dns_doh_key_file"):
        _validate_and_warn({"dns_enable_http3": True})

    with pytest.raises(ValueError, match="dns_enable_http3 requires dns_doh_cert_file and dns_doh_key_file"):
        _validate_and_warn({"dns_enable_http3": True, "dns_doh_cert_file": "/tmp/cert.pem"})


def test_load_config_parses_all_extra_sections(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["server"] = {"listen_ip": "127.0.0.2", "listen_port": "5354"}
    cfg["resolver"] = {
        "verbose": "true",
        "disable_ipv6": "true",
        "dns_max_payload": "2048",
        "dns_enable_dot": "true",
        "dns_dot_port": "853",
        "dns_dot_cert_file": "/tmp/dot-cert.pem",
        "dns_dot_key_file": "/tmp/dot-key.pem",
        "dns_enable_doh": "true",
        "dns_doh_port": "443",
        "dns_doh_cert_file": "/tmp/doh-cert.pem",
        "dns_doh_key_file": "/tmp/doh-key.pem",
        "dns_doh_path": "/dns-query",
    }
    cfg["cache"] = {"ttl": "123", "max_size": "456", "negative_ttl": "7"}
    cfg["timeouts"] = {"udp": "1.5", "tcp": "4.5", "doh": "9.5"}
    cfg["advanced"] = {
        "retries": "5",
        "rate_limit_rps": "6.5",
        "rate_limit_burst": "7.5",
        "optimistic_cache_enabled": "true",
        "optimistic_stale_max_age": "100",
        "optimistic_stale_response_ttl": "11",
        "pool_max_size": "12",
        "pool_idle_timeout": "13.5",
        "doh_version": "3",
        "doh_auto_cache_ttl": "14",
    }
    cfg["security"] = {
        "dnssec_enabled": "true",
        "trust_anchors_file": "/tmp/anchors.txt",
        "pinned_certs": "a.example.com=abc,*.example.com=def",
        "rebind_protection": "true",
        "rebind_action": "BLOCK",
        "dns_privilege_drop_user": "dns",
        "dns_privilege_drop_group": "nogroup",
        "dns_chroot_dir": "/var/empty",
    }
    cfg["logging"] = {
        "enabled": "true",
        "retention_days": "8",
        "log_dir": "/tmp/dnslog",
        "log_prefix": "custom-log",
    }
    cfg["metrics"] = {
        "enabled": "true",
        "port": "9100",
        "uvloop_enable": "true",
    }
    cfg["bootstrap"] = {"servers": "1.1.1.1:53,8.8.4.4:53", "timeout": "3.5", "retries": "6"}
    cfg["upstreams"] = {"servers": "primary,secondary"}
    cfg["upstreams.primary"] = {
        "address": "dns1.example.com",
        "protocol": "TLS",
        "port": "853",
        "hostname": "dns1.example.com",
        "doh_version": "2",
        "path": "/dns-query",
    }
    cfg["upstreams.secondary"] = {
        "address": "dns2.example.com",
        "protocol": "https",
    }
    cfg["blocklists"] = {
        "enabled": "true",
        "urls": "https://a/list.txt,https://b/list.txt",
        "interval_seconds": "1234",
        "action": "REFUSED",
        "local_blocklist_dir": "/tmp/bl",
        "reload_on_change": "false",
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    config = load_config(str(cfg_path))

    assert config["listen_ip"] == "127.0.0.2"
    assert config["dns_cache_ttl"] == 123
    assert config["dns_negative_cache_ttl"] == 7
    assert config["dns_pinned_certs"] == {"a.example.com": "abc", "*.example.com": "def"}
    assert config["dns_ecs_enabled"] is True
    assert config["dns_max_payload"] == 2048
    assert config["dns_enable_dot"] is True
    assert config["dns_dot_port"] == 853
    assert config["dns_dot_cert_file"] == "/tmp/dot-cert.pem"
    assert config["dns_dot_key_file"] == "/tmp/dot-key.pem"
    assert config["dns_enable_doh"] is True
    assert config["dns_doh_port"] == 443
    assert config["dns_doh_cert_file"] == "/tmp/doh-cert.pem"
    assert config["dns_doh_key_file"] == "/tmp/doh-key.pem"
    assert config["dns_doh_path"] == "/dns-query"
    assert config["dnssec_enabled"] is True
    assert config["upstreams"][0]["doh_version"] == "2"