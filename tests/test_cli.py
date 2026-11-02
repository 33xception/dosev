import sys
import os
from unittest.mock import patch

from dosev.cli import main


def test_main_loads_config_and_starts_server(monkeypatch):
    called = {}

    monkeypatch.setattr("dosev.cli.load_config", lambda path: {
        "listen_ip": "127.0.0.1",
        "listen_port": 5353,
    })

    def fake_run_server_sync(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr("dosev.cli.run_server_sync", fake_run_server_sync)
    monkeypatch.setattr(sys, "argv", ["dosev", "--config", "custom.conf"])

    main()

    assert called["listen_ip"] == "127.0.0.1"
    assert called["listen_port"] == 5353


def test_main_exits_on_config_error(monkeypatch):
    # Prevent default config creation
    monkeypatch.setattr("dosev.cli.get_default_config_path", lambda: "/nonexistent/path")
    monkeypatch.setattr("os.path.exists", lambda x: True)  # so it doesn't create
    monkeypatch.setattr("dosev.cli.load_config", lambda path: (_ for _ in ()).throw(RuntimeError("bad config")))
    monkeypatch.setattr(sys, "argv", ["dosev"])

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 1
    else:
        assert False, "main() should exit on config errors"


def test_main_check_config_flag(monkeypatch, capsys, tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg_path.write_text("[server]\nlisten_port = 53\n", encoding="utf-8")

    monkeypatch.setattr("dosev.cli.load_config", lambda path: {"listen_ip": "0.0.0.0", "listen_port": 53})
    monkeypatch.setattr("dosev.cli.run_server_sync", lambda **kwargs: (_ for _ in ()).throw(AssertionError("server should not start")))
    monkeypatch.setattr(sys, "argv", ["dosev", "--config", str(cfg_path), "--check-config"])

    main()

    captured = capsys.readouterr()
    assert "Configuration is valid." in captured.out


def test_main_version_flag(monkeypatch, capsys):
    """Test that --version prints the version and exits."""
    monkeypatch.setattr(sys, "argv", ["dosev", "--version"])
    # Mock version function to return a known value
    def fake_version(name):
        return "1.6.0"
    monkeypatch.setattr("dosev.cli.version", fake_version)

    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "dosev 1.6.0" in captured.out


def test_main_crypto_info_flag(monkeypatch, capsys):
    """Test that --crypto-info prints diagnostics and exits without config."""
    monkeypatch.setattr(sys, "argv", ["dosev", "--crypto-info"])

    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "Post-Quantum Readiness Diagnostics" in captured.out
    assert "Python/OpenSSL Environment:" in captured.out
    assert "Package Versions:" in captured.out
    assert "Transport PQ Status:" in captured.out


def test_main_crypto_info_no_config_file_needed(monkeypatch, capsys):
    """Test that --crypto-info works without a config file."""
    # Ensure no config file exists
    monkeypatch.setattr("dosev.cli.get_default_config_path", lambda: "/nonexistent/path")
    monkeypatch.setattr(sys, "argv", ["dosev", "--crypto-info"])

    try:
        main()
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "Post-Quantum Readiness Diagnostics" in captured.out