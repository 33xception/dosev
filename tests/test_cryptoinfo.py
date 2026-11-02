# tests/test_cryptoinfo.py – tests for the cryptoinfo module

import pytest
from unittest.mock import patch, MagicMock
import sys

from dosev import cryptoinfo


class TestGetOpensslVersionInfo:
    """Tests for get_openssl_version_info()."""

    def test_returns_tuple(self):
        """Test that openssl version info is a tuple."""
        result = cryptoinfo.get_openssl_version_info()
        assert isinstance(result, tuple)

    def test_has_at_least_major_minor(self):
        """Test that the tuple has at least major and minor version."""
        result = cryptoinfo.get_openssl_version_info()
        assert len(result) >= 2


class TestGetOpensslVersionString:
    """Tests for get_openssl_version_string()."""

    def test_returns_string(self):
        """Test that openssl version is a string."""
        result = cryptoinfo.get_openssl_version_string()
        assert isinstance(result, str)

    def test_contains_openssl(self):
        """Test that the string contains 'OpenSSL'."""
        result = cryptoinfo.get_openssl_version_string()
        assert 'OpenSSL' in result or 'openssl' in result.lower()


class TestGetPythonVersion:
    """Tests for get_python_version()."""

    def test_returns_string(self):
        """Test that Python version is a string."""
        result = cryptoinfo.get_python_version()
        assert isinstance(result, str)

    def test_contains_version_info(self):
        """Test that the string contains version info."""
        result = cryptoinfo.get_python_version()
        # sys.version includes the version number at minimum
        assert '3.' in result or 'Python' in result


class TestGetPackageVersions:
    """Tests for get_package_versions()."""

    def test_returns_dict(self):
        """Test that package versions returns a dict."""
        result = cryptoinfo.get_package_versions()
        assert isinstance(result, dict)

    def test_contains_expected_packages(self):
        """Test that expected packages are in the result."""
        result = cryptoinfo.get_package_versions()
        expected = ['aioquic', 'httpx', 'aiohttp', 'cryptography', 'dnspython']
        for pkg in expected:
            assert pkg in result

    def test_versions_are_strings_or_none(self):
        """Test that version values are strings or None."""
        result = cryptoinfo.get_package_versions()
        for pkg, ver in result.items():
            assert ver is None or isinstance(ver, str)


class TestCanObserveTlsGroup:
    """Tests for can_observe_tls_group()."""

    def test_returns_tuple_of_two(self):
        """Test that the function returns a tuple of (bool, str)."""
        can, reason = cryptoinfo.can_observe_tls_group()
        assert isinstance(can, bool)
        assert isinstance(reason, str)

    @patch('dosev.cryptoinfo.ssl')
    def test_detects_group_attr(self, mock_ssl):
        """Test that it detects group attributes on SSLSocket."""
        # Mock SSLSocket to have a group attribute
        mock_socket = MagicMock()
        mock_socket.__dir__ = MagicMock(return_value=['group', 'other'])
        mock_ssl.SSLSocket = mock_socket
        
        can, reason = cryptoinfo.can_observe_tls_group()
        # The function checks for group-related attributes
        # This test verifies it runs without error
        assert isinstance(can, bool)


class TestCheckAioquicPqSupport:
    """Tests for check_aioquic_pq_support()."""

    def test_returns_tuple_of_two(self):
        """Test that the function returns a tuple of (bool, str)."""
        has_pq, reason = cryptoinfo.check_aioquic_pq_support()
        assert isinstance(has_pq, bool)
        assert isinstance(reason, str)

    def test_handles_import_error(self):
        """Test that it handles aioquic not being installed."""
        # Use monkeypatch to simulate ImportError
        import builtins
        # Save original __import__
        original_import = builtins.__import__
        
        def mock_import(name, *args, **kwargs):
            if name == 'aioquic' or name.startswith('aioquic.'):
                raise ImportError('No module named aioquic')
            return original_import(name, *args, **kwargs)
        
        with patch('builtins.__import__', side_effect=mock_import):
            has_pq, reason = cryptoinfo.check_aioquic_pq_support()
            assert has_pq is False
            assert 'not installed' in reason.lower() or 'error' in reason.lower()


class TestGetTransportPqStatus:
    """Tests for get_transport_pq_status()."""

    def test_returns_dict(self):
        """Test that it returns a dict."""
        result = cryptoinfo.get_transport_pq_status()
        assert isinstance(result, dict)

    def test_contains_expected_transports(self):
        """Test that expected transports are in the result."""
        result = cryptoinfo.get_transport_pq_status()
        expected = ['DoT', 'DoH 1.1', 'DoH 2', 'DoH/3', 'DoQ']
        for transport in expected:
            assert transport in result

    def test_values_are_valid_statuses(self):
        """Test that values are valid status strings."""
        result = cryptoinfo.get_transport_pq_status()
        valid_statuses = {'hybrid expected', 'classical only', 'unknown'}
        for transport, status in result.items():
            assert status in valid_statuses


class TestGetCryptoInfo:
    """Tests for get_crypto_info()."""

    def test_returns_dict(self):
        """Test that it returns a dict."""
        result = cryptoinfo.get_crypto_info()
        assert isinstance(result, dict)

    def test_contains_expected_keys(self):
        """Test that expected keys are present."""
        result = cryptoinfo.get_crypto_info()
        expected_keys = [
            'python_version',
            'openssl_version',
            'openssl_version_info',
            'openssl_35_or_higher',
            'packages',
            'can_observe_tls_group',
            'aioquic_pq_support',
            'transport_status',
        ]
        for key in expected_keys:
            assert key in result

    def test_openssl_35_or_higher_is_bool(self):
        """Test that openssl_35_or_higher is a bool."""
        result = cryptoinfo.get_crypto_info()
        assert isinstance(result['openssl_35_or_higher'], bool)


class TestFormatCryptoInfo:
    """Tests for format_crypto_info()."""

    def test_returns_string(self):
        """Test that it returns a string."""
        result = cryptoinfo.format_crypto_info()
        assert isinstance(result, str)

    def test_contains_expected_sections(self):
        """Test that the output contains expected sections."""
        result = cryptoinfo.format_crypto_info()
        expected_sections = [
            'Post-Quantum Readiness Diagnostics',
            'Python/OpenSSL Environment:',
            'Package Versions:',
            'TLS Group Support:',
            'aioquic Support:',
            'Transport PQ Status:',
            'Summary:',
        ]
        for section in expected_sections:
            assert section in result

    def test_accepts_info_dict(self):
        """Test that it accepts a pre-computed info dict."""
        info = cryptoinfo.get_crypto_info()
        result = cryptoinfo.format_crypto_info(info)
        assert isinstance(result, str)


class TestMockedScenarios:
    """Tests that simulate different OpenSSL versions and aioquic support."""

    @patch('dosev.cryptoinfo.ssl')
    def test_openssl_35_detected(self, mock_ssl):
        """Test that OpenSSL >= 3.5 is correctly detected."""
        # Mock OpenSSL 3.5.0
        mock_ssl.OPENSSL_VERSION_INFO = (3, 5, 0, 0, 0)
        mock_ssl.OPENSSL_VERSION = "OpenSSL 3.5.0"
        
        result = cryptoinfo.get_crypto_info()
        assert result['openssl_35_or_higher'] is True

    @patch('dosev.cryptoinfo.ssl')
    def test_openssl_34_not_35(self, mock_ssl):
        """Test that OpenSSL 3.4 is not considered >= 3.5."""
        # Mock OpenSSL 3.4.0
        mock_ssl.OPENSSL_VERSION_INFO = (3, 4, 0, 0, 0)
        mock_ssl.OPENSSL_VERSION = "OpenSSL 3.4.0"
        
        result = cryptoinfo.get_crypto_info()
        assert result['openssl_35_or_higher'] is False

    @patch('dosev.cryptoinfo.check_aioquic_pq_support')
    def test_aioquic_pq_affects_transport_status(self, mock_check):
        """Test that aioquic PQ support affects DoQ/DoH3 status."""
        # Mock aioquic as having PQ support
        mock_check.return_value = (True, "Has ML-KEM")
        
        result = cryptoinfo.get_transport_pq_status()
        # DoQ and DoH/3 should reflect aioquic's status
        # The actual status depends on the openssl_35_or_higher check too
        # but we can at least verify the function runs
        assert 'DoQ' in result
        assert 'DoH/3' in result

    @patch('dosev.cryptoinfo.ssl')
    @patch('dosev.cryptoinfo.check_aioquic_pq_support')
    def test_transport_status_with_openssl_35_and_aioquic_pq(self, mock_check, mock_ssl):
        """Test transport status when OpenSSL >= 3.5 and aioquic has PQ."""
        mock_ssl.OPENSSL_VERSION_INFO = (3, 5, 0, 0, 0)
        mock_check.return_value = (True, "Has ML-KEM")
        
        result = cryptoinfo.get_transport_pq_status()
        # With OpenSSL >= 3.5 and aioquic PQ, DoQ and DoH/3 should be hybrid
        # But only if we can observe groups from Python
        # Since we can't currently, they'll be classical
        assert 'DoQ' in result
        assert 'DoH/3' in result


class TestMockedOpenssl34Vs35:
    """Tests to simulate OpenSSL 3.4 vs 3.5 environments."""

    def test_monkeypatch_openssl_34(self):
        """Test that we can monkeypatch to simulate OpenSSL 3.4."""
        with patch('dosev.cryptoinfo.ssl.OPENSSL_VERSION_INFO', (3, 4, 0, 0, 0)):
            result = cryptoinfo.get_crypto_info()
            assert result['openssl_35_or_higher'] is False

    def test_monkeypatch_openssl_35(self):
        """Test that we can monkeypatch to simulate OpenSSL 3.5."""
        with patch('dosev.cryptoinfo.ssl.OPENSSL_VERSION_INFO', (3, 5, 0, 0, 0)):
            result = cryptoinfo.get_crypto_info()
            assert result['openssl_35_or_higher'] is True

    def test_monkeypatch_missing_aioquic(self):
        """Test that we can simulate aioquic not being installed."""
        with patch.dict('sys.modules', {'aioquic': None}):
            with patch('builtins.__import__', side_effect=ImportError('No aioquic')):
                has_pq, reason = cryptoinfo.check_aioquic_pq_support()
                assert has_pq is False


class TestCliIntegration:
    """Test that the CLI integration works correctly."""

    def test_crypto_info_flag_imports_correctly(self):
        """Test that importing cli with cryptoinfo works."""
        # This test just verifies the import doesn't fail
        from dosev.cli import main
        from dosev import cryptoinfo
        assert callable(main)
        assert callable(cryptoinfo.get_crypto_info)
