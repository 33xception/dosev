"""
Phase 3 - Tests for pqc_mode configuration and behavior.
"""
import ssl
import logging
from unittest.mock import patch, MagicMock
import pytest

from dosev.resolver import DNSResolver


class TestPqcModeConfig:
    """Tests for pqc_mode configuration."""

    def test_pqc_mode_default(self):
        """Test that pqc_mode defaults to 'auto'."""
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
        )
        assert resolver.pqc_mode == 'auto'

    def test_pqc_mode_off(self):
        """Test that pqc_mode can be set to 'off'."""
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
            pqc_mode='off',
        )
        assert resolver.pqc_mode == 'off'

    def test_pqc_mode_case_insensitive(self):
        """Test that pqc_mode is case-insensitive."""
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
            pqc_mode='AUTO',
        )
        assert resolver.pqc_mode == 'auto'
        
        resolver2 = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
            pqc_mode='Off',
        )
        assert resolver2.pqc_mode == 'off'

    def test_pqc_mode_invalid_defaults_to_auto(self):
        """Test that invalid pqc_mode defaults to 'auto'."""
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
            pqc_mode='invalid',
        )
        assert resolver.pqc_mode == 'auto'


class TestPqcModeStartupWarning:
    """Tests for pqc_mode startup warnings."""

    def test_no_warning_when_openssl_35_plus(self):
        """Test that no warning is emitted when OpenSSL >= 3.5."""
        # We need to patch ssl before importing dosev.resolver
        # Since we can't reimport, we need to directly mock the values
        import dosev.resolver as resolver_module
        
        warning_messages = []
        original_warning = logging.Logger.warning
        original_version_info = resolver_module.ssl.OPENSSL_VERSION_INFO
        original_version = resolver_module.ssl.OPENSSL_VERSION
        
        def mock_warning(self, msg, *args, **kwargs):
            warning_messages.append(msg)
            return original_warning(self, msg, *args, **kwargs)
        
        # Temporarily set the ssl version to 3.5+
        resolver_module.ssl.OPENSSL_VERSION_INFO = (3, 5, 0, 0, 0)
        resolver_module.ssl.OPENSSL_VERSION = "OpenSSL 3.5.0"
        
        try:
            with patch.object(logging.Logger, 'warning', mock_warning):
                resolver = DNSResolver(
                    upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
                    pqc_mode='auto',
                )
                
            # Filter for PQC-related warnings
            pqc_warnings = [msg for msg in warning_messages if 'OPENSSL_CONF' in msg or 'PQC' in msg or 'post-quantum' in msg]
            assert len(pqc_warnings) == 0
        finally:
            resolver_module.ssl.OPENSSL_VERSION_INFO = original_version_info
            resolver_module.ssl.OPENSSL_VERSION = original_version

    def test_warning_when_openssl_less_than_35(self):
        """Test that warning is emitted when OpenSSL < 3.5."""
        import dosev.resolver as resolver_module
        
        warning_messages = []
        original_version_info = resolver_module.ssl.OPENSSL_VERSION_INFO
        original_version = resolver_module.ssl.OPENSSL_VERSION
        
        # Temporarily set the ssl version to < 3.5
        resolver_module.ssl.OPENSSL_VERSION_INFO = (3, 0, 0, 18, 0)
        resolver_module.ssl.OPENSSL_VERSION = "OpenSSL 3.0.18"
        
        try:
            # Capture log messages at the module level
            import logging
            logger = logging.getLogger("dosev.DNSResolver")
            original_logger_warning = logger.warning
            
            def mock_logger_warning(msg, *args, **kwargs):
                warning_messages.append(msg)
                return original_logger_warning(msg, *args, **kwargs)
            
            logger.warning = mock_logger_warning
            
            resolver = DNSResolver(
                upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
                pqc_mode='auto',
            )
            
            # A warning should have been emitted
            pqc_warnings = [msg for msg in warning_messages if 'OPENSSL_CONF' in msg or 'PQC' in msg or 'post-quantum' in msg]
            assert len(pqc_warnings) >= 1
            assert any('OPENSSL_CONF' in msg for msg in pqc_warnings)
            assert any('3.5' in msg for msg in pqc_warnings)
        finally:
            resolver_module.ssl.OPENSSL_VERSION_INFO = original_version_info
            resolver_module.ssl.OPENSSL_VERSION = original_version

    def test_no_warning_when_pqc_mode_off(self):
        """Test that no warning is emitted when pqc_mode is 'off'."""
        import dosev.resolver as resolver_module
        
        warning_messages = []
        original_version_info = resolver_module.ssl.OPENSSL_VERSION_INFO
        original_version = resolver_module.ssl.OPENSSL_VERSION
        
        # Temporarily set the ssl version to < 3.5
        resolver_module.ssl.OPENSSL_VERSION_INFO = (3, 0, 0, 18, 0)
        resolver_module.ssl.OPENSSL_VERSION = "OpenSSL 3.0.18"
        
        try:
            # Capture log messages at the module level
            import logging
            logger = logging.getLogger("dosev.DNSResolver")
            original_logger_warning = logger.warning
            
            def mock_logger_warning(msg, *args, **kwargs):
                warning_messages.append(msg)
                return original_logger_warning(msg, *args, **kwargs)
            
            logger.warning = mock_logger_warning
            
            resolver = DNSResolver(
                upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
                pqc_mode='off',
            )
            
            # No warning should have been emitted for PQC
            # (There might be other warnings, but not about PQC)
            pqc_warnings = [msg for msg in warning_messages if 'pqc' in msg.lower() or 'OPENSSL_CONF' in msg]
            assert len(pqc_warnings) == 0
        finally:
            resolver_module.ssl.OPENSSL_VERSION_INFO = original_version_info
            resolver_module.ssl.OPENSSL_VERSION = original_version


class TestPqcModeReload:
    """Tests for pqc_mode reloading via update_config."""

    def test_pqc_mode_can_be_updated(self):
        """Test that pqc_mode can be updated via update_config."""
        import asyncio
        
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
            pqc_mode='auto',
        )
        
        assert resolver.pqc_mode == 'auto'
        
        async def update():
            await resolver.update_config(pqc_mode='off')
            assert resolver.pqc_mode == 'off'
            
            await resolver.update_config(pqc_mode='AUTO')
            assert resolver.pqc_mode == 'auto'
        
        asyncio.run(update())

    def test_pqc_mode_invalid_on_update_defaults_to_auto(self):
        """Test that invalid pqc_mode on update defaults to 'auto'."""
        import asyncio
        
        resolver = DNSResolver(
            upstreams=[{"address": "1.1.1.1", "protocol": "udp"}],
            pqc_mode='auto',
        )
        
        async def update():
            await resolver.update_config(pqc_mode='invalid')
            assert resolver.pqc_mode == 'auto'
        
        asyncio.run(update())
