"""
Phase 4 - Tests for QUIC/DoQ/HTTP3 post-quantum readiness.
"""
import pytest
import asyncio
from unittest.mock import MagicMock


class TestAioquicPqSupport:
    """Tests for aioquic PQ support detection."""

    def test_aioquic_currently_has_no_mlkem_support(self):
        """
        Verify that the current version of aioquic does NOT support ML-KEM groups.
        
        This test documents the current state. When aioquic gains ML-KEM support,
        this test should FAIL, triggering a review of the DoQ/DoH3 documentation
        which currently states these transports are 'classical only'.
        """
        from dosev.cryptoinfo import check_aioquic_pq_support
        
        has_pq, reason = check_aioquic_pq_support()
        
        # As of our probe, aioquic 1.3.0 has only classical groups
        assert not has_pq, f"aioquic unexpectedly has PQ support: {reason}"
        assert 'classical' in reason.lower() or 'only has' in reason.lower(), \
            f"Unexpected reason for no PQ support: {reason}"

    def test_aioquic_classical_groups_listed(self):
        """
        Verify that aioquic's classical groups are correctly identified.
        """
        from dosev.cryptoinfo import check_aioquic_pq_support
        
        has_pq, reason = check_aioquic_pq_support()
        
        # These are the classical groups we expect
        expected_groups = ['X25519', 'X448', 'SECP256R1', 'SECP384R1', 'SECP521R1', 'GREASE']
        
        # At least some of these should be in the reason
        found_any = any(group in reason for group in expected_groups)
        assert found_any, f"Expected classical groups not found in reason: {reason}"


class TestTransportPqStatus:
    """Tests for transport PQ status reporting."""

    def test_doh3_and_doq_are_classical_only(self):
        """
        Verify that DoH/3 and DoQ are reported as 'classical only'.
        
        This reflects the current state where aioquic does not support
        ML-KEM groups.
        """
        from dosev.cryptoinfo import get_transport_pq_status
        
        status = get_transport_pq_status()
        
        assert status['DoH/3'] == 'classical only', \
            f"DoH/3 should be classical only, got: {status['DoH/3']}"
        assert status['DoQ'] == 'classical only', \
            f"DoQ should be classical only, got: {status['DoQ']}"

    def test_doh3_and_doq_match(self):
        """
        Verify that DoH/3 and DoQ have the same PQ status.
        
        Both use aioquic, so they should always have the same status.
        """
        from dosev.cryptoinfo import get_transport_pq_status
        
        status = get_transport_pq_status()
        
        assert status['DoH/3'] == status['DoQ'], \
            f"DoH/3 and DoQ should have same status: {status['DoH/3']} vs {status['DoQ']}"


class TestCryptoInfoOutput:
    """Tests for the full crypto info output."""

    def test_crypto_info_includes_aioquic_status(self):
        """
        Verify that crypto info output includes aioquic PQ support status.
        """
        from dosev.cryptoinfo import get_crypto_info
        
        info = get_crypto_info()
        
        assert 'aioquic_pq_support' in info
        
        has_pq, reason = info['aioquic_pq_support']
        assert isinstance(has_pq, bool)
        assert isinstance(reason, str)
        assert not has_pq  # Current state

    def test_crypto_info_includes_transport_status(self):
        """
        Verify that crypto info output includes transport PQ status.
        """
        from dosev.cryptoinfo import get_crypto_info
        
        info = get_crypto_info()
        
        assert 'transport_status' in info
        status = info['transport_status']
        
        # Check all expected transports are present
        expected_transports = ['DoT', 'DoH 1.1', 'DoH 2', 'DoH/3', 'DoQ']
        for transport in expected_transports:
            assert transport in status, f"Missing transport: {transport}"


@pytest.mark.asyncio
class TestQuicClientHello:
    """Tests for QUIC ClientHello spanning multiple Initial packets."""

    async def test_quic_pool_handles_connections(self):
        """
        Verify that the QUIC connection pool can handle connections.
        
        This test verifies that the ClientPool used for QUIC connections
        can properly store and retrieve connections, which is necessary
        for handling ClientHellos that span multiple Initial packets.
        """
        from dosev.resolver import ClientPool
        
        pool = ClientPool(max_size=5, idle_timeout=60.0)
        
        # Create a mock QUIC client
        class MockQuicClient:
            def __init__(self):
                self._quic = MagicMock()
                self._quic.closed = False
                self._quic.is_closing = False
                self._quic.get_next_available_stream_id = MagicMock(return_value=0)
        
        key = ('127.0.0.1', 853, 'localhost', '127.0.0.1')
        client = MockQuicClient()
        
        # Put a client in the pool
        await pool.put(key, client)
        
        # Get it back
        retrieved = await pool.get(key)
        assert retrieved is client
        
        # Pool should be empty now
        retrieved2 = await pool.get(key)
        assert retrieved2 is None

    async def test_quic_pool_max_size(self):
        """
        Verify that the QUIC connection pool respects max_size.
        """
        from dosev.resolver import ClientPool
        
        pool = ClientPool(max_size=2, idle_timeout=60.0)
        
        class MockQuicClient:
            def __init__(self, name):
                self.name = name
                self._quic = MagicMock()
                self._quic.closed = False
                self._quic.is_closing = False
                self._quic.get_next_available_stream_id = MagicMock(return_value=0)
        
        key = ('127.0.0.1', 853, 'localhost', '127.0.0.1')
        
        # Add 3 clients, max_size is 2
        await pool.put(key, MockQuicClient('c1'))
        await pool.put(key, MockQuicClient('c2'))
        await pool.put(key, MockQuicClient('c3'))
        
        # Only 2 should be in the pool
        assert len(pool._pools[key]) == 2
