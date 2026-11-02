# dosev/cryptoinfo.py – crypto environment diagnostics for post-quantum readiness
"""
This module provides diagnostics about the cryptographic environment to help
assess post-quantum readiness for encrypted DNS transports (DoT, DoH, DoQ).
"""

import sys
import ssl
from typing import Dict, Any, Optional, List, Tuple


def get_openssl_version_info() -> Tuple[int, ...]:
    """Get OpenSSL version as a tuple (major, minor, patch, ...)."""
    return ssl.OPENSSL_VERSION_INFO


def get_openssl_version_string() -> str:
    """Get OpenSSL version string from ssl module."""
    return ssl.OPENSSL_VERSION


def get_python_version() -> str:
    """Get Python version string."""
    return sys.version


def get_package_versions() -> Dict[str, Optional[str]]:
    """
    Get versions of relevant packages for PQ assessment.
    Returns a dict with package names and their versions, or None if not installed.
    """
    versions = {}
    
    # Try to get versions of relevant packages
    packages = [
        'aioquic',
        'httpx',
        'aiohttp',
        'cryptography',
        'dnspython',
    ]
    
    for pkg in packages:
        try:
            if pkg == 'dnspython':
                import dns
                versions[pkg] = dns.__version__
            else:
                mod = __import__(pkg)
                versions[pkg] = getattr(mod, '__version__', 'unknown')
        except (ImportError, AttributeError):
            versions[pkg] = None
    
    return versions


def can_observe_tls_group() -> Tuple[bool, str]:
    """
    Check if the negotiated TLS group can be observed from Python.
    
    Returns a tuple of (can_observe, explanation).
    """
    # Check if ssl.SSLSocket has a group or key_exchange attribute
    # or if there's any way to get the negotiated group
    sock_attrs = [attr.lower() for attr in dir(ssl.SSLSocket)]
    
    group_attrs = ['group', 'key_exchange', 'ke', 'kex', 'ecdh_curve', 'negotiated_group']
    has_group_attr = any(attr in sock_attrs for attr in group_attrs)
    
    if has_group_attr:
        return True, "ssl.SSLSocket has group/key_exchange attributes"
    
    # Check SSLContext for group control
    ctx_attrs = [attr.lower() for attr in dir(ssl.SSLContext)]
    ctx_group_attrs = ['set_groups', 'set_group', 'groups', 'key_exchange_groups']
    has_ctx_group_attr = any(attr in ctx_attrs for attr in ctx_group_attrs)
    
    if has_ctx_group_attr:
        return True, "ssl.SSLContext has group control methods"
    
    return False, "No group observation or control API found in Python ssl module"


def check_aioquic_pq_support() -> Tuple[bool, str]:
    """
    Check if aioquic supports ML-KEM groups.
    
    Returns a tuple of (has_pq_support, explanation).
    """
    try:
        from aioquic.tls import Group
        
        # Check if ML-KEM groups are defined
        pq_groups = []
        for name in dir(Group):
            if not name.startswith('_'):
                val = getattr(Group, name)
                if isinstance(val, Group):
                    # Check if the group name contains ML-KEM or PQ
                    if 'MLKEM' in name.upper() or 'ML-KEM' in name.upper():
                        pq_groups.append(name)
        
        if pq_groups:
            return True, f"aioquic has ML-KEM groups: {', '.join(pq_groups)}"
        else:
            # List available groups
            available = []
            for name in dir(Group):
                if not name.startswith('_'):
                    val = getattr(Group, name)
                    if isinstance(val, Group):
                        available.append(name)
            return False, f"aioquic only has classical groups: {', '.join(available)}"
    except ImportError:
        return False, "aioquic is not installed"
    except Exception as e:
        return False, f"Error checking aioquic: {e}"


def get_transport_pq_status() -> Dict[str, str]:
    """
    Get PQ readiness status for each DNS transport.
    
    Returns a dict mapping transport names to their status:
    - 'hybrid expected': PQ hybrid groups are expected to work
    - 'classical only': Only classical ECDH/RSA groups available
    - 'unknown': Cannot determine
    """
    status = {}
    
    # Check if we have OpenSSL >= 3.5
    openssl_info = get_openssl_version_info()
    has_openssl_35 = openssl_info >= (3, 5, 0, 0, 0)
    
    # Check if we can observe/control groups from Python
    can_observe, _ = can_observe_tls_group()
    
    # DoT (DNS-over-TLS): Uses Python's ssl module
    # PQ support requires OpenSSL >= 3.5 AND the ability to set groups
    # For now, even with OpenSSL 3.5, Python doesn't expose group control
    # So DoT will be classical unless OPENSSL_CONF is set externally
    if has_openssl_35 and can_observe:
        status['DoT'] = 'hybrid expected'
    else:
        status['DoT'] = 'classical only'
    
    # DoH 1.1/2: Uses aiohttp which uses Python's ssl
    # Same as DoT
    status['DoH 1.1'] = status['DoT']
    status['DoH 2'] = status['DoT']
    
    # DoH/3 (HTTP/3): Uses aioquic
    aioquic_has_pq, aioquic_reason = check_aioquic_pq_support()
    if aioquic_has_pq:
        status['DoH/3'] = 'hybrid expected'
    else:
        status['DoH/3'] = 'classical only'
    
    # DoQ: Uses aioquic
    status['DoQ'] = status['DoH/3']
    
    return status


def get_crypto_info() -> Dict[str, Any]:
    """
    Get comprehensive crypto environment information.
    
    Returns a dict with:
    - python_version: Python version string
    - openssl_version: OpenSSL version string from ssl module
    - openssl_version_info: OpenSSL version as tuple
    - openssl_35_or_higher: bool
    - packages: dict of package versions
    - can_observe_tls_group: tuple of (bool, explanation)
    - aioquic_pq_support: tuple of (bool, explanation)
    - transport_status: dict of transport PQ status
    """
    return {
        'python_version': get_python_version(),
        'openssl_version': get_openssl_version_string(),
        'openssl_version_info': get_openssl_version_info(),
        'openssl_35_or_higher': get_openssl_version_info() >= (3, 5, 0, 0, 0),
        'packages': get_package_versions(),
        'can_observe_tls_group': can_observe_tls_group(),
        'aioquic_pq_support': check_aioquic_pq_support(),
        'transport_status': get_transport_pq_status(),
    }


def format_crypto_info(info: Optional[Dict[str, Any]] = None) -> str:
    """
    Format crypto info as a human-readable string.
    
    If info is None, calls get_crypto_info() to get the current info.
    """
    if info is None:
        info = get_crypto_info()
    
    lines = []
    lines.append("Post-Quantum Readiness Diagnostics")
    lines.append("=" * 40)
    lines.append("")
    
    # Python and OpenSSL
    lines.append("Python/OpenSSL Environment:")
    lines.append(f"  Python version: {info['python_version']}")
    lines.append(f"  ssl.OPENSSL_VERSION: {info['openssl_version']}")
    lines.append(f"  ssl.OPENSSL_VERSION_INFO: {info['openssl_version_info']}")
    openssl_35 = info['openssl_35_or_higher']
    lines.append(f"  OpenSSL >= 3.5: {'YES' if openssl_35 else 'NO'}")
    lines.append("")
    
    # Package versions
    lines.append("Package Versions:")
    for pkg, ver in info['packages'].items():
        status = "OK" if ver is not None else "NOT INSTALLED"
        lines.append(f"  {pkg}: {ver or 'N/A'} ({status})")
    lines.append("")
    
    # Group observation
    can_observe, observe_reason = info['can_observe_tls_group']
    lines.append("TLS Group Support:")
    lines.append(f"  Can observe negotiated group from Python: {'YES' if can_observe else 'NO'}")
    lines.append(f"  Reason: {observe_reason}")
    lines.append("")
    
    # aioquic support
    aioquic_has_pq, aioquic_reason = info['aioquic_pq_support']
    lines.append("aioquic Support:")
    lines.append(f"  ML-KEM support: {'YES' if aioquic_has_pq else 'NO'}")
    lines.append(f"  Reason: {aioquic_reason}")
    lines.append("")
    
    # Transport status
    lines.append("Transport PQ Status:")
    lines.append("  (Status can be: 'hybrid expected', 'classical only', or 'unknown')")
    for transport, status in info['transport_status'].items():
        lines.append(f"  {transport}: {status}")
    lines.append("")
    
    # Summary
    lines.append("Summary:")
    if openssl_35:
        lines.append("  OpenSSL >= 3.5 detected - ML-KEM groups are available at the library level.")
    else:
        lines.append("  OpenSSL < 3.5 - ML-KEM groups are NOT available.")
    
    if not can_observe:
        lines.append("  Python ssl module does NOT expose group observation/control APIs.")
        lines.append("  Workaround: Use OPENSSL_CONF environment variable to configure groups.")
    
    return "\n".join(lines)
