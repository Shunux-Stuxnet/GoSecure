import ssl
import socket
from typing import Optional

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "aNULL", "eNULL", "MD5", "ADH", "AECDH"]


def _try_connect(host: str, port: int, context: ssl.SSLContext, timeout: int = 5) -> Optional[tuple]:
    """Attempt an SSL connection. Returns (tls_version, cipher_tuple) or None on failure."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version(), ssock.cipher()
    except Exception:
        return None


def _probe_legacy_tls(host: str, port: int, tls_version: "ssl.TLSVersion") -> Optional[bool]:
    """Try connecting with a capped TLS version. Returns True/False/None (None = cannot determine)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = tls_version
        result = _try_connect(host, port, ctx)
        return result is not None
    except Exception:
        return None


def analyze_tls(domain: str) -> dict:
    port = 443
    issues = []

    # Default connection — negotiates highest mutual TLS version
    default_ctx = ssl.create_default_context()
    default_ctx.check_hostname = False
    default_ctx.verify_mode = ssl.CERT_NONE

    result = _try_connect(domain, port, default_ctx)
    if result is None:
        return {"error": f"Could not establish TLS connection to {domain}:{port}"}

    tls_version, cipher_info = result
    cipher_name = cipher_info[0] if cipher_info else "Unknown"
    cipher_protocol = cipher_info[1] if cipher_info else "Unknown"
    key_bits = cipher_info[2] if cipher_info else 0

    # Weak cipher check
    for kw in WEAK_CIPHER_KEYWORDS:
        if kw.upper() in cipher_name.upper():
            issues.append(f"Weak cipher in use: {cipher_name}")
            break

    # Deprecated TLS version negotiated
    if tls_version in ("TLSv1", "TLSv1.1"):
        issues.append(f"Negotiated TLS version {tls_version} is deprecated")

    # Probe for TLS 1.0 support
    tls10_supported = None
    tls11_supported = None
    if hasattr(ssl, "TLSVersion"):
        tls10_supported = _probe_legacy_tls(domain, port, ssl.TLSVersion.TLSv1)
        tls11_supported = _probe_legacy_tls(domain, port, ssl.TLSVersion.TLSv1_1)
        if tls10_supported is True:
            issues.append("TLS 1.0 accepted by server (deprecated since RFC 8996, 2021)")
        if tls11_supported is True:
            issues.append("TLS 1.1 accepted by server (deprecated since RFC 8996, 2021)")

    return {
        "tlsVersion": tls_version,
        "cipher": cipher_name,
        "cipherProtocol": cipher_protocol,
        "keyBits": key_bits,
        "tls10Supported": tls10_supported,
        "tls11Supported": tls11_supported,
        "issues": issues,
        "safe": len(issues) == 0,
    }
