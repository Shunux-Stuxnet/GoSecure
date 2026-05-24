import socket
import ssl


# A representative subset of common ciphers across TLS 1.2 / 1.3
PROBE_CIPHERS = [
    # TLS 1.3 (server picks from these implicitly)
    ("TLS_AES_256_GCM_SHA384", "TLS1.3"),
    ("TLS_CHACHA20_POLY1305_SHA256", "TLS1.3"),
    ("TLS_AES_128_GCM_SHA256", "TLS1.3"),
    # TLS 1.2 modern
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "TLS1.2"),
    ("ECDHE-RSA-AES256-GCM-SHA384", "TLS1.2"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "TLS1.2"),
    ("ECDHE-RSA-CHACHA20-POLY1305", "TLS1.2"),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "TLS1.2"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "TLS1.2"),
    # Weaker (still seen)
    ("ECDHE-RSA-AES256-SHA384", "TLS1.2"),
    ("ECDHE-RSA-AES128-SHA256", "TLS1.2"),
    ("AES256-GCM-SHA384", "TLS1.2"),
    ("AES128-GCM-SHA256", "TLS1.2"),
    # Insecure (legacy)
    ("DES-CBC3-SHA", "weak"),
    ("RC4-SHA", "weak"),
    ("RC4-MD5", "weak"),
]


def enumerate_ciphers(domain: str, port: int = 443) -> dict:
    from urllib.parse import urlparse
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    supported = []
    weak_supported = []

    # Use a default handshake to get what the server picks
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                negotiated = {
                    "cipher": ssock.cipher(),
                    "version": ssock.version(),
                }
    except Exception as exc:
        return {"error": str(exc)}

    # Probe each cipher individually
    for cipher, kind in PROBE_CIPHERS:
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            if not cipher.startswith("TLS_"):
                try:
                    c.set_ciphers(cipher)
                except ssl.SSLError:
                    continue
            with socket.create_connection((domain, port), timeout=4) as sock:
                with c.wrap_socket(sock, server_hostname=domain) as ssock:
                    info = ssock.cipher()
                    supported.append({"cipher": info[0], "version": info[1]})
                    if kind == "weak":
                        weak_supported.append(info[0])
        except Exception:
            continue

    # Dedupe by cipher name
    seen = set()
    unique = []
    for s in supported:
        if s["cipher"] not in seen:
            seen.add(s["cipher"])
            unique.append(s)

    return {
        "negotiated": {
            "cipher": negotiated["cipher"][0] if negotiated["cipher"] else None,
            "version": negotiated["version"],
        },
        "supportedCiphers": unique,
        "totalSupported": len(unique),
        "weakCiphersSupported": weak_supported,
        "safe": not weak_supported,
        "summary": "No weak ciphers detected" if not weak_supported
                   else f"Weak ciphers accepted: {', '.join(weak_supported)}",
    }
