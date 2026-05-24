import asyncio
import socket
import ssl


async def check_http_protocols(url: str) -> dict:
    """Detect HTTP/2 and HTTP/3 support via ALPN and Alt-Svc."""
    import httpx
    from urllib.parse import urlparse

    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    result = {"http1": True, "http2": False, "http3": False, "altSvc": "", "alpn": None}

    # HTTP/2 via ALPN
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        def _alpn():
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.selected_alpn_protocol()

        alpn = await asyncio.to_thread(_alpn)
        result["alpn"] = alpn
        if alpn == "h2":
            result["http2"] = True
    except Exception as exc:
        result["alpnError"] = str(exc)

    # HTTP/3 via Alt-Svc header
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            resp = await client.get(url)
        alt_svc = resp.headers.get("alt-svc", "")
        result["altSvc"] = alt_svc
        if "h3" in alt_svc or "h3-" in alt_svc or "quic" in alt_svc:
            result["http3"] = True
    except Exception as exc:
        result["altSvcError"] = str(exc)

    proto = "HTTP/3" if result["http3"] else ("HTTP/2" if result["http2"] else "HTTP/1.1")
    result["highestProtocol"] = proto
    return result
