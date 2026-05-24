import httpx
from urllib.parse import urlparse


DANGEROUS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
SAFE_PROBE = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH"]


async def enumerate_http_methods(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    allow_header = ""
    advertised = []
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
            resp = await client.request("OPTIONS", url)
        allow_header = resp.headers.get("allow") or resp.headers.get("access-control-allow-methods") or ""
        advertised = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    except Exception:
        pass

    # Active probing — short timeout, ignore body
    probed = {}
    async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=False) as client:
        for m in SAFE_PROBE:
            try:
                r = await client.request(m, url)
                probed[m] = r.status_code
            except Exception as exc:
                probed[m] = f"err: {type(exc).__name__}"

    # Consider a method "supported" if status != 405/501
    supported = [m for m, sc in probed.items()
                 if isinstance(sc, int) and sc not in (405, 501)]

    dangerous_enabled = [m for m in supported if m in DANGEROUS]

    return {
        "advertisedAllow": advertised,
        "probed": probed,
        "supported": supported,
        "dangerousMethodsEnabled": dangerous_enabled,
        "safe": not dangerous_enabled,
        "summary": "All dangerous methods rejected" if not dangerous_enabled
                   else f"Potentially exposed: {', '.join(dangerous_enabled)}",
    }
