import httpx
from urllib.parse import urlparse


async def check_security_txt(url: str) -> dict:
    """Look for /.well-known/security.txt (RFC 9116)."""
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.hostname}"

    paths = ["/.well-known/security.txt", "/security.txt"]
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        for p in paths:
            try:
                resp = await client.get(base + p)
                if resp.status_code == 200 and resp.text.strip():
                    body = resp.text[:5000]
                    fields = {}
                    for line in body.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or ":" not in line:
                            continue
                        k, _, v = line.partition(":")
                        fields.setdefault(k.strip(), []).append(v.strip())
                    return {
                        "found": True,
                        "url": base + p,
                        "fields": fields,
                        "raw": body,
                    }
            except Exception:
                continue
    return {"found": False, "url": base + paths[0],
            "message": "No security.txt found — site has no published responsible-disclosure contact."}
