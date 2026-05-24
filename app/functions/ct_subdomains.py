"""Subdomain discovery via Certificate Transparency logs (crt.sh).
Reveals subdomains that have ever had a TLS certificate issued for them."""

import httpx
from urllib.parse import urlparse


CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def find_ct_subdomains(url: str) -> dict:
    if url.startswith("http"):
        url = urlparse(url).hostname or url
    domain = url

    try:
        async with httpx.AsyncClient(
            timeout=30,
            headers={"User-Agent": "GoSecure-CT-Subdomain"},
        ) as client:
            r = await client.get(CRTSH_URL.format(domain=domain))
    except Exception as exc:
        return {"domain": domain, "error": str(exc), "subdomains": [], "count": 0}

    if r.status_code != 200:
        return {"domain": domain, "error": f"crt.sh returned HTTP {r.status_code}",
                "subdomains": [], "count": 0}

    try:
        entries = r.json()
    except Exception:
        return {"domain": domain, "error": "crt.sh returned non-JSON",
                "subdomains": [], "count": 0}

    seen = set()
    for e in entries:
        # name_value may contain multiple names separated by newlines + wildcards
        names = (e.get("name_value") or "").split("\n")
        for n in names:
            n = n.strip().lower().lstrip("*.")
            if n and n.endswith(domain) and n != domain and " " not in n:
                seen.add(n)

    subs = sorted(seen)
    return {
        "domain": domain,
        "source": "crt.sh (Certificate Transparency logs)",
        "count": len(subs),
        "subdomains": subs[:300],   # cap for response size
        "truncated": len(subs) > 300,
        "summary": f"Found {len(subs)} unique subdomain(s) in CT logs",
    }
