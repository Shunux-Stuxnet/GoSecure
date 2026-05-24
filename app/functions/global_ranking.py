"""Global website ranking via the Tranco list (free, no key).
Tranco is a research-grade aggregation of Alexa, Majestic, Umbrella & Cisco lists."""

import httpx
from urllib.parse import urlparse


TRANCO_API = "https://tranco-list.eu/api/ranks/domain/{domain}"

# Common multi-part public suffixes; for anything not in here we fall back
# to "last two labels" which is correct for the vast majority of TLDs.
_MULTI_SUFFIXES = {
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za", "com.au", "com.br",
    "com.mx", "com.tw", "com.cn", "com.hk", "com.sg", "com.ar", "com.tr",
    "com.pl", "com.ph", "ac.uk", "gov.uk", "org.uk", "net.au", "org.au",
    "ac.in", "gov.in", "nic.in", "edu.in", "gov.au", "edu.au",
}


def _registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


async def get_global_ranking(url: str) -> dict:
    if not url.startswith("http"):
        url = "http://" + url
    host = urlparse(url).hostname or url

    # Tranco ranks registrable domain (eTLD+1)
    registrable = _registrable(host)

    out = {"host": host, "registrable": registrable}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(TRANCO_API.format(domain=registrable))
            if r.status_code != 200:
                return {**out, "ranked": False, "error": f"HTTP {r.status_code}",
                        "summary": "Could not fetch Tranco ranking"}
            data = r.json()
    except Exception as exc:
        return {**out, "ranked": False, "error": str(exc),
                "summary": "Could not fetch Tranco ranking"}

    ranks = data.get("ranks") or []
    latest = ranks[0] if ranks else None
    out["ranked"] = bool(latest and latest.get("rank"))
    out["latest"] = latest
    out["history"] = ranks[:10]

    if out["ranked"]:
        rank = latest.get("rank")
        if rank <= 1000:
            tier = "Top 1,000 (extremely popular)"
        elif rank <= 10000:
            tier = "Top 10,000 (very popular)"
        elif rank <= 100000:
            tier = "Top 100,000 (popular)"
        elif rank <= 1000000:
            tier = "Top 1,000,000"
        else:
            tier = "Beyond top 1M"
        out["tier"] = tier
        out["summary"] = f"Tranco rank: #{rank:,} ({tier})"
    else:
        out["summary"] = f"{registrable} is not in the top 1,000,000 sites (per Tranco)"

    return out
