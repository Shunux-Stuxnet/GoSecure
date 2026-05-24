import asyncio
import dns.resolver
from urllib.parse import urlparse


FILTERS = [
    # name, label, resolver IP, response indicating block
    ("Quad9 (security)",   "Quad9",       "9.9.9.9"),
    ("Cloudflare Family",  "Cloudflare",  "1.1.1.3"),
    ("OpenDNS FamilyShield","OpenDNS",    "208.67.222.123"),
    ("CleanBrowsing Security","CleanBrowsing","185.228.168.9"),
    ("AdGuard Family",     "AdGuard",     "94.140.14.15"),
    ("Google Public DNS",  "Google",      "8.8.8.8"),  # baseline reference
]


def _resolve(domain: str, server: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]
    resolver.lifetime = 4
    resolver.timeout = 4
    try:
        answers = resolver.resolve(domain, "A")
        ips = sorted({r.address for r in answers})
        return {"ips": ips, "blocked": _looks_blocked(ips)}
    except dns.resolver.NXDOMAIN:
        return {"ips": [], "blocked": True, "reason": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"ips": [], "blocked": True, "reason": "NoAnswer"}
    except Exception as exc:
        return {"ips": [], "blocked": None, "error": str(exc)}


def _looks_blocked(ips):
    # Block-page sentinels commonly returned by family/security filters
    block_ips = {"0.0.0.0", "127.0.0.1", "146.112.61.106", "146.112.61.108"}
    return bool(ips) and all(ip in block_ips or ip.startswith("146.112.61.") for ip in ips)


async def check_dns_blocks(domain: str) -> dict:
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    async def _ck(name, label, ip):
        res = await asyncio.to_thread(_resolve, domain, ip)
        return {"resolver": name, "label": label, "ip": ip, **res}

    results = await asyncio.gather(*[_ck(n, l, ip) for n, l, ip in FILTERS])
    blocked_by = [r["label"] for r in results if r.get("blocked") is True]

    return {
        "domain": domain,
        "results": results,
        "blockedByCount": len(blocked_by),
        "blockedBy": blocked_by,
        "summary": "Not blocked by any tested filter" if not blocked_by
                   else f"Domain blocked by: {', '.join(blocked_by)}",
    }
