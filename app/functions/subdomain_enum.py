import asyncio
import dns.resolver
import dns.exception

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "app", "portal", "cdn", "m", "mobile", "vpn",
    "ns1", "ns2", "smtp", "pop", "imap", "secure", "login", "auth",
    "remote", "office", "webmail", "support", "help", "forum", "docs",
    "static", "assets", "media", "img", "images", "video", "files",
    "backup", "beta", "demo", "old", "new", "v1", "v2", "web",
    "git", "gitlab", "jenkins", "jira", "confluence", "dashboard",
    "panel", "control", "cp", "whm", "cpanel", "intranet", "internal",
    "status", "monitor", "metrics", "grafana", "kibana",
    "autodiscover", "autoconfig", "exchange", "owa",
    "db", "redis", "ci", "cd", "deploy", "build",
    "staging2", "uat", "preview", "sandbox", "qa", "preprod",
]


def _resolve_a(fqdn: str):
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        return [r.address for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None


async def enumerate_subdomains(domain: str) -> dict:
    async def check(sub: str):
        fqdn = f"{sub}.{domain}"
        ips = await asyncio.to_thread(_resolve_a, fqdn)
        if ips:
            return {"subdomain": fqdn, "ip": ips}
        return None

    results = await asyncio.gather(*[check(sub) for sub in COMMON_SUBDOMAINS])
    found = [r for r in results if r is not None]

    return {
        "domain": domain,
        "subdomains": found,
        "count": len(found),
        "checked": len(COMMON_SUBDOMAINS),
    }
