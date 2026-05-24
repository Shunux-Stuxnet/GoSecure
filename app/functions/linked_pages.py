import re
import httpx
from urllib.parse import urlparse, urljoin


_HREF = re.compile(r'<a\s+[^>]*?href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


async def audit_linked_pages(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    base = urlparse(url)
    base_host = base.hostname or ""

    async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)
    html = resp.text[:500_000]

    internal, external, other = set(), set(), set()
    for m in _HREF.finditer(html):
        href = m.group(1).strip()
        if not href or href.startswith("#"):
            continue
        if href.startswith(("mailto:", "tel:", "javascript:")):
            other.add(href.split(":", 1)[0])
            continue
        full = urljoin(url, href)
        host = urlparse(full).hostname or ""
        if not host or host == base_host or host.endswith("." + base_host):
            internal.add(full)
        else:
            external.add(full)

    # External hosts breakdown
    ext_hosts = {}
    for u in external:
        h = urlparse(u).hostname or "unknown"
        ext_hosts[h] = ext_hosts.get(h, 0) + 1
    top_ext = sorted(ext_hosts.items(), key=lambda x: -x[1])[:15]

    return {
        "totalLinks": len(internal) + len(external),
        "internalCount": len(internal),
        "externalCount": len(external),
        "externalHosts": dict(top_ext),
        "internalSample": sorted(internal)[:25],
        "externalSample": sorted(external)[:25],
        "specialLinkTypes": sorted(other),
    }
