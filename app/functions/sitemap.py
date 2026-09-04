from typing import Optional

import httpx


# Common conventional sitemap locations to probe when robots.txt is silent.
COMMON_SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/sitemap/sitemap.xml",
    "/sitemap.xml.gz",
]


async def get_sitemap_url(url_str: str) -> str:
    host = url_str.replace("https://", "").replace("http://", "").strip("/")
    # Try both bare and www. host variants (sitemaps often live on www.).
    hosts = [host]
    if host.startswith("www."):
        hosts.append(host[4:])
    else:
        hosts.append("www." + host)

    bases = []
    for h in hosts:
        bases.append("https://" + h)
        bases.append("http://" + h)

    xml_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; GoSecure/1.0)",
        "Accept": "application/xml,text/xml,application/xhtml+xml,text/html;q=0.9,*/*;q=0.8",
    }

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True, headers=xml_headers) as client:
        # 1. Prefer the sitemap declared in robots.txt.
        for base in bases:
            try:
                resp = await client.get(base + "/robots.txt")
                if resp.status_code == 200:
                    sitemap_url = _extract_sitemap_from_robots(resp.text, base)
                    if sitemap_url:
                        return sitemap_url
            except Exception:
                pass

        # 2. Fallback: probe conventional /sitemap.xml locations directly.
        #    Many sites serve a sitemap without ever declaring it in robots.txt.
        for base in bases:
            for path in COMMON_SITEMAP_PATHS:
                candidate = base + path
                try:
                    resp = await client.get(candidate)
                    if resp.status_code == 200 and _looks_like_sitemap(resp.text):
                        return str(resp.url)
                except Exception:
                    pass

    raise Exception("No sitemap found in robots.txt or at common sitemap paths")


def _looks_like_sitemap(body: str) -> bool:
    head = body[:1000].lower()
    return ("<urlset" in head) or ("<sitemapindex" in head) or ("<?xml" in head and "sitemap" in head)


def _extract_sitemap_from_robots(robots_txt: str, base_url: str) -> Optional[str]:
    for line in robots_txt.split("\n"):
        if line.strip().startswith("Sitemap:"):
            sitemap_url = line.split("Sitemap:", 1)[1].strip()
            if sitemap_url:
                if not sitemap_url.startswith("http"):
                    sitemap_url = base_url.rstrip("/") + "/" + sitemap_url.lstrip("/")
                return sitemap_url
    return None


async def fetch_sitemap(sitemap_url: str) -> str:
    xml_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; GoSecure/1.0)",
        "Accept": "application/xml,text/xml,application/xhtml+xml,text/html;q=0.9,*/*;q=0.8",
    }
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True, headers=xml_headers) as client:
        resp = await client.get(sitemap_url)

    if resp.status_code != 200:
        raise Exception(f"Failed to fetch sitemap, status: {resp.status_code}")

    return resp.text
