from typing import Optional

import httpx


async def get_sitemap_url(url_str: str) -> str:
    url_http = "http://" + url_str
    url_https = "https://" + url_str

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        # Try HTTP first
        try:
            resp = await client.get(url_http + "/robots.txt")
            if resp.status_code == 200:
                sitemap_url = _extract_sitemap_from_robots(resp.text, url_http)
                if sitemap_url:
                    return sitemap_url
        except Exception:
            pass

        # Try HTTPS
        try:
            resp = await client.get(url_https + "/robots.txt")
            if resp.status_code == 200:
                sitemap_url = _extract_sitemap_from_robots(resp.text, url_https)
                if sitemap_url:
                    return sitemap_url
        except Exception:
            pass

    raise Exception("Sitemap not found in robots.txt for both http and https versions")


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
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(sitemap_url)

    if resp.status_code != 200:
        raise Exception(f"Failed to fetch sitemap, status: {resp.status_code}")

    return resp.text
