import httpx
from urllib.parse import urlparse


def add_schema_if_missing(site_url: str) -> str:
    if not site_url.startswith("http://") and not site_url.startswith("https://"):
        return "https://" + site_url
    return site_url


async def fetch_robots_txt(site_url: str) -> str:
    parsed = urlparse(site_url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("Invalid url query parameter")

    robots_url = f"{parsed.scheme}://{parsed.hostname}/robots.txt"

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(robots_url)

    if resp.status_code == 200:
        return resp.text

    raise Exception(f"Failed to fetch robots.txt, statusCode: {resp.status_code}")
