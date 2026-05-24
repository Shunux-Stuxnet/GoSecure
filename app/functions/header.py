from urllib.parse import urlparse

import httpx


def has_protocol_scheme(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme != ""
    except Exception:
        return False


async def get_remote_data(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        resp = await client.get(url)

    return dict(resp.headers)
