from urllib.parse import urlparse

import httpx


def has_protocol_scheme(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme != ""
    except Exception:
        return False


async def get_remote_data(url: str) -> dict:
    from app.functions.http_client import resilient_get

    resp = await resilient_get(url)
    return dict(resp.headers)
