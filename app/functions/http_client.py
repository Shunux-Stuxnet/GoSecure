import asyncio
import random
from typing import Optional

import httpx

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_DEFAULT_HEADERS = {
    "User-Agent": _UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_LIMITS = httpx.Limits(max_connections=20, max_keepalive_connections=10)

# Errors worth retrying (transient network / server-side blips).
_RETRYABLE = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)

_client: Optional[httpx.AsyncClient] = None
_lock = asyncio.Lock()


async def get_client() -> httpx.AsyncClient:
    """Return the process-wide shared AsyncClient, creating it once."""
    global _client
    if _client is None:
        async with _lock:
            if _client is None:
                _client = httpx.AsyncClient(
                    timeout=15,
                    verify=False,
                    follow_redirects=True,
                    limits=_LIMITS,
                    headers=_DEFAULT_HEADERS,
                )
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def resilient_get(url: str, *, tries: int = 3, **kwargs) -> httpx.Response:
    """GET with retry + exponential backoff and jitter on transient errors.

    Honors Retry-After on 429/503 responses.
    """
    client = await get_client()
    last_exc: Optional[Exception] = None

    for attempt in range(tries):
        try:
            resp = await client.get(url, **kwargs)
            if resp.status_code in (429, 503) and attempt < tries - 1:
                delay = _retry_after(resp) or _backoff(attempt)
                await asyncio.sleep(delay)
                continue
            return resp
        except _RETRYABLE as exc:
            last_exc = exc
            if attempt == tries - 1:
                raise
            await asyncio.sleep(_backoff(attempt))

    if last_exc:
        raise last_exc
    raise httpx.HTTPError("resilient_get exhausted retries")


def _backoff(attempt: int) -> float:
    return (2 ** attempt) * 0.4 + random.random() * 0.3


def _retry_after(resp: httpx.Response) -> Optional[float]:
    val = resp.headers.get("retry-after")
    if not val:
        return None
    try:
        return min(float(val), 10.0)  # cap so a scan never stalls
    except ValueError:
        return None
