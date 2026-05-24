import time
from urllib.parse import urlparse

import httpx


async def check_server_status(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "http://" + raw_url

    start_time = time.time()

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        resp = await client.get(raw_url)

    response_time = time.time() - start_time

    status_code = resp.status_code
    if status_code < 200 or status_code >= 400:
        return f"Received non-success response code: {status_code}"

    return f"Server is up!\nResponse Code: {status_code}\nResponse Time: {response_time:.2f} seconds"
