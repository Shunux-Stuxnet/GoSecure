import asyncio
from urllib.parse import urljoin, urlparse

import httpx

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "goto",
    "target", "dest", "destination", "redir", "redirect_url",
    "return_url", "forward", "continue", "back",
]

CANARY = "https://evil.example.com"


async def check_open_redirect(url: str) -> dict:
    # Strip existing query string and fragment so we inject cleanly
    base_url = url.split("?")[0].split("#")[0]
    base_hostname = (urlparse(base_url).hostname or "").lower().rstrip(".")
    vulnerable = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=5, verify=False) as client:

        async def test_param(param: str):
            # Test both full URL and protocol-relative payloads
            for payload in [CANARY, f"//{CANARY.replace('https://', '')}"]:
                test_url = f"{base_url}?{param}={payload}"
                try:
                    resp = await client.get(test_url)
                    location = resp.headers.get("location", "")
                    if resp.status_code not in (301, 302, 303, 307, 308) or not location:
                        continue

                    # Follow same-domain hops only. Once a redirect leaves the
                    # target host, the destination is already observable and
                    # requesting an untrusted canary host is unnecessary.
                    final_url = urljoin(test_url, location)
                    visited = set()
                    for _ in range(10):
                        if final_url in visited:
                            break
                        visited.add(final_url)
                        final_hostname = (urlparse(final_url).hostname or "").lower().rstrip(".")
                        if final_hostname != base_hostname:
                            break
                        next_resp = await client.get(final_url)
                        next_location = next_resp.headers.get("location")
                        if next_resp.status_code not in (301, 302, 303, 307, 308) or not next_location:
                            break
                        final_url = urljoin(final_url, next_location)

                    final_hostname = (urlparse(final_url).hostname or "").lower().rstrip(".")
                    if final_hostname == "evil.example.com" and final_hostname != base_hostname:
                        return {
                            "parameter": param,
                            "payload": payload,
                            "statusCode": resp.status_code,
                            "location": location,
                            "finalUrl": final_url,
                        }
                except Exception:
                    pass
            return None

        results = await asyncio.gather(*[test_param(p) for p in REDIRECT_PARAMS])

    vulnerable = [r for r in results if r is not None]

    return {
        "testedUrl": base_url,
        "parametersChecked": REDIRECT_PARAMS,
        "vulnerable": vulnerable,
        "vulnerableCount": len(vulnerable),
        "safe": len(vulnerable) == 0,
    }
