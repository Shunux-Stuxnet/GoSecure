import asyncio
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
    vulnerable = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=5, verify=False) as client:

        async def test_param(param: str):
            # Test both full URL and protocol-relative payloads
            for payload in [CANARY, f"//{CANARY.replace('https://', '')}"]:
                test_url = f"{base_url}?{param}={payload}"
                try:
                    resp = await client.get(test_url)
                    location = resp.headers.get("location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and "evil.example.com" in location:
                        return {
                            "parameter": param,
                            "payload": payload,
                            "statusCode": resp.status_code,
                            "location": location,
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
