from urllib.parse import urljoin

import httpx

MAX_HOPS = 10


async def trace_redirects(url: str) -> dict:
    chain = []
    visited = set()
    warnings = []
    has_loop = False
    has_http_downgrade = False
    current_url = url

    async with httpx.AsyncClient(follow_redirects=False, timeout=10, verify=False) as client:
        for _ in range(MAX_HOPS):
            if current_url in visited:
                has_loop = True
                warnings.append(f"Loop detected at {current_url}")
                break
            visited.add(current_url)

            resp = await client.get(current_url)
            location = resp.headers.get("location")

            chain.append({
                "url": current_url,
                "statusCode": resp.status_code,
                "location": location,
            })

            if resp.status_code not in (301, 302, 303, 307, 308):
                break

            if location is None:
                warnings.append("Redirect response missing Location header")
                break

            # Detect HTTPS → HTTP downgrade
            next_url = urljoin(current_url, location)

            if current_url.startswith("https://") and next_url.startswith("http://"):
                has_http_downgrade = True
                warnings.append(f"HTTP downgrade detected: {current_url} → {next_url}")

            current_url = next_url
        else:
            warnings.append(f"Stopped after {MAX_HOPS} hops")

    final_url = chain[-1]["url"] if chain else url
    total_hops = sum(1 for hop in chain if hop["statusCode"] in (301, 302, 303, 307, 308))

    return {
        "chain": chain,
        "finalUrl": final_url,
        "totalHops": total_hops,
        "hasLoop": has_loop,
        "hasHttpDowngrade": has_http_downgrade,
        "warnings": warnings,
    }
