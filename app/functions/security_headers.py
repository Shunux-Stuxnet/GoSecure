import httpx

HEADERS_CONFIG = {
    "Content-Security-Policy": 25,
    "X-Frame-Options": 20,
    "X-Content-Type-Options": 15,
    "Referrer-Policy": 15,
    "Permissions-Policy": 15,
    "Strict-Transport-Security": 10,
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


async def check_security_headers(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    present = []
    missing = []
    found_headers = {}
    score = 0

    for header, points in HEADERS_CONFIG.items():
        value = resp.headers.get(header)
        if value:
            present.append(header)
            found_headers[header] = value
            score += points
        else:
            missing.append(header)

    return {
        "grade": _grade(score),
        "score": score,
        "present": present,
        "missing": missing,
        "headers": found_headers,
    }
