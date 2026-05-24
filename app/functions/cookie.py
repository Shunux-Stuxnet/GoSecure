import httpx


def _parse_set_cookie(header_value: str) -> dict:
    parts = [p.strip() for p in header_value.split(";")]
    name_value = parts[0]
    eq = name_value.find("=")
    name = name_value[:eq] if eq != -1 else name_value
    value = name_value[eq + 1:] if eq != -1 else ""

    flags = [p.lower() for p in parts[1:]]
    secure = any(f == "secure" for f in flags)
    http_only = any(f == "httponly" for f in flags)
    same_site = next(
        (p.split("=", 1)[1] for p in parts[1:] if p.lower().startswith("samesite=")),
        None,
    )

    issues = []
    if not secure:
        issues.append("Missing Secure flag")
    if not http_only:
        issues.append("Missing HttpOnly flag")
    if not same_site:
        issues.append("Missing SameSite attribute")

    return {
        "name": name,
        "value": value,
        "secure": secure,
        "httpOnly": http_only,
        "sameSite": same_site,
        "issues": issues,
    }


async def find_cookies(domain: str) -> dict:
    url = "https://" + domain

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        resp = await client.get(url)

    raw_cookies = [
        v.decode("utf-8", errors="replace")
        for k, v in resp.headers.raw
        if k.lower() == b"set-cookie"
    ]
    cookies = [_parse_set_cookie(h) for h in raw_cookies]

    return {
        "status": f"{resp.status_code} {resp.reason_phrase}",
        "cookies": cookies,
    }
