import httpx
from typing import Optional


def _parse_frame_ancestors(csp: str) -> Optional[str]:
    for directive in csp.split(";"):
        directive = directive.strip()
        if directive.lower().startswith("frame-ancestors"):
            return directive
    return None


async def check_clickjacking(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    xfo = resp.headers.get("X-Frame-Options")
    csp = resp.headers.get("Content-Security-Policy", "")
    frame_ancestors = _parse_frame_ancestors(csp)

    xfo_protected = xfo and xfo.upper() in ("DENY", "SAMEORIGIN")
    csp_protected = frame_ancestors is not None and any(
        token in frame_ancestors.lower() for token in ("'none'", "'self'")
    )

    if xfo_protected or csp_protected:
        protection_level = "protected"
        vulnerable = False
        if xfo_protected:
            details = f"Protected via X-Frame-Options: {xfo}"
        else:
            details = f"Protected via CSP frame-ancestors: {frame_ancestors}"
    elif xfo or frame_ancestors:
        protection_level = "partial"
        vulnerable = True
        details = "Partial protection — review X-Frame-Options or frame-ancestors value"
    else:
        protection_level = "none"
        vulnerable = True
        details = "No clickjacking protection found (missing X-Frame-Options and CSP frame-ancestors)"

    return {
        "xFrameOptions": xfo,
        "cspFrameAncestors": frame_ancestors,
        "vulnerable": vulnerable,
        "protectionLevel": protection_level,
        "details": details,
    }
