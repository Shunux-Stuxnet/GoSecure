import re
import httpx


_META_RE = re.compile(
    r'<meta\s+[^>]*?(?:property|name)\s*=\s*["\']([^"\']+)["\'][^>]*?content\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_META_RE_REV = re.compile(
    r'<meta\s+[^>]*?content\s*=\s*["\']([^"\']*)["\'][^>]*?(?:property|name)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def audit_social_tags(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)
    html = resp.text[:200000]

    og, tw, meta = {}, {}, {}
    for m in _META_RE.finditer(html):
        key, val = m.group(1).lower(), m.group(2)
        if key.startswith("og:"):
            og[key] = val
        elif key.startswith("twitter:"):
            tw[key] = val
        else:
            meta[key] = val
    for m in _META_RE_REV.finditer(html):
        val, key = m.group(1), m.group(2).lower()
        if key.startswith("og:") and key not in og:
            og[key] = val
        elif key.startswith("twitter:") and key not in tw:
            tw[key] = val

    title = ""
    tm = _TITLE_RE.search(html)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:300]

    score = 0
    if og.get("og:title"): score += 25
    if og.get("og:description"): score += 25
    if og.get("og:image"): score += 25
    if tw.get("twitter:card"): score += 25

    return {
        "title": title,
        "description": meta.get("description", ""),
        "openGraph": og,
        "twitterCard": tw,
        "ogCount": len(og),
        "twitterCount": len(tw),
        "socialReadinessScore": score,
        "rating": "A" if score >= 100 else "B" if score >= 75 else "C" if score >= 50 else "D" if score >= 25 else "F",
    }
