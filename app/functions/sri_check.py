from typing import Optional
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


def _is_external(resource_url: str, page_host: str) -> bool:
    if resource_url.startswith("//"):
        return True
    if resource_url.startswith("http://") or resource_url.startswith("https://"):
        return urlparse(resource_url).netloc != page_host
    return False


def _sri_issue(has_integrity: bool, has_crossorigin: bool) -> Optional[str]:
    if not has_integrity:
        return "Missing integrity hash — resource can be tampered with silently"
    if not has_crossorigin:
        return "Has integrity but missing crossorigin='anonymous' — SRI may not be enforced by browser"
    return None


async def audit_sri(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    page_host = urlparse(str(resp.url)).netloc
    soup = BeautifulSoup(resp.text, "html.parser")
    resources = []

    # External <script src="...">
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "")
        if not _is_external(src, page_host):
            continue
        has_integrity = bool(tag.get("integrity"))
        has_crossorigin = tag.get("crossorigin", "").lower() == "anonymous"
        issue = _sri_issue(has_integrity, has_crossorigin)
        resources.append({
            "type": "script",
            "url": src,
            "hasIntegrity": has_integrity,
            "hasCrossorigin": has_crossorigin,
            "sriValid": has_integrity and has_crossorigin,
            "issue": issue,
        })

    # External <link rel="stylesheet|preload" href="...">
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel", [])
        if isinstance(rel, list):
            rel_lower = [r.lower() for r in rel]
        else:
            rel_lower = [rel.lower()]
        if "stylesheet" not in rel_lower and "preload" not in rel_lower:
            continue
        href = tag.get("href", "")
        if not _is_external(href, page_host):
            continue
        has_integrity = bool(tag.get("integrity"))
        has_crossorigin = tag.get("crossorigin", "").lower() == "anonymous"
        issue = _sri_issue(has_integrity, has_crossorigin)
        resources.append({
            "type": "stylesheet",
            "url": href,
            "hasIntegrity": has_integrity,
            "hasCrossorigin": has_crossorigin,
            "sriValid": has_integrity and has_crossorigin,
            "issue": issue,
        })

    missing = [r for r in resources if not r["sriValid"]]

    return {
        "externalResources": resources,
        "totalExternal": len(resources),
        "missingSRI": len(missing),
        "safe": len(missing) == 0,
    }
