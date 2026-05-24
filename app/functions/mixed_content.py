import httpx
from bs4 import BeautifulSoup

# (tag_name, attribute, severity, content_type)
MIXED_TAGS = [
    ("script", "src", "critical", "active"),
    ("iframe", "src", "critical", "active"),
    ("embed", "src", "critical", "active"),
    ("object", "data", "critical", "active"),
    ("form", "action", "high", "active"),
    ("link", "href", "high", "passive"),
    ("img", "src", "medium", "passive"),
    ("audio", "src", "medium", "passive"),
    ("video", "src", "medium", "passive"),
    ("source", "src", "medium", "passive"),
]


async def detect_mixed_content(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    final_url = str(resp.url)
    is_https = final_url.startswith("https://")

    if not is_https:
        return {
            "pageUrl": final_url,
            "isHttps": False,
            "mixedContent": [],
            "count": 0,
            "safe": True,
            "summary": "Page is not served over HTTPS — mixed content analysis not applicable",
        }

    soup = BeautifulSoup(resp.text, "html.parser")
    found = []

    for tag_name, attr, severity, content_type in MIXED_TAGS:
        for tag in soup.find_all(tag_name, **{attr: True}):
            value = tag.get(attr, "")
            if value.startswith("http://"):
                found.append({
                    "tag": tag_name,
                    "attribute": attr,
                    "url": value,
                    "severity": severity,
                    "type": content_type,
                })

    active = [f for f in found if f["type"] == "active"]
    passive = [f for f in found if f["type"] == "passive"]

    return {
        "pageUrl": final_url,
        "isHttps": True,
        "mixedContent": found,
        "count": len(found),
        "activeCount": len(active),
        "passiveCount": len(passive),
        "safe": len(found) == 0,
    }
