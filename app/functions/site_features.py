"""Site Features check: detects PWA / HTML5 / modern web platform features
by parsing the HTML of the landing page. Free, no external API."""

import re
import httpx
from urllib.parse import urljoin


SIGNALS = [
    # (key, label, regex)
    ("viewport",         "Responsive viewport meta", re.compile(r'<meta[^>]+name=["\']viewport["\']', re.I)),
    ("charsetUtf8",      "UTF-8 charset",            re.compile(r'<meta[^>]+charset=["\']?utf-?8', re.I)),
    ("themeColor",       "Theme color meta",         re.compile(r'<meta[^>]+name=["\']theme-color["\']', re.I)),
    ("favicon",          "Favicon",                  re.compile(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\']', re.I)),
    ("appleTouchIcon",   "Apple touch icon",         re.compile(r'<link[^>]+rel=["\']apple-touch-icon', re.I)),
    ("manifest",         "Web App Manifest (PWA)",   re.compile(r'<link[^>]+rel=["\']manifest["\']', re.I)),
    ("serviceWorker",    "Service Worker",           re.compile(r'navigator\.serviceWorker', re.I)),
    ("openGraph",        "Open Graph metadata",      re.compile(r'<meta[^>]+property=["\']og:', re.I)),
    ("twitterCard",      "Twitter Card",             re.compile(r'<meta[^>]+name=["\']twitter:', re.I)),
    ("canonical",        "Canonical URL",            re.compile(r'<link[^>]+rel=["\']canonical["\']', re.I)),
    ("language",         "Language declared (<html lang>)", re.compile(r'<html[^>]+lang=', re.I)),
    ("structuredData",   "Structured data (JSON-LD)", re.compile(r'<script[^>]+type=["\']application/ld\+json["\']', re.I)),
    ("rss",              "RSS / Atom feed",          re.compile(r'<link[^>]+type=["\']application/(rss|atom)\+xml', re.I)),
    ("preconnect",       "Resource preconnect",      re.compile(r'<link[^>]+rel=["\']preconnect["\']', re.I)),
    ("preload",          "Resource preload",         re.compile(r'<link[^>]+rel=["\']preload["\']', re.I)),
    ("lazyLoading",      "Native lazy-loaded images", re.compile(r'<img[^>]+loading=["\']lazy["\']', re.I)),
    ("modulesESM",       "ES Modules (type=module)", re.compile(r'<script[^>]+type=["\']module["\']', re.I)),
    ("noscript",         "Noscript fallback",        re.compile(r'<noscript', re.I)),
    ("ampVersion",       "AMP version available",    re.compile(r'<link[^>]+rel=["\']amphtml["\']', re.I)),
    ("darkMode",         "Dark mode (prefers-color-scheme)", re.compile(r'prefers-color-scheme', re.I)),
]


async def audit_site_features(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    async with httpx.AsyncClient(timeout=15, follow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 GoSecure-SiteFeatures"}) as client:
        r = await client.get(url)
        html = r.text or ""

    detected = []
    missing = []
    for key, label, pat in SIGNALS:
        if pat.search(html):
            detected.append({"key": key, "label": label})
        else:
            missing.append({"key": key, "label": label})

    # Optionally fetch manifest if present
    manifest_data = None
    m = re.search(r'<link[^>]+rel=["\']manifest["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
    if m:
        try:
            man_url = urljoin(url, m.group(1))
            async with httpx.AsyncClient(timeout=8) as c2:
                mr = await c2.get(man_url)
                if mr.status_code == 200:
                    manifest_data = {
                        "url": man_url,
                        "snippet": mr.text[:500],
                    }
        except Exception:
            pass

    total = len(SIGNALS)
    score = round(len(detected) / total * 100)
    grade = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 30 else "F"
    return {
        "url": url,
        "totalSignals": total,
        "detectedCount": len(detected),
        "detected": detected,
        "missing": missing,
        "manifest": manifest_data,
        "score": score,
        "grade": grade,
        "summary": f"Found {len(detected)} of {total} modern web features",
    }
