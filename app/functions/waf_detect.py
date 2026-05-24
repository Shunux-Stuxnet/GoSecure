import httpx


# Header / cookie fingerprints for common WAFs & CDNs
SIGNATURES = [
    ("Cloudflare",  "WAF/CDN", {"headers": ["cf-ray", "cf-cache-status", "server: cloudflare"], "cookies": ["__cfduid", "__cf_bm"]}),
    ("Akamai",      "WAF/CDN", {"headers": ["akamai-", "x-akamai", "server: akamaighost"], "cookies": ["ak_bmsc"]}),
    ("AWS CloudFront","CDN",   {"headers": ["x-amz-cf-id", "via: cloudfront", "x-amz-cf-pop"], "cookies": []}),
    ("AWS WAF",     "WAF",     {"headers": ["x-amzn-requestid", "x-amzn-waf"], "cookies": ["aws-waf-token"]}),
    ("Fastly",      "CDN",     {"headers": ["x-fastly", "x-served-by: cache-", "fastly-debug"], "cookies": []}),
    ("Sucuri",      "WAF",     {"headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"], "cookies": []}),
    ("Imperva / Incapsula","WAF",{"headers": ["x-iinfo", "x-cdn: incapsula"], "cookies": ["incap_ses", "visid_incap"]}),
    ("F5 BIG-IP",   "WAF",     {"headers": ["server: bigip", "x-waf-event-info"], "cookies": ["BIGipServer", "TS01"]}),
    ("Barracuda",   "WAF",     {"headers": ["x-barracuda"], "cookies": ["barra_counter_session"]}),
    ("StackPath",   "WAF/CDN", {"headers": ["x-sp-edge", "server: stackpath"], "cookies": []}),
    ("Vercel",      "Edge",    {"headers": ["x-vercel-", "server: vercel"], "cookies": []}),
    ("Netlify",     "Edge",    {"headers": ["x-nf-request-id", "server: netlify"], "cookies": []}),
    ("Fly.io",      "Edge",    {"headers": ["server: fly", "fly-request-id"], "cookies": []}),
    ("KeyCDN",      "CDN",     {"headers": ["server: keycdn"], "cookies": []}),
    ("Cloudfront ELB","CDN",   {"headers": ["x-amz-cf-id"], "cookies": []}),
    ("Google Frontend","Edge", {"headers": ["server: gws", "x-google"], "cookies": []}),
]


async def detect_waf(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    # Build a single searchable string
    hdr_blob = "\n".join(f"{k.lower()}: {v}" for k, v in resp.headers.items())
    cookies_blob = "; ".join(c.name for c in resp.cookies.jar)

    matches = []
    for name, kind, sig in SIGNATURES:
        hit = None
        for pat in sig["headers"]:
            if pat.lower() in hdr_blob.lower():
                hit = pat
                break
        if not hit:
            for c in sig["cookies"]:
                if c.lower() in cookies_blob.lower():
                    hit = "cookie:" + c
                    break
        if hit:
            matches.append({"name": name, "kind": kind, "matched": hit})

    return {
        "detected": bool(matches),
        "matches": matches,
        "count": len(matches),
        "server": resp.headers.get("server", ""),
        "summary": ", ".join(m["name"] for m in matches) if matches else "No known WAF/CDN fingerprints detected",
    }
