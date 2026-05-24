import re
import httpx

# Each signature has optional keys: header_patterns, body_patterns, cookie_patterns, meta_generator
SIGNATURES = [
    {
        "name": "WordPress",
        "category": "CMS",
        "header_patterns": {},
        "body_patterns": ["/wp-content/", "/wp-includes/", "wp-json"],
        "cookie_patterns": ["wordpress_", "wp-settings-", "wp_"],
        "meta_generator": "wordpress",
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "header_patterns": {"X-Generator": "Drupal", "X-Drupal-Cache": None},
        "body_patterns": ["/sites/default/files/", "Drupal.settings"],
        "cookie_patterns": [],
        "meta_generator": "drupal",
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "header_patterns": {},
        "body_patterns": ["/components/com_", "/media/jui/"],
        "cookie_patterns": [],
        "meta_generator": "joomla",
    },
    {
        "name": "Laravel",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": [],
        "cookie_patterns": ["laravel_session", "XSRF-TOKEN"],
    },
    {
        "name": "Django",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": [],
        "cookie_patterns": ["csrftoken", "sessionid"],
    },
    {
        "name": "Ruby on Rails",
        "category": "Framework",
        "header_patterns": {"X-Powered-By": "Phusion Passenger"},
        "body_patterns": [],
        "cookie_patterns": ["_session_id", "_rails"],
    },
    {
        "name": "Next.js",
        "category": "Framework",
        "header_patterns": {"x-nextjs-cache": None, "x-nextjs-stale-time": None},
        "body_patterns": ["__NEXT_DATA__", "/_next/static/"],
        "cookie_patterns": [],
    },
    {
        "name": "Nuxt.js",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": ["__nuxt", "/_nuxt/"],
        "cookie_patterns": [],
    },
    {
        "name": "Angular",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": ["ng-version=", 'ng-app="'],
        "cookie_patterns": [],
    },
    {
        "name": "React",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": ["data-reactroot", "__reactFiber", "react.production"],
        "cookie_patterns": [],
    },
    {
        "name": "Vue.js",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": ["__vue_app__", "vue.runtime.min.js"],
        "cookie_patterns": [],
    },
    {
        "name": "ASP.NET",
        "category": "Framework",
        "header_patterns": {"X-Powered-By": "ASP.NET", "X-AspNet-Version": None},
        "body_patterns": ["__VIEWSTATE", "WebResource.axd"],
        "cookie_patterns": ["ASP.NET_SessionId"],
    },
    {
        "name": "PHP",
        "category": "Language",
        "header_patterns": {"X-Powered-By": "PHP"},
        "body_patterns": [],
        "cookie_patterns": ["PHPSESSID"],
    },
    {
        "name": "Express.js",
        "category": "Framework",
        "header_patterns": {"X-Powered-By": "Express"},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "Java / Spring",
        "category": "Framework",
        "header_patterns": {},
        "body_patterns": [],
        "cookie_patterns": ["JSESSIONID"],
    },
    {
        "name": "Nginx",
        "category": "Web Server",
        "header_patterns": {"Server": "nginx"},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "Apache",
        "category": "Web Server",
        "header_patterns": {"Server": "Apache"},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "IIS",
        "category": "Web Server",
        "header_patterns": {"Server": "IIS"},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "Cloudflare",
        "category": "CDN / Security",
        "header_patterns": {"Server": "cloudflare", "cf-ray": None},
        "body_patterns": [],
        "cookie_patterns": ["__cflb", "__cf_bm"],
    },
    {
        "name": "Vercel",
        "category": "Hosting",
        "header_patterns": {"x-vercel-id": None},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "AWS CloudFront",
        "category": "CDN",
        "header_patterns": {"x-amz-cf-id": None},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "Google Cloud",
        "category": "Hosting",
        "header_patterns": {"server": "Google Frontend"},
        "body_patterns": [],
        "cookie_patterns": [],
    },
    {
        "name": "Fastly",
        "category": "CDN",
        "header_patterns": {"x-served-by": None, "x-cache": "HIT"},
        "body_patterns": [],
        "cookie_patterns": [],
    },
]


def _meta_generator(body: str) -> str:
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        body,
        re.IGNORECASE,
    )
    if not m:
        m = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
            body,
            re.IGNORECASE,
        )
    return m.group(1).lower() if m else ""


async def detect_tech(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookie_str = " ".join(
        v.decode("utf-8", errors="replace")
        for k, v in resp.headers.raw
        if k.lower() == b"set-cookie"
    )
    body = resp.text[:60000]
    meta_gen = _meta_generator(body)

    detected = []
    seen: set = set()

    for sig in SIGNATURES:
        name = sig["name"]
        if name in seen:
            continue

        evidence = None

        # Header patterns
        for h_key, h_val in sig.get("header_patterns", {}).items():
            actual = headers.get(h_key.lower(), "")
            if not actual:
                continue
            if h_val is None or h_val.lower() in actual.lower():
                evidence = f"{h_key}: {actual}"
                break

        # Body patterns
        if not evidence:
            for pattern in sig.get("body_patterns", []):
                if pattern.lower() in body.lower():
                    evidence = f"Found '{pattern}' in page source"
                    break

        # Cookie patterns
        if not evidence:
            for pat in sig.get("cookie_patterns", []):
                if pat.lower() in cookie_str.lower():
                    evidence = f"Cookie matches '{pat}'"
                    break

        # Meta generator
        if not evidence and sig.get("meta_generator"):
            if sig["meta_generator"].lower() in meta_gen:
                evidence = f"Meta generator: {meta_gen}"

        if evidence:
            detected.append({"name": name, "category": sig["category"], "evidence": evidence})
            seen.add(name)

    return {"technologies": detected, "count": len(detected)}
