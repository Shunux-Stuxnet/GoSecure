import httpx


def _parse_csp(header: str) -> dict:
    """Parse CSP header string into {directive: [values]} dict."""
    directives = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    return directives


def _effective_src(directives: dict, directive: str) -> list:
    """Return values for directive, falling back to default-src."""
    return directives.get(directive, directives.get("default-src", []))


def _check_directives(directives: dict) -> list:
    issues = []

    script_src = _effective_src(directives, "script-src")
    sl = [s.lower() for s in script_src]

    if "script-src" not in directives and "default-src" not in directives:
        issues.append({
            "severity": "high",
            "directive": "script-src",
            "issue": "No script-src or default-src — JavaScript sources are unrestricted",
        })

    if "'unsafe-inline'" in sl:
        issues.append({
            "severity": "high",
            "directive": "script-src",
            "issue": "'unsafe-inline' allows execution of inline scripts — primary XSS vector",
        })

    if "'unsafe-eval'" in sl:
        issues.append({
            "severity": "high",
            "directive": "script-src",
            "issue": "'unsafe-eval' allows eval() and Function() — enables dynamic code execution",
        })

    if "*" in sl or "http:" in sl or "https:" in sl:
        issues.append({
            "severity": "critical",
            "directive": "script-src",
            "issue": "Wildcard or bare scheme (*, http:, https:) loads scripts from any origin",
        })

    if "data:" in sl:
        issues.append({
            "severity": "high",
            "directive": "script-src",
            "issue": "'data:' URI allows base64-encoded inline script execution",
        })

    # object-src
    obj_src = _effective_src(directives, "object-src")
    if "'none'" not in [s.lower() for s in obj_src]:
        issues.append({
            "severity": "medium",
            "directive": "object-src",
            "issue": "object-src not 'none' — Flash/plugin execution may be possible",
        })

    # base-uri
    if "base-uri" not in directives:
        issues.append({
            "severity": "medium",
            "directive": "base-uri",
            "issue": "Missing base-uri directive — base tag injection can redirect relative URLs",
        })

    # frame-ancestors
    if "frame-ancestors" not in directives:
        issues.append({
            "severity": "medium",
            "directive": "frame-ancestors",
            "issue": "Missing frame-ancestors — clickjacking protection not enforced via CSP",
        })

    # upgrade-insecure-requests
    if "upgrade-insecure-requests" not in directives:
        issues.append({
            "severity": "low",
            "directive": "upgrade-insecure-requests",
            "issue": "Missing upgrade-insecure-requests — mixed HTTP content not auto-upgraded",
        })

    return issues


def _rating(issues: list) -> str:
    sevs = [i["severity"] for i in issues]
    if "critical" in sevs:
        return "F"
    if sevs.count("high") >= 2:
        return "D"
    if "high" in sevs:
        return "C"
    if "medium" in sevs:
        return "B"
    if issues:
        return "B"
    return "A"


async def analyze_csp(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        resp = await client.get(url)

    csp_header = resp.headers.get("Content-Security-Policy")

    if not csp_header:
        return {
            "cspPresent": False,
            "directives": {},
            "issues": [{
                "severity": "critical",
                "directive": "N/A",
                "issue": "No Content-Security-Policy header — all content sources unrestricted",
            }],
            "issueCount": 1,
            "rating": "F",
        }

    directives = _parse_csp(csp_header)
    issues = _check_directives(directives)

    return {
        "cspPresent": True,
        "directives": {k: " ".join(v) for k, v in directives.items()},
        "issues": issues,
        "issueCount": len(issues),
        "rating": _rating(issues),
    }
