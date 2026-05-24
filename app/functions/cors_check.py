import httpx

EVIL_ORIGIN = "https://evil.example.com"


async def check_cors(url: str) -> dict:
    issues = []
    allow_origin = None
    allow_credentials = False
    null_origin_allowed = False

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        # Test 1: reflected origin
        resp = await client.get(url, headers={"Origin": EVIL_ORIGIN})
        allow_origin = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        allow_credentials = acac == "true"

        if allow_origin == "*":
            issues.append("Wildcard origin (ACAO: *)")
        elif allow_origin == EVIL_ORIGIN:
            issues.append("Origin reflection")

        if allow_credentials and allow_origin and allow_origin != "null":
            issues.append("Credentials allowed with permissive CORS (critical)")

        # Test 2: null origin
        null_resp = await client.get(url, headers={"Origin": "null"})
        null_acao = null_resp.headers.get("Access-Control-Allow-Origin")
        if null_acao == "null":
            null_origin_allowed = True
            issues.append("Null origin accepted")

    return {
        "allowOrigin": allow_origin,
        "allowCredentials": allow_credentials,
        "nullOriginAllowed": null_origin_allowed,
        "vulnerable": len(issues) > 0,
        "issues": issues,
    }
