import httpx


async def check_hsts(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        resp = await client.get(url)

    hsts_header = resp.headers.get("strict-transport-security", "")

    if not hsts_header:
        return {"message": "Site does not serve any HSTS headers.", "compatible": False}

    if "max-age" in hsts_header:
        try:
            max_age_str = hsts_header.split("max-age=")[1].split(";")[0].strip()
            max_age = int(max_age_str)
            if max_age < 10886400:
                return {"message": "HSTS max-age is less than 10886400.", "compatible": False}
        except (IndexError, ValueError):
            return {"message": "Could not parse HSTS max-age.", "compatible": False}

    if "includesubdomains" not in hsts_header.lower():
        return {"message": "HSTS header does not include all subdomains.", "compatible": False}

    if "preload" not in hsts_header.lower():
        return {"message": "HSTS header does not contain the preload directive.", "compatible": False}

    return {
        "message": "Site is compatible with the HSTS preload list!",
        "compatible": True,
        "hstsHeader": hsts_header,
    }
