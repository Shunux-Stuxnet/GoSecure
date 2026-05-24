import socket
import httpx
from urllib.parse import urlparse


async def get_ip_geo(domain: str) -> dict:
    if domain.startswith("http"):
        domain = urlparse(domain).hostname or domain

    try:
        ip = socket.gethostbyname(domain)
    except Exception as exc:
        return {"error": f"DNS resolution failed: {exc}"}

    # ip-api.com — free, no key, 45 req/min limit
    fields = "status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
        data = resp.json()
        if data.get("status") != "success":
            return {"ip": ip, "error": data.get("message", "lookup failed")}
        return {
            "ip": ip,
            "country": data.get("country"),
            "countryCode": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "zip": data.get("zip"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "asnName": data.get("asname"),
            "reverseDns": data.get("reverse"),
        }
    except Exception as exc:
        return {"ip": ip, "error": f"Geo lookup failed: {exc}"}
