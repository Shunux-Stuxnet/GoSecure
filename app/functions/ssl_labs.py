"""SSL Labs deep TLS security audit (free, no API key).
NOTE: This is intentionally NOT included in the Full Audit because
the first scan for any host can take 60-180 seconds. User must
trigger it manually from the UI."""

import asyncio
import httpx
from urllib.parse import urlparse


API_BASE = "https://api.ssllabs.com/api/v3"


async def ssl_labs_audit(url: str, from_cache: bool = True) -> dict:
    if url.startswith("http"):
        url = urlparse(url).hostname or url
    host = url

    params = {
        "host": host,
        "publish": "off",
        "all": "done",
        "ignoreMismatch": "on",
    }
    if from_cache:
        params["fromCache"] = "on"
        params["maxAge"] = "24"   # accept results up to 24h old

    async with httpx.AsyncClient(timeout=60) as client:
        # Poll until READY or ERROR (cap ~2 min wall-clock)
        deadline = 120
        elapsed = 0
        last = None
        while elapsed < deadline:
            try:
                r = await client.get(f"{API_BASE}/analyze", params=params)
            except Exception as exc:
                return {"host": host, "error": f"Network: {exc}", "status": "error"}
            if r.status_code != 200:
                return {"host": host, "error": f"HTTP {r.status_code}", "status": "error",
                        "body": r.text[:300]}
            data = r.json()
            status = data.get("status")
            last = data
            if status in ("READY", "ERROR"):
                break
            await asyncio.sleep(5)
            elapsed += 5
            # Subsequent polls should NOT force fromCache
            params.pop("fromCache", None)
            params.pop("maxAge", None)

        if not last or last.get("status") != "READY":
            return {"host": host, "status": last.get("status") if last else "unknown",
                    "summary": "SSL Labs scan did not complete in time",
                    "raw": last}

        endpoints = []
        for ep in last.get("endpoints", []) or []:
            details = ep.get("details") or {}
            endpoints.append({
                "ip": ep.get("ipAddress"),
                "grade": ep.get("grade"),
                "gradeTrustIgnored": ep.get("gradeTrustIgnored"),
                "serverName": ep.get("serverName"),
                "hasWarnings": ep.get("hasWarnings"),
                "isExceptional": ep.get("isExceptional"),
                "forwardSecrecy": details.get("forwardSecrecy"),
                "supportsRc4": details.get("supportsRc4"),
                "vulnBeast": details.get("vulnBeast"),
                "heartbleed": details.get("heartbleed"),
                "poodle": details.get("poodle"),
                "freak": details.get("freak"),
                "logjam": details.get("logjam"),
                "drownVulnerable": details.get("drownVulnerable"),
                "bleichenbacher": details.get("bleichenbacher") if not isinstance(details.get("bleichenbacher"), dict) else details["bleichenbacher"].get("result"),
                "openSslCcs": details.get("openSslCcs"),
                "openSSLLuckyMinus20": details.get("openSSLLuckyMinus20"),
                "ticketbleed": details.get("ticketbleed"),
                "robotResult": details.get("robot") if not isinstance(details.get("robot"), dict) else details["robot"].get("result"),
            })

        grades = sorted({e["grade"] for e in endpoints if e.get("grade")}) or ["?"]
        return {
            "host": host,
            "status": "READY",
            "engineVersion": last.get("engineVersion"),
            "criteriaVersion": last.get("criteriaVersion"),
            "testTime": last.get("testTime"),
            "endpoints": endpoints,
            "endpointCount": len(endpoints),
            "grade": grades[0] if len(grades) == 1 else "/".join(grades),
            "summary": f"SSL Labs grade: {'/'.join(grades)} ({len(endpoints)} endpoint(s))",
            "reportUrl": f"https://www.ssllabs.com/ssltest/analyze.html?d={host}",
        }
