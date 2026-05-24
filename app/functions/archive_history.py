import httpx
from urllib.parse import urlparse, quote


async def get_archive_history(url: str) -> dict:
    """Query Wayback Machine for snapshot history. Free, no API key."""
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or url

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # Latest snapshot
        latest = None
        try:
            r = await client.get(f"https://archive.org/wayback/available?url={quote(host)}")
            j = r.json()
            snap = (j.get("archived_snapshots") or {}).get("closest") or {}
            if snap.get("available"):
                latest = {
                    "url": snap.get("url"),
                    "timestamp": snap.get("timestamp"),
                    "status": snap.get("status"),
                }
        except Exception:
            pass

        # Total snapshot count + earliest/latest via CDX API
        first_ts = last_ts = None
        total = 0
        try:
            r = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={quote(host)}&output=json"
                "&fl=timestamp&limit=1&filter=statuscode:200"
            )
            rows = r.json()
            if len(rows) > 1:
                first_ts = rows[1][0]
        except Exception:
            pass
        try:
            r = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={quote(host)}&output=json"
                "&fl=timestamp&limit=-1&filter=statuscode:200"
            )
            rows = r.json()
            if len(rows) > 1:
                last_ts = rows[1][0]
        except Exception:
            pass
        try:
            r = await client.get(
                f"https://web.archive.org/cdx/search/cdx?url={quote(host)}&output=json"
                "&showNumPages=true"
            )
            j = r.json()
            # showNumPages returns a single int in some cases
            if isinstance(j, list) and j:
                total = j[0] * 150_000 if isinstance(j[0], int) else 0
        except Exception:
            pass

    def fmt(ts):
        if not ts or len(ts) < 8:
            return None
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"

    return {
        "found": bool(latest or first_ts),
        "latest": latest,
        "firstSnapshot": fmt(first_ts),
        "lastSnapshot": fmt(last_ts),
        "approxTotal": total if total else None,
        "summary": f"First archived {fmt(first_ts)}, latest {fmt(last_ts)}" if first_ts
                   else "Site has never been archived by the Wayback Machine",
    }
