import httpx
from urllib.parse import urlparse


# Hosts known to run on green/renewable infrastructure (subset of TGWF list)
GREEN_HOSTERS = {
    "cloudflare.com", "google.com", "googleusercontent.com",
    "github.io", "github.com", "amazonaws.com", "azurewebsites.net",
    "netlify.app", "vercel.app", "fly.dev", "pages.dev",
}


async def estimate_carbon(url: str) -> dict:
    """
    Estimate CO2 emissions per page visit.
    Uses websitecarbon.com /data endpoint (no API key required).
    We fetch the page ourselves to measure bytes, then send to the calculator.
    """
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""

    # 1. Measure page size by fetching the HTML
    try:
        async with httpx.AsyncClient(timeout=20, verify=False, follow_redirects=True) as client:
            r = await client.get(url)
        page_bytes = len(r.content)
    except Exception as exc:
        return {"error": str(exc), "message": "Could not fetch page to measure size"}

    if page_bytes == 0:
        return {"error": "Empty response", "message": "Page returned no content"}

    # 2. Guess if hosted on green infrastructure (heuristic)
    is_green = any(host == g or host.endswith("." + g) for g in GREEN_HOSTERS)

    # 3. Call websitecarbon /data API (no key required)
    api = f"https://api.websitecarbon.com/data?bytes={page_bytes}&green={'1' if is_green else '0'}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(api)
        if resp.status_code != 200:
            return {
                "pageBytes": page_bytes,
                "greenHosting": is_green,
                "error": f"Calculator API returned HTTP {resp.status_code}",
            }
        data = resp.json()
        st = data.get("statistics", {}) or {}
        co2 = st.get("co2", {}) or {}
        grid = co2.get("grid", {}) or {}
        renew = co2.get("renewable", {}) or {}
        return {
            "pageBytes": page_bytes,
            "pageSizeKB": round(page_bytes / 1024, 1),
            "greenHosting": is_green,
            "rating": data.get("rating"),
            "co2_grid_grams_per_visit": grid.get("grams"),
            "co2_renewable_grams_per_visit": renew.get("grams"),
            "energy_kWh_per_visit": st.get("energy"),
            "adjustedBytes": st.get("adjustedBytes"),
            "summary": f"~{round(grid.get('grams', 0), 3)}g CO\u2082 per visit (rating: {data.get('rating')})"
                       + (" \u2014 green hosting" if is_green else ""),
        }
    except Exception as exc:
        return {"pageBytes": page_bytes, "greenHosting": is_green, "error": str(exc)}
