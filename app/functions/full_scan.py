import asyncio
import time
from urllib.parse import urlparse

from app.functions.security_headers import check_security_headers
from app.functions.cookie import find_cookies
from app.functions.email_security import check_email_security
from app.functions.cors_check import check_cors
from app.functions.clickjacking import check_clickjacking
from app.functions.redirect_chain import trace_redirects
from app.functions.outdated_check import check_outdated_software
from app.functions.js_libraries import audit_js_libraries
from app.functions.tls_analysis import analyze_tls
from app.functions.csp_analysis import analyze_csp
from app.functions.mixed_content import detect_mixed_content
from app.functions.sri_check import audit_sri
from app.functions.open_redirect import check_open_redirect
from app.functions.hsts_checker import check_hsts
# Additional checks for full coverage
from app.functions.whois_info import get_whois_info
from app.functions.dns_info import perform_dns_lookup
from app.functions.dnssec import get_rrsig_with_key
from app.functions.server_info import get_server_info
from app.functions.subdomain_enum import enumerate_subdomains
from app.functions.header import get_remote_data
from app.functions.port_scan import scan_ports
from app.functions.check_server_status import check_server_status
from app.functions.ssl_info import get_ssl_info
from app.functions.tech_detect import detect_tech
from app.functions.sitemap import get_sitemap_url, fetch_sitemap
from app.functions.crawler import fetch_robots_txt
# Phase 5: more free checks
from app.functions.http_protocols import check_http_protocols
from app.functions.security_txt import check_security_txt
from app.functions.social_tags import audit_social_tags
from app.functions.waf_detect import detect_waf
from app.functions.caa_records import get_caa_records
from app.functions.ip_geo import get_ip_geo
from app.functions.archive_history import get_archive_history
from app.functions.carbon import estimate_carbon
from app.functions.http_methods import enumerate_http_methods
from app.functions.cipher_suites import enumerate_ciphers
from app.functions.linked_pages import audit_linked_pages
from app.functions.dns_block_check import check_dns_blocks
# Phase 6: web-check parity additions (SSL Labs excluded - too slow for full scan)
from app.functions.site_features import audit_site_features
from app.functions.malware_check import check_malware
from app.functions.global_ranking import get_global_ranking
from app.functions.ssl_chain import get_ssl_chain
from app.functions.ct_subdomains import find_ct_subdomains
from app.functions.bimi import check_bimi

# Per-check max scores (must sum to 100)
WEIGHTS = {
    "securityHeaders": 14,
    "tls": 14,
    "csp": 14,
    "hsts": 9,
    "clickjacking": 9,
    "cors": 9,
    "cookies": 5,
    "openRedirect": 5,
    "mixedContent": 5,
    "sri": 5,
    "outdatedSoftware": 5,
    "emailSecurity": 6,
}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _eval_security_headers(d: dict) -> tuple:
    earned = round(d.get("score", 0) / 100 * WEIGHTS["securityHeaders"])
    g = d.get("grade", "F")
    status = "pass" if g in ("A", "B") else "warn" if g == "C" else "fail"
    return status, earned


def _eval_tls(d: dict) -> tuple:
    if d.get("safe"):
        return "pass", WEIGHTS["tls"]
    issues = d.get("issues", [])
    serious = any(kw in i for i in issues for kw in ("1.0", "1.1", "Weak", "weak"))
    return ("fail", 0) if serious else ("warn", WEIGHTS["tls"] // 2)


def _eval_csp(d: dict) -> tuple:
    rating = d.get("rating", "F")
    pct = {"A": 1.0, "B": 0.85, "C": 0.6, "D": 0.3, "F": 0.0}.get(rating, 0.0)
    status = "pass" if rating in ("A", "B") else "warn" if rating == "C" else "fail"
    return status, round(pct * WEIGHTS["csp"])


def _eval_hsts(d: dict) -> tuple:
    return ("pass", WEIGHTS["hsts"]) if d.get("compatible") else ("fail", 0)


def _eval_clickjacking(d: dict) -> tuple:
    return ("pass", WEIGHTS["clickjacking"]) if not d.get("vulnerable") else ("fail", 0)


def _eval_cors(d: dict) -> tuple:
    if not d.get("vulnerable"):
        return "pass", WEIGHTS["cors"]
    issues = d.get("issues", [])
    critical = any("critical" in i.lower() or "credentials" in i.lower() for i in issues)
    return ("fail", 0) if critical else ("warn", WEIGHTS["cors"] // 2)


def _eval_cookies(d: dict) -> tuple:
    total_issues = sum(len(c.get("issues", [])) for c in d.get("cookies", []))
    if total_issues == 0:
        return "pass", WEIGHTS["cookies"]
    return "warn", max(0, WEIGHTS["cookies"] - total_issues)


def _eval_open_redirect(d: dict) -> tuple:
    return ("pass", WEIGHTS["openRedirect"]) if d.get("safe") else ("fail", 0)


def _eval_mixed_content(d: dict) -> tuple:
    if d.get("safe"):
        return "pass", WEIGHTS["mixedContent"]
    return ("fail", 0) if d.get("activeCount", 0) > 0 else ("warn", WEIGHTS["mixedContent"] // 2)


def _eval_sri(d: dict) -> tuple:
    total = d.get("totalExternal", 0)
    missing = d.get("missingSRI", 0)
    if missing == 0:
        return "pass", WEIGHTS["sri"]
    ratio = (total - missing) / total if total > 0 else 0
    return "warn", round(ratio * WEIGHTS["sri"])


def _eval_outdated(d: dict) -> tuple:
    if d.get("safe"):
        return "pass", WEIGHTS["outdatedSoftware"]
    critical = sum(1 for i in d.get("issues", []) if i.get("severity") in ("critical", "high"))
    return ("fail", 0) if critical else ("warn", WEIGHTS["outdatedSoftware"] // 2)


def _eval_email(d: dict) -> tuple:
    spf = d.get("spf", {}).get("present", False)
    dmarc = d.get("dmarc", {}).get("present", False)
    if spf and dmarc:
        return "pass", WEIGHTS["emailSecurity"]
    if spf or dmarc:
        return "warn", WEIGHTS["emailSecurity"] // 2
    return "fail", 0


EVALUATORS = {
    "securityHeaders": _eval_security_headers,
    "tls": _eval_tls,
    "csp": _eval_csp,
    "hsts": _eval_hsts,
    "clickjacking": _eval_clickjacking,
    "cors": _eval_cors,
    "cookies": _eval_cookies,
    "openRedirect": _eval_open_redirect,
    "mixedContent": _eval_mixed_content,
    "sri": _eval_sri,
    "outdatedSoftware": _eval_outdated,
    "emailSecurity": _eval_email,
}


async def run_full_scan(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    https_url = f"https://{domain}"
    start = time.time()

    async def safe(name: str, coro):
        try:
            return name, await coro, None
        except Exception as exc:
            return name, None, str(exc)

    async def _sitemap_check(d: str):
        sitemap_url = await get_sitemap_url(d)
        content = await fetch_sitemap(sitemap_url)
        return {"url": sitemap_url, "content": content[:2000] if content else ""}

    raw = await asyncio.gather(
        # --- Scored security checks ---
        safe("securityHeaders", check_security_headers(https_url)),
        safe("cookies",          find_cookies(domain)),
        safe("emailSecurity",    asyncio.to_thread(check_email_security, domain)),
        safe("cors",             check_cors(https_url)),
        safe("clickjacking",     check_clickjacking(https_url)),
        safe("redirectChain",    trace_redirects(f"http://{domain}")),
        safe("outdatedSoftware", check_outdated_software(https_url)),
        safe("jsLibraries",      audit_js_libraries(https_url)),
        safe("tls",              asyncio.to_thread(analyze_tls, domain)),
        safe("csp",              analyze_csp(https_url)),
        safe("mixedContent",     detect_mixed_content(https_url)),
        safe("sri",              audit_sri(https_url)),
        safe("openRedirect",     check_open_redirect(https_url)),
        safe("hsts",             check_hsts(https_url)),
        # --- Informational: DNS ---
        safe("whois",            asyncio.to_thread(get_whois_info, domain)),
        safe("dnsLookup",        asyncio.to_thread(perform_dns_lookup, domain)),
        safe("dnssec",           asyncio.to_thread(get_rrsig_with_key, domain)),
        safe("serverInfo",       get_server_info(domain)),
        safe("subdomainEnum",    enumerate_subdomains(domain)),
        # --- Informational: Tech Stack ---
        safe("remoteHeaders",    get_remote_data(https_url)),
        safe("portScan",         scan_ports(domain)),
        safe("serverStatus",     check_server_status(https_url)),
        safe("sslInfo",          asyncio.to_thread(get_ssl_info, domain)),
        safe("techDetect",       detect_tech(https_url)),
        safe("sitemap",          _sitemap_check(domain)),
        safe("crawlRules",       fetch_robots_txt(https_url)),
        # --- Phase 5: extra free checks ---
        safe("httpProtocols",    check_http_protocols(https_url)),
        safe("securityTxt",      check_security_txt(https_url)),
        safe("socialTags",       audit_social_tags(https_url)),
        safe("wafDetect",        detect_waf(https_url)),
        safe("caaRecords",       asyncio.to_thread(get_caa_records, domain)),
        safe("ipGeo",            get_ip_geo(domain)),
        safe("archiveHistory",   get_archive_history(https_url)),
        safe("carbon",           estimate_carbon(https_url)),
        safe("httpMethods",      enumerate_http_methods(https_url)),
        safe("cipherSuites",     asyncio.to_thread(enumerate_ciphers, domain)),
        safe("linkedPages",      audit_linked_pages(https_url)),
        safe("dnsBlocks",        check_dns_blocks(domain)),
        # --- Phase 6: web-check parity (free, no key) ---
        safe("siteFeatures",     audit_site_features(https_url)),
        safe("malwareCheck",     check_malware(https_url)),
        safe("globalRanking",    get_global_ranking(https_url)),
        safe("sslChain",         get_ssl_chain(domain)),
        safe("ctSubdomains",     find_ct_subdomains(domain)),
        safe("bimi",             asyncio.to_thread(check_bimi, domain)),
    )

    results = {name: (data, err) for name, data, err in raw}
    checks = {}
    total_earned = 0

    for name, eval_fn in EVALUATORS.items():
        data, err = results.get(name, (None, "not run"))
        if err or data is None:
            checks[name] = {"status": "error", "score": 0, "maxScore": WEIGHTS[name], "error": err}
            continue
        status, earned = eval_fn(data)
        total_earned += earned
        checks[name] = {"status": status, "score": earned, "maxScore": WEIGHTS[name], "data": data}

    # Non-scored informational checks (all tabs)
    INFO_CHECKS = (
        "redirectChain", "jsLibraries",
        "whois", "dnsLookup", "dnssec", "serverInfo", "subdomainEnum",
        "remoteHeaders", "portScan", "serverStatus", "sslInfo",
        "techDetect", "sitemap", "crawlRules",
        # Phase 5
        "httpProtocols", "securityTxt", "socialTags", "wafDetect",
        "caaRecords", "ipGeo", "archiveHistory", "carbon",
        "httpMethods", "cipherSuites", "linkedPages", "dnsBlocks",
        # Phase 6
        "siteFeatures", "malwareCheck", "globalRanking", "sslChain",
        "ctSubdomains", "bimi",
    )
    for name in INFO_CHECKS:
        if name in checks:
            continue
        data, err = results.get(name, (None, None))
        if err:
            checks[name] = {"status": "error", "error": err}
        elif data is not None:
            if isinstance(data, (str, list)):
                data = {"result": data}
            checks[name] = {"status": "info", "data": data}

    counts = {"pass": 0, "warn": 0, "fail": 0, "error": 0}
    for c in checks.values():
        s = c.get("status", "error")
        if s in counts:
            counts[s] += 1

    return {
        "domain": domain,
        "overallGrade": _grade(total_earned),
        "overallScore": total_earned,
        "summary": counts,
        "checks": checks,
        "scanDuration": round(time.time() - start, 2),
    }
