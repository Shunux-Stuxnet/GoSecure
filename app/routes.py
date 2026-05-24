from urllib.parse import urlparse

from fastapi import APIRouter, Form, Query, HTTPException

from app.functions.dns_info import perform_dns_lookup
from app.functions.header import has_protocol_scheme, get_remote_data
from app.functions.port_scan import scan_ports
from app.functions.hsts_checker import check_hsts
from app.functions.check_server_status import check_server_status
from app.functions.dnssec import get_rrsig_with_key
from app.functions.server_info import get_server_info
from app.functions.ssl_info import get_ssl_info
from app.functions.cookie import find_cookies
from app.functions.whois_info import get_whois_info
from app.functions.sitemap import get_sitemap_url, fetch_sitemap
from app.functions.crawler import add_schema_if_missing, fetch_robots_txt
from app.functions.security_headers import check_security_headers
from app.functions.email_security import check_email_security
from app.functions.cors_check import check_cors
from app.functions.clickjacking import check_clickjacking
from app.functions.redirect_chain import trace_redirects
from app.functions.tech_detect import detect_tech
from app.functions.outdated_check import check_outdated_software
from app.functions.js_libraries import audit_js_libraries
from app.functions.tls_analysis import analyze_tls
from app.functions.csp_analysis import analyze_csp
from app.functions.mixed_content import detect_mixed_content
from app.functions.sri_check import audit_sri
from app.functions.open_redirect import check_open_redirect
from app.functions.subdomain_enum import enumerate_subdomains
from app.functions.full_scan import run_full_scan

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

# Phase 6: web-check parity additions
from app.functions.site_features import audit_site_features
from app.functions.malware_check import check_malware
from app.functions.global_ranking import get_global_ranking
from app.functions.ssl_chain import get_ssl_chain
from app.functions.ct_subdomains import find_ct_subdomains
from app.functions.bimi import check_bimi
from app.functions.ssl_labs import ssl_labs_audit

router = APIRouter()


@router.post("/dnsinfo")
async def dns_info_handler(hostname: str = Form(...)):
    if hostname.startswith("http://") or hostname.startswith("https://"):
        parsed = urlparse(hostname)
        hostname = parsed.hostname

    try:
        resp = perform_dns_lookup(hostname)
        return resp
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS lookup error: {e}")


@router.get("/getData")
async def header_handler(url: str = Query(...)):
    if not url:
        raise HTTPException(status_code=400, detail="url query string parameter is required")

    if not has_protocol_scheme(url):
        url = "http://" + url

    try:
        headers = await get_remote_data(url)
        return headers
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan")
async def scan_handler(hostname: str = Form(...)):
    if not hostname:
        raise HTTPException(status_code=400, detail="You must provide a hostname!")

    try:
        results = await scan_ports(hostname)
        return {"ports": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


@router.post("/hsts")
async def hsts_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL parameter is missing!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid URL format!")

    try:
        result = await check_hsts(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking HSTS policy: {e}")


@router.post("/servs")
async def server_status_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    try:
        result = await check_server_status(url)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


@router.post("/dnssec")
async def dnssec_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    try:
        result = get_rrsig_with_key(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error while querying DNS records: {e}")


@router.post("/resolve")
async def dns_server_handler(url: str = Form(...)):
    domain = url.removeprefix("http://").removeprefix("https://")

    try:
        result = await get_server_info(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while resolving DNS. {e}")


@router.post("/sslinfo")
async def ssl_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    try:
        ssl_info = get_ssl_info(url)
        return ssl_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error while fetching SSL Details: {e}")


@router.post("/cookie")
async def cookie_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    try:
        cookie_info = await find_cookies(url)
        return cookie_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error while fetching cookie: {e}")


@router.post("/whois")
async def whois_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    try:
        whois_info = get_whois_info(url)
        return whois_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching WHOIS information: {e}")


@router.post("/sitemap")
async def sitemap_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        sitemap_url = await get_sitemap_url(url)
        sitemap_data = await fetch_sitemap(sitemap_url)
        return {"URL": url, "Sitemap": sitemap_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crawlcheck")
async def crawl_handler(siteURL: str = Form(...)):
    if not siteURL:
        raise HTTPException(status_code=400, detail="Missing url query parameter")

    site_url = add_schema_if_missing(siteURL)

    try:
        robots_txt = await fetch_robots_txt(site_url)
        return {"Crawling Rules ": robots_txt}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching robots.txt: {e}")


@router.post("/security-headers")
async def security_headers_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await check_security_headers(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/email-security")
async def email_security_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a domain!")

    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]

    try:
        result = check_email_security(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cors-check")
async def cors_check_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await check_cors(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/clickjacking")
async def clickjacking_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await check_clickjacking(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/redirect-chain")
async def redirect_chain_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    try:
        result = await trace_redirects(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tech-detect")
async def tech_detect_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await detect_tech(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/outdated-check")
async def outdated_check_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await check_outdated_software(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/js-audit")
async def js_audit_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await audit_js_libraries(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tls-analysis")
async def tls_analysis_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a domain!")

    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]

    try:
        result = analyze_tls(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/csp-analysis")
async def csp_analysis_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await analyze_csp(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mixed-content")
async def mixed_content_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await detect_mixed_content(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sri-check")
async def sri_check_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await audit_sri(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/open-redirect")
async def open_redirect_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        result = await check_open_redirect(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/subdomain-enum")
async def subdomain_enum_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a domain!")

    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]

    try:
        result = await enumerate_subdomains(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full-scan")
async def full_scan_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL or domain!")

    try:
        result = await run_full_scan(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- New free checks (Phase 5) ----------------------------------

@router.post("/http-protocols")
async def http_protocols_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await check_http_protocols(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security-txt")
async def security_txt_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await check_security_txt(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/social-tags")
async def social_tags_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await audit_social_tags(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/waf-detect")
async def waf_detect_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await detect_waf(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/caa-records")
async def caa_records_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return get_caa_records(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ip-geo")
async def ip_geo_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await get_ip_geo(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/archive-history")
async def archive_history_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await get_archive_history(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/carbon")
async def carbon_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await estimate_carbon(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/http-methods")
async def http_methods_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await enumerate_http_methods(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cipher-suites")
async def cipher_suites_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        import asyncio
        return await asyncio.to_thread(enumerate_ciphers, domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/linked-pages")
async def linked_pages_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await audit_linked_pages(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns-blocks")
async def dns_blocks_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await check_dns_blocks(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ----- Phase 6: web-check parity additions -----

@router.post("/site-features")
async def site_features_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await audit_site_features(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/malware-check")
async def malware_check_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await check_malware(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/global-ranking")
async def global_ranking_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await get_global_ranking(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ssl-chain")
async def ssl_chain_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await get_ssl_chain(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ct-subdomains")
async def ct_subdomains_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await find_ct_subdomains(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bimi")
async def bimi_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        import asyncio
        return await asyncio.to_thread(check_bimi, domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ssl-labs")
async def ssl_labs_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="Domain is required")
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await ssl_labs_audit(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
