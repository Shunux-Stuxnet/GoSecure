import asyncio
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.functions.dns_info import perform_dns_lookup
from app.functions.port_scan import scan_ports
from app.functions.server_info import get_server_info
from app.functions.ssl_info import get_ssl_info
from app.functions.whois_info import get_whois_info
from app.functions.tls_analysis import analyze_tls
from app.functions.cipher_suites import enumerate_ciphers
from app.functions.http_protocols import check_http_protocols
from app.functions.ip_geo import get_ip_geo
from app.functions.ssl_chain import get_ssl_chain

app = FastAPI(
    title="GoSecure Socket Service",
    description="Internal microservice — handles routes that require OS-level sockets",
    docs_url=None,   # disable public docs
    redoc_url=None,
)

# Only allow requests from the Cloudflare Workers origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://gosecure.workers.dev"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ── DNS Info ──────────────────────────────────────────────────────────────────
@app.post("/dnsinfo")
async def dns_info_handler(hostname: str = Form(...)):
    if hostname.startswith("http://") or hostname.startswith("https://"):
        hostname = urlparse(hostname).hostname
    try:
        return perform_dns_lookup(hostname)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS lookup error: {e}")


# ── Port Scanner ──────────────────────────────────────────────────────────────
@app.post("/scan")
async def scan_handler(hostname: str = Form(...)):
    if not hostname:
        raise HTTPException(status_code=400, detail="You must provide a hostname!")
    try:
        results = await scan_ports(hostname)
        return {"ports": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {e}")


# ── DNS Server Info ───────────────────────────────────────────────────────────
@app.post("/resolve")
async def dns_server_handler(url: str = Form(...)):
    domain = url.removeprefix("http://").removeprefix("https://")
    try:
        return await get_server_info(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS resolve error: {e}")


# ── SSL Certificate ───────────────────────────────────────────────────────────
@app.post("/sslinfo")
async def ssl_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")
    try:
        return get_ssl_info(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL error: {e}")


# ── WHOIS ─────────────────────────────────────────────────────────────────────
@app.post("/whois")
async def whois_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="You must provide a URL!")
    try:
        return get_whois_info(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"WHOIS error: {e}")


# ── TLS Analysis ──────────────────────────────────────────────────────────────
@app.post("/tls-analysis")
async def tls_analysis_handler(url: str = Form(...)):
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return analyze_tls(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Cipher Suites ─────────────────────────────────────────────────────────────
@app.post("/cipher-suites")
async def cipher_suites_handler(url: str = Form(...)):
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await asyncio.to_thread(enumerate_ciphers, domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── HTTP Protocols (HTTP/2, HTTP/3) ───────────────────────────────────────────
@app.post("/http-protocols")
async def http_protocols_handler(url: str = Form(...)):
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        return await check_http_protocols(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── IP Geolocation ────────────────────────────────────────────────────────────
@app.post("/ip-geo")
async def ip_geo_handler(url: str = Form(...)):
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await get_ip_geo(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── SSL Certificate Chain ─────────────────────────────────────────────────────
@app.post("/ssl-chain")
async def ssl_chain_handler(url: str = Form(...)):
    domain = url.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        return await get_ssl_chain(domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
