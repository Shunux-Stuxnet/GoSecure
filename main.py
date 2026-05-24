import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.routes import router

app = FastAPI(title="GoSecure", description="A cyber security tool with web interface")
app.include_router(router)

# Routes that require real OS-level sockets — proxied to Render
SOCKET_ROUTES = {
    "/scan",
    "/dnsinfo",
    "/resolve",
    "/sslinfo",
    "/tls-analysis",
    "/cipher-suites",
    "/http-protocols",
    "/ip-geo",
    "/whois",
    "/ssl-chain",
}


@app.middleware("http")
async def proxy_socket_routes(request: Request, call_next):
    """
    Intercept socket-dependent routes and transparently forward them
    to the Render microservice. All other routes are handled locally.
    """
    if request.url.path in SOCKET_ROUTES:
        render_url = os.environ.get("RENDER_SOCKET_URL", "").rstrip("/")
        if not render_url:
            return Response(
                content='{"detail": "Socket service unavailable — RENDER_SOCKET_URL not set"}',
                status_code=503,
                media_type="application/json",
            )
        target = f"{render_url}{request.url.path}"
        body = await request.body()
        # Forward headers but strip Host to avoid conflicts
        forward_headers = {
            k: v for k, v in request.headers.items() if k.lower() != "host"
        }
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.request(
                    method=request.method,
                    url=target,
                    headers=forward_headers,
                    content=body,
                    params=dict(request.query_params),
                )
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type=resp.headers.get("content-type", "application/json"),
            )
        except httpx.TimeoutException:
            return Response(
                content='{"detail": "Socket service timed out"}',
                status_code=504,
                media_type="application/json",
            )
        except Exception as exc:
            return Response(
                content=f'{{"detail": "Socket service error: {exc}"}}',
                status_code=502,
                media_type="application/json",
            )

    return await call_next(request)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
