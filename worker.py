"""
GoSecure — Cloudflare Workers entry point (thin edge proxy).

Static assets (HTML, CSS, JS) are served directly from Cloudflare's CDN
via the [assets] config in wrangler.toml.

ALL API requests are transparently proxied to the Render backend which
runs the full FastAPI application with OS-level socket access.
"""
import os

from workers import WorkerEntrypoint, Response, Request, fetch


class Default(WorkerEntrypoint):
    async def fetch(self, request: Request) -> Response:
        url = request.url
        # Static assets are handled automatically by Cloudflare Assets binding.
        # Any non-static request (API calls) gets proxied to Render.
        render_url = self.env.RENDER_SOCKET_URL.rstrip("/") if hasattr(self.env, "RENDER_SOCKET_URL") else ""

        if not render_url:
            return Response.json(
                {"detail": "Backend service unavailable — RENDER_SOCKET_URL not configured"},
                status=503,
            )

        # Build the proxy target URL preserving path + query string
        parsed = url.split("//", 1)[-1]          # strip scheme
        path_and_query = parsed.split("/", 1)[-1] if "/" in parsed else ""
        target = f"{render_url}/{path_and_query}"

        # Forward the request to Render
        proxy_request = Request(target, method=request.method, headers=request.headers, body=request.body)
        return await fetch(proxy_request)
