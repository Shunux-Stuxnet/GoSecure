"""
GoSecure — Cloudflare Workers edge proxy.

Static assets served by Cloudflare CDN ([assets] in wrangler.toml).
All other requests proxied to the Render backend.
"""
from js import fetch, Request, Headers, Response
from workers import WorkerEntrypoint


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        url = str(request.url)

        # Try to get the Render backend URL from env
        render_url = ""
        try:
            render_url = str(self.env.RENDER_SOCKET_URL).rstrip("/")
        except Exception:
            pass

        if not render_url:
            return Response.json(
                '{"detail":"RENDER_SOCKET_URL not configured"}',
                status=503,
            )

        # Extract path + query from the incoming URL
        # e.g. https://gosecure.shunux.workers.dev/scan?x=1 → /scan?x=1
        parts = url.split("//", 1)
        if len(parts) > 1:
            after_scheme = parts[1]
            slash_idx = after_scheme.find("/")
            if slash_idx != -1:
                path_query = after_scheme[slash_idx:]
            else:
                path_query = "/"
        else:
            path_query = "/"

        target = render_url + path_query

        # Build proxy headers (strip host)
        proxy_headers = Headers.new()
        entries = request.headers.entries()
        while True:
            result = entries.next()
            if result.done:
                break
            key = result.value[0]
            val = result.value[1]
            if key.lower() != "host":
                proxy_headers.set(key, val)

        # Forward the request
        proxy_req = Request.new(target, method=request.method, headers=proxy_headers, body=request.body, redirect="follow")
        return await fetch(proxy_req)
