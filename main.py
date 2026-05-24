"""
GoSecure — Full FastAPI application.

Deployed on Render as the complete backend. Cloudflare Workers acts as
a CDN + proxy edge layer that forwards all API requests here.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.routes import router

app = FastAPI(title="GoSecure", description="A cyber security tool with web interface")

# Allow CORS from the Cloudflare Workers origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # tighten to your Workers domain in production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Serve static files and index.html for local development / fallback
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def serve_index():
    return FileResponse("views/index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
