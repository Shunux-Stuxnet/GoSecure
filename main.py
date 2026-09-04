import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no external dependency). Loads KEY=VALUE lines
    into os.environ without overriding vars already set in the shell."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


_load_dotenv()

from app.routes import router

app = FastAPI(title="GoSecure", description="A cyber security tool with web interface")

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(router)


@app.on_event("shutdown")
async def _shutdown():
    from app.functions.http_client import close_client
    await close_client()


@app.get("/")
async def index():
    return FileResponse("views/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
