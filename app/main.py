from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import asyncio

from .routers import ui, api, health
from core.config import settings
from core.database import init_db
from core.ddns_engine import DDNSEngine
from core.annotation_watcher import AnnotationWatcher
from core.traefik_watcher import TraefikWatcher

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting Cloudflare DDNS service v0.3.0...")
    init_db()

    engine = DDNSEngine()
    asyncio.create_task(engine.start_background_task())

    if settings.enable_annotation_discovery:
        watcher = AnnotationWatcher()
        asyncio.create_task(asyncio.to_thread(watcher.watch_resources))

    if settings.enable_traefik_discovery:
        traefik = TraefikWatcher()
        asyncio.create_task(asyncio.to_thread(traefik.watch_ingress_routes))

    yield
    print("Shutting down...")

app = FastAPI(
    title="Cloudflare DDNS",
    description="Modern Cloudflare Dynamic DNS with Web UI, annotation discovery, and Traefik integration",
    version="0.3.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(ui.router, tags=["ui"])
app.include_router(api.router, prefix="/api", tags=["api"])