"""FastAPI application entrypoint."""
import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers import api, health, ui
from core.auth import AuthMiddleware, router as auth_router
from core.config import settings
from core.database import init_db
from core.ddns_engine import DDNSEngine

log = logging.getLogger("cfddns")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting Cloudflare DDNS v%s", app.version)
    init_db()

    # DDNS engine
    engine = DDNSEngine()
    app.state.engine = engine
    asyncio.create_task(engine.start_background_task())

    # Optional discovery threads
    if settings.enable_annotation_discovery:
        try:
            from core.annotation_watcher import AnnotationWatcher
            watcher = AnnotationWatcher()
            asyncio.create_task(asyncio.to_thread(watcher.watch_loop, settings.poll_interval_seconds))
            log.info("Annotation discovery enabled")
        except Exception as e:
            log.warning("Annotation discovery not started: %s", e)

    if settings.enable_traefik_discovery:
        try:
            from core.traefik_watcher import TraefikWatcher
            traefik = TraefikWatcher()
            asyncio.create_task(asyncio.to_thread(traefik.watch_loop, settings.poll_interval_seconds))
            log.info("Traefik / Ingress discovery enabled")
        except Exception as e:
            log.warning("Traefik discovery not started: %s", e)

    yield
    log.info("Shutting down")


app = FastAPI(
    title="Cloudflare DDNS",
    description="Modern self-hosted Cloudflare DDNS with Web UI and K8s discovery",
    version="0.5.2",
    lifespan=lifespan,
)

# Auth middleware — checks the EFFECTIVE auth_mode at request time, so
# switching modes via the Settings page takes effect immediately.
app.add_middleware(AuthMiddleware)

# Static dir (created if missing so mount never fails)
_static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(_static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=_static_dir), name="static")

app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(auth_router, tags=["auth"])
app.include_router(ui.router, tags=["ui"])
app.include_router(api.router, prefix="/api", tags=["api"])
