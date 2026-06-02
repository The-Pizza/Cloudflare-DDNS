"""Health and readiness endpoints."""
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from core.database import get_session

log = logging.getLogger("cfddns.health")

router = APIRouter()


@router.get("/live")
async def live() -> dict:
    """Liveness: the process is up and serving HTTP. Never touches the DB."""
    return {"status": "ok"}


@router.get("/ready")
async def ready():
    """Readiness: the app can actually serve requests.

    Verifies the database is reachable with a trivial query. Returns 503 when
    the DB is unavailable so Kubernetes keeps the pod out of the Service
    endpoints (and rollouts wait) until it can do real work.
    """
    try:
        sess = get_session()
        try:
            sess.execute(text("SELECT 1"))
        finally:
            sess.close()
    except Exception as e:
        log.warning("Readiness check failed: %s", e)
        return JSONResponse(
            {"status": "not-ready", "reason": f"database unavailable: {e}"},
            status_code=503,
        )
    return {"status": "ready"}
