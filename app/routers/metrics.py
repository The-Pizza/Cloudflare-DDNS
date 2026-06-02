"""Prometheus metrics endpoint."""
from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter()


@router.get("/metrics")
async def metrics() -> Response:
    """Expose metrics in Prometheus text exposition format.

    Allow-listed in AuthMiddleware so Prometheus can scrape without a session.
    """
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
