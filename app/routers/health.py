"""Health and readiness endpoints."""
import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/live")
async def live() -> dict:
    return {"status": "ok"}


@router.get("/ready")
async def ready() -> dict:
    # Always ready once HTTP is up; DB is lazily initialised
    return {"status": "ready"}
