from fastapi import APIRouter
router = APIRouter()

@router.get("/live")
async def liveness():
    return {"status": "ok"}

@router.get("/ready")
async def readiness():
    return {"status": "ready"}