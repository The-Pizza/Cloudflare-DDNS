from fastapi import APIRouter
from pydantic import BaseModel
from core.cloudflare_client import CloudflareClient
from core.database import get_session
from core.models import ManagedRecord

router = APIRouter()
cf = CloudflareClient()

@router.get("/zones")
async def get_zones():
    zones = await cf.list_zones()
    return [{"id": z["id"], "name": z["name"]} for z in zones]

@router.get("/zones/{zone_id}/records")
async def get_records(zone_id: str):
    records = await cf.list_dns_records(zone_id)
    session = get_session()
    managed = {m.record_id: m for m in session.query(ManagedRecord).filter(ManagedRecord.zone_id == zone_id).all()}

    result = []
    for r in records:
        if r["type"] not in ["A", "AAAA"]:
            continue
        m = managed.get(r["id"])
        result.append({
            "id": r["id"],
            "name": r["name"],
            "type": r["type"],
            "content": r.get("content"),
            "enabled": m.enabled if m else False,
            "source": m.source if m else "manual",
        })
    return result

class ToggleRequest(BaseModel):
    enabled: bool

@router.post("/records/{record_id}/toggle")
async def toggle_record(record_id: str, payload: ToggleRequest):
    session = get_session()
    record = session.get(ManagedRecord, record_id)
    if not record:
        record = ManagedRecord(record_id=record_id, zone_id="pending", zone_name="pending", record_name="pending", enabled=payload.enabled)
        session.add(record)
    else:
        record.enabled = payload.enabled
    session.commit()
    return {"status": "ok"}