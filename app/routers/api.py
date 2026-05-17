"""JSON API for the web UI and external automation."""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.cloudflare_client import CloudflareClient
from core.database import get_session
from core.models import DiscoveredHost, ManagedRecord

log = logging.getLogger("cfddns.api")
router = APIRouter()


def _cf() -> CloudflareClient:
    # Per-call so token refresh / hot reload works
    return CloudflareClient()


# ---- Zones / records ----

@router.get("/zones")
async def list_zones():
    zones = await _cf().list_zones()
    return [{"id": z["id"], "name": z["name"], "status": z.get("status")} for z in zones]


@router.get("/zones/{zone_id}/records")
async def list_records(zone_id: str):
    cf_records = await _cf().list_dns_records(zone_id)
    sess = get_session()
    try:
        managed = {
            m.record_id: m
            for m in sess.query(ManagedRecord).filter(ManagedRecord.zone_id == zone_id).all()
        }
    finally:
        sess.close()
    out = []
    for r in cf_records:
        if r["type"] not in ("A", "AAAA"):
            continue
        m = managed.get(r["id"])
        out.append({
            "id": r["id"],
            "name": r["name"],
            "type": r["type"],
            "content": r.get("content"),
            "proxied": r.get("proxied", False),
            "ttl": r.get("ttl", 1),
            "enabled": bool(m and m.enabled),
            "source": m.source if m else None,
            "last_ip": m.last_ip if m else None,
            "last_updated": m.last_updated.isoformat() if m and m.last_updated else None,
        })
    return out


# ---- Toggle / manage records ----

class ToggleRequest(BaseModel):
    enabled: bool
    proxied: Optional[bool] = None
    ttl: Optional[int] = None


@router.post("/zones/{zone_id}/records/{record_id}/toggle")
async def toggle_record(zone_id: str, record_id: str, body: ToggleRequest):
    # Fetch the record from Cloudflare so we know name/type/proxied/ttl
    records = await _cf().list_dns_records(zone_id)
    target = next((r for r in records if r["id"] == record_id), None)
    if not target:
        raise HTTPException(404, "Record not found in zone")
    zones = await _cf().list_zones()
    zone = next((z for z in zones if z["id"] == zone_id), None)
    if not zone:
        raise HTTPException(404, "Zone not found")

    sess = get_session()
    try:
        existing = (
            sess.query(ManagedRecord)
            .filter(ManagedRecord.record_id == record_id)
            .first()
        )
        if existing:
            existing.enabled = body.enabled
            if body.proxied is not None:
                existing.proxied = body.proxied
            if body.ttl is not None:
                existing.ttl = body.ttl
        else:
            sess.add(
                ManagedRecord(
                    zone_id=zone_id,
                    zone_name=zone["name"],
                    record_id=record_id,
                    record_name=target["name"],
                    record_type=target["type"],
                    enabled=body.enabled,
                    proxied=body.proxied if body.proxied is not None else target.get("proxied", True),
                    ttl=body.ttl if body.ttl is not None else target.get("ttl", 1),
                    source="manual",
                )
            )
        sess.commit()
    finally:
        sess.close()
    return {"status": "ok"}


# ---- Discovered hosts ----

@router.get("/discovered")
async def discovered():
    sess = get_session()
    try:
        rows = sess.query(DiscoveredHost).all()
        return [
            {
                "id": r.id,
                "host": r.host,
                "source": r.source,
                "namespace": r.namespace,
                "resource_name": r.resource_name,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            }
            for r in rows
        ]
    finally:
        sess.close()


# ---- Engine status ----

@router.get("/status")
async def engine_status(request: Request):
    engine = getattr(request.app.state, "engine", None)
    sess = get_session()
    try:
        managed_count = sess.query(ManagedRecord).count()
        enabled_count = sess.query(ManagedRecord).filter(ManagedRecord.enabled == True).count()  # noqa: E712
    finally:
        sess.close()
    return {
        "version": request.app.version,
        "current_ip": engine.current_ip if engine else None,
        "last_update": engine.last_update.isoformat() if engine and engine.last_update else None,
        "last_error": engine.last_error if engine else None,
        "managed_records": managed_count,
        "enabled_records": enabled_count,
    }
