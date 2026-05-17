"""JSON API for the web UI and external automation."""
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.cloudflare_client import CloudflareClient
from core.config import RUNTIME_SETTINGS_KEYS, SECRET_KEYS, env_locked, get_effective, settings
from core.database import get_session
from core.models import DiscoveredHost, ManagedRecord, Setting

log = logging.getLogger("cfddns.api")
router = APIRouter()


def _cf() -> CloudflareClient:
    # Per-call so token refresh / hot reload works
    tok = get_effective("cf_api_token")
    return CloudflareClient(token=str(tok) if tok else settings.cf_api_token)


# ---- Zones / records ----

@router.get("/zones")
async def list_zones():
    zones = await _cf().list_zones()
    return [{"id": z["id"], "name": z["name"], "status": z.get("status")} for z in zones]


def _host_in_zone(host: str, zone_name: str) -> bool:
    return host == zone_name or host.endswith("." + zone_name)


def _is_tunnel_cname(rec: dict) -> bool:
    """Cloudflare Tunnel public hostnames are CNAMEs to <uuid>.cfargotunnel.com."""
    if rec.get("type") != "CNAME":
        return False
    content = (rec.get("content") or "").lower().rstrip(".")
    return content.endswith(".cfargotunnel.com") or content == "cfargotunnel.com"


@router.get("/zones/{zone_id}/records")
async def list_records(zone_id: str):
    """Return CF A/AAAA records, Cloudflare Tunnel CNAMEs (read-only), AND
    discovered hosts in this zone that lack any matching CF record."""
    cf = _cf()
    cf_records = await cf.list_dns_records(zone_id)
    zones = await cf.list_zones()
    zone = next((z for z in zones if z["id"] == zone_id), None)
    if not zone:
        raise HTTPException(404, "Zone not found")
    zone_name = zone["name"]

    sess = get_session()
    try:
        managed = {
            m.record_id: m
            for m in sess.query(ManagedRecord).filter(ManagedRecord.zone_id == zone_id).all()
        }
        discovered = sess.query(DiscoveredHost).all()
    finally:
        sess.close()

    out: List[dict] = []
    # Track every CF name we've surfaced (A/AAAA/Tunnel) so we don't double-list
    # a discovered host that's already DNS-managed (incl. via tunnel CNAMEs).
    cf_names_seen = set()

    for r in cf_records:
        rtype = r["type"]
        is_tunnel = _is_tunnel_cname(r)
        if rtype not in ("A", "AAAA") and not is_tunnel:
            continue
        cf_names_seen.add(r["name"])
        m = managed.get(r["id"])
        discovered_match = next((d for d in discovered if d.host == r["name"]), None)
        source = (
            m.source if m else (discovered_match.source if discovered_match else None)
        )
        if is_tunnel:
            # Tunnel CNAMEs are managed by cloudflared — surface as read-only.
            out.append({
                "id": r["id"],
                "name": r["name"],
                "type": "Tunnel",
                "content": r.get("content"),
                "proxied": r.get("proxied", True),
                "ttl": r.get("ttl", 1),
                "enabled": False,
                "source": source,
                "exists_in_cf": True,
                "is_tunnel": True,
                "ignored": True,
                "ignore_reason": "Managed by Cloudflare Tunnel (cloudflared)",
                "last_ip": None,
                "last_updated": None,
            })
            continue
        out.append({
            "id": r["id"],
            "name": r["name"],
            "type": rtype,
            "content": r.get("content"),
            "proxied": r.get("proxied", False),
            "ttl": r.get("ttl", 1),
            "enabled": bool(m and m.enabled),
            "source": source,
            "exists_in_cf": True,
            "is_tunnel": False,
            "ignored": False,
            "last_ip": m.last_ip if m else None,
            "last_updated": m.last_updated.isoformat() if m and m.last_updated else None,
        })

    # Discovered hosts in this zone with no matching CF record of ANY surfaced type
    for d in discovered:
        if not _host_in_zone(d.host, zone_name):
            continue
        if d.host in cf_names_seen:
            continue
        out.append({
            "id": None,
            "name": d.host,
            "type": "A",
            "content": None,
            "proxied": None,
            "ttl": None,
            "enabled": False,
            "source": d.source,
            "exists_in_cf": False,
            "is_tunnel": False,
            "ignored": False,
            "namespace": d.namespace,
            "resource_name": d.resource_name,
        })
    out.sort(key=lambda r: r["name"])
    return out


# ---- Toggle / manage records ----

class ToggleRequest(BaseModel):
    enabled: bool
    proxied: Optional[bool] = None
    ttl: Optional[int] = None


@router.post("/zones/{zone_id}/records/{record_id}/toggle")
async def toggle_record(zone_id: str, record_id: str, body: ToggleRequest):
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


class ProxiedRequest(BaseModel):
    proxied: bool


@router.post("/zones/{zone_id}/records/{record_id}/proxied")
async def set_record_proxied(zone_id: str, record_id: str, body: ProxiedRequest):
    """Flip the proxied flag in Cloudflare AND in our managed record (if any)."""
    await _cf().patch_dns_record(zone_id, record_id, proxied=body.proxied)
    sess = get_session()
    try:
        m = sess.query(ManagedRecord).filter(ManagedRecord.record_id == record_id).first()
        if m:
            m.proxied = body.proxied
            sess.commit()
    finally:
        sess.close()
    return {"status": "ok", "proxied": body.proxied}


# ---- Manual create ----

class CreateRecordRequest(BaseModel):
    name: str
    type: str = "A"
    content: Optional[str] = None      # if None, use current detected public IP
    proxied: bool = False
    ttl: int = 1
    enable: bool = True


@router.post("/zones/{zone_id}/records")
async def create_record(zone_id: str, body: CreateRecordRequest, request: Request):
    zones = await _cf().list_zones()
    zone = next((z for z in zones if z["id"] == zone_id), None)
    if not zone:
        raise HTTPException(404, "Zone not found")

    # If name is bare label, qualify it with zone
    name = body.name.strip()
    if name and not name.endswith(zone["name"]):
        name = f"{name}.{zone['name']}"

    content = (body.content or "").strip()
    if not content:
        engine = getattr(request.app.state, "engine", None)
        content = (engine.current_ip if engine else None) or ""
        if not content:
            # last resort: probe right now
            if engine:
                content = await engine.get_current_ip() or ""
        if not content:
            raise HTTPException(400, "No content provided and public IP unknown")

    try:
        created = await _cf().create_dns_record(
            zone_id=zone_id, name=name, ip=content,
            record_type=body.type, proxied=body.proxied, ttl=body.ttl,
        )
    except Exception as e:
        raise HTTPException(400, f"Cloudflare create failed: {e}")
    rec = created.get("result", created)

    if body.enable:
        sess = get_session()
        try:
            sess.add(
                ManagedRecord(
                    zone_id=zone_id,
                    zone_name=zone["name"],
                    record_id=rec["id"],
                    record_name=rec["name"],
                    record_type=rec["type"],
                    enabled=True,
                    proxied=bool(rec.get("proxied", body.proxied)),
                    ttl=int(rec.get("ttl", body.ttl)),
                    source="manual",
                )
            )
            sess.commit()
        finally:
            sess.close()
    return {"status": "ok", "record": rec}


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


# ---- Verify / Check Now ----

@router.post("/verify")
async def verify_now(request: Request):
    engine = getattr(request.app.state, "engine", None)
    if not engine:
        raise HTTPException(503, "Engine not running")
    return await engine.verify_all()


# ---- Settings ----

@router.get("/settings")
async def get_settings():
    """Return the full settings view: effective value + whether env-locked."""
    locked = env_locked()
    sess = get_session()
    try:
        rows = {s.key: s.value for s in sess.query(Setting).all()}
    finally:
        sess.close()
    out = {}
    for key in RUNTIME_SETTINGS_KEYS:
        value = get_effective(key, rows.get(key))
        display = value
        if key in SECRET_KEYS and value:
            s = str(value)
            display = f"{s[:4]}…{s[-4:]}" if len(s) > 8 else "set"
        out[key] = {
            "value": display,
            "raw_set": bool(rows.get(key)),
            "env_locked": key in locked,
        }
    return out


class SettingUpdateRequest(BaseModel):
    key: str
    value: str


@router.post("/settings")
async def update_setting(body: SettingUpdateRequest):
    if body.key not in RUNTIME_SETTINGS_KEYS:
        raise HTTPException(400, f"Unknown setting: {body.key}")
    if body.key in env_locked():
        raise HTTPException(409, f"Setting {body.key} is pinned by env / ConfigMap and cannot be edited via UI")
    sess = get_session()
    try:
        existing = sess.query(Setting).filter(Setting.key == body.key).first()
        if existing:
            existing.value = body.value
            existing.updated_at = datetime.utcnow()
        else:
            sess.add(Setting(key=body.key, value=body.value))
        sess.commit()
    finally:
        sess.close()
    return {"status": "ok"}


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
        "auth_mode": str(get_effective("auth_mode") or "none"),
    }
