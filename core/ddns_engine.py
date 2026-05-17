"""Background DDNS engine.

Periodically:
  - Detects current public IP
  - For every enabled ManagedRecord, ensures Cloudflare matches
"""
import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Optional

import httpx

from core.cloudflare_client import CloudflareClient
from core.config import settings
from core.database import get_session
from core.models import ManagedRecord

log = logging.getLogger("cfddns.engine")


class DDNSEngine:
    def __init__(self):
        self.cf = CloudflareClient()
        self.current_ip: Optional[str] = None
        self.last_update: Optional[datetime] = None
        self.last_error: Optional[str] = None

    async def get_current_ip(self) -> Optional[str]:
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
                r = await cli.get(settings.ipv4_endpoint)
                r.raise_for_status()
                return r.text.strip()
        except Exception as e:
            log.warning("Failed to detect public IP: %s", e)
            self.last_error = f"ip-detect: {e}"
            return None

    async def import_legacy_config(self) -> int:
        """One-shot: import records.json into the DB if present."""
        path = settings.config_path
        if not (settings.import_legacy_config and os.path.exists(path)):
            return 0
        try:
            with open(path, "r") as f:
                items = json.load(f)
        except Exception as e:
            log.warning("Could not read legacy config %s: %s", path, e)
            return 0

        # We need to resolve zone_id and record_id from the CF API
        sess = get_session()
        try:
            zones = await self.cf.list_zones()
            zone_by_name = {z["name"]: z for z in zones}
            cache_records = {}
            imported = 0
            for item in items:
                zname = item.get("zone")
                rname = item.get("name")
                if not zname or not rname:
                    continue
                # Cloudflare stores names as fully-qualified
                fqdn = rname if rname == zname or rname.endswith("." + zname) else f"{rname}.{zname}"
                zone = zone_by_name.get(zname)
                if not zone:
                    log.warning("Legacy import: unknown zone %s", zname)
                    continue
                if zone["id"] not in cache_records:
                    cache_records[zone["id"]] = await self.cf.list_dns_records(zone["id"])
                match = next(
                    (r for r in cache_records[zone["id"]] if r["name"] == fqdn and r["type"] == item.get("type", "A")),
                    None,
                )
                if not match:
                    log.warning("Legacy import: record %s not found in CF, skipping", fqdn)
                    continue
                if sess.get(ManagedRecord, match["id"]):
                    continue
                # Skip duplicate by record_id (unique constraint)
                existing = (
                    sess.query(ManagedRecord)
                    .filter(ManagedRecord.record_id == match["id"])
                    .first()
                )
                if existing:
                    continue
                sess.add(
                    ManagedRecord(
                        zone_id=zone["id"],
                        zone_name=zname,
                        record_id=match["id"],
                        record_name=fqdn,
                        record_type=match["type"],
                        enabled=True,
                        proxied=bool(item.get("proxied", settings.default_proxied)),
                        ttl=int(item.get("ttl", settings.default_ttl)),
                        source="legacy-config",
                    )
                )
                imported += 1
            sess.commit()
            log.info("Legacy import: %d records imported from %s", imported, path)
            return imported
        finally:
            sess.close()

    async def run_once(self) -> None:
        ip = await self.get_current_ip()
        if not ip:
            return

        if ip != self.current_ip:
            log.info("Public IPv4 changed: %s -> %s", self.current_ip, ip)
            self.current_ip = ip

        sess = get_session()
        try:
            records = sess.query(ManagedRecord).filter(ManagedRecord.enabled == True).all()  # noqa: E712
        finally:
            sess.close()

        for rec in records:
            if rec.last_ip == ip:
                continue
            try:
                await self.cf.update_dns_record(
                    rec.zone_id, rec.record_id, rec.record_name,
                    ip, rec.record_type, rec.proxied, rec.ttl,
                )
                # commit the update on the record
                s = get_session()
                try:
                    fresh = s.get(ManagedRecord, rec.id)
                    if fresh:
                        fresh.last_ip = ip
                        fresh.last_updated = datetime.utcnow()
                        s.commit()
                finally:
                    s.close()
                log.info("Updated %s -> %s", rec.record_name, ip)
            except Exception as e:
                log.warning("Failed updating %s: %s", rec.record_name, e)
                self.last_error = str(e)

        self.last_update = datetime.utcnow()

    async def verify_all(self) -> dict:
        """One-shot validation pass over every enabled ManagedRecord.

        Returns counts the UI can show as a toast:
            {checked, in_sync, updated, errors, ip}
        """
        ip = await self.get_current_ip()
        result = {"checked": 0, "in_sync": 0, "updated": 0, "errors": 0, "ip": ip}
        if not ip:
            result["errors"] = 1
            return result
        self.current_ip = ip

        # Snapshot enabled records
        sess = get_session()
        try:
            records = list(sess.query(ManagedRecord).filter(ManagedRecord.enabled == True).all())  # noqa: E712
        finally:
            sess.close()

        # Cache CF state by zone so we only pull once per zone
        zone_cache: dict = {}

        for rec in records:
            result["checked"] += 1
            try:
                if rec.zone_id not in zone_cache:
                    zone_cache[rec.zone_id] = {
                        r["id"]: r for r in await self.cf.list_dns_records(rec.zone_id)
                    }
                cf_rec = zone_cache[rec.zone_id].get(rec.record_id)
                if not cf_rec:
                    result["errors"] += 1
                    log.warning("verify: record %s not in CF anymore", rec.record_name)
                    continue
                # Defensive: never touch tunnel CNAMEs (cloudflared owns them)
                if cf_rec.get("type") == "CNAME" and (cf_rec.get("content") or "").lower().rstrip(".").endswith(".cfargotunnel.com"):
                    result["in_sync"] += 1
                    continue
                desired_drift = (
                    cf_rec.get("content") != ip
                    or bool(cf_rec.get("proxied")) != bool(rec.proxied)
                    or int(cf_rec.get("ttl", 1)) != int(rec.ttl)
                )
                if not desired_drift:
                    result["in_sync"] += 1
                    continue
                await self.cf.update_dns_record(
                    rec.zone_id, rec.record_id, rec.record_name,
                    ip, rec.record_type, rec.proxied, rec.ttl,
                )
                s = get_session()
                try:
                    fresh = s.get(ManagedRecord, rec.id)
                    if fresh:
                        fresh.last_ip = ip
                        fresh.last_updated = datetime.utcnow()
                        s.commit()
                finally:
                    s.close()
                result["updated"] += 1
                log.info("verify: updated %s -> %s", rec.record_name, ip)
            except Exception as e:
                log.warning("verify: %s failed: %s", rec.record_name, e)
                result["errors"] += 1
                self.last_error = str(e)
        self.last_update = datetime.utcnow()
        return result

    async def start_background_task(self) -> None:
        # Best-effort legacy import once
        try:
            await self.import_legacy_config()
        except Exception as e:
            log.warning("Legacy import failed: %s", e)

        while True:
            try:
                await self.run_once()
            except Exception as e:
                log.exception("DDNS loop error: %s", e)
                self.last_error = str(e)
            await asyncio.sleep(settings.poll_interval_seconds)
