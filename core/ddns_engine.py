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
from core.models import IpHistoryEntry, ManagedRecord
from core import metrics

log = logging.getLogger("cfddns.engine")


class DDNSEngine:
    def __init__(self):
        self.cf = CloudflareClient()
        self.current_ip: Optional[str] = None        # IPv4 (kept for backward-compat / UI)
        self.current_ipv6: Optional[str] = None       # IPv6 (None if disabled / undetected)
        self.last_update: Optional[datetime] = None
        self.last_error: Optional[str] = None

    def _record_ip_change(self, previous_ip: Optional[str], new_ip: str, note: str) -> None:
        """Persist an IP transition to the history table. Best-effort — never
        let history bookkeeping break the DDNS loop."""
        try:
            sess = get_session()
            try:
                sess.add(IpHistoryEntry(previous_ip=previous_ip or None, new_ip=new_ip, note=note))
                sess.commit()
            finally:
                sess.close()
        except Exception as e:
            log.warning("Failed to record IP history (%s -> %s): %s", previous_ip, new_ip, e)

    async def _detect(self, endpoint: str) -> Optional[str]:
        """Fetch a plain-text IP from an endpoint. Returns None on any failure."""
        if not endpoint:
            return None
        family = "ipv6" if endpoint == settings.ipv6_endpoint else "ipv4"
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
                r = await cli.get(endpoint)
                r.raise_for_status()
                return r.text.strip()
        except Exception as e:
            log.warning("Failed to detect IP from %s: %s", endpoint, e)
            self.last_error = f"ip-detect: {e}"
            metrics.IP_DETECT_FAILURES.labels(family=family).inc()
            return None

    async def get_current_ip(self) -> Optional[str]:
        """Detect the public IPv4 address (back-compat alias)."""
        return await self._detect(settings.ipv4_endpoint)

    async def get_current_ipv6(self) -> Optional[str]:
        """Detect the public IPv6 address. Returns None when ipv6_endpoint is
        blank (AAAA management disabled) or detection fails."""
        return await self._detect(settings.ipv6_endpoint)

    @staticmethod
    def _ip_for_type(record_type: str, ipv4: Optional[str], ipv6: Optional[str]) -> Optional[str]:
        """Map a DNS record type to the matching address family.

        A    -> IPv4
        AAAA -> IPv6
        anything else -> None (we don't manage it)
        """
        rt = (record_type or "").upper()
        if rt == "A":
            return ipv4
        if rt == "AAAA":
            return ipv6
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
        ipv4 = await self.get_current_ip()
        ipv6 = await self.get_current_ipv6()
        if not ipv4 and not ipv6:
            return

        if ipv4 and ipv4 != self.current_ip:
            log.info("Public IPv4 changed: %s -> %s", self.current_ip, ipv4)
            self._record_ip_change(self.current_ip, ipv4, "ip-change" if self.current_ip else "boot")
            self.current_ip = ipv4
            metrics.IP_CHANGES.labels(family="ipv4").inc()
        if ipv4:
            metrics.set_current_ip("ipv4", ipv4)
        if ipv6 and ipv6 != self.current_ipv6:
            log.info("Public IPv6 changed: %s -> %s", self.current_ipv6, ipv6)
            self._record_ip_change(self.current_ipv6, ipv6, "ipv6-change" if self.current_ipv6 else "boot-ipv6")
            self.current_ipv6 = ipv6
            metrics.IP_CHANGES.labels(family="ipv6").inc()
        if ipv6:
            metrics.set_current_ip("ipv6", ipv6)

        sess = get_session()
        try:
            records = sess.query(ManagedRecord).filter(ManagedRecord.enabled == True).all()  # noqa: E712
        finally:
            sess.close()

        for rec in records:
            target_ip = self._ip_for_type(rec.record_type, ipv4, ipv6)
            if not target_ip:
                # AAAA record but no IPv6 detected (or unmanaged type) — skip,
                # never write an IPv4 into an AAAA record.
                if (rec.record_type or "").upper() == "AAAA" and not ipv6:
                    log.debug("Skipping AAAA %s: no IPv6 detected (ipv6_endpoint set?)", rec.record_name)
                continue
            if rec.last_ip == target_ip:
                continue
            try:
                await self.cf.update_dns_record(
                    rec.zone_id, rec.record_id, rec.record_name,
                    target_ip, rec.record_type, rec.proxied, rec.ttl,
                )
                # commit the update on the record
                s = get_session()
                try:
                    fresh = s.get(ManagedRecord, rec.id)
                    if fresh:
                        fresh.last_ip = target_ip
                        fresh.last_updated = datetime.utcnow()
                        s.commit()
                finally:
                    s.close()
                log.info("Updated %s (%s) -> %s", rec.record_name, rec.record_type, target_ip)
                metrics.RECORD_UPDATES.labels(record_type=(rec.record_type or "A").upper()).inc()
            except Exception as e:
                log.warning("Failed updating %s: %s", rec.record_name, e)
                self.last_error = str(e)
                metrics.RECORD_UPDATE_ERRORS.labels(record_type=(rec.record_type or "A").upper()).inc()

        self.last_update = datetime.utcnow()
        metrics.LAST_RUN_TIMESTAMP.set(self.last_update.timestamp())

    async def verify_all(self) -> dict:
        """One-shot validation pass over every enabled ManagedRecord.

        Returns counts the UI can show as a toast:
            {checked, in_sync, updated, errors, ip, ipv6}
        """
        ipv4 = await self.get_current_ip()
        ipv6 = await self.get_current_ipv6()
        result = {"checked": 0, "in_sync": 0, "updated": 0, "errors": 0, "ip": ipv4, "ipv6": ipv6}
        if not ipv4 and not ipv6:
            result["errors"] = 1
            return result
        if ipv4:
            self.current_ip = ipv4
        if ipv6:
            self.current_ipv6 = ipv6

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
            target_ip = self._ip_for_type(rec.record_type, ipv4, ipv6)
            if not target_ip:
                # AAAA with no IPv6 available (or unmanaged type): can't verify,
                # but it isn't an error caused by us — count as in_sync (no-op).
                result["in_sync"] += 1
                continue
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
                    cf_rec.get("content") != target_ip
                    or bool(cf_rec.get("proxied")) != bool(rec.proxied)
                    or int(cf_rec.get("ttl", 1)) != int(rec.ttl)
                )
                if not desired_drift:
                    result["in_sync"] += 1
                    continue
                await self.cf.update_dns_record(
                    rec.zone_id, rec.record_id, rec.record_name,
                    target_ip, rec.record_type, rec.proxied, rec.ttl,
                )
                s = get_session()
                try:
                    fresh = s.get(ManagedRecord, rec.id)
                    if fresh:
                        fresh.last_ip = target_ip
                        fresh.last_updated = datetime.utcnow()
                        s.commit()
                finally:
                    s.close()
                result["updated"] += 1
                log.info("verify: updated %s (%s) -> %s", rec.record_name, rec.record_type, target_ip)
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
