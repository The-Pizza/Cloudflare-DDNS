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
from core.models import DiscoveredHost, IpHistoryEntry, ManagedRecord
from core import metrics

log = logging.getLogger("cfddns.engine")


def _is_tunnel_cname(cf_rec: dict) -> bool:
    """True if a Cloudflare record is a cloudflared-managed tunnel CNAME.

    These are owned by cloudflared (CNAME -> <id>.cfargotunnel.com) and must
    never be adopted or mutated by the DDNS engine.
    """
    return (
        cf_rec.get("type") == "CNAME"
        and (cf_rec.get("content") or "").lower().rstrip(".").endswith(".cfargotunnel.com")
    )


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

    async def reconcile_annotation_managed(self, ipv4: Optional[str], ipv6: Optional[str]) -> None:
        """Promote declaratively-managed DiscoveredHosts into ManagedRecords.

        For every DiscoveredHost with `managed=True` that hasn't been reconciled
        yet (no `managed_record_id`), find its zone, then either ADOPT an existing
        Cloudflare record of the right name+type or CREATE a new one. The standard
        DDNS loop then keeps it pointed at the public IP.

        This is the engine half of Option B (declarative annotation management).
        It is intentionally conservative:
          - never touches cloudflared tunnel CNAMEs,
          - skips a host when the address family it needs isn't available yet,
          - records per-host errors on the DiscoveredHost rather than aborting.
        """
        if not settings.enable_annotation_management:
            return

        sess = get_session()
        try:
            pending = list(
                sess.query(DiscoveredHost)
                .filter(DiscoveredHost.managed == True,                # noqa: E712
                        DiscoveredHost.managed_record_id == None)       # noqa: E711
                .all()
            )
        finally:
            sess.close()
        if not pending:
            return

        # Resolve zones once for the batch.
        try:
            zones = await self.cf.list_zones()
        except Exception as e:
            log.warning("annotation-manage: could not list zones: %s", e)
            return
        # Longest-suffix match so a host in a subdomain lands in the right zone.
        zones_sorted = sorted(zones, key=lambda z: len(z["name"]), reverse=True)
        zone_records_cache: dict = {}

        for host in pending:
            fqdn = host.host.strip().rstrip(".")
            rtype = (host.desired_type or "A").upper()
            target_ip = self._ip_for_type(rtype, ipv4, ipv6)
            if not target_ip and not host.desired_content:
                # Need the public IP for this family but it's not available yet.
                log.debug("annotation-manage: %s (%s) deferred -- no %s address yet",
                          fqdn, rtype, rtype)
                continue
            content = host.desired_content or target_ip
            if not content:
                # Defensive: guarded above, but keep the type contract explicit.
                continue
            zone = next(
                (z for z in zones_sorted
                 if fqdn == z["name"] or fqdn.endswith("." + z["name"])),
                None,
            )
            if not zone:
                self._set_reconcile_error(host.id, f"no Cloudflare zone owns {fqdn}")
                log.warning("annotation-manage: no zone for %s", fqdn)
                continue
            zid = zone["id"]
            proxied = host.desired_proxied if host.desired_proxied is not None else settings.default_proxied
            ttl = host.desired_ttl if host.desired_ttl is not None else settings.default_ttl

            try:
                if zid not in zone_records_cache:
                    zone_records_cache[zid] = await self.cf.list_dns_records(zid)
                existing = next(
                    (r for r in zone_records_cache[zid]
                     if r.get("name") == fqdn and r.get("type") == rtype),
                    None,
                )
                # Guard: never adopt/clobber a cloudflared tunnel CNAME for this host.
                tunnel = next(
                    (r for r in zone_records_cache[zid]
                     if r.get("name") == fqdn and _is_tunnel_cname(r)),
                    None,
                )
                if tunnel:
                    self._set_reconcile_error(
                        host.id, f"{fqdn} is a cloudflared tunnel CNAME; refusing to manage")
                    log.warning("annotation-manage: %s is a tunnel CNAME -- skipping", fqdn)
                    continue

                if existing:
                    record_id = existing["id"]
                    log.info("annotation-manage: adopting existing %s (%s) %s", fqdn, rtype, record_id)
                else:
                    created = await self.cf.create_dns_record(
                        zone_id=zid, name=fqdn, ip=content,
                        record_type=rtype, proxied=proxied, ttl=ttl,
                    )
                    rec = created.get("result", created)
                    record_id = rec["id"]
                    log.info("annotation-manage: created %s (%s) -> %s proxied=%s",
                             fqdn, rtype, content, proxied)

                self._promote_to_managed_record(
                    host_id=host.id, zone_id=zid, zone_name=zone["name"],
                    record_id=record_id, record_name=fqdn, record_type=rtype,
                    proxied=proxied, ttl=ttl,
                )
                metrics.RECORD_UPDATES.labels(record_type=rtype).inc()
            except Exception as e:
                self._set_reconcile_error(host.id, str(e))
                log.warning("annotation-manage: failed reconciling %s: %s", fqdn, e)

    def _set_reconcile_error(self, host_id: Optional[int], msg: str) -> None:
        if host_id is None:
            return
        s = get_session()
        try:
            h = s.get(DiscoveredHost, host_id)
            if h:
                h.last_reconcile_error = msg[:500]
                s.commit()
        finally:
            s.close()

    def _promote_to_managed_record(
        self, *, host_id: Optional[int], zone_id: str, zone_name: str,
        record_id: str, record_name: str, record_type: str,
        proxied: bool, ttl: int,
    ) -> None:
        """Create the ManagedRecord (idempotently) and stamp the DiscoveredHost."""
        s = get_session()
        try:
            existing = (
                s.query(ManagedRecord)
                .filter(ManagedRecord.record_id == record_id)
                .first()
            )
            if not existing:
                s.add(
                    ManagedRecord(
                        zone_id=zone_id, zone_name=zone_name,
                        record_id=record_id, record_name=record_name,
                        record_type=record_type, enabled=True,
                        proxied=bool(proxied), ttl=int(ttl),
                        source="annotation",
                    )
                )
            h = s.get(DiscoveredHost, host_id) if host_id is not None else None
            if h:
                h.managed_record_id = record_id
                h.last_reconcile_error = None
            s.commit()
        finally:
            s.close()

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

        # Promote any declaratively-managed annotation hosts into ManagedRecords
        # BEFORE the sync loop, so a freshly-discovered host is created/adopted
        # and then immediately pointed at the public IP in the same pass.
        try:
            await self.reconcile_annotation_managed(ipv4, ipv6)
        except Exception as e:
            log.warning("annotation-manage reconcile pass failed: %s", e)

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
