"""Tests for the DDNS engine — especially the IPv4/IPv6 (A/AAAA) routing fix.

These guard the critical bug where an IPv4 address could be written into an
AAAA record.
"""
import pytest

from core.database import get_session
from core.ddns_engine import DDNSEngine
from core.models import ManagedRecord


class FakeCF:
    """Records every update_dns_record call and serves canned list responses."""

    def __init__(self, records_by_zone=None):
        self.updates = []                       # list of dicts
        self._records_by_zone = records_by_zone or {}

    async def update_dns_record(self, zone_id, record_id, name, ip, record_type="A", proxied=True, ttl=1):
        self.updates.append(
            {"zone_id": zone_id, "record_id": record_id, "name": name,
             "ip": ip, "type": record_type, "proxied": proxied, "ttl": ttl}
        )
        return {"result": {"id": record_id}}

    async def list_dns_records(self, zone_id):
        return self._records_by_zone.get(zone_id, [])


def _add_record(**kw):
    sess = get_session()
    try:
        rec = ManagedRecord(**kw)
        sess.add(rec)
        sess.commit()
        sess.refresh(rec)
        return rec.id
    finally:
        sess.close()


# --- _ip_for_type --------------------------------------------------------

def test_ip_for_type_maps_families():
    assert DDNSEngine._ip_for_type("A", "1.2.3.4", "::1") == "1.2.3.4"
    assert DDNSEngine._ip_for_type("AAAA", "1.2.3.4", "::1") == "::1"
    assert DDNSEngine._ip_for_type("a", "1.2.3.4", "::1") == "1.2.3.4"     # case-insensitive
    assert DDNSEngine._ip_for_type("CNAME", "1.2.3.4", "::1") is None
    assert DDNSEngine._ip_for_type("AAAA", "1.2.3.4", None) is None       # no v6 available


# --- run_once: the core regression ---------------------------------------

@pytest.mark.asyncio
async def test_run_once_never_writes_ipv4_into_aaaa(monkeypatch):
    """An AAAA record must NOT receive the IPv4 address when no IPv6 is known."""
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-a",
                record_name="a.example.com", record_type="A", enabled=True)
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-aaaa",
                record_name="aaaa.example.com", record_type="AAAA", enabled=True)

    eng = DDNSEngine()
    eng.cf = FakeCF()
    # IPv4 detected, IPv6 disabled (None)
    monkeypatch.setattr(eng, "get_current_ip", lambda: _coro("203.0.113.5"))
    monkeypatch.setattr(eng, "get_current_ipv6", lambda: _coro(None))

    await eng.run_once()

    updated = {u["name"]: u for u in eng.cf.updates}
    assert "a.example.com" in updated
    assert updated["a.example.com"]["ip"] == "203.0.113.5"
    # The AAAA record must have been skipped entirely
    assert "aaaa.example.com" not in updated


@pytest.mark.asyncio
async def test_run_once_routes_each_family(monkeypatch):
    """With both v4 and v6 detected, each record type gets the right address."""
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-a",
                record_name="a.example.com", record_type="A", enabled=True)
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-aaaa",
                record_name="aaaa.example.com", record_type="AAAA", enabled=True)

    eng = DDNSEngine()
    eng.cf = FakeCF()
    monkeypatch.setattr(eng, "get_current_ip", lambda: _coro("203.0.113.5"))
    monkeypatch.setattr(eng, "get_current_ipv6", lambda: _coro("2001:db8::1"))

    await eng.run_once()

    updated = {u["name"]: u for u in eng.cf.updates}
    assert updated["a.example.com"]["ip"] == "203.0.113.5"
    assert updated["aaaa.example.com"]["ip"] == "2001:db8::1"


@pytest.mark.asyncio
async def test_run_once_skips_unchanged(monkeypatch):
    """A record whose last_ip already matches is not re-pushed to CF."""
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-a",
                record_name="a.example.com", record_type="A", enabled=True,
                last_ip="203.0.113.5")

    eng = DDNSEngine()
    eng.cf = FakeCF()
    monkeypatch.setattr(eng, "get_current_ip", lambda: _coro("203.0.113.5"))
    monkeypatch.setattr(eng, "get_current_ipv6", lambda: _coro(None))

    await eng.run_once()
    assert eng.cf.updates == []


@pytest.mark.asyncio
async def test_run_once_no_ip_detected_is_noop(monkeypatch):
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-a",
                record_name="a.example.com", record_type="A", enabled=True)
    eng = DDNSEngine()
    eng.cf = FakeCF()
    monkeypatch.setattr(eng, "get_current_ip", lambda: _coro(None))
    monkeypatch.setattr(eng, "get_current_ipv6", lambda: _coro(None))
    await eng.run_once()
    assert eng.cf.updates == []


# --- verify_all ----------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_all_detects_drift_per_family(monkeypatch):
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-a",
                record_name="a.example.com", record_type="A", enabled=True,
                proxied=False, ttl=1)
    # CF currently has a stale content for the A record
    cf = FakeCF(records_by_zone={"z1": [
        {"id": "r-a", "type": "A", "content": "198.51.100.9", "proxied": False, "ttl": 1},
    ]})
    eng = DDNSEngine()
    eng.cf = cf
    monkeypatch.setattr(eng, "get_current_ip", lambda: _coro("203.0.113.5"))
    monkeypatch.setattr(eng, "get_current_ipv6", lambda: _coro(None))

    result = await eng.verify_all()
    assert result["updated"] == 1
    assert result["checked"] == 1
    assert cf.updates[0]["ip"] == "203.0.113.5"


@pytest.mark.asyncio
async def test_verify_all_skips_tunnel_cnames(monkeypatch):
    _add_record(zone_id="z1", zone_name="example.com", record_id="r-tun",
                record_name="tun.example.com", record_type="A", enabled=True)
    cf = FakeCF(records_by_zone={"z1": [
        {"id": "r-tun", "type": "CNAME", "content": "abc123.cfargotunnel.com", "proxied": True, "ttl": 1},
    ]})
    eng = DDNSEngine()
    eng.cf = cf
    monkeypatch.setattr(eng, "get_current_ip", lambda: _coro("203.0.113.5"))
    monkeypatch.setattr(eng, "get_current_ipv6", lambda: _coro(None))

    result = await eng.verify_all()
    assert result["in_sync"] == 1
    assert result["updated"] == 0
    assert cf.updates == []     # tunnel CNAME never touched


# --- helper --------------------------------------------------------------

async def _coro(value):
    """Wrap a plain value in an awaitable so it can stand in for an async method."""
    return value
