"""Tests for declarative annotation management (Option B).

Covers:
  - config.management_keys() prefix derivation (incl. multi-key / custom domain)
  - annotation_watcher._truthy() tri-state parsing
  - DDNSEngine.reconcile_annotation_managed(): create, adopt, tunnel-guard,
    zone resolution, and deferral when the address family isn't available.
"""
import pytest

from core import config
from core.annotation_watcher import _truthy
from core.database import get_session
from core.ddns_engine import DDNSEngine, _is_tunnel_cname
from core.models import DiscoveredHost, ManagedRecord


# --- config.management_keys ------------------------------------------------

def test_management_keys_default_prefix():
    assert config.management_keys("manage") == ["cloudflare-ddns.io/manage"]
    assert config.management_keys("proxied") == ["cloudflare-ddns.io/proxied"]


def test_management_keys_follows_custom_and_multi_key(monkeypatch):
    # Simulate a repo that customised annotation_key to its own domain AND
    # listed two keys for a migration. management_keys must mirror both prefixes.
    monkeypatch.setattr(config, "get_effective",
                         lambda k: "acme.example.com/dns-name, cloudflare-ddns.io/dns-name")
    keys = config.management_keys("proxied")
    assert keys == ["acme.example.com/proxied", "cloudflare-ddns.io/proxied"]


# --- _truthy ---------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("True", True), ("1", True), ("yes", True), ("on", True),
    ("false", False), ("0", False), ("no", False), ("off", False),
    (None, None), ("", None), ("  ", None), ("maybe", None),
])
def test_truthy_tristate(raw, expected):
    assert _truthy(raw) is expected


# --- _is_tunnel_cname ------------------------------------------------------

def test_is_tunnel_cname():
    assert _is_tunnel_cname({"type": "CNAME", "content": "abc123.cfargotunnel.com"})
    assert _is_tunnel_cname({"type": "CNAME", "content": "ABC.CFARGOTUNNEL.COM."})
    assert not _is_tunnel_cname({"type": "A", "content": "1.2.3.4"})
    assert not _is_tunnel_cname({"type": "CNAME", "content": "example.com"})


# --- reconcile fakes -------------------------------------------------------

class FakeCF:
    """Captures create calls and serves canned zones/records."""

    def __init__(self, zones, records_by_zone=None):
        self._zones = zones
        self._records_by_zone = records_by_zone or {}
        self.created = []

    async def list_zones(self):
        return self._zones

    async def list_dns_records(self, zone_id):
        return self._records_by_zone.get(zone_id, [])

    async def create_dns_record(self, zone_id, name, ip, record_type="A", proxied=True, ttl=1):
        self.created.append(
            {"zone_id": zone_id, "name": name, "ip": ip,
             "type": record_type, "proxied": proxied, "ttl": ttl}
        )
        return {"result": {"id": f"new-{name}-{record_type}", "name": name, "type": record_type}}


def _add_host(**kw):
    sess = get_session()
    try:
        h = DiscoveredHost(source="annotation", **kw)
        sess.add(h)
        sess.commit()
        sess.refresh(h)
        return h.id
    finally:
        sess.close()


ZONES = [{"id": "z1", "name": "witschger.net"}]


# --- reconcile: create -----------------------------------------------------

@pytest.mark.asyncio
async def test_reconcile_creates_grey_cloud_record():
    hid = _add_host(host="ctrl.ziti.witschger.net", managed=True,
                    desired_type="A", desired_proxied=False, desired_ttl=1)
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES)
    await eng.reconcile_annotation_managed("203.0.113.5", None)

    # A CF create happened, grey-cloud, at the public IP.
    assert len(eng.cf.created) == 1
    c = eng.cf.created[0]
    assert c["name"] == "ctrl.ziti.witschger.net"
    assert c["ip"] == "203.0.113.5"
    assert c["proxied"] is False
    assert c["type"] == "A"

    # A ManagedRecord was promoted and the host stamped.
    sess = get_session()
    try:
        mr = sess.query(ManagedRecord).filter(ManagedRecord.record_name == "ctrl.ziti.witschger.net").first()
        assert mr is not None
        assert mr.source == "annotation"
        assert mr.proxied is False
        h = sess.get(DiscoveredHost, hid)
        assert h.managed_record_id == mr.record_id
        assert h.last_reconcile_error is None
    finally:
        sess.close()


# --- reconcile: adopt existing --------------------------------------------

@pytest.mark.asyncio
async def test_reconcile_adopts_existing_record_without_creating():
    _add_host(host="router.ziti.witschger.net", managed=True, desired_type="A",
              desired_proxied=False)
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES, records_by_zone={"z1": [
        {"id": "existing-1", "name": "router.ziti.witschger.net", "type": "A",
         "content": "198.51.100.9", "proxied": False, "ttl": 1},
    ]})
    await eng.reconcile_annotation_managed("203.0.113.5", None)

    # No create — it adopted the existing record id.
    assert eng.cf.created == []
    sess = get_session()
    try:
        mr = sess.query(ManagedRecord).filter(ManagedRecord.record_name == "router.ziti.witschger.net").first()
        assert mr is not None
        assert mr.record_id == "existing-1"
    finally:
        sess.close()


# --- reconcile: never touch a cloudflared tunnel CNAME ---------------------

@pytest.mark.asyncio
async def test_reconcile_refuses_tunnel_cname():
    hid = _add_host(host="ziti.witschger.net", managed=True, desired_type="A")
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES, records_by_zone={"z1": [
        {"id": "tun-1", "name": "ziti.witschger.net", "type": "CNAME",
         "content": "deadbeef.cfargotunnel.com", "proxied": True, "ttl": 1},
    ]})
    await eng.reconcile_annotation_managed("203.0.113.5", None)

    assert eng.cf.created == []
    sess = get_session()
    try:
        assert sess.query(ManagedRecord).count() == 0
        h = sess.get(DiscoveredHost, hid)
        assert h.managed_record_id is None
        assert "tunnel CNAME" in (h.last_reconcile_error or "")
    finally:
        sess.close()


# --- reconcile: no zone owns the host -------------------------------------

@pytest.mark.asyncio
async def test_reconcile_records_error_when_no_zone():
    hid = _add_host(host="ctrl.example.org", managed=True, desired_type="A")
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES)  # only owns witschger.net
    await eng.reconcile_annotation_managed("203.0.113.5", None)

    assert eng.cf.created == []
    sess = get_session()
    try:
        h = sess.get(DiscoveredHost, hid)
        assert h.managed_record_id is None
        assert "no Cloudflare zone" in (h.last_reconcile_error or "")
    finally:
        sess.close()


# --- reconcile: AAAA deferred when no IPv6 --------------------------------

@pytest.mark.asyncio
async def test_reconcile_defers_aaaa_without_ipv6():
    hid = _add_host(host="ctrl.ziti.witschger.net", managed=True, desired_type="AAAA")
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES)
    await eng.reconcile_annotation_managed("203.0.113.5", None)  # no ipv6

    assert eng.cf.created == []
    sess = get_session()
    try:
        h = sess.get(DiscoveredHost, hid)
        assert h.managed_record_id is None   # deferred, not errored
    finally:
        sess.close()


# --- reconcile: unmanaged hosts are ignored -------------------------------

@pytest.mark.asyncio
async def test_reconcile_ignores_unmanaged_hosts():
    _add_host(host="app.witschger.net", managed=False, desired_type="A")
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES)
    await eng.reconcile_annotation_managed("203.0.113.5", None)
    assert eng.cf.created == []
    sess = get_session()
    try:
        assert sess.query(ManagedRecord).count() == 0
    finally:
        sess.close()


# --- reconcile: explicit content overrides public IP ----------------------

@pytest.mark.asyncio
async def test_reconcile_explicit_content():
    _add_host(host="static.witschger.net", managed=True, desired_type="A",
              desired_content="192.0.2.50", desired_proxied=True)
    eng = DDNSEngine()
    eng.cf = FakeCF(ZONES)
    await eng.reconcile_annotation_managed("203.0.113.5", None)
    assert len(eng.cf.created) == 1
    assert eng.cf.created[0]["ip"] == "192.0.2.50"
    assert eng.cf.created[0]["proxied"] is True
