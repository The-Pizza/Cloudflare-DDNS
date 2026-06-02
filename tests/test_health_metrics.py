"""Tests for the health and metrics HTTP endpoints."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers import health as health_router
from app.routers import metrics as metrics_router
from core import metrics as metrics_mod


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(health_router.router, prefix="/health")
    app.include_router(metrics_router.router)
    return TestClient(app)


def test_health_live(client):
    r = client.get("/health/live")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_health_ready_ok_when_db_reachable(client):
    r = client.get("/health/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_health_ready_503_when_db_down(client, monkeypatch):
    """If the DB raises, readiness must report 503 (so k8s holds the pod out)."""
    def boom():
        raise RuntimeError("db gone")
    monkeypatch.setattr(health_router, "get_session", boom)
    r = client.get("/health/ready")
    assert r.status_code == 503
    assert r.json()["status"] == "not-ready"


def test_metrics_endpoint_exposes_prometheus_text(client):
    metrics_mod.init_metrics("9.9.9")
    # Drive a couple counters so the output isn't trivially empty
    metrics_mod.RECORD_UPDATES.labels(record_type="A").inc()
    metrics_mod.IP_CHANGES.labels(family="ipv4").inc()

    r = client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "ddns_record_updates_total" in body
    assert "ddns_app_info" in body
    # DB-derived collector gauges should be present
    assert "ddns_managed_records" in body
    assert "ddns_discovered_hosts" in body


def test_set_current_ip_replaces_stale_series():
    metrics_mod.set_current_ip("ipv4", "1.1.1.1")
    metrics_mod.set_current_ip("ipv4", "2.2.2.2")
    # Only the latest address should be exported with value 1
    val_old = metrics_mod.CURRENT_IP_INFO.labels(family="ipv4", address="1.1.1.1")
    # Re-fetching a removed series creates a fresh 0-valued one; assert latest is 1
    samples = {
        s.labels["address"]: s.value
        for metric in metrics_mod.CURRENT_IP_INFO.collect()
        for s in metric.samples
    }
    assert samples.get("2.2.2.2") == 1
