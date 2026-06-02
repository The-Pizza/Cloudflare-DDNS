"""Prometheus metrics for Cloudflare DDNS.

Two kinds of metrics:

  * **Event counters/gauges** (module-level) are mutated at runtime by the
    engine and Cloudflare client as things happen (record updates, errors,
    API calls, detected IPs).

  * **DB-derived gauges** are produced fresh on every scrape by a custom
    collector, so counts (managed / enabled / discovered) and the last-update
    timestamp always reflect current state without bookkeeping.

Everything is registered on the default REGISTRY, which the /metrics endpoint
renders with prometheus_client.generate_latest().
"""
from __future__ import annotations

import logging
from typing import Optional

from prometheus_client import REGISTRY, Counter, Gauge
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

log = logging.getLogger("cfddns.metrics")

# --- Build / liveness info -------------------------------------------------

APP_INFO = Gauge(
    "ddns_app_info",
    "Static application info; value is always 1.",
    ["version"],
)

# --- Event counters (mutated at runtime) -----------------------------------

RECORD_UPDATES = Counter(
    "ddns_record_updates_total",
    "Cloudflare DNS records successfully updated by the engine.",
    ["record_type"],            # A | AAAA
)

RECORD_UPDATE_ERRORS = Counter(
    "ddns_record_update_errors_total",
    "Failed attempts to update a Cloudflare DNS record.",
    ["record_type"],
)

IP_CHANGES = Counter(
    "ddns_ip_changes_total",
    "Detected public IP changes, by address family.",
    ["family"],                 # ipv4 | ipv6
)

CF_API_REQUESTS = Counter(
    "ddns_cloudflare_api_requests_total",
    "Cloudflare API requests issued, by HTTP method and outcome.",
    ["method", "outcome"],      # outcome: success | error
)

IP_DETECT_FAILURES = Counter(
    "ddns_ip_detect_failures_total",
    "Failures detecting the public IP from the configured endpoint.",
    ["family"],
)

# --- Runtime gauges (set by the engine each loop) --------------------------

LAST_RUN_TIMESTAMP = Gauge(
    "ddns_last_run_timestamp_seconds",
    "Unix timestamp of the last completed DDNS engine run.",
)

CURRENT_IP_INFO = Gauge(
    "ddns_current_ip_info",
    "Current detected public IP; value is always 1, address is in the label.",
    ["family", "address"],
)

# Remember the last address per family so we can clear stale label series.
_last_ip: dict[str, Optional[str]] = {"ipv4": None, "ipv6": None}


def set_current_ip(family: str, address: Optional[str]) -> None:
    """Publish the current public IP for a family as a labelled gauge (value 1).

    Removes the previous address series for this family so exactly one address
    per family is exported at a time (no stale series after an IP change).
    """
    try:
        prev = _last_ip.get(family)
        if prev and prev != address:
            try:
                CURRENT_IP_INFO.remove(family, prev)
            except KeyError:
                pass
        if address:
            CURRENT_IP_INFO.labels(family=family, address=address).set(1)
        _last_ip[family] = address
    except Exception as e:
        log.debug("set_current_ip(%s) failed: %s", family, e)


class _DBStatsCollector(Collector):
    """Collect gauges derived from the database at scrape time.

    Implemented as a custom collector (rather than Gauge.set on a timer) so the
    numbers are always live and we never double-count. Import is done lazily to
    avoid a circular import at module load.
    """

    def collect(self):
        managed = enabled = 0
        discovered_by_source: dict[str, int] = {}
        ip_history_total = 0
        try:
            from sqlmodel import func, select

            from core.database import get_session
            from core.models import DiscoveredHost, IpHistoryEntry, ManagedRecord

            sess = get_session()
            try:
                managed = sess.query(ManagedRecord).count()
                enabled = sess.query(ManagedRecord).filter(ManagedRecord.enabled == True).count()  # noqa: E712
                ip_history_total = sess.query(IpHistoryEntry).count()
                for source, cnt in sess.execute(
                    select(DiscoveredHost.source, func.count()).group_by(DiscoveredHost.source)
                ).all():
                    discovered_by_source[source or "unknown"] = cnt
            finally:
                sess.close()
        except Exception as e:
            log.debug("metrics DB collect failed: %s", e)

        g_managed = GaugeMetricFamily(
            "ddns_managed_records", "Total ManagedRecord rows in the database."
        )
        g_managed.add_metric([], managed)
        yield g_managed

        g_enabled = GaugeMetricFamily(
            "ddns_enabled_records", "ManagedRecord rows with auto-update enabled."
        )
        g_enabled.add_metric([], enabled)
        yield g_enabled

        g_hist = GaugeMetricFamily(
            "ddns_ip_history_entries", "Rows in the public-IP change-history table."
        )
        g_hist.add_metric([], ip_history_total)
        yield g_hist

        g_disc = GaugeMetricFamily(
            "ddns_discovered_hosts",
            "Discovered hosts, labelled by discovery source.",
            labels=["source"],
        )
        if discovered_by_source:
            for source, cnt in sorted(discovered_by_source.items()):
                g_disc.add_metric([source], cnt)
        else:
            g_disc.add_metric(["none"], 0)
        yield g_disc


_collector_registered = False


def init_metrics(version: str) -> None:
    """Register the DB collector and set static app info. Idempotent."""
    global _collector_registered
    APP_INFO.labels(version=version).set(1)
    if not _collector_registered:
        REGISTRY.register(_DBStatsCollector())
        _collector_registered = True
