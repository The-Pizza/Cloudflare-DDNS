"""Annotation-based discovery.

Scans Services, Ingresses, Deployments for the configured annotation
key (default `cloudflare-ddns.io/dns-name`) and records the
resulting hostnames as DiscoveredHost rows for the user to enable.

`annotation_key` may be a comma-separated list of keys; a workload
carrying ANY of them is discovered. This makes migrating from an old
annotation key to a new one a non-breaking operation.
"""
import logging
import time
from typing import Optional

from kubernetes import client, config

from core.config import annotation_keys, management_keys, settings
from core.database import get_session
from core.models import DiscoveredHost

log = logging.getLogger("cfddns.annotation")


def _truthy(val: Optional[str]) -> Optional[bool]:
    """Parse an annotation string to a tri-state bool.

    Returns None when the annotation is absent/empty so callers can fall back
    to a default. Recognises the usual truthy/falsey spellings.
    """
    if val is None:
        return None
    v = val.strip().lower()
    if v == "":
        return None
    if v in ("1", "true", "yes", "on", "enabled"):
        return True
    if v in ("0", "false", "no", "off", "disabled"):
        return False
    return None


class AnnotationWatcher:
    def __init__(self):
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()
        self.net = client.NetworkingV1Api()

    @staticmethod
    def _first(anns: dict, keys: list) -> Optional[str]:
        """Return the value of the first annotation key present (non-empty)."""
        return next((anns[k] for k in keys if anns.get(k)), None)

    def _record(
        self,
        host: str,
        kind: str,
        namespace: str,
        name: str,
        *,
        managed: bool = False,
        desired_type: str = "A",
        desired_proxied: Optional[bool] = None,
        desired_ttl: Optional[int] = None,
        desired_content: Optional[str] = None,
    ) -> None:
        sess = get_session()
        try:
            existing = (
                sess.query(DiscoveredHost)
                .filter(DiscoveredHost.host == host, DiscoveredHost.source == "annotation")
                .first()
            )
            if existing:
                existing.namespace = namespace
                existing.resource_name = f"{kind}/{name}"
                # Refresh declarative intent from the live annotations every scan
                # so editing the manifest is reflected without a restart. We never
                # clear managed_record_id here -- that's owned by the engine.
                existing.managed = managed
                existing.desired_type = desired_type
                existing.desired_proxied = desired_proxied
                existing.desired_ttl = desired_ttl
                existing.desired_content = desired_content
            else:
                sess.add(
                    DiscoveredHost(
                        host=host,
                        source="annotation",
                        namespace=namespace,
                        resource_name=f"{kind}/{name}",
                        managed=managed,
                        desired_type=desired_type,
                        desired_proxied=desired_proxied,
                        desired_ttl=desired_ttl,
                        desired_content=desired_content,
                    )
                )
            sess.commit()
        finally:
            sess.close()
        log.info(
            "Annotation discovery: %s on %s/%s/%s (managed=%s type=%s proxied=%s)",
            host, namespace, kind, name, managed, desired_type, desired_proxied,
        )

    def _walk(self, items, kind: str) -> None:
        keys = annotation_keys()
        manage_keys = management_keys("manage")
        proxied_keys = management_keys("proxied")
        type_keys = management_keys("type")
        ttl_keys = management_keys("ttl")
        content_keys = management_keys("content")
        for it in items:
            md = it.metadata
            anns = md.annotations or {}
            # First matching key wins; supports migrating between keys.
            host = self._first(anns, keys)
            if not host:
                continue

            # ---- Declarative management intent (Option B) ----
            managed = False
            desired_type = "A"
            desired_proxied: Optional[bool] = None
            desired_ttl: Optional[int] = None
            desired_content: Optional[str] = None
            if settings.enable_annotation_management:
                managed = bool(_truthy(self._first(anns, manage_keys)))
            if managed:
                rtype = (self._first(anns, type_keys) or "A").strip().upper()
                desired_type = rtype if rtype in ("A", "AAAA") else "A"
                desired_proxied = _truthy(self._first(anns, proxied_keys))
                ttl_raw = self._first(anns, ttl_keys)
                if ttl_raw:
                    try:
                        desired_ttl = int(ttl_raw.strip())
                    except ValueError:
                        log.warning("Ignoring non-integer ttl annotation %r on %s/%s",
                                    ttl_raw, md.namespace, md.name)
                content_raw = self._first(anns, content_keys)
                desired_content = content_raw.strip() if content_raw else None

            self._record(
                host, kind, md.namespace or "", md.name or "",
                managed=managed,
                desired_type=desired_type,
                desired_proxied=desired_proxied,
                desired_ttl=desired_ttl,
                desired_content=desired_content,
            )

    def scan_once(self) -> None:
        try:
            self._walk(self.core.list_service_for_all_namespaces().items, "Service")
        except Exception as e:
            log.warning("Service scan failed: %s", e)
        try:
            self._walk(self.apps.list_deployment_for_all_namespaces().items, "Deployment")
        except Exception as e:
            log.warning("Deployment scan failed: %s", e)
        try:
            self._walk(self.net.list_ingress_for_all_namespaces().items, "Ingress")
        except Exception as e:
            log.warning("Ingress scan failed: %s", e)

    def watch_loop(self, interval_seconds: int = 60) -> None:
        while True:
            try:
                self.scan_once()
            except Exception as e:
                log.exception("Annotation scan failed: %s", e)
            time.sleep(interval_seconds)
