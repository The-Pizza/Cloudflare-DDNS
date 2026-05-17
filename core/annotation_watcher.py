"""Annotation-based discovery.

Scans Services, Ingresses, Deployments for the configured annotation
key (default `cloudflare-ddns.witschger.home/dns-name`) and records the
resulting hostnames as DiscoveredHost rows for the user to enable.
"""
import logging
import time

from kubernetes import client, config

from core.config import settings
from core.database import get_session
from core.models import DiscoveredHost

log = logging.getLogger("cfddns.annotation")


class AnnotationWatcher:
    def __init__(self):
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()
        self.net = client.NetworkingV1Api()

    def _record(self, host: str, kind: str, namespace: str, name: str) -> None:
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
            else:
                sess.add(
                    DiscoveredHost(
                        host=host,
                        source="annotation",
                        namespace=namespace,
                        resource_name=f"{kind}/{name}",
                    )
                )
            sess.commit()
        finally:
            sess.close()
        log.info("Annotation discovery: %s on %s/%s/%s", host, namespace, kind, name)

    def _walk(self, items, kind: str) -> None:
        for it in items:
            md = it.metadata
            anns = md.annotations or {}
            host = anns.get(settings.annotation_key)
            if host:
                self._record(host, kind, md.namespace or "", md.name or "")

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
