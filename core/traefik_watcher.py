"""Watch Traefik IngressRoutes and standard Ingresses for hosts to auto-manage."""
import logging
import re
import time

from kubernetes import client, config, watch

from core.database import get_session
from core.models import DiscoveredHost

log = logging.getLogger("cfddns.traefik")

# Match Host(`foo.bar`) and HostRegexp(`foo.bar`)
_HOST_RE = re.compile(r"Host(?:SNI|Regexp)?\(`([^`]+)`\)")


class TraefikWatcher:
    """Discovers hostnames from Traefik IngressRoute CRDs and standard Ingress resources."""

    def __init__(self):
        try:
            config.load_incluster_config()
            log.info("Loaded in-cluster kube config")
        except Exception:
            try:
                config.load_kube_config()
                log.info("Loaded local kube config")
            except Exception as e:
                log.warning("Could not load kube config: %s", e)
                raise
        self.custom = client.CustomObjectsApi()
        self.networking = client.NetworkingV1Api()

    def _record(self, host: str, source: str, namespace: str, name: str) -> None:
        sess = get_session()
        existing = (
            sess.query(DiscoveredHost)
            .filter(DiscoveredHost.host == host, DiscoveredHost.source == source)
            .first()
        )
        if existing:
            existing.namespace = namespace
            existing.resource_name = name
        else:
            sess.add(
                DiscoveredHost(
                    host=host,
                    source=source,
                    namespace=namespace,
                    resource_name=name,
                )
            )
        sess.commit()
        sess.close()
        log.info("Discovered host: %s (source=%s, %s/%s)", host, source, namespace, name)

    def _scan_ingressroutes(self) -> None:
        """One-shot scan of all Traefik IngressRoutes."""
        try:
            resp = self.custom.list_cluster_custom_object(
                group="traefik.io", version="v1alpha1", plural="ingressroutes"
            )
        except client.exceptions.ApiException as e:
            if e.status == 404:
                log.debug("Traefik CRD not present, skipping IngressRoute scan")
                return
            raise

        for item in resp.get("items", []):
            md = item.get("metadata", {})
            for route in item.get("spec", {}).get("routes", []):
                match = route.get("match", "")
                for host in _HOST_RE.findall(match):
                    self._record(host, "traefik-ingressroute", md.get("namespace", ""), md.get("name", ""))

    def _scan_ingresses(self) -> None:
        """One-shot scan of all standard Ingress resources."""
        try:
            resp = self.networking.list_ingress_for_all_namespaces()
        except Exception as e:
            log.warning("Failed listing Ingresses: %s", e)
            return
        for ing in resp.items:
            for rule in (ing.spec.rules or []):
                if rule.host:
                    self._record(
                        rule.host,
                        "ingress",
                        ing.metadata.namespace,
                        ing.metadata.name,
                    )

    def scan_once(self) -> None:
        self._scan_ingressroutes()
        self._scan_ingresses()

    def watch_loop(self, interval_seconds: int = 60) -> None:
        """Periodic scan loop. Lighter than CRD watch (works for both CRD + builtin)."""
        while True:
            try:
                self.scan_once()
            except Exception as e:
                log.exception("Traefik scan failed: %s", e)
            time.sleep(interval_seconds)
