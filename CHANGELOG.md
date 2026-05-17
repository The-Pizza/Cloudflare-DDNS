# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-05-17

### Added
- Modern **FastAPI** application replacing the legacy `cloudflare-ddns.py`
  script.
- **Web UI** (Tailwind, no bundler) for browsing zones and toggling
  per-record auto-update.
- **Annotation discovery** for any Service/Deployment/Ingress carrying
  the `cloudflare-ddns.witschger.home/dns-name` annotation.
- **Traefik IngressRoute + standard Ingress** host discovery.
- **SQLite persistence** on a PVC: managed records and discovered hosts
  survive restarts and image upgrades.
- One-shot **legacy `records.json` import** on first boot so existing
  installs upgrade seamlessly.
- `/health/live`, `/health/ready`, `/api/status`, OpenAPI at `/docs`.
- **RBAC**: ClusterRole with list/watch on Services, Deployments,
  Ingresses, Traefik IngressRoutes.
- Multi-arch container image (amd64 + arm64).

### Changed
- Kubernetes manifests are now numbered (`00-…` … `50-…`) so
  `kubectl apply -f k8s/` applies them in dependency order.
- Deployment strategy changed to `Recreate` to keep the SQLite PVC
  single-writer.
- Cert-manager integration uses an Ingress annotation
  (`cert-manager.io/cluster-issuer: localca`) instead of a standalone
  `Certificate` resource.

### Removed
- Legacy `cloudflare-ddns.py` script.
- Legacy `cf_export_a_records.py` helper.
- Top-level `k8s-deploy.yaml` (superseded by the `k8s/` directory).
- Standalone PowerShell helper that was only useful during one
  bootstrap session.

## [0.2.0] - 2025-08-28

### Added
- Watchdog-based hot reload of `records.json`.

## [0.1.0] - 2025-08-26

### Added
- Initial Python-based DDNS updater (single script + ConfigMap).
