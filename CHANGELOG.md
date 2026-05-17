# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-17

### Added
- **Merged zone view**: each zone page now shows real Cloudflare A/AAAA
  records AND discovered hostnames belonging to that zone. Discovered
  hosts without a matching CF record get a one-click **Create** button
  that creates the record at the current public IP and enables DDNS.
- **Inline proxied toggle** per record — click the ☁️/○ icon to flip
  Cloudflare's `proxied` flag without leaving the page.
- **Manual "Add record" form** on every zone page for fast ad-hoc
  record creation (subdomain or FQDN, A/AAAA, optional value defaulting
  to current public IP, proxied checkbox).
- **"Check now" button** runs a full validate-and-sync over every
  enabled record and reports a toast like
  `34 checked · 33 in sync · 1 updated · 0 errors`.
- **Settings page** (`/settings`) for runtime config: CF API token,
  IPv4/IPv6 endpoints, poll interval, default proxied/TTL, annotation
  key, auth mode. Values backed by SQLite. Fields supplied via
  env / ConfigMap are auto-detected, greyed out, and tagged
  **env-locked** so operators retain authority.
- `Setting` SQLModel table for runtime-mutable config.
- `auth_mode` setting (`none` | `forward-auth`) — advisory flag for
  pairing with an external Authentik forward-auth middleware.

### Changed
- Top nav: **Health** link removed (probes still exposed at
  `/health/live` and `/health/ready` for Kubernetes); replaced with
  **Settings**.

## [0.3.1] - 2025-05-17

### Added
- `version` field on `/api/status` (matches the Python package version).
- Dashboard footer shows the running version + repo link.
- LICENSE (MIT), CONTRIBUTING.md, CHANGELOG.md, SECURITY.md.
- `.github/` housekeeping: dependabot, CODEOWNERS, issue and PR templates.
- `examples/` directory with annotated Deployment, standard Ingress
  and Traefik IngressRoute samples.
- `k8s/README.md` documenting every manifest.
- `.dockerignore` + `.gitattributes` for cleaner builds.

### Changed
- README rewritten with badges, quickstart, full endpoints / config
  tables and legacy upgrade instructions.

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
