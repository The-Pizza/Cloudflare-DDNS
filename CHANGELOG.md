# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-06-02

### Added
- **Prometheus metrics** at `/metrics` (no auth required — allow-listed so
  Prometheus can scrape; protect at the network layer). Exposes:
  `ddns_app_info`, `ddns_record_updates_total{record_type}`,
  `ddns_record_update_errors_total{record_type}`,
  `ddns_ip_changes_total{family}`, `ddns_ip_detect_failures_total{family}`,
  `ddns_cloudflare_api_requests_total{method,outcome}`,
  `ddns_last_run_timestamp_seconds`, `ddns_current_ip_info{family,address}`,
  and DB-derived gauges `ddns_managed_records`, `ddns_enabled_records`,
  `ddns_discovered_hosts{source}`, `ddns_ip_history_entries`.
- **Real IPv6 / AAAA support**. The engine now detects the public IPv6 address
  from `IPV6_ENDPOINT` and routes each record to the matching address family
  (A→IPv4, AAAA→IPv6). `/api/status` gains `current_ipv6`.
- **Unit test suite** (`pytest`, 29 tests) covering the A/AAAA routing fix,
  JWKS validation, the session-cookie Secure flag, config/annotation parsing,
  readiness, and metrics. New `tests` CI workflow runs them on every PR
  (Python 3.12 + 3.13).
- `SESSION_COOKIE_SECURE` setting (default **true**).

### Fixed
- **AAAA records no longer get an IPv4 address written into them.** Previously
  every enabled record received the detected IPv4 regardless of type, which
  corrupted or caused Cloudflare to reject AAAA records. (Critical.)
- **Session cookie now sets the `Secure` flag** by default (was hard-coded
  `secure=False`), so the auth cookie is HTTPS-only. Configurable via
  `SESSION_COOKIE_SECURE` for local HTTP dev.
- **OIDC `id_token` signatures are now cryptographically verified** against the
  provider's JWKS (signature + issuer + audience + expiry) before any claims
  are trusted for authorization. Previously claims were base64-decoded without
  verification. (Security.)
- **`/health/ready` now performs a real database check** and returns 503 when
  the DB is unreachable, so Kubernetes keeps the pod out of rotation until it
  can actually serve.

## [0.7.1] - 2026-06-02

### Fixed
- **Container crash-on-startup regression in 0.7.0**. The 0.7.0 image
  was built on `python:3.14-slim`, but SQLModel 0.0.22 + Pydantic 2 fail
  to construct table models on Python 3.14 (PEP 649 deferred annotations
  break SQLModel's metaclass — `Field 'id' requires a type annotation`).
  The image built fine but crash-looped at runtime. Base image is now
  pinned to `python:3.13-slim`.

### Added
- **Build-time import smoke test** in the Dockerfile: the build now
  imports `app.main` and fails if the app can't start, so runtime-only
  breakage (like the 3.14 issue above) is caught at build time instead
  of in production.
- Dependabot is configured to ignore Python base-image bumps `>=3.14`
  until SQLModel supports it.

## [0.7.0] - 2026-06-02

### Changed
- **Default annotation key is now vendor-neutral**:
  `cloudflare-ddns.io/dns-name` (was a deployment-specific internal
  domain). This is the key the discovery loop looks up on
  Services/Deployments/Ingresses.

### Added
- **Multi-key annotation discovery**. `ANNOTATION_KEY` now accepts a
  comma-separated list of keys; a workload carrying ANY of them is
  discovered. This makes migrating from an old annotation key to a new
  one a non-breaking, two-step operation: list both keys, re-annotate
  your workloads, then drop the old key.

### Migration
- Existing deployments that used the old annotation key keep working by
  setting `ANNOTATION_KEY="cloudflare-ddns.io/dns-name,<your-old-key>"`,
  re-annotating workloads with the new key, then removing the old key
  from the list. New installs need no action.

## [0.6.0] - 2026-05-17

### Added
- **Public-IP change history**. New `IpHistoryEntry` table records every
  detected transition with previous IP, new IP, timestamp, and note
  (`boot` for the first observation, `ip-change` for subsequent shifts).
- **Dashboard popup**: the "Current Public IP" card is now clickable
  (📜 history label) and opens a modal listing every recorded change,
  newest first. Esc or click-outside closes it.
- `GET /api/ip-history?limit=N` (default 100, max 1000).

## [0.5.4] - 2026-05-17

### Fixed
- `auth_mode` dropdown no longer auto-saves on change — flipping to
  `forward-auth` while you have no reverse-proxy in front would
  immediately lock you out of the UI. Now the dropdown only toggles
  which auth section is visible; nothing persists until you click Save.

## [0.5.3] - 2026-05-17

### Fixed
- `/auth/whoami` reads the session cookie / forward-auth headers
  directly when called from the always-allow path, so signed-in users
  no longer see a 'sign in' link in the nav.
- Zone records table: switched to `table-fixed` with explicit column
  widths, badges are `whitespace-nowrap` (Source column no longer wraps
  to two lines), long tunnel CNAMEs truncate with a tooltip instead of
  pushing the layout, all cells share consistent vertical padding.

### Changed
- Settings page only renders the OIDC client section when
  `auth_mode=oidc` and the Forward-auth headers section when
  `auth_mode=forward-auth`. Changing the dropdown auto-saves and
  re-renders.

## [0.5.2] - 2026-05-17

### Fixed
- Session cookie payload now uses base64-encoded JSON instead of an
  ASCII Unit Separator (`\\x1f`). `http.cookies` rejects control chars in
  cookie values, so the prior format raised
  `CookieError: Control characters are not allowed in cookies` on the
  OIDC callback and returned 500 to the browser.

## [0.5.1] - 2026-05-17

### Fixed
- **`get_effective()` now reads the DB when called without a pre-fetched
  value** (previously it fell straight through to env / dataclass
  defaults). This means the runtime middleware actually honours
  Settings-page changes for `auth_mode` and every other runtime key —
  prior to this fix, flipping `auth_mode=oidc` in the UI silently kept
  the app open. Critical security fix for the auth feature.

### Changed
- Settings GET response masks every key in `SECRET_KEYS`
  (`cf_api_token`, `oidc_client_secret`, `session_secret`), not just
  the Cloudflare token.

## [0.5.0] - 2026-05-17

### Added
- **Built-in OpenID Connect login** (`auth_mode=oidc`). Authorization Code
  flow with PKCE against any OIDC provider via discovery
  (`<issuer>/.well-known/openid-configuration`). Verified shape works
  with Authentik, Keycloak, Authelia, Dex, Zitadel, Google, Okta.
  Settings: `oidc_issuer`, `oidc_client_id`, `oidc_client_secret`,
  `oidc_scopes`, `oidc_redirect_url`, `oidc_username_claim`,
  `oidc_email_claim`, `oidc_groups_claim`, `oidc_allowed_groups`,
  `oidc_allowed_emails`.
- **Forward-auth mode** (`auth_mode=forward-auth`) for users who put
  Authentik / Authelia / oauth2-proxy in front via Traefik or nginx.
  Configurable identity headers (`forward_auth_user_header`,
  `forward_auth_email_header`, `forward_auth_groups_header`,
  `forward_auth_groups_separator`); defaults match Authentik.
- `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/whoami`
  endpoints.
- Signed-session cookie (itsdangerous) with auto-generated
  `session_secret` (persisted across restarts).
- Group/email allow-lists enforced for both auth modes.
- Settings page now groups fields (Cloudflare / DDNS engine / Discovery
  / Authentication / OIDC client / Forward-auth headers) and shows a
  signed-in banner + sign-out link.
- Top-nav shows `· username · sign out` when authenticated, `· sign in`
  in oidc mode when not.

### Notes
- `none` remains the default — the container is open out of the box,
  exactly as before.
- Probes (`/health/*`) and `/api/status` are always reachable so k8s
  liveness/readiness and the footer version banner keep working.

## [0.4.1] - 2026-05-17

### Added
- **Cloudflare Tunnel detection**: CNAMEs pointing to
  `<uuid>.cfargotunnel.com` are now surfaced as a read-only **🚇 Tunnel**
  row with an `⛔ ignored` manage cell and a tooltip explaining that the
  record is managed by `cloudflared`. Discovered hosts whose name
  already exists as a tunnel CNAME no longer offer a misleading
  **Create** button (which would fail with CF error 81054).
- Defensive guard in the verify loop: never modifies tunnel CNAMEs even
  if they somehow end up in `ManagedRecord`.

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
  the `cloudflare-ddns.io/dns-name` annotation.
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
