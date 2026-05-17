# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
