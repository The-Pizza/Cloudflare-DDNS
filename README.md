# Cloudflare DDNS

A modern, self-hosted Cloudflare Dynamic DNS updater with a Web UI,
Kubernetes-aware auto-discovery, and persistent state.

[![release-image](https://github.com/The-Pizza/Cloudflare-DDNS/actions/workflows/release-image.yaml/badge.svg)](https://github.com/The-Pizza/Cloudflare-DDNS/actions/workflows/release-image.yaml)

## Features

* **Web UI** — browse every zone on your Cloudflare account, toggle which
  A/AAAA records should be kept in sync with your public IP.
* **Annotation discovery** — annotate any `Service`, `Deployment`, or
  `Ingress` with `cloudflare-ddns.witschger.home/dns-name: foo.example.com`
  and the host shows up in the "Discovered" tab.
* **Traefik & Ingress discovery** — host rules from Traefik `IngressRoute`
  CRDs and standard `Ingress` resources are also discovered automatically.
* **Reliable updater** — only writes to Cloudflare when the public IP
  actually changes (or a record's `last_ip` differs); handles per-record
  errors without crashing the loop.
* **Persistent** — SQLite-backed; survives pod restarts and image upgrades.
* **Legacy compatible** — if you mount the original `records.json` ConfigMap
  on first boot, those records are imported once into the database.
* **Observable** — JSON status endpoint, structured logs, `/health/live`
  and `/health/ready` probes.

## Image

Published to GHCR by the `release-image` workflow on every published GitHub
release. Tags produced:

```
ghcr.io/the-pizza/cloudflare-ddns:<version>     # e.g. 0.3.0
ghcr.io/the-pizza/cloudflare-ddns:<major.minor>
ghcr.io/the-pizza/cloudflare-ddns:<major>
ghcr.io/the-pizza/cloudflare-ddns:latest        # only for non-prerelease
```

> Tags do **not** carry a leading `v`. If you cut release `v0.3.0` on GitHub
> the resulting image is `:0.3.0` (semver pattern strips the `v`).

## Configuration

All knobs are environment variables (no prefix). See `.env.example`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CF_API_TOKEN` | _(required)_ | Cloudflare API token with `Zone:Read` and `DNS:Edit` on the zones you want to manage. |
| `POLL_INTERVAL_SECONDS` | `60` | How often to re-check the public IP. |
| `IPV4_ENDPOINT` | `https://ipinfo.io/ip` | Returns plain-text current IPv4. |
| `IPV6_ENDPOINT` | _(empty)_ | Set to enable AAAA updates. |
| `DATABASE_URL` | `sqlite:////app/data/cloudflare-ddns.db` | SQLAlchemy URL. |
| `CONFIG_PATH` | `/etc/config/records.json` | Optional legacy `records.json` to import on first boot. |
| `IMPORT_LEGACY_CONFIG` | `true` | Disable to skip legacy import. |
| `ENABLE_ANNOTATION_DISCOVERY` | `true` | Scan K8s objects for `ANNOTATION_KEY`. |
| `ENABLE_TRAEFIK_DISCOVERY` | `true` | Scan Traefik IngressRoute + standard Ingress for hosts. |
| `ANNOTATION_KEY` | `cloudflare-ddns.witschger.home/dns-name` | Key checked by annotation discovery. |
| `LOG_LEVEL` | `INFO` | Standard Python levels. |

## Kubernetes

Manifests are in `k8s/`. Apply in order:

```bash
kubectl apply -f k8s/
```

Required up-front:

1. Namespace `cloudflare-ddns` (created by `00-namespace.yaml`).
2. Secret `cloudflare-ddns-secret` with key `CF_API_TOKEN`:

```bash
kubectl -n cloudflare-ddns create secret generic cloudflare-ddns-secret \
  --from-literal=CF_API_TOKEN=cfut_xxx
```

3. (Optional, legacy) ConfigMap `cloudflare-ddns-config` with `records.json`
   to import existing records.
4. (Optional) ConfigMap `cloudflare-ddns-settings` to override env vars
   without editing the Deployment.

### Internal TLS

`k8s/50-certificate.yaml` issues a cert from the `localca` ClusterIssuer
for `ddns.witschger.home`. The `Ingress` (`k8s/60-ingress.yaml`) references
the resulting `ddns-witschger-home-tls` secret. The hostname is internal:
add an `A` record `ddns.witschger.home -> <traefik-internal LB IP>` in your
local DNS.

## Local development

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export CF_API_TOKEN=cfut_xxx
uvicorn app.main:app --reload
# -> http://127.0.0.1:8000
```

## Endpoints

| Path | Description |
| --- | --- |
| `/` | Dashboard (status + zones) |
| `/zones/{zone_id}?name=…` | Per-zone record manager |
| `/discovered` | Annotation / Traefik / Ingress discovery results |
| `/api/zones` | JSON list of zones |
| `/api/zones/{zone_id}/records` | JSON list of A/AAAA records with managed-state |
| `/api/zones/{zone_id}/records/{record_id}/toggle` | `POST {"enabled": bool}` |
| `/api/discovered` | JSON discovered hosts |
| `/api/status` | Engine status JSON |
| `/health/live` `/health/ready` | Probes |
| `/docs` | OpenAPI |

## License

MIT
