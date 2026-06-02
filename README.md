# Cloudflare DDNS

> Self-hosted Cloudflare Dynamic DNS with a real Web UI and Kubernetes auto-discovery.

[![release-image](https://github.com/The-Pizza/Cloudflare-DDNS/actions/workflows/release-image.yaml/badge.svg)](https://github.com/The-Pizza/Cloudflare-DDNS/actions/workflows/release-image.yaml)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-cloudflare--ddns-blue?logo=github)](https://github.com/The-Pizza/Cloudflare-DDNS/pkgs/container/cloudflare-ddns)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

A modern replacement for the original `cloudflare-ddns.py` script: now a
proper FastAPI service with persistent state, a Tailwind web UI, and
Kubernetes-aware discovery so you can stop hand-editing `records.json`.

## ✨ Features

* **🌐 Web UI** — Tailwind dashboard for browsing every Cloudflare zone
  on your account and toggling per-record auto-update with one click.
* **🏷️ Annotation discovery** — Tag any `Service`, `Deployment`, or
  `Ingress` with `cloudflare-ddns.io/dns-name: foo.example.com`
  and it shows up in the **Discovered** tab.
* **🛣️ Traefik & Ingress discovery** — Host rules from Traefik
  `IngressRoute` CRDs and standard `networking.k8s.io/v1` Ingresses are
  also auto-discovered.
* **🔁 Reliable updater** — Only writes to Cloudflare when the public IP
  actually changes; per-record errors don’t crash the loop.
* **💾 Persistent** — SQLite on a PVC; survives upgrades, restarts and
  pod rescheduling.
* **🪶 Lightweight** — Single container, no Helm chart, no JS bundler.
* **🩺 Observable** — `/health/live`, `/health/ready` (real DB check), JSON
  `/api/status`, and **Prometheus `/metrics`** for Grafana dashboards.
* **🌍 IPv4 + IPv6** — manages `A` records from your public IPv4 and `AAAA`
  records from your public IPv6 (set `IPV6_ENDPOINT` to enable).

## 🚀 Quick start (Kubernetes)

```bash
# 1. Create the namespace + secret
kubectl create namespace cloudflare-ddns
kubectl -n cloudflare-ddns create secret generic cloudflare-ddns-secret \
  --from-literal=CF_API_TOKEN=cfut_xxx

# 2. Apply the manifests (they are numbered to be applied in order)
kubectl apply -f https://raw.githubusercontent.com/The-Pizza/Cloudflare-DDNS/main/k8s/00-namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/The-Pizza/Cloudflare-DDNS/main/k8s/

# 3. Point your internal DNS record (e.g. ddns.example.lan -> your-traefik-LB-IP)
# 4. Open https://ddns.example.lan
```

Or clone and apply:

```bash
git clone https://github.com/The-Pizza/Cloudflare-DDNS.git
kubectl apply -f Cloudflare-DDNS/k8s/
```

The default manifests assume:

* IngressClass `traefik-internal` (change in `k8s/50-ingress.yaml`)
* cert-manager `ClusterIssuer` named `localca` (change the annotation
  if you use Let's Encrypt etc.)
* StorageClass `nfs-csi` (or any RWO; tweak `k8s/20-pvc.yaml`)

## 🐳 Container image

Published by GitHub Actions on every release:

| Tag pattern | Example | Notes |
| --- | --- | --- |
| `<version>` | `0.3.0` | Exact release (no leading `v`). |
| `<major.minor>` | `0.3` | Floats with patches. |
| `<major>` | `0` | Floats with minors. |
| `latest` | `latest` | Only for non-prerelease tags. |

```
ghcr.io/the-pizza/cloudflare-ddns:0.3.0
```

Linux `amd64` + `arm64`.

## ⚙️ Configuration

Every setting is an environment variable. Copy `.env.example` to `.env`
for local dev.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CF_API_TOKEN` | _(required)_ | API token with `Zone:Read` + `DNS:Edit`. |
| `POLL_INTERVAL_SECONDS` | `60` | How often to re-check the public IP and run discovery. |
| `IPV4_ENDPOINT` | `https://ipinfo.io/ip` | Returns plain-text IPv4. |
| `IPV6_ENDPOINT` | _(empty)_ | Set to enable AAAA updates. |
| `SESSION_COOKIE_SECURE` | `true` | Send the auth session cookie only over HTTPS. Set `false` for local HTTP dev. |
| `DATABASE_URL` | `sqlite:////app/data/cloudflare-ddns.db` | SQLAlchemy URL. |
| `CONFIG_PATH` | `/etc/config/records.json` | Optional legacy file to import once. |
| `IMPORT_LEGACY_CONFIG` | `true` | Set `false` to skip legacy import. |
| `ENABLE_ANNOTATION_DISCOVERY` | `true` | Scan K8s objects for `ANNOTATION_KEY`. |
| `ENABLE_TRAEFIK_DISCOVERY` | `true` | Scan Traefik + standard Ingress. |
| `ANNOTATION_KEY` | `cloudflare-ddns.io/dns-name` | Annotation looked up by the discovery loop. Accepts a comma-separated list to match multiple keys (e.g. during migration). |
| `LOG_LEVEL` | `INFO` | Standard Python log level. |

## 🧪 Local development

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export CF_API_TOKEN=cfut_xxx
uvicorn app.main:app --reload
# -> http://127.0.0.1:8000
```

Build the container:

```bash
podman build -t cloudflare-ddns:dev .
podman run --rm -p 8080:8080 -e CF_API_TOKEN=cfut_xxx cloudflare-ddns:dev
```

## 🌐 Endpoints

| Path | Description |
| --- | --- |
| `/` | Dashboard (status + zones) |
| `/zones/{zone_id}?name=…` | Per-zone record manager |
| `/discovered` | Annotation / Traefik / Ingress discovery results |
| `/api/zones` | JSON list of zones |
| `/api/zones/{zone_id}/records` | JSON list of A/AAAA records + managed-state |
| `/api/zones/{zone_id}/records/{record_id}/toggle` | `POST {"enabled": bool}` |
| `/api/discovered` | JSON discovered hosts |
| `/api/status` | Engine status JSON |
| `/health/live` `/health/ready` | Probes |
| `/metrics` | Prometheus metrics (text exposition format) |
| `/docs` | OpenAPI / Swagger UI |

## 📊 Metrics & Grafana

Prometheus-format metrics are exposed at `/metrics` (allow-listed, no auth —
keep it on a trusted network or behind your scrape-only firewall rule).

Scrape config:

```yaml
scrape_configs:
  - job_name: cloudflare-ddns
    metrics_path: /metrics
    static_configs:
      - targets: ["cloudflare-ddns.cloudflare-ddns.svc:8080"]
```

Or, with the Prometheus Operator, a `PodMonitor`/`ServiceMonitor` targeting the
`cloudflare-ddns` Service on port `http`.

Key series:

| Metric | Type | Notes |
| --- | --- | --- |
| `ddns_record_updates_total{record_type}` | counter | Successful CF record writes |
| `ddns_record_update_errors_total{record_type}` | counter | Failed writes |
| `ddns_ip_changes_total{family}` | counter | Public IP changes (ipv4/ipv6) |
| `ddns_cloudflare_api_requests_total{method,outcome}` | counter | CF API call volume / errors |
| `ddns_ip_detect_failures_total{family}` | counter | Public-IP detection failures |
| `ddns_last_run_timestamp_seconds` | gauge | Use for a freshness/staleness alert |
| `ddns_current_ip_info{family,address}` | gauge | Current public IP (value 1) |
| `ddns_managed_records` / `ddns_enabled_records` | gauge | DB-derived counts |
| `ddns_discovered_hosts{source}` | gauge | Discovery results by source |

Example staleness alert (no successful run in 15 min):

```promql
time() - ddns_last_run_timestamp_seconds > 900
```

## 🧪 Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite runs on every push/PR via the `tests` workflow (Python 3.12 + 3.13).

## 🔄 Legacy upgrade

If you’re coming from the `0.1.x` / `0.2.x` script-based releases:

1. Apply the new manifests — your existing `cloudflare-ddns-config`
   ConfigMap (with `records.json`) is **automatically imported once** on
   first boot, all records enabled.
2. After confirming the records show up in the **Zones** UI, you can
   delete the ConfigMap if you no longer want the legacy import on disk:
   `kubectl delete cm cloudflare-ddns-config -n cloudflare-ddns`.
3. The new pod uses different env vars (no `CFDDNS_` prefix); the old
   `cloudflare-ddns-settings` ConfigMap is still read (as `envFrom`) but
   its keys are ignored unless they happen to match new variable names.

## 🛠 Contributing

Bug reports and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## 📝 License

[MIT](LICENSE) © Ryan Witschger
