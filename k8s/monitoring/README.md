# Monitoring (Prometheus + Grafana)

Optional manifests to scrape Cloudflare-DDNS metrics, ship a Grafana dashboard,
and load alerting rules. Assumes an existing
[kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)
(Prometheus Operator + Grafana with the dashboard sidecar).

## What's here

| File | Kind | Purpose |
|------|------|---------|
| `servicemonitor.yaml` | `ServiceMonitor` | Tells Prometheus to scrape the app's `/metrics` (port `http`/8080) every 30s. |
| `prometheusrule.yaml` | `PrometheusRule` | 5 alerts: target down, engine stale, update errors, IP-detect failures, Cloudflare API errors. |
| `dashboard-configmap.yaml` | `ConfigMap` | Grafana dashboard (uid `cloudflare-ddns`), auto-imported by the Grafana sidecar. |

## Before you apply — match your stack's labels

These manifests use the **defaults** for a Helm release named `prom`:

- **ServiceMonitor / PrometheusRule selector:** `labels.release: prom`
  — Prometheus only picks up objects carrying the label its
  `serviceMonitorSelector` / `ruleSelector` matches. Find yours:
  ```bash
  kubectl -n monitoring get servicemonitor <any-working-one> -o jsonpath='{.metadata.labels}'
  ```
- **Grafana dashboard sidecar label:** `labels.grafana_dashboard: "1"`
  ```bash
  kubectl -n monitoring get deploy <grafana> \
    -o jsonpath='{.spec.template.spec.containers[?(@.name=="grafana-sc-dashboard")].env}'
  ```
- **Datasource UID:** the dashboard JSON references `uid: prometheus` (the
  kube-prometheus-stack default). If yours differs, find it with:
  ```bash
  kubectl -n monitoring get cm -l grafana_datasource -o yaml | grep -E '^\s+uid:'
  ```
  and replace `"uid": "prometheus"` in `dashboard-configmap.yaml`.

Edit the labels/UID to match your cluster if they differ, then:

```bash
kubectl apply -f k8s/monitoring/
```

## Verify

```bash
# Scrape target should be up
kubectl -n monitoring port-forward svc/<prometheus-svc> 9090:9090 &
curl -s 'http://localhost:9090/api/v1/targets?state=any' | grep cloudflare-ddns

# Grafana sidecar imported the dashboard
kubectl -n monitoring logs deploy/<grafana> -c grafana-sc-dashboard --tail=20 | grep cloudflare-ddns
```

## Metrics reference

Exposed at `/metrics` (Prometheus text format):

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `ddns_app_info` | gauge | `version` | Always 1; build version in label. |
| `ddns_record_updates_total` | counter | `record_type` | Successful DNS record updates. |
| `ddns_record_update_errors_total` | counter | `record_type` | Failed record updates. |
| `ddns_ip_changes_total` | counter | `family` | Public-IP changes (ipv4/ipv6). |
| `ddns_cloudflare_api_requests_total` | counter | `method`, `outcome` | Cloudflare API calls. |
| `ddns_ip_detect_failures_total` | counter | `family` | Public-IP detection failures. |
| `ddns_last_run_timestamp_seconds` | gauge | — | Unix time of last completed engine run. |
| `ddns_current_ip_info` | gauge | `family`, `address` | Always 1; current IP in label. |
| `ddns_managed_records` | gauge | — | Managed DNS records in DB. |
| `ddns_enabled_records` | gauge | — | Records with auto-update on. |
| `ddns_ip_history_entries` | gauge | — | Rows in IP change history. |
| `ddns_discovered_hosts` | gauge | `source` | Discovered hosts by source. |

## Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| `CloudflareDDNSDown` | `up == 0` for 5m | critical |
| `CloudflareDDNSStale` | last run > 15m ago | warning |
| `CloudflareDDNSUpdateErrors` | any update error in 15m | warning |
| `CloudflareDDNSIPDetectFailing` | > 3 IP-detect failures in 15m | warning |
| `CloudflareDDNSCloudflareAPIErrors` | > 5 CF API errors in 15m | warning |
