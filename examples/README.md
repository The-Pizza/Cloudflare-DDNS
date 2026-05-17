# Examples

Drop-in Kubernetes manifests that demonstrate how the Cloudflare DDNS
discovery loop picks up hostnames from your existing workloads.

| File | What it shows |
| --- | --- |
| `annotated-deployment.yaml` | A `Deployment` carrying the `cloudflare-ddns.witschger.home/dns-name` annotation. Annotation discovery only — the workload itself doesn’t even need to expose HTTP. |
| `standard-ingress.yaml` | A vanilla `networking.k8s.io/v1` Ingress. Hosts in `spec.rules[].host` are discovered automatically. |
| `traefik-ingressroute.yaml` | A Traefik `IngressRoute` CRD. Hosts inside `Host(\`…\`)` / `HostRegexp(\`…\`)` matchers are parsed out. |

Apply any of them and refresh the **Discovered** tab in the UI — the
new host should appear within `POLL_INTERVAL_SECONDS` (default 60s).
