# Kubernetes manifests

Apply in directory order (filenames are numbered):

```bash
kubectl apply -f k8s/
```

| File | Resource | Notes |
| --- | --- | --- |
| `00-namespace.yaml` | Namespace | `cloudflare-ddns` |
| `10-rbac.yaml` | ServiceAccount + ClusterRole + ClusterRoleBinding | List/watch on Services, Deployments, Ingresses, Traefik IngressRoutes. |
| `20-pvc.yaml` | PVC | 256Mi RWO for SQLite state. Adjust `storageClassName` to your env. |
| `30-deployment.yaml` | Deployment | Single replica, `Recreate` strategy. Pins the image tag; Keel can roll within the same minor. |
| `40-service.yaml` | Service | ClusterIP on port 8080. |
| `50-ingress.yaml` | Ingress | `traefik-internal` class + cert-manager `localca` annotation. Adjust hostname for your env. |

## Prerequisites

1. **Cloudflare API token** with `Zone:Read` and `DNS:Edit`:
   ```bash
   kubectl -n cloudflare-ddns create secret generic cloudflare-ddns-secret \
     --from-literal=CF_API_TOKEN=cfut_xxx
   ```
2. **Internal DNS record** `ddns.<your-domain>` pointing at your
   internal Traefik LoadBalancer IP.
3. **cert-manager** with a ClusterIssuer (default expected name:
   `localca`). Change the annotation in `50-ingress.yaml` if you use a
   different issuer.

## Optional

- **Legacy `records.json`**: If you bring forward a ConfigMap named
  `cloudflare-ddns-config` with a `records.json` key, the app imports it
  into the database on first boot (one-shot).
- **Settings overrides**: If you create a ConfigMap named
  `cloudflare-ddns-settings`, it’s pulled in via `envFrom` so you can
  override any env var without editing the Deployment.
