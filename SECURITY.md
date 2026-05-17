# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security reports.

Email the maintainer directly (see the GitHub profile of the repository
owner) or use [GitHub's private vulnerability reporting](https://github.com/The-Pizza/Cloudflare-DDNS/security/advisories/new).

Expected response: acknowledgement within 7 days, fix or mitigation
within 30 days for confirmed issues.

## Scope

Issues considered in-scope:

- Authentication / authorisation bypass on the web UI or API
- Cloudflare API token leakage from logs, error responses, or state
  endpoints
- Container escapes from the image as shipped
- Kubernetes RBAC over-privileging from the manifests in `k8s/`

Out of scope:

- Misconfiguration (wrong RBAC for your cluster, exposed ingress, etc.)
- Issues in upstream dependencies — please report those upstream first
