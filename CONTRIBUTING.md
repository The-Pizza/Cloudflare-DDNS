# Contributing

Thanks for your interest! This is a small focused project — keep PRs
focused too.

## Dev loop

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export CF_API_TOKEN=cfut_xxx
uvicorn app.main:app --reload --port 8080
```

The web UI is at `http://127.0.0.1:8080`, OpenAPI at `/docs`.

## Code style

* Black-compatible formatting (4-space indent, double quotes).
* Type hints encouraged on public functions.
* Async on the request path; sync helpers OK in background threads.
* Log via `logging.getLogger("cfddns.<subsystem>")`, never `print` in
  production code paths.

## Project layout

```
app/                  # FastAPI app
  main.py             # FastAPI() + lifespan + router wiring
  routers/            # Thin HTTP handlers
  templates/          # Jinja2 HTML (base + per-page)
  static/             # Tailwind only (CDN) -- no bundler
core/                 # Domain logic, reusable from anywhere
  cloudflare_client.py
  ddns_engine.py
  annotation_watcher.py
  traefik_watcher.py
  models.py / database.py / config.py
k8s/                  # Numbered for apply-in-order via `kubectl apply -f k8s/`
.github/workflows/    # Release-triggered GHCR build
```

## Releases

1. Update version in `app/main.py` (`FastAPI(version=…)`).
2. Commit, push to `main`.
3. Create a GitHub Release with tag `vMAJOR.MINOR.PATCH`.
4. The `release-image` workflow builds and pushes
   `ghcr.io/the-pizza/cloudflare-ddns:<MAJOR.MINOR.PATCH>` + `:latest`.

Tag names start with `v` (e.g. `v0.3.0`); image tags do **not** carry the
`v` (e.g. `0.3.0`) — that’s `docker/metadata-action`’s semver pattern at
work, intentional and matches `keel.sh/policy: minor` expectations.

## Testing

There is no automated test suite yet (PRs welcome). For now, manual
smoke tests:

* `uvicorn app.main:app --reload`
* Hit `/health/live`, `/api/zones`, `/api/status` with `curl`.
* Toggle a record in the UI; verify the corresponding Cloudflare record
  was updated.

## Filing issues

Use the issue templates in `.github/ISSUE_TEMPLATE/`. Include:

* App version (`/api/status` shows it, or look at the image tag).
* Pod logs (`kubectl logs -n cloudflare-ddns -l app.kubernetes.io/name=cloudflare-ddns`).
* The relevant manifest snippet if it’s a deployment issue.
