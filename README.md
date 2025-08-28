# Cloudflare Dynamic DNS Updater (IPv4-only)

A lightweight service that keeps **Cloudflare DNS A records** updated with your current public IPv4 address.  
It polls a configurable endpoint (default: `ipinfo.io`), compares the current IP against Cloudflare, and creates or updates DNS records as needed.

Works with **Cloudflare API Tokens** (recommended) or legacy **Global API Key + email**.

---

## Features

- Updates **A (IPv4)** records based on your current public IP.
- **IPv6/AAAA support has been removed** for reliability in Kubernetes environments.
- Creates records if they don’t exist.
- Optional per-record overrides for TTL and “proxied” (orange-cloud) status.
- Longest-suffix zone matching when zone is not provided in the config.
- Auto-reloads configuration from a JSON file on a timer.
- Only runs IP checks after a successful Cloudflare auth/resync.
- Graceful handling of Cloudflare API errors and public IP endpoints.
- Lightweight: Python with `requests` and standard library.

---

## Bootstrapper: Initial Config Generator

A helper script, [`cf_export_a_records.py`](./cf_export_a_records.py), can bootstrap your config by pulling **all existing A records** from your Cloudflare account and writing them into a `records.json` file.

Usage:

```bash
python cf_export_a_records.py
```

You’ll be prompted for your Cloudflare API token (or legacy API key/email).  
It will then:

- List all zones available to your credentials.
- Extract all existing **A records**.
- Write them into a `records.json` file compatible with the updater.

This provides a quick starting point to customize before running the updater.

---

## Configuration file

The config is a JSON array of record objects at `CONFIG_PATH` (default: `/etc/config/records.json`).  
Each object:

- `name` (string, required) – record name (relative or FQDN)
- `type` (string, required) – must be `"A"` (IPv4-only)
- `ttl` (int, optional) – seconds; `1` means “auto” in Cloudflare; defaults to `DEFAULT_TTL`
- `proxied` (bool, optional) – Cloudflare proxy (orange cloud) on/off; defaults to `DEFAULT_PROXIED`
- `zone` (string, optional) – the zone name (e.g., `example.com`). If omitted, the app picks the best matching zone by longest suffix.

Example `records.json`:

```json
[
  {
    "name": "home",
    "zone": "example.com",
    "type": "A",
    "ttl": 300,
    "proxied": false
  },
  {
    "name": "vpn.example.net",
    "type": "A",
    "proxied": true
  }
]
```

Notes:
- Booleans must be `true`/`false` (not `"true"`/`"false"`).
- If `name` is not an FQDN but `zone` is specified, the code normalizes it by appending the zone.
- The app exits on JSON parse errors and logs the offending line number.

---

## Environment variables

- `CF_API_TOKEN` – Cloudflare API Token (preferred)
- `CF_API_KEY` – Cloudflare Global API Key (legacy)
- `CF_API_EMAIL` – Cloudflare account email (required if using CF_API_KEY)
- `CF_API_URL` – Cloudflare API base URL (default: https://api.cloudflare.com/client/v4)
- `CONFIG_PATH` – Path to records JSON (default: /etc/config/records.json)
- `IP_POLL_INTERVAL_SECONDS` – Interval to poll IP endpoints (default: 60)
- `CF_RESYNC_INTERVAL_SECONDS` – Interval to resync Cloudflare zones/cache (default: 3600)
- `REQUEST_TIMEOUT_SECONDS` – HTTP timeout for requests (default: 10)
- `IPV4_ENDPOINT` – IPv4 endpoint to detect public IP (default: https://ipinfo.io/ip)
- `LOG_LEVEL` – logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) (default: INFO)
- `DEFAULT_TTL` – default TTL for records unless overridden (default: 300; `1` means auto)
- `DEFAULT_PROXIED` – default proxied flag unless overridden (default: false)

---

## Requirements

- Python 3.8+
- Dependencies listed in [`requirements.txt`](./requirements.txt)

Install manually:

```bash
pip install -r requirements.txt
```

---

## Running locally

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Export your Cloudflare API token:

   ```bash
   export CF_API_TOKEN=your_token_here
   ```

3. Create or bootstrap a config file:

   ```bash
   python cf_export_a_records.py
   ```

   This generates `records.json`, which you can edit if needed.

4. Run:

   ```bash
   python cloudflare-ddns.py
   ```

Logs will show zone discovery, record cache status, current IPs, and create/update actions.

---

## Docker

The project ships with a Dockerfile that installs dependencies via `requirements.txt`.

Build:

```bash
docker build -t cf-dns-updater:latest .
```

Run (mount your config read-only and pass credentials):

```bash
docker run --rm   -e CF_API_TOKEN=your_token_here   -v $(pwd)/records.json:/etc/config/records.json:ro   cf-dns-updater:latest
```

Example `docker-compose.yml`:

```yaml
services:
  cf-dns-updater:
    image: cf-dns-updater:latest
    environment:
      - CF_API_TOKEN=${CF_API_TOKEN}
      - LOG_LEVEL=INFO
    volumes:
      - ./records.json:/etc/config/records.json:ro
    restart: unless-stopped
```

---

## Cloudflare API token setup

1. Go to Cloudflare Dashboard → My Profile → API Tokens → Create Custom Token.
2. Permissions:
   - Zone → Read
   - DNS → Edit
3. Zone Resources: restrict to the specific zones you intend to manage (recommended) or All zones (broader).
4. Copy the token and set it as `CF_API_TOKEN`.

The updater lists zones available to the token and picks the best matching zone for each record by suffix. If a zone is missing or the token lacks access, the log will show an error and skip that record.

---

## Development Notes

- IPv6/AAAA support has been removed. The updater only manages IPv4 A records.
- [`requirements.txt`](./requirements.txt) defines Python dependencies for local runs and the Docker image.
- [`cf_export_a_records.py`](./cf_export_a_records.py) bootstraps your `records.json` config.
- [`cloudflare-ddns.py`](./cloudflare-ddns.py) is the main updater service.
- Dockerfile uses Python 3.12 slim with a non-root user.

---

## License

Add a license file (e.g., MIT, Apache-2.0) appropriate for your project.
