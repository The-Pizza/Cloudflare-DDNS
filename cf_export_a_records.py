#!/usr/bin/env python3
import json
import sys
import getpass
import requests
from typing import Dict, List, Optional, Tuple

CF_API_URL_DEFAULT = "https://api.cloudflare.com/client/v4"

def prompt_credentials() -> Tuple[str, Dict[str, str]]:
    print("Cloudflare credentials\n"
          "1) API Token (recommended)\n"
          "2) Global API Key + Email (legacy)")
    choice = input("Select auth method [1/2] (default 1): ").strip() or "1"

    headers = {"Content-Type": "application/json"}
    base_url = input(f"Cloudflare API base URL [{CF_API_URL_DEFAULT}]: ").strip() or CF_API_URL_DEFAULT

    if choice == "2":
        email = input("Cloudflare account email: ").strip()
        api_key = getpass.getpass("Global API Key: ").strip()
        if not email or not api_key:
            print("Email and Global API Key are required.", file=sys.stderr)
            sys.exit(1)
        headers.update({
            "X-Auth-Email": email,
            "X-Auth-Key": api_key,
        })
    else:
        token = getpass.getpass("API Token: ").strip()
        if not token:
            print("API Token is required.", file=sys.stderr)
            sys.exit(1)
        headers["Authorization"] = f"Bearer {token}"

    return base_url.rstrip("/"), headers


def cf_handle(resp: requests.Response, action: str) -> dict:
    if resp.status_code == 429:
        ra = resp.headers.get("Retry-After", "unknown")
        raise RuntimeError(f"Rate limited during {action} (HTTP 429). Retry-After={ra}. Body={resp.text}")
    if not resp.ok:
        raise RuntimeError(f"HTTP error during {action}: status={resp.status_code} body={resp.text}")
    data = resp.json()
    if not data.get("success", False):
        raise RuntimeError(f"Cloudflare error during {action}: {data.get('errors')}")
    return data


def list_zones(base_url: str, headers: Dict[str, str]) -> Dict[str, str]:
    zones: Dict[str, str] = {}
    page, per_page = 1, 50
    while True:
        r = requests.get(f"{base_url}/zones", headers=headers, params={"page": page, "per_page": per_page}, timeout=15)
        data = cf_handle(r, "list zones")
        for z in data.get("result", []):
            zones[z["name"].lower()] = z["id"]
        info = data.get("result_info") or {}
        if page >= (info.get("total_pages") or 1):
            break
        page += 1
    return zones


def list_a_records(base_url: str, headers: Dict[str, str], zone_id: str) -> List[dict]:
    records: List[dict] = []
    page, per_page = 1, 100
    while True:
        r = requests.get(
            f"{base_url}/zones/{zone_id}/dns_records",
            headers=headers,
            params={"type": "A", "page": page, "per_page": per_page},
            timeout=15,
        )
        data = cf_handle(r, f"list A records for zone {zone_id}")
        records.extend(data.get("result", []))
        info = data.get("result_info") or {}
        if page >= (info.get("total_pages") or 1):
            break
        page += 1
    return records


def to_config_items(zone_name: str, recs: List[dict]) -> List[dict]:
    """
    Convert Cloudflare A records to your records.json schema.
    - If record is inside the zone, set {"name": <relative_or_zone>, "zone": <zone>, "type":"A", ...}
      * apex: name == zone_name
      * sub:  name == "host" (without the zone tail)
    - If record name is not under the zone (rare), omit zone and keep full FQDN in name.
    - Include 'proxied' always; include 'ttl' only when meaningful (non-proxied or explicitly set).
    """
    out: List[dict] = []
    z = zone_name.lower().rstrip(".")
    for r in recs:
        fqdn = r.get("name", "").rstrip(".")
        proxied = bool(r.get("proxied", False))
        ttl = int(r.get("ttl", 300))

        item: Dict[str, object] = {"type": "A", "proxied": proxied}

        if fqdn.lower() == z:
            # apex
            item["name"] = zone_name  # keep zone in name; loader will accept with zone and treat as apex
            item["zone"] = zone_name
        elif fqdn.lower().endswith("." + z):
            # sub within zone -> use relative label
            label = fqdn[:-(len(z) + 1)]
            item["name"] = label
            item["zone"] = zone_name
        else:
            # out-of-zone FQDN (fallback)
            item["name"] = fqdn

        # TTL rules for your updater:
        # - When proxied=True Cloudflare forces TTL=1; your updater also forces ttl=1 when proxied.
        #   We can omit TTL in that case (matches your sample).
        # - Otherwise include the ttl we saw (including 1 if user had "auto" and not proxied).
        if not proxied:
            item["ttl"] = ttl

        out.append(item)
    return out


def main():
    base_url, headers = prompt_credentials()

    try:
        zones = list_zones(base_url, headers)
    except Exception as e:
        print(f"Failed to list zones: {e}", file=sys.stderr)
        sys.exit(1)

    if not zones:
        print("No zones found in this Cloudflare account.", file=sys.stderr)
        sys.exit(2)

    all_items: List[dict] = []
    for zname, zid in sorted(zones.items()):
        try:
            a_records = list_a_records(base_url, headers, zid)
        except Exception as e:
            print(f"[WARN] Skipping zone {zname}: {e}", file=sys.stderr)
            continue
        if not a_records:
            continue
        items = to_config_items(zname, a_records)
        all_items.extend(items)

    if not all_items:
        print("No A records found in any zone.", file=sys.stderr)
        sys.exit(3)

    # Sort for readability: by zone (if present), then name
    def sort_key(d: dict) -> Tuple[str, str]:
        zone = (d.get("zone") or "").lower()
        name = str(d.get("name") or "").lower()
        return (zone, name)

    all_items.sort(key=sort_key)

    # Ask where to write
    out_path = input("Output path for records.json [./records.json]: ").strip() or "./records.json"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(all_items, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to write {out_path}: {e}", file=sys.stderr)
        sys.exit(4)

    print(f"Wrote {len(all_items)} A records to {out_path}")
    print("You can now run your updater with CONFIG_PATH set to this file (IPv4-only; AAAA disabled).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCanceled by user.")
        sys.exit(130)
