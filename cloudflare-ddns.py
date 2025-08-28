import os
import sys
import json
import time
import logging
import ipaddress
import requests
from typing import Dict, List, Optional, Tuple

# ----------------------------
# Configuration via environment
# ----------------------------
CF_API_URL = os.environ.get("CF_API_URL", "https://api.cloudflare.com/client/v4")
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")  # Preferred
CF_API_KEY = os.environ.get("CF_API_KEY")      # Global API key (legacy)
CF_API_EMAIL = os.environ.get("CF_API_EMAIL")  # Required if using CF_API_KEY

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/etc/config/records.json")
IP_POLL_INTERVAL_SECONDS = int(os.environ.get("IP_POLL_INTERVAL_SECONDS", "60"))
CONFIG_RELOAD_INTERVAL_SECONDS = int(os.environ.get("CONFIG_RELOAD_INTERVAL_SECONDS", "300"))
CF_RESYNC_INTERVAL_SECONDS = int(os.environ.get("CF_RESYNC_INTERVAL_SECONDS", "3600"))
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "10"))

# IPv4 endpoint only
IPV4_ENDPOINT = os.environ.get("IPV4_ENDPOINT", "https://ipinfo.io/ip")

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Defaults for records (overridable per-record in the file)
DEFAULT_TTL = int(os.environ.get("DEFAULT_TTL", "300"))      # 1 means "auto" in Cloudflare; otherwise seconds
DEFAULT_PROXIED = os.environ.get("DEFAULT_PROXIED", "false").lower() in ("1", "true", "yes")

# ----------------------------
# Logging setup
# ----------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("cf-updater")


# ----------------------------
# Cloudflare API client
# ----------------------------
class CloudflareClient:
    def __init__(self, api_url: str, api_token: Optional[str], api_key: Optional[str], api_email: Optional[str]):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        if api_token:
            self.session.headers.update({"Authorization": f"Bearer {api_token}"})
        elif api_key and api_email:
            # Legacy auth; not recommended, but supported here
            self.session.headers.update({
                "X-Auth-Email": api_email,
                "X-Auth-Key": api_key,
            })
        else:
            raise ValueError("Cloudflare credentials missing. Provide CF_API_TOKEN or CF_API_KEY + CF_API_EMAIL.")
        self.zones_cache: Dict[str, str] = {}  # zone_name -> zone_id

    def _handle_response(self, resp: requests.Response, action: str) -> dict:
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "unknown")
            raise RuntimeError(f"Rate limited by Cloudflare during {action}; HTTP 429. Retry-After={retry}. Body={resp.text}")
        if not resp.ok:
            raise RuntimeError(f"HTTP error during {action}: status={resp.status_code} body={resp.text}")
        data = resp.json()
        if not data.get("success", False):
            errors = data.get("errors", [])
            raise RuntimeError(f"Cloudflare error during {action}: errors={errors} body={resp.text}")
        return data

    def refresh_zones(self) -> Dict[str, str]:
        logger.debug("Refreshing Cloudflare zones list")
        zones: Dict[str, str] = {}
        page = 1
        per_page = 50
        while True:
            url = f"{self.api_url}/zones"
            params = {"page": page, "per_page": per_page}
            resp = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
            data = self._handle_response(resp, "list zones")
            for z in data.get("result", []):
                zones[z["name"].lower()] = z["id"]
            result_info = data.get("result_info") or {}
            total_pages = result_info.get("total_pages") or 1
            if page >= total_pages:
                break
            page += 1
        self.zones_cache = zones
        logger.debug("Zones loaded: %s", ", ".join(sorted(zones.keys())) if zones else "(none)")
        return zones

    def get_dns_record(self, zone_id: str, name: str, rtype: str) -> Optional[dict]:
        url = f"{self.api_url}/zones/{zone_id}/dns_records"
        params = {"type": rtype.upper(), "name": name}
        resp = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        data = self._handle_response(resp, f"get dns record {name} {rtype}")
        results = data.get("result", [])
        if not results:
            return None
        return results[0]

    def create_dns_record(self, zone_id: str, name: str, rtype: str, content: str, ttl: int, proxied: bool) -> dict:
        url = f"{self.api_url}/zones/{zone_id}/dns_records"
        payload = {"type": rtype.upper(), "name": name, "content": content, "ttl": ttl, "proxied": proxied}
        resp = self.session.post(url, data=json.dumps(payload), timeout=REQUEST_TIMEOUT_SECONDS)
        data = self._handle_response(resp, f"create dns record {name} {rtype}")
        return data["result"]

    def update_dns_record(self, zone_id: str, record_id: str, name: str, rtype: str, content: str, ttl: int, proxied: bool) -> dict:
        url = f"{self.api_url}/zones/{zone_id}/dns_records/{record_id}"
        payload = {"type": rtype.upper(), "name": name, "content": content, "ttl": ttl, "proxied": proxied}
        resp = self.session.patch(url, data=json.dumps(payload), timeout=REQUEST_TIMEOUT_SECONDS)
        data = self._handle_response(resp, f"update dns record {name} {rtype}")
        return data["result"]


# ----------------------------
# Config handling
# ----------------------------
class ConfigError(Exception):
    pass


def load_config(path: str) -> Tuple[List[dict], str]:
    """
    Load and validate the JSON config file.
    Returns (records_list, raw_text).
    Exits on JSON parse error with line number as required.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        logger.error("Config file not found at %s", path)
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to read config file %s: %s", path, e)
        sys.exit(1)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("JSON parse error in %s at line %d column %d: %s", path, e.lineno, e.colno, e.msg)
        try:
            offending_line = raw.splitlines()[e.lineno - 1]
            logger.error("Offending line %d: %s", e.lineno, offending_line)
        except Exception:
            pass
        sys.exit(1)

    if not isinstance(data, list):
        logger.error("Config must be a JSON array of record objects. Top-level type is: %s", type(data).__name__)
        sys.exit(1)

    # Validate records
    # Each item must have: name (str), type ('A')
    # Optional: ttl (int), proxied (bool), zone (str)
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            line_hint = find_item_line_hint(raw, idx, None)
            logger.error("Record at index %d is not an object (line ~%s).", idx, line_hint or "?")
            sys.exit(1)
        name = item.get("name")
        rtype = item.get("type")
        if not isinstance(name, str) or not name:
            line_hint = find_item_line_hint(raw, idx, "name")
            logger.error("Record %d missing/invalid 'name' (line ~%s).", idx, line_hint or "?")
            sys.exit(1)
        if rtype != "A":
            line_hint = find_item_line_hint(raw, idx, "type", name)
            logger.error("Record %d ('%s') has invalid 'type' '%s' (IPv6/AAAA disabled). Only 'A' is allowed (line ~%s).",
                         idx, name, rtype, line_hint or "?")
            sys.exit(1)
        ttl = item.get("ttl", DEFAULT_TTL)
        if not isinstance(ttl, int) or ttl < 1:
            line_hint = find_item_line_hint(raw, idx, "ttl", name)
            logger.error("Record %d ('%s') has invalid 'ttl' (must be positive int) (line ~%s).", idx, name, line_hint or "?")
            sys.exit(1)
        proxied = item.get("proxied", DEFAULT_PROXIED)
        if not isinstance(proxied, bool):
            line_hint = find_item_line_hint(raw, idx, "proxied", name)
            logger.error("Record %d ('%s') has invalid 'proxied' (must be boolean) (line ~%s).", idx, name, line_hint or "?")
            sys.exit(1)
        zone = item.get("zone")
        if zone is not None and not isinstance(zone, str):
            line_hint = find_item_line_hint(raw, idx, "zone", name)
            logger.error("Record %d ('%s') has invalid 'zone' (must be string) (line ~%s).", idx, name, line_hint or "?")
            sys.exit(1)

    return data, raw


def find_item_line_hint(raw_text: str, index: int, key: Optional[str], name_value: Optional[str] = None) -> Optional[int]:
    """
    Best-effort line number hint for schema errors by searching for the index-th object and key or name value.
    This is approximate, but gives a line number.
    """
    lines = raw_text.splitlines()
    if name_value:
        needle = f'"name": "{name_value}"'
        for i, line in enumerate(lines, start=1):
            if needle in line:
                return i
    count = 0
    for i, line in enumerate(lines, start=1):
        count += line.count("{")
        if count >= index + 1:
            return i
    return None


# ----------------------------
# Utility helpers
# ----------------------------
def best_zone_for_name(zones_by_name: Dict[str, str], fqdn: str) -> Optional[Tuple[str, str]]:
    """
    Find the longest matching zone for a given FQDN.
    Returns (zone_name, zone_id) or None.
    """
    fqdn_l = fqdn.lower().rstrip(".")
    best = None
    for zname, zid in zones_by_name.items():
        if fqdn_l == zname or fqdn_l.endswith("." + zname):
            if best is None or len(zname) > len(best[0]):
                best = (zname, zid)
    return best


def normalize_name(name: str, zone: Optional[str]) -> str:
    """
    If zone is provided and name isn't FQDN, append zone.
    """
    n = name.rstrip(".")
    if zone:
        z = zone.rstrip(".")
        if n.lower() == z.lower() or n.lower().endswith("." + z.lower()):
            return n
        return f"{n}.{z}"
    return n


def fetch_public_ipv4(endpoint: str) -> Optional[str]:
    """
    Fetch the public IPv4 from endpoint.
    Returns None on HTTP/parse error or if the result isn't IPv4.
    """
    try:
        resp = requests.get(endpoint, timeout=REQUEST_TIMEOUT_SECONDS)
        if resp.status_code != 200:
            logger.warning("IPv4 endpoint returned %d: %s", resp.status_code, resp.text)
            return None

        text = resp.text.strip()
        if not text:
            logger.warning("Empty response from %s", endpoint)
            return None

        ip_str = text.split()[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning("Invalid IP format from %s: '%s'", endpoint, text)
            return None

        if ip_obj.version != 4:
            logger.warning("Received non-IPv4 address '%s' from %s; ignoring.", ip_str, endpoint)
            return None

        return ip_str

    except requests.RequestException as e:
        logger.warning("IPv4 endpoint unreachable: %s", e)
        return None
    except Exception as e:
        logger.warning("Unexpected error fetching public IPv4: %s", e)
        return None


# ----------------------------
# Main control loop
# ----------------------------
def main():
    # Validate credentials early
    try:
        cf = CloudflareClient(CF_API_URL, CF_API_TOKEN, CF_API_KEY, CF_API_EMAIL)
    except Exception as e:
        logger.error("Cloudflare credentials error: %s", e)
        sys.exit(1)

    logger.info("Starting Cloudflare DNS updater (IPv4-only; AAAA disabled)")
    logger.info("Config path: %s", CONFIG_PATH)

    records_cfg, raw_cfg = load_config(CONFIG_PATH)
    logger.info("Loaded %d records from config", len(records_cfg))

    # Next run trackers
    now = time.monotonic()
    next_config_reload = now + CONFIG_RELOAD_INTERVAL_SECONDS
    next_cf_resync = now  # do an immediate resync to validate CF and block IP fetch until OK
    next_ip_poll = now    # but will be skipped until CF OK

    # State
    cf_ok = False
    zones_by_name: Dict[str, str] = {}
    # local CF cache: key (name,'A') -> dict(record_id, content, ttl, proxied, zone_id)
    cf_cache: Dict[Tuple[str, str], dict] = {}
    current_ipv4: Optional[str] = None

    while True:
        loop_start = time.monotonic()

        # 1) Reload config periodically
        if loop_start >= next_config_reload:
            try:
                records_cfg, raw_cfg = load_config(CONFIG_PATH)
                logger.debug("Reloaded config: %d records", len(records_cfg))
                next_cf_resync = loop_start
            except SystemExit:
                raise
            except Exception as e:
                logger.error("Unexpected error reloading config: %s", e)
            next_config_reload = loop_start + CONFIG_RELOAD_INTERVAL_SECONDS

        # 2) Cloudflare resync (and credential check)
        if loop_start >= next_cf_resync:
            try:
                zones_by_name = cf.refresh_zones()
                # Build/update cf_cache for all configured A records
                new_cache: Dict[Tuple[str, str], dict] = {}
                for rec in records_cfg:
                    name = rec["name"]
                    rtype = rec["type"].upper()  # already validated == 'A'
                    proxied = rec.get("proxied", DEFAULT_PROXIED)
                    ttl = 1 if proxied else rec.get("ttl", DEFAULT_TTL)
                    zone_hint = rec.get("zone")

                    fqdn = normalize_name(name, zone_hint)
                    zone_sel = best_zone_for_name(zones_by_name, fqdn) if not zone_hint else (zone_hint.lower(), zones_by_name.get(zone_hint.lower()))
                    if not zone_sel or not zone_sel[1]:
                        logger.error("No matching Cloudflare zone found for record '%s' (type %s). Ensure zone exists and is in this account.", fqdn, rtype)
                        continue
                    zone_name, zone_id = zone_sel

                    try:
                        record = cf.get_dns_record(zone_id, fqdn, rtype)
                        if record:
                            new_cache[(fqdn, rtype)] = {
                                "record_id": record["id"],
                                "content": record["content"],
                                "ttl": record.get("ttl", ttl),
                                "proxied": record.get("proxied", proxied),
                                "zone_id": zone_id,
                                "zone_name": zone_name,
                            }
                        else:
                            new_cache[(fqdn, rtype)] = {
                                "record_id": None,
                                "content": None,
                                "ttl": ttl,
                                "proxied": proxied,
                                "zone_id": zone_id,
                                "zone_name": zone_name,
                            }
                    except Exception as e:
                        raise RuntimeError(f"Failed to query record {fqdn} {rtype}: {e}")
                
                # --- Diff vs previous cache and log any changes at INFO ---
                # Treat missing cf_cache as empty on first run
                prev_cache: Dict[Tuple[str, str], dict] = cf_cache or {}

                # 1) New or changed entries
                for key, new in new_cache.items():
                    old = prev_cache.get(key)
                    fqdn, rtype = key
                    if not old:
                        # Newly discovered since last resync
                        if new["record_id"] and new["content"] is not None:
                            logger.info("Discovered DNS %s %s now exists: %s (ttl=%s, proxied=%s) in zone %s",
                                        fqdn, rtype, new['content'], new['ttl'], new['proxied'], new['zone_name'])
                        else:
                            logger.info("DNS %s %s not present in Cloudflare (will be created on reconcile) in zone %s",
                                        fqdn, rtype, new['zone_name'])
                        continue

                    # Compare fields for changes
                    changes = []
                    for field in ("content", "ttl", "proxied", "record_id", "zone_id"):
                        if old.get(field) != new.get(field):
                            changes.append((field, old.get(field), new.get(field)))
                    if changes:
                        # Summarize most important changes first
                        # Prefer content/ttl/proxied in the log line; include others compactly
                        content_change = next(((o, n) for f, o, n in changes if f == "content"), None)
                        ttl_change = next(((o, n) for f, o, n in changes if f == "ttl"), None)
                        proxied_change = next(((o, n) for f, o, n in changes if f == "proxied"), None)
                        extra = [(f, o, n) for f, o, n in changes if f not in ("content","ttl","proxied")]
                        msg_bits = []
                        if content_change: msg_bits.append(f"content {content_change[0]} -> {content_change[1]}")
                        if ttl_change:     msg_bits.append(f"ttl {ttl_change[0]} -> {ttl_change[1]}")
                        if proxied_change: msg_bits.append(f"proxied {proxied_change[0]} -> {proxied_change[1]}")
                        for f, o, n in extra:
                            msg_bits.append(f"{f} {o} -> {n}")
                        logger.info("DNS %s %s changed: %s (zone %s)", fqdn, rtype, "; ".join(msg_bits), new["zone_name"])

                # 2) Removed entries (present before, absent now)
                removed_keys = set(prev_cache.keys()) - set(new_cache.keys())
                for fqdn, rtype in removed_keys:
                    old = prev_cache[(fqdn, rtype)]
                    logger.info("DNS %s %s disappeared from Cloudflare (was %s, ttl=%s, proxied=%s) in zone %s",
                                fqdn, rtype, old.get('content'), old.get('ttl'), old.get('proxied'), old.get('zone_name'))

                # Replace cache after diff/logging
                cf_cache = new_cache
                cf_ok = True
                logger.debug("Cloudflare resync complete. Cached %d entries.", len(cf_cache))
            except Exception as e:
                logger.error("Cloudflare resync/login failed: %s", e)
                cf_ok = False
            finally:
                next_cf_resync = loop_start + CF_RESYNC_INTERVAL_SECONDS

        # 3) IP polling (only if CF is OK)
        if cf_ok and loop_start >= next_ip_poll:
            v4 = fetch_public_ipv4(IPV4_ENDPOINT)
            if v4 is None:
                logger.warning("Public IPv4 not available this cycle; skipping record reconciliation.")
            else:
                if current_ipv4 != v4:
                    logger.info("Public IPv4 changed: %s -> %s", current_ipv4 or "(none)", v4)
                else:
                    logger.debug("Public IPv4 unchanged: %s", v4)
                current_ipv4 = v4
            next_ip_poll = loop_start + IP_POLL_INTERVAL_SECONDS

        # 4) Reconcile desired state (only if CF OK and we have current IPv4)
        if cf_ok and cf_cache and records_cfg and current_ipv4:
            for rec in records_cfg:
                rtype = "A"  # enforced
                name = rec["name"]
                proxied = rec.get("proxied", DEFAULT_PROXIED)
                ttl = 1 if proxied else rec.get("ttl", DEFAULT_TTL)
                zone_hint = rec.get("zone")
                fqdn = normalize_name(name, zone_hint)

                cache_key = (fqdn, rtype)
                entry = cf_cache.get(cache_key)
                if not entry:
                    logger.debug("No cache entry for %s %s (zone missing or not in account).", fqdn, rtype)
                    continue

                zone_id = entry["zone_id"]
                record_id = entry["record_id"]
                current_content = entry["content"]

                try:
                    if record_id is None:
                        created = cf.create_dns_record(zone_id, fqdn, rtype, current_ipv4, ttl, proxied)
                        cf_cache[cache_key] = {
                            "record_id": created["id"],
                            "content": created["content"],
                            "ttl": created.get("ttl", ttl),
                            "proxied": created.get("proxied", proxied),
                            "zone_id": zone_id,
                            "zone_name": entry.get("zone_name"),
                        }
                        logger.info("Created DNS %s %s -> %s (ttl=%s proxied=%s)", rtype, fqdn, current_ipv4, ttl, proxied)
                    else:
                        if current_content != current_ipv4 or entry.get("ttl") != ttl or entry.get("proxied") != proxied:
                            updated = cf.update_dns_record(zone_id, record_id, fqdn, rtype, current_ipv4, ttl, proxied)
                            entry.update({
                                "content": updated["content"],
                                "ttl": updated.get("ttl", ttl),
                                "proxied": updated.get("proxied", proxied),
                            })
                            logger.info("Updated DNS %s %s: %s -> %s (ttl=%s proxied=%s)", rtype, fqdn, current_content, current_ipv4, ttl, proxied)
                        else:
                            logger.debug("No change for %s %s; current=%s", rtype, fqdn, current_content)
                except Exception as e:
                    msg = str(e)
                    logger.error("Cloudflare update error for %s %s: %s", rtype, fqdn, msg)
                    if "401" in msg or "403" in msg or "authentication" in msg.lower() or "unauthorized" in msg.lower():
                        cf_ok = False
                        logger.error("Marking Cloudflare status as not OK due to authentication/authorization error.")

        # Sleep until next polling event
        now = time.monotonic()
        deadlines = [next_config_reload, next_cf_resync]
        if cf_ok:
            deadlines.append(next_ip_poll)
        time.sleep(max(0.1, min(d - now for d in deadlines)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted; exiting.")
        sys.exit(0)
