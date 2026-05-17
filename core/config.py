"""Application configuration via environment variables.

All settings can be overridden by env vars (no prefix) or a .env file.
Runtime-mutable settings can ALSO be set in the DB via the Settings page,
but the env / ConfigMap value always wins — `env_locked()` reports which
keys are pinned by env so the UI can grey them out.
"""
import logging
import os
from typing import Optional, Set

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- Cloudflare ----
    cf_api_token: str = ""           # CF_API_TOKEN
    cf_api_url: str = "https://api.cloudflare.com/client/v4"

    # ---- DDNS engine ----
    poll_interval_seconds: int = 60
    cf_resync_interval_seconds: int = 3600
    request_timeout_seconds: int = 10
    ipv4_endpoint: str = "https://ipinfo.io/ip"
    ipv6_endpoint: str = ""           # leave blank to disable AAAA
    default_ttl: int = 1
    default_proxied: bool = False

    # ---- Persistence ----
    database_url: str = "sqlite:////app/data/cloudflare-ddns.db"

    # ---- Discovery features ----
    enable_annotation_discovery: bool = True
    enable_traefik_discovery: bool = True
    annotation_key: str = "cloudflare-ddns.witschger.home/dns-name"

    # ---- Legacy: read static records.json on startup, import into DB once ----
    config_path: str = "/etc/config/records.json"
    import_legacy_config: bool = True

    # ---- Auth (advisory — actual enforcement is via reverse-proxy / Authentik forward-auth) ----
    auth_mode: str = "none"           # none | forward-auth

    # ---- HTTP server ----
    log_level: str = "INFO"


settings = Settings()

# Keys exposed/editable on the Settings page. Anything in env wins.
RUNTIME_SETTINGS_KEYS = (
    "cf_api_token",
    "ipv4_endpoint",
    "ipv6_endpoint",
    "poll_interval_seconds",
    "default_proxied",
    "default_ttl",
    "annotation_key",
    "auth_mode",
)


def env_locked() -> Set[str]:
    """Return the runtime-setting keys whose value was provided via env / ConfigMap.

    Env vars are upper-case; we also look at os.environ directly because
    pydantic-settings strips env_file values too.
    """
    locked: Set[str] = set()
    for key in RUNTIME_SETTINGS_KEYS:
        env_name = key.upper()
        if env_name in os.environ and os.environ[env_name] != "":
            locked.add(key)
    return locked


def get_effective(key: str, db_value: Optional[str] = None):
    """Return the active value for a runtime-tunable setting.

    Order: env (already absorbed into `settings`) wins; otherwise DB value;
    otherwise the dataclass default.
    """
    if key in env_locked():
        return getattr(settings, key)
    if db_value is not None and db_value != "":
        # Coerce to the expected type based on the dataclass default
        default = getattr(settings, key)
        if isinstance(default, bool):
            return db_value.lower() in ("1", "true", "yes", "on")
        if isinstance(default, int):
            try:
                return int(db_value)
            except ValueError:
                return default
        return db_value
    return getattr(settings, key)


# Initialise logging once
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
