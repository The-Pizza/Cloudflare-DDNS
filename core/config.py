"""Application configuration via environment variables.

All settings can be overridden by env vars (no prefix) or a .env file.
"""
import logging
from typing import Optional

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

    # ---- HTTP server ----
    log_level: str = "INFO"


settings = Settings()

# Initialise logging once
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
