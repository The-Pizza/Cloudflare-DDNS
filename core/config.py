from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    cloudflare_api_token: str
    cloudflare_account_id: Optional[str] = None

    poll_interval_seconds: int = 60
    ipv4_endpoint: str = "https://ipinfo.io/ip"
    ipv6_endpoint: str = "https://api6.ipify.org"

    enable_traefik_discovery: bool = True
    enable_annotation_discovery: bool = True

    database_url: str = "sqlite:///./data/cloudflare-ddns.db"

    class Config:
        env_file = ".env"
        env_prefix = "CFDDNS_"

settings = Settings()