"""SQLModel database tables."""
from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class ManagedRecord(SQLModel, table=True):
    """A Cloudflare DNS record we are actively keeping up-to-date with the public IP."""
    id: Optional[int] = Field(default=None, primary_key=True)
    zone_id: str = Field(index=True)
    zone_name: str
    record_id: str = Field(index=True, unique=True)
    record_name: str = Field(index=True)
    record_type: str = "A"
    enabled: bool = True
    proxied: bool = True
    ttl: int = 1
    last_ip: Optional[str] = None
    last_updated: Optional[datetime] = None
    source: str = "manual"          # manual | legacy-config | annotation | ingress


class DiscoveredHost(SQLModel, table=True):
    """Host names discovered from K8s annotations / Traefik / Ingress.
    Not necessarily managed -- user decides via UI."""
    id: Optional[int] = Field(default=None, primary_key=True)
    host: str = Field(index=True)
    source: str = Field(index=True)        # annotation | traefik-ingressroute | ingress
    namespace: str = ""
    resource_name: str = ""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
