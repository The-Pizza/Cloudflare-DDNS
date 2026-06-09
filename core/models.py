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
    source: str = "manual"          # manual | legacy-config | annotation | ingress | discovered


class DiscoveredHost(SQLModel, table=True):
    """Host names discovered from K8s annotations / Traefik / Ingress.

    Discover-only by default -- the user decides via UI. When the workload
    additionally carries the management annotations (`.../manage: "true"`),
    the discovery loop records the desired record state below and the DDNS
    engine reconciles it into a ManagedRecord automatically (declarative /
    GitOps-style), with no UI click required.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    host: str = Field(index=True)
    source: str = Field(index=True)        # annotation | traefik-ingressroute | ingress
    namespace: str = ""
    resource_name: str = ""
    first_seen: datetime = Field(default_factory=datetime.utcnow)

    # ---- Declarative management intent (Option B) ----
    # When `managed` is True, the engine promotes this host into a ManagedRecord
    # (adopting an existing Cloudflare record or creating one) and then keeps it
    # pointed at the detected public IP. All fields below come from sibling
    # annotations on the SAME workload (see core/config.py management keys).
    managed: bool = Field(default=False, index=True)
    desired_type: str = "A"                       # A | AAAA
    desired_proxied: Optional[bool] = None        # None -> fall back to default_proxied
    desired_ttl: Optional[int] = None             # None -> fall back to default_ttl
    desired_content: Optional[str] = None         # None -> track detected public IP
    # Set once the host has been reconciled into a ManagedRecord, so we don't
    # repeatedly try to create/adopt the same record every loop.
    managed_record_id: Optional[str] = Field(default=None, index=True)
    last_reconcile_error: Optional[str] = None


class Setting(SQLModel, table=True):
    """Runtime-mutable configuration, settable via the Settings page.

    Values here only take effect if the corresponding env var is NOT set
    (env / ConfigMap always wins, so operators retain authority).
    """
    key: str = Field(primary_key=True)
    value: str = ""
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class IpHistoryEntry(SQLModel, table=True):
    """One row per detected public-IP transition. The engine appends a row
    whenever `current_ip` changes (including the very first detection)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    previous_ip: Optional[str] = None      # None on the very first observation
    new_ip: str
    changed_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    note: str = ""                         # e.g. "boot", "ip-change", "manual-verify"
