from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional

class ManagedRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    zone_id: str
    zone_name: str
    record_id: str
    record_name: str
    record_type: str = "A"
    enabled: bool = True
    proxied: bool = True
    ttl: int = 1
    last_ip: Optional[str] = None
    last_updated: Optional[datetime] = None
    source: str = "manual"

class AnnotationTarget(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    namespace: str
    name: str
    kind: str
    dns_name: str
    enabled: bool = True
    last_seen: datetime = Field(default_factory=datetime.utcnow)