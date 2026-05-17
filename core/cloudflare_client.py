import httpx
from typing import List, Dict, Any
from core.config import settings

class CloudflareClient:
    def __init__(self):
        self.token = settings.cloudflare_api_token
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    async def list_zones(self) -> List[Dict[str, Any]]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/zones", headers=self.headers)
            resp.raise_for_status()
            return resp.json()["result"]

    async def list_dns_records(self, zone_id: str) -> List[Dict[str, Any]]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.base_url}/zones/{zone_id}/dns_records", headers=self.headers)
            resp.raise_for_status()
            return resp.json()["result"]

    async def update_dns_record(self, zone_id: str, record_id: str, name: str, ip: str, record_type: str = "A", proxied: bool = True, ttl: int = 1):
        data = {"type": record_type, "name": name, "content": ip, "ttl": ttl, "proxied": proxied}
        async with httpx.AsyncClient() as client:
            resp = await client.put(f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}", headers=self.headers, json=data)
            resp.raise_for_status()
            return resp.json()