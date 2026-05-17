"""Thin async Cloudflare API client."""
import logging
from typing import Any, Dict, List, Optional

import httpx

from core.config import settings

log = logging.getLogger("cfddns.cf")


class CloudflareError(RuntimeError):
    pass


class CloudflareClient:
    """Async client. Caller is responsible for providing a valid API token."""

    def __init__(self, token: Optional[str] = None, base_url: Optional[str] = None):
        self.token = token or settings.cf_api_token
        self.base_url = (base_url or settings.cf_api_url).rstrip("/")
        if not self.token:
            log.warning("Cloudflare API token is empty; calls will fail.")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
            r = await cli.get(f"{self.base_url}{path}", headers=self._headers(), params=params)
        if r.status_code >= 400:
            raise CloudflareError(f"GET {path} -> {r.status_code}: {r.text}")
        return r.json()

    async def _put(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
            r = await cli.put(f"{self.base_url}{path}", headers=self._headers(), json=body)
        if r.status_code >= 400:
            raise CloudflareError(f"PUT {path} -> {r.status_code}: {r.text}")
        return r.json()

    async def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
            r = await cli.post(f"{self.base_url}{path}", headers=self._headers(), json=body)
        if r.status_code >= 400:
            raise CloudflareError(f"POST {path} -> {r.status_code}: {r.text}")
        return r.json()

    async def _patch(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
            r = await cli.patch(f"{self.base_url}{path}", headers=self._headers(), json=body)
        if r.status_code >= 400:
            raise CloudflareError(f"PATCH {path} -> {r.status_code}: {r.text}")
        return r.json()

    async def _delete(self, path: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as cli:
            r = await cli.delete(f"{self.base_url}{path}", headers=self._headers())
        if r.status_code >= 400:
            raise CloudflareError(f"DELETE {path} -> {r.status_code}: {r.text}")
        return r.json()

    # ---- High-level ----

    async def list_zones(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = await self._get("/zones", params={"per_page": 50, "page": page})
            out.extend(data.get("result", []))
            info = data.get("result_info") or {}
            if page >= info.get("total_pages", page):
                break
            page += 1
        return out

    async def list_dns_records(self, zone_id: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = await self._get(
                f"/zones/{zone_id}/dns_records",
                params={"per_page": 100, "page": page},
            )
            out.extend(data.get("result", []))
            info = data.get("result_info") or {}
            if page >= info.get("total_pages", page):
                break
            page += 1
        return out

    async def update_dns_record(
        self,
        zone_id: str,
        record_id: str,
        name: str,
        ip: str,
        record_type: str = "A",
        proxied: bool = True,
        ttl: int = 1,
    ) -> Dict[str, Any]:
        body = {"type": record_type, "name": name, "content": ip, "proxied": proxied, "ttl": ttl}
        return await self._put(f"/zones/{zone_id}/dns_records/{record_id}", body)

    async def create_dns_record(
        self,
        zone_id: str,
        name: str,
        ip: str,
        record_type: str = "A",
        proxied: bool = True,
        ttl: int = 1,
    ) -> Dict[str, Any]:
        body = {"type": record_type, "name": name, "content": ip, "proxied": proxied, "ttl": ttl}
        return await self._post(f"/zones/{zone_id}/dns_records", body)

    async def patch_dns_record(
        self,
        zone_id: str,
        record_id: str,
        **fields,
    ) -> Dict[str, Any]:
        """Partial update — pass only the fields you want changed (proxied, ttl, name, content, type)."""
        return await self._patch(f"/zones/{zone_id}/dns_records/{record_id}", fields)

    async def delete_dns_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        return await self._delete(f"/zones/{zone_id}/dns_records/{record_id}")
