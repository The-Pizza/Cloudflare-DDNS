import asyncio
import httpx
from datetime import datetime
from core.cloudflare_client import CloudflareClient
from core.config import settings
from core.database import get_session
from core.models import ManagedRecord

class DDNSEngine:
    def __init__(self):
        self.cf = CloudflareClient()
        self.current_ip = None

    async def get_current_ip(self) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.get(settings.ipv4_endpoint, timeout=10)
            return resp.text.strip()

    async def run_once(self):
        try:
            new_ip = await self.get_current_ip()
            if new_ip == self.current_ip:
                return

            print(f"IP changed: {self.current_ip} -> {new_ip}")
            self.current_ip = new_ip

            session = get_session()
            records = session.query(ManagedRecord).filter(ManagedRecord.enabled == True).all()

            for record in records:
                if record.last_ip == new_ip:
                    continue
                try:
                    await self.cf.update_dns_record(
                        record.zone_id, record.record_id, record.record_name,
                        new_ip, record.record_type, record.proxied, record.ttl
                    )
                    record.last_ip = new_ip
                    record.last_updated = datetime.utcnow()
                    session.commit()
                    print(f"Updated {record.record_name}")
                except Exception as e:
                    print(f"Update failed for {record.record_name}: {e}")

        except Exception as e:
            print(f"DDNS error: {e}")

    async def start_background_task(self):
        while True:
            await self.run_once()
            await asyncio.sleep(settings.poll_interval_seconds)