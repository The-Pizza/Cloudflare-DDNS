from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "title": "Cloudflare DDNS"})

@router.get("/zones/{zone_id}", response_class=HTMLResponse)
async def zone_records(request: Request, zone_id: str, name: str):
    return templates.TemplateResponse("zone_records.html", {"request": request, "zone_id": zone_id, "zone_name": name})