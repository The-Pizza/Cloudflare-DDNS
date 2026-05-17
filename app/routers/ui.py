"""HTML pages."""
import os

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()

_templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=_templates_dir)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@router.get("/zones/{zone_id}", response_class=HTMLResponse)
async def zone_detail(request: Request, zone_id: str, name: str = ""):
    return templates.TemplateResponse(
        request,
        "zone_records.html",
        {"zone_id": zone_id, "zone_name": name},
    )


@router.get("/discovered", response_class=HTMLResponse)
async def discovered_page(request: Request):
    return templates.TemplateResponse(request, "discovered.html")
