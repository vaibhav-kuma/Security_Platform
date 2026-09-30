"""Health and readiness endpoints."""

from fastapi import APIRouter

from app.config import get_settings

router = APIRouter()


@router.get("")
async def health() -> dict[str, str]:
    settings = get_settings()
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}


@router.get("/ready")
async def ready() -> dict[str, str]:
    return {"status": "ready"}
