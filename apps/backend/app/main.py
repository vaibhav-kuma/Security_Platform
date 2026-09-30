"""FastAPI application factory.

Phase 1 scope: health/readiness endpoints only. Routers for later phases
attach via ``create_app()`` as they are implemented.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # Development-only CORS; tighten origins per environment in later phases.
    if settings.app_env == "development":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(health_router, prefix="/api/health", tags=["health"])
    return app


app = create_app()
