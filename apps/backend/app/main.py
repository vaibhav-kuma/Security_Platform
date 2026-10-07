"""FastAPI application factory.

Phase 1 scope: health/readiness endpoints only. Routers for later phases
attach via ``create_app()`` as they are implemented.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.api.v1 import api_router as v1_router
from app.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging
from app.core.rate_limit import init_rate_limiter
from app.core.request_size_limit import RequestSizeLimitMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.websocket import scan_websocket_endpoint


def create_app() -> FastAPI:
    settings = get_settings()

    # Setup logging early
    setup_logging(level="DEBUG" if settings.debug else "INFO", json_format=settings.app_env == "production")

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # Security headers middleware (should be added early)
    app.add_middleware(SecurityHeadersMiddleware)

    # Request size limit middleware (should be added early, before body parsing)
    app.add_middleware(RequestSizeLimitMiddleware)

    # Development-only CORS; tighten origins per environment in later phases.
    if settings.app_env == "development":
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000"],
            allow_methods=["*"],
            allow_headers=["*"],
            allow_credentials=True,
        )
    else:
        # Production CORS - configurable via environment
        # In production, origins MUST be explicitly configured
        cors_origins = settings.cors_origins
        if not cors_origins:
            raise RuntimeError(
                "CORS_ORIGINS must be set in production (APP_ENV != development). "
                "Set CORS_ORIGINS to a comma-separated list of allowed origins."
            )
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["*"],
            allow_credentials=True,
        )

    # Register exception handlers for structured error responses
    register_exception_handlers(app)

    # Initialize rate limiter
    init_rate_limiter(app)

    app.include_router(health_router, prefix="/api/health", tags=["health"])
    app.include_router(v1_router, tags=["v1"])

    # WebSocket endpoint for real-time scan events
    app.websocket("/ws/scans/{scan_id}")(scan_websocket_endpoint)

    return app


app = create_app()
