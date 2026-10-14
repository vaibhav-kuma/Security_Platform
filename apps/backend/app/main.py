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
from app.core.metrics import PrometheusMetricsMiddleware, metrics_endpoint
from app.core.rate_limit import init_rate_limiter
from app.core.request_size_limit import RequestSizeLimitMiddleware
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.tracing import init_tracing
from app.core.websocket import scan_websocket_endpoint


def create_app() -> FastAPI:
    settings = get_settings()

    # Setup logging early
    setup_logging(
        level=settings.log_level,
        json_format=settings.log_json_format,
    )

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

    # Prometheus metrics middleware
    if settings.prometheus_metrics_enabled:
        app.add_middleware(PrometheusMetricsMiddleware)

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

    # Initialize OpenTelemetry tracing
    if settings.tracing_enabled:
        tracer = init_tracing(
            service_name="sasp-backend",
            service_version=settings.app_version,
            otlp_endpoint=settings.otlp_endpoint,
            use_console_exporter=settings.app_env == "development",
        )
        # Store tracer in app state for access in routes
        app.state.tracer = tracer

    app.include_router(health_router, prefix="/api/health", tags=["health"])
    app.include_router(v1_router, tags=["v1"])

    # Prometheus metrics endpoint
    if settings.prometheus_metrics_enabled:
        from starlette.responses import Response
        from starlette.requests import Request
        
        async def metrics_route(request: Request) -> Response:
            return metrics_endpoint()
        
        app.add_route("/api/metrics", metrics_route, methods=["GET"])

    # WebSocket endpoint for real-time scan events
    app.websocket("/ws/scans/{scan_id}")(scan_websocket_endpoint)

    # Instrument libraries after app creation
    if settings.tracing_enabled:
        # Note: engine and celery_app will be instrumented when they're created
        pass

    return app


app = create_app()
