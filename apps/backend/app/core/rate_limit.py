"""Rate limiting configuration using slowapi."""

from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings


P = ParamSpec("P")
R = TypeVar("R")


def get_client_identifier(request: Request) -> str:
    """Get client identifier for rate limiting.

    Uses X-Forwarded-For header only if request comes from a trusted proxy,
    otherwise falls back to client host. Caches trusted proxy check per process.
    """
    settings = get_settings()
    trusted_proxies = getattr(settings, "trusted_proxies", [])
    
    # Cache trusted proxy check (trusted_proxies rarely changes)
    # Use a function attribute for simple caching
    if not hasattr(get_client_identifier, "_trusted_proxy_cache"):
        get_client_identifier._trusted_proxy_cache = set(trusted_proxies)
    elif get_client_identifier._trusted_proxy_cache != set(trusted_proxies):
        get_client_identifier._trusted_proxy_cache = set(trusted_proxies)
    
    # Check if request comes from a trusted proxy
    client_host = get_remote_address(request)
    if trusted_proxies and client_host in get_client_identifier._trusted_proxy_cache:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return client_host


def create_limiter(storage_uri: str | None = None, testing: bool = False) -> Limiter:
    """Create rate limiter instance with settings."""
    settings = get_settings()
    uri = storage_uri or settings.redis_url
    if testing:
        uri = "memory://"
    return Limiter(
        key_func=get_client_identifier,
        default_limits=[f"{settings.rate_limit_requests_per_minute}/minute"],
        storage_uri=uri,
    )


# Global limiter instance (created lazily)
_limiter: Limiter | None = None


def get_limiter() -> Limiter:
    """Get or create the rate limiter singleton."""
    global _limiter
    if _limiter is None:
        _limiter = create_limiter()
    return _limiter


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Custom handler for rate limit exceeded."""
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "error_code": "RATE_LIMITED",
                "message": f"Rate limit exceeded: {exc.detail}",
                "details": {"retry_after": exc.retry_after}
            }
        },
    )


def init_rate_limiter(app: FastAPI) -> None:
    """Initialize rate limiter on FastAPI app."""
    settings = get_settings()
    # Only use in-memory storage in test environment (APP_ENV=test)
    # Never use in-memory in development or production
    testing = settings.app_env == "test"
    limiter = create_limiter(testing=testing)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


# Decorators for common rate limit tiers
def _create_rate_limit_decorator(limit: str, testing: bool = False) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Create a rate limit decorator with proper testing support."""
    if testing:
        def no_op_decorator(func: Callable[P, R]) -> Callable[P, R]:
            return func
        return no_op_decorator
    return get_limiter().limit(limit)  # type: ignore[return-value]


def auth_rate_limit() -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Strict rate limit for auth endpoints (5 requests/minute)."""
    settings = get_settings()
    return _create_rate_limit_decorator(
        f"{settings.rate_limit_auth_requests_per_minute}/minute",
        testing=settings.app_env == "test"
    )


def api_rate_limit() -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Standard rate limit for API endpoints (60 requests/minute)."""
    settings = get_settings()
    return _create_rate_limit_decorator(
        f"{settings.rate_limit_requests_per_minute}/minute",
        testing=settings.app_env == "test"
    )


def strict_rate_limit() -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Very strict rate limit (10 requests/minute)."""
    settings = get_settings()
    return _create_rate_limit_decorator(
        "10/minute",
        testing=settings.app_env == "test"
    )
