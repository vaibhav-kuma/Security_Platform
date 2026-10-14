"""Security headers middleware for FastAPI.

Adds standard security headers to all responses:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS) - production only
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cache-Control for sensitive endpoints
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        csp_policy: str | None = None,
        hsts_max_age: int = 31536000,  # 1 year
        include_subdomains: bool = True,
        preload: bool = True,
    ) -> None:
        super().__init__(app)
        self.settings = get_settings()
        self.csp_policy = csp_policy or self._default_csp_policy()
        self.hsts_max_age = hsts_max_age
        self.include_subdomains = include_subdomains
        self.preload = preload

    def _default_csp_policy(self) -> str:
        """Default CSP policy for the API.
        
        Restrictive policy for API endpoints - no inline scripts/styles,
        no external resources except self.
        """
        # For API, we don't serve HTML, so CSP is mainly for defense-in-depth
        # If frontend is served from same origin, adjust accordingly
        return (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint handles sensitive data (auth, tokens, etc.)."""
        sensitive_paths = [
            "/api/v1/auth/",
            "/auth/",
            "/login",
            "/register",
            "/refresh",
            "/logout",
            "/password",
            "/token",
            "/me",
        ]
        return any(path.startswith(p) for p in sensitive_paths)

    def _build_hsts_header(self) -> str:
        """Build HSTS header value."""
        parts = [f"max-age={self.hsts_max_age}"]
        if self.include_subdomains:
            parts.append("includeSubDomains")
        if self.preload:
            parts.append("preload")
        return "; ".join(parts)

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Content-Security-Policy
        response.headers["Content-Security-Policy"] = self.csp_policy

        # X-Frame-Options - prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # X-Content-Type-Options - prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer-Policy - limit referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy - restrict browser features
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), "
            "camera=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "payment=(), "
            "usb=()"
        )

        # HSTS - only in production and for HTTPS
        if self.settings.app_env == "production":
            # Only add HSTS if we're on HTTPS (or behind a proxy that terminates TLS)
            # The proxy should set X-Forwarded-Proto
            forwarded_proto = request.headers.get("X-Forwarded-Proto")
            is_https = (
                request.url.scheme == "https"
                or forwarded_proto == "https"
            )
            if is_https:
                response.headers["Strict-Transport-Security"] = self._build_hsts_header()

        # Cache-Control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response


def create_security_headers_middleware(
    app: ASGIApp,
    *,
    csp_policy: str | None = None,
    hsts_max_age: int = 31536000,
    include_subdomains: bool = True,
    preload: bool = True,
) -> SecurityHeadersMiddleware:
    """Factory function to create security headers middleware with custom options."""
    return SecurityHeadersMiddleware(
        app,
        csp_policy=csp_policy,
        hsts_max_age=hsts_max_age,
        include_subdomains=include_subdomains,
        preload=preload,
    )
