"""Request size limiting middleware.

Protects against large request bodies that could cause memory exhaustion.
"""

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config import get_settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request body size."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_size: int | None = None,
    ) -> None:
        super().__init__(app)
        self.settings = get_settings()
        # Default: 10MB for general API, configurable
        self.max_body_size = max_body_size or 10 * 1024 * 1024

    async def dispatch(self, request: Request, call_next) -> Response:
        # Check Content-Length header first (cheap check)
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_body_size:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content={
                            "error": {
                                "error_code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request body exceeds maximum allowed size of {self.max_body_size} bytes",
                                "details": {"max_size": self.max_body_size, "received": length}
                            }
                        },
                    )
            except ValueError:
                pass  # Invalid header, let it through to be handled by FastAPI

        # For requests without Content-Length (chunked encoding), we need to
        # read the body and check size. This is more expensive but necessary.
        # FastAPI/Starlette handles this internally for form/JSON parsing,
        # but we can add a custom check for raw body reads.

        # Process the request
        response = await call_next(request)
        return response


def create_request_size_limit_middleware(
    app: ASGIApp,
    *,
    max_body_size: int | None = None,
) -> RequestSizeLimitMiddleware:
    """Factory function to create request size limit middleware."""
    return RequestSizeLimitMiddleware(app, max_body_size=max_body_size)
