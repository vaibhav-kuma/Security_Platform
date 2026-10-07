"""Structured error handling and exception classes.

All API errors follow a consistent format with:
- error_code: stable machine-readable code (e.g., TARGET_OUT_OF_SCOPE)
- message: human-readable description
- details: optional structured context for debugging/clients
"""

from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Structured error detail."""

    error_code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    """Standard error response envelope."""

    error: ErrorDetail


# ---- Base exception ---------------------------------------------------------


class AppException(HTTPException):
    """Base application exception with structured error detail."""

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=ErrorDetail(
            error_code=error_code,
            message=message,
            details=details,
        ).model_dump())


# ---- Common error codes -----------------------------------------------------


class NotFoundError(AppException):
    """Resource not found."""

    def __init__(self, resource: str, identifier: str | None = None, details: dict[str, Any] | None = None):
        msg = f"{resource} not found"
        if identifier:
            msg += f": {identifier}"
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="NOT_FOUND",
            message=msg,
            details=details,
        )


class ValidationError(AppException):
    """Request validation failed."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR",
            message=message,
            details=details,
        )


class UnauthorizedError(AppException):
    """Authentication required or invalid."""

    def __init__(self, message: str = "Authentication required", details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="UNAUTHORIZED",
            message=message,
            details=details,
        )


class ForbiddenError(AppException):
    """Access denied to resource."""

    def __init__(self, message: str = "Access denied", details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="FORBIDDEN",
            message=message,
            details=details,
        )


class ConflictError(AppException):
    """Resource conflict (e.g., duplicate unique field)."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            error_code="CONFLICT",
            message=message,
            details=details,
        )


class ScopeViolationError(AppException):
    """Attempted access to out-of-scope target."""

    def __init__(self, target: str, details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="TARGET_OUT_OF_SCOPE",
            message=f"Target {target} is outside the authorized scope",
            details=details,
        )


class RateLimitError(AppException):
    """Rate limit exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE_LIMITED",
            message=message,
            details=details,
        )


class InternalError(AppException):
    """Unexpected server error."""

    def __init__(self, message: str = "Internal server error", details: dict[str, Any] | None = None):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="INTERNAL_ERROR",
            message=message,
            details=details,
        )


# ---- Exception handlers -----------------------------------------------------


async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """Convert AppException to structured JSON response."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=ErrorDetail(**exc.detail)).model_dump(),
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Convert generic HTTPException to structured format."""
    if isinstance(exc.detail, dict) and "error_code" in exc.detail:
        # Already structured
        return JSONResponse(status_code=exc.status_code, content=ErrorResponse(error=ErrorDetail(**exc.detail)).model_dump())

    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=ErrorDetail(
                error_code="HTTP_ERROR",
                message=str(exc.detail),
                details=None,
            )
        ).model_dump(),
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle Pydantic validation errors."""
    from pydantic import ValidationError as PydanticValidationError

    if isinstance(exc, PydanticValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error=ErrorDetail(
                    error_code="VALIDATION_ERROR",
                    message="Request validation failed",
                    details={"errors": exc.errors()},
                )
            ).model_dump(),
        )
    # Fallback
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error=ErrorDetail(
                error_code="INTERNAL_ERROR",
                message="Validation error handling failed",
            )
        ).model_dump(),
    )


def register_exception_handlers(app: "FastAPI") -> None:
    """Register all exception handlers on the FastAPI app."""

    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    # Pydantic ValidationError is caught by FastAPI's default handler but we can override
    # app.add_exception_handler(PydanticValidationError, validation_exception_handler)
