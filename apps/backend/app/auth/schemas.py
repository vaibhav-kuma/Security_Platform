"""Pydantic schemas for authentication API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    """Login credentials."""

    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]


class RegisterRequest(BaseModel):
    """Registration request for initial org/user setup."""

    email: EmailStr
    password: Annotated[str, Field(min_length=8, max_length=128)]
    full_name: Annotated[str, Field(min_length=1, max_length=255)]
    organization_name: Annotated[str, Field(min_length=1, max_length=255)]


class TokenResponse(BaseModel):
    """Token response (access in body, refresh in httpOnly cookie)."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105 - This is OAuth2 standard, not a password
    expires_in: int
    user: "UserResponse"


class RefreshRequest(BaseModel):
    """Refresh token request (empty body; token comes from cookie)."""

    pass


class UserResponse(BaseModel):
    """Public user information."""

    id: UUID
    email: str
    full_name: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationResponse(BaseModel):
    """Public organization information."""

    id: UUID
    name: str
    description: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuthStatusResponse(BaseModel):
    """Current authentication status."""

    authenticated: bool
    user: UserResponse | None = None
    organization: OrganizationResponse | None = None


# Update forward references
TokenResponse.model_rebuild()
