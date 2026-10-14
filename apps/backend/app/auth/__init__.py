"""Auth package exports."""

from app.auth.dependencies import (
    get_current_user,
    get_current_user_optional,
    get_refresh_token,
    require_organization_member,
    require_project_member,
)
from app.auth.password import hash_password, verify_password
from app.auth.router import router as auth_router
from app.auth.schemas import (
    AuthStatusResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.auth.token import (
    TokenPair,
    TokenPayload,
    create_access_token,
    create_refresh_token,
    create_token_pair,
    decode_token,
    validate_access_token,
    validate_refresh_token,
)

__all__ = [
    "AuthStatusResponse",
    "LoginRequest",
    "RegisterRequest",
    "TokenPair",
    "TokenPayload",
    "TokenResponse",
    "UserResponse",
    "auth_router",
    "create_access_token",
    "create_refresh_token",
    "create_token_pair",
    "decode_token",
    "get_current_user",
    "get_current_user_optional",
    "get_refresh_token",
    "hash_password",
    "require_organization_member",
    "require_project_member",
    "validate_access_token",
    "validate_refresh_token",
    "verify_password",
]
