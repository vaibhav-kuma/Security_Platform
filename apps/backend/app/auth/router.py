"""Authentication API router (login, register, refresh, logout, status)."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user_optional, get_refresh_token
from app.auth.password import hash_password, verify_password
from app.auth.schemas import (
    AuthStatusResponse,
    LoginRequest,
    OrganizationResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.auth.token import TokenPair, create_token_pair
from app.config import get_settings
from app.core.rate_limit import auth_rate_limit
from app.db.seed import seed_system_rbac
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.enums import SecurityEventType
from app.models.identity import Organization, Role, RoleScope, User, UserRole

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@auth_rate_limit()
def register(
    request: RegisterRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    """Register a new organization and owner user.

    Creates an organization with the requesting user as owner (system 'owner' role).
    Only available when no organizations exist (bootstrap) or for authorized admins.
    """
    # Check if this is bootstrap (no orgs exist yet)
    existing_org = db.query(Organization).first()
    if existing_org:
        # In production, this would require admin authorization
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration not allowed; contact administrator",
        )

    # Create organization
    org = Organization(name=request.organization_name)
    db.add(org)
    db.flush()

    # Create user
    user = User(
        email=request.email,
        full_name=request.full_name,
        password_hash=hash_password(request.password),
    )
    db.add(user)
    db.flush()

    # Assign system owner role to user
    seed_system_rbac(db)  # ensures system roles exist

    owner_role = db.query(Role).filter(
        Role.name == "owner", Role.scope == RoleScope.SYSTEM
    ).first()
    if owner_role:
        user_role = UserRole(user_id=user.id, role_id=owner_role.id)
        db.add(user_role)

    db.commit()
    db.refresh(user)
    db.refresh(org)

    # Audit log
    audit = AuditLog(
        actor_id=user.id,
        action=SecurityEventType.AUTH_REGISTER.value,
        entity_type="organization",
        entity_id=org.id,
        details={"organization_id": str(org.id)},
    )
    db.add(audit)
    db.commit()

    # Create tokens
    tokens = create_token_pair(user_id=str(user.id), email=user.email, org_id=str(org.id))
    _set_auth_cookies(response, tokens)

    return TokenResponse(
        access_token=tokens.access_token,
        expires_in=tokens.expires_in,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=TokenResponse)
@auth_rate_limit()
def login(
    request: LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    """Authenticate user and return access + refresh tokens."""
    user = db.query(User).filter(User.email == request.email).first()

    if not user or not user.password_hash or not verify_password(
        request.password, user.password_hash
    ):
        # Audit failed login
        audit = AuditLog(
            actor_id=user.id if user else None,
            action=SecurityEventType.AUTH_LOGIN.value,
            entity_type="user",
            entity_id=user.id if user else None,
            details={"email": request.email, "success": False},
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Update last login
    user.last_login_at = datetime.now(UTC)
    db.commit()

    # Audit successful login
    audit = AuditLog(
        actor_id=user.id,
        action=SecurityEventType.AUTH_LOGIN.value,
        entity_type="user",
        entity_id=user.id,
        details={"success": True},
    )
    db.add(audit)
    db.commit()

    # Determine user's primary organization (first org role)
    org_role = db.query(UserRole).filter(
        UserRole.user_id == user.id,
        UserRole.organization_id.isnot(None),
    ).first()
    org_id = str(org_role.organization_id) if org_role else None

    tokens = create_token_pair(user_id=str(user.id), email=user.email, org_id=org_id)
    _set_auth_cookies(response, tokens)

    return TokenResponse(
        access_token=tokens.access_token,
        expires_in=tokens.expires_in,
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenResponse)
@auth_rate_limit()
def refresh(
    request: Request,
    response: Response,
    payload: Annotated[dict, Depends(get_refresh_token)],
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    """Rotate refresh token and issue new access token.

    Secure rotation: revoke old token BEFORE creating new one.
    """
    user_id = payload["sub"]
    email = payload["email"]
    org_id = payload.get("org_id")
    refresh_jti = payload.get("jti")  # This is the refresh token's JTI
    refresh_exp = payload.get("exp")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Revoke the old refresh token FIRST (secure rotation)
    if refresh_jti and refresh_exp:
        from app.auth.token import revoke_refresh_token_and_create_new
        tokens = revoke_refresh_token_and_create_new(
            old_refresh_jti=refresh_jti,
            old_refresh_exp=refresh_exp,
            user_id=user_id,
            email=email,
            org_id=org_id,
        )
    else:
        # Fallback if token doesn't have JTI/exp (shouldn't happen)
        from app.auth.token import create_token_pair
        tokens = create_token_pair(user_id=user_id, email=email, org_id=org_id)
    _set_auth_cookies(response, tokens)

    # Audit token refresh
    audit = AuditLog(
        actor_id=UUID(user_id),
        action=SecurityEventType.AUTH_TOKEN_REFRESH.value,
        entity_type="user",
        entity_id=UUID(user_id),
        details={},
    )
    db.add(audit)
    db.commit()

    return TokenResponse(
        access_token=tokens.access_token,
        expires_in=tokens.expires_in,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    current_user: Annotated[User | None, Depends(get_current_user_optional)],
    db: Annotated[Session, Depends(get_db)],
    # Get tokens from cookies to revoke them
    access_token: Annotated[str | None, Cookie(alias="access_token")] = None,
    refresh_token: Annotated[str | None, Cookie(alias="refresh_token")] = None,
) -> None:
    """Clear auth cookies and invalidate refresh token."""
    settings = get_settings()
    secure = settings.cookie_secure
    # Audit logout
    if current_user:
        audit = AuditLog(
            actor_id=current_user.id,
            action=SecurityEventType.AUTH_LOGOUT.value,
            entity_type="user",
            entity_id=current_user.id,
            details={},
        )
        db.add(audit)
        db.commit()

    # Revoke tokens if present
    if access_token or refresh_token:
        from app.auth.token import decode_token, revoke_token_pair
        try:
            if access_token:
                access_payload = decode_token(access_token)
            else:
                access_payload = None
            if refresh_token:
                refresh_payload = decode_token(refresh_token)
            else:
                refresh_payload = None

            if access_payload and refresh_payload:
                revoke_token_pair(
                    access_payload.jti, access_payload.exp,
                    refresh_payload.jti, refresh_payload.exp
                )
            elif access_payload:
                from app.auth.token import revoke_access_token
                revoke_access_token(access_payload.jti, access_payload.exp)
            elif refresh_payload:
                from app.auth.token import revoke_refresh_token
                revoke_refresh_token(refresh_payload.jti, refresh_payload.exp)
        except ValueError:
            # Token already invalid/expired, ignore
            pass

    response.delete_cookie(
        "access_token", path="/", httponly=True, secure=secure, samesite="lax"
    )
    response.delete_cookie(
        "refresh_token", path="/", httponly=True, secure=secure, samesite="strict"
    )


@router.get("/me", response_model=AuthStatusResponse)
def me(
    current_user: Annotated[User | None, Depends(get_current_user_optional)],
    db: Annotated[Session, Depends(get_db)],
) -> AuthStatusResponse:
    """Return current authentication status and user info."""
    if not current_user:
        return AuthStatusResponse(authenticated=False)

    # Get user's organization
    org_role = db.query(UserRole).filter(
        UserRole.user_id == current_user.id,
        UserRole.organization_id.isnot(None),
    ).first()

    org = None
    if org_role:
        org = db.query(Organization).filter(Organization.id == org_role.organization_id).first()

    return AuthStatusResponse(
        authenticated=True,
        user=UserResponse.model_validate(current_user),
        organization=org and OrganizationResponse.model_validate(org),
    )


def _set_auth_cookies(response: Response, tokens: TokenPair) -> None:
    """Set httpOnly auth cookies."""
    settings = get_settings()
    # Use secure cookies in production; allow non-secure in development
    # In development with HTTPS (mkcert), set COOKIE_SECURE=true
    secure = settings.cookie_secure if settings.app_env == "production" else False

    response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=tokens.expires_in,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        httponly=True,
        secure=secure,
        samesite="strict",  # stricter for refresh token
        max_age=60 * 60 * 24 * 7,  # 7 days
        path="/",
    )
