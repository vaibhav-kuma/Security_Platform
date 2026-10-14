"""JWT token handling for authentication.

Access tokens are short-lived (15 min); refresh tokens are long-lived (7 days)
and rotated on each use. Both are HS256-signed JWTs stored only in httpOnly
cookies — never in localStorage or Authorization headers — to mitigate XSS.
"""

import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import redis
from jose import JWTError, jwt
from pydantic import BaseModel

from app.auth.blacklist import get_token_blacklist
from app.config import get_settings


class TokenPayload(BaseModel):
    """Decoded JWT payload."""

    sub: str  # user_id as string
    email: str
    org_id: str | None = None
    exp: int
    iat: int
    type: str  # "access" | "refresh"
    jti: str  # unique token ID for revocation
    kid: str | None = None  # Key ID for key rotation


class TokenPair(BaseModel):
    """Access + refresh token pair returned on login/refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - This is OAuth2 standard, not a password
    expires_in: int  # access token TTL in seconds


# ---- Key management for rotation -------------------------------------------

_REDIS_KEY_PREFIX = "jwt:signing_key:"
_KEY_LOCK_PREFIX = "jwt:key_lock:"


def _get_redis_client() -> redis.Redis:
    """Get Redis client for key storage."""
    settings = get_settings()
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)


def _acquire_key_lock(client: redis.Redis, lock_name: str, timeout: int = 10) -> bool:
    """Acquire a distributed lock for key operations.

    Args:
        client: Redis client
        lock_name: Lock identifier
        timeout: Lock timeout in seconds

    Returns:
        True if lock acquired, False otherwise
    """
    lock_key = f"{_KEY_LOCK_PREFIX}{lock_name}"
    # Use SET NX EX for atomic lock acquisition
    return client.set(lock_key, "1", nx=True, ex=timeout)


def _release_key_lock(client: redis.Redis, lock_name: str) -> None:
    """Release a distributed lock."""
    lock_key = f"{_KEY_LOCK_PREFIX}{lock_name}"
    client.delete(lock_key)


def _get_current_key() -> tuple[str, int]:
    """Get current signing key and its version from Redis.

    Uses distributed lock for multi-process safety.

    Raises:
        RuntimeError: If Redis is unavailable or no key exists.
    """
    settings = get_settings()
    client = _get_redis_client()

    # Get current key version from Redis
    version_key = f"{_REDIS_KEY_PREFIX}current_version"
    version_str = client.get(version_key)

    if version_str is None:
        # No key exists yet - initialize with secret_key using distributed lock
        lock_acquired = _acquire_key_lock(client, "init")
        if not lock_acquired:
            # Another process is initializing, wait and retry
            time.sleep(0.1)
            version_str = client.get(version_key)
            if version_str is None:
                raise RuntimeError("Failed to initialize signing key - concurrent initialization")
            version = int(version_str)
        else:
            try:
                # Double-check after acquiring lock
                version_str = client.get(version_key)
                if version_str is None:
                    # Initialize first key
                    client.set(f"{_REDIS_KEY_PREFIX}1", settings.secret_key)
                    client.set(version_key, "1")
                    return settings.secret_key, 1
                version = int(version_str)
            finally:
                _release_key_lock(client, "init")
    else:
        version = int(version_str)

    # Get the actual key
    key = client.get(f"{_REDIS_KEY_PREFIX}{version}")
    if key is None:
        raise RuntimeError(f"Signing key version {version} not found in Redis")

    return key, version


def _get_key_for_verification(kid: str | None) -> str:
    """Get key for verifying a token by kid from Redis.

    Validates kid format strictly to prevent key confusion attacks.

    Raises:
        RuntimeError: If key version not found in Redis or kid is invalid.
    """
    if kid is None:
        # Legacy token without kid - get current key
        key, _ = _get_current_key()
        return key

    # Strict validation: kid must be a positive integer (key version)
    try:
        version = int(kid)
        if version <= 0:
            raise ValueError("Key version must be positive")
    except ValueError as e:
        raise RuntimeError(f"Invalid key ID format: {kid}") from e

    client = _get_redis_client()
    key = client.get(f"{_REDIS_KEY_PREFIX}{version}")

    if key is None:
        raise RuntimeError(f"Signing key version {version} not found in Redis")

    return key


def rotate_signing_key() -> int:
    """Rotate to a new signing key. Returns new key version.

    This operation is atomic using Redis WATCH/MULTI/EXEC with distributed lock for multi-process safety.
    """
    client = _get_redis_client()

    # Acquire distributed lock for rotation
    lock_acquired = _acquire_key_lock(client, "rotate", timeout=30)
    if not lock_acquired:
        raise RuntimeError("Could not acquire key rotation lock - another rotation in progress")

    try:
        while True:
            try:
                with client.pipeline() as pipe:
                    # Watch the current version key
                    pipe.watch(f"{_REDIS_KEY_PREFIX}current_version")

                    current_version_str = pipe.get(f"{_REDIS_KEY_PREFIX}current_version")
                    current_version = int(current_version_str) if current_version_str else 0
                    new_version = current_version + 1

                    new_key = secrets.token_urlsafe(64)

                    # Atomic update
                    pipe.multi()
                    pipe.set(f"{_REDIS_KEY_PREFIX}{new_version}", new_key)
                    pipe.set(f"{_REDIS_KEY_PREFIX}current_version", str(new_version))
                    pipe.execute()

                    return new_version

            except redis.WatchError:
                # Another client modified the key, retry
                continue
            except Exception:
                import logging

                logging.getLogger(__name__).warning("Failed to persist signing key to Redis")
                raise
    finally:
        _release_key_lock(client, "rotate")


# ---- Token creation ---------------------------------------------------------


def create_access_token(
    *,
    user_id: str,
    email: str,
    org_id: str | None = None,
) -> str:
    """Create a short-lived access token."""
    settings = get_settings()
    key, kid = _get_current_key()
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "email": email,
        "org_id": org_id,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "type": "access",
        "jti": _generate_jti(),
        "kid": str(kid),
    }
    # Include kid in header for proper key lookup during validation
    headers = {"kid": str(kid)}
    return jwt.encode(payload, key, algorithm=settings.algorithm, headers=headers)


def create_refresh_token(
    *,
    user_id: str,
    email: str,
    org_id: str | None = None,
) -> str:
    """Create a long-lived refresh token."""
    settings = get_settings()
    key, kid = _get_current_key()
    now = datetime.now(UTC)
    expire = now + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": user_id,
        "email": email,
        "org_id": org_id,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "type": "refresh",
        "jti": _generate_jti(),
        "kid": str(kid),
    }
    # Include kid in header for proper key lookup during validation
    headers = {"kid": str(kid)}
    return jwt.encode(payload, key, algorithm=settings.algorithm, headers=headers)


def create_token_pair(
    *,
    user_id: str,
    email: str,
    org_id: str | None = None,
) -> TokenPair:
    """Create both access and refresh tokens."""
    settings = get_settings()
    access = create_access_token(user_id=user_id, email=email, org_id=org_id)
    refresh = create_refresh_token(user_id=user_id, email=email, org_id=org_id)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


# ---- Token validation -------------------------------------------------------


def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT, raising on any failure."""
    settings = get_settings()
    try:
        # First decode header only (without verification) to get kid
        # Using get_unverified_header() instead of get_unverified_claims()
        # to prevent algorithm confusion attacks where a malicious token
        # could have a crafted 'kid' pointing to an arbitrary key
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # Explicitly reject "none" algorithm
        if unverified_header.get("alg") == "none":
            raise ValueError("Algorithm 'none' not allowed")

        # Validate kid format before using it
        if kid is not None:
            try:
                version = int(kid)
                if version <= 0:
                    raise ValueError("Key version must be positive")
            except ValueError as e:
                raise ValueError(f"Invalid key ID format: {kid}") from e

        key = _get_key_for_verification(kid)

        # Explicitly validate algorithm - only allow configured algorithm
        # This prevents algorithm confusion attacks
        allowed_algorithms = [settings.algorithm]
        payload = jwt.decode(token, key, algorithms=allowed_algorithms)
        return TokenPayload(**payload)
    except JWTError as exc:
        raise ValueError("Invalid or expired token") from exc


def validate_access_token(token: str) -> TokenPayload:
    """Validate an access token specifically."""
    payload = decode_token(token)
    if payload.type != "access":
        raise ValueError("Token is not an access token")
    # Check blacklist
    blacklist = get_token_blacklist()
    if blacklist.is_access_revoked(payload.jti):
        raise ValueError("Token has been revoked")
    return payload


def validate_refresh_token(token: str) -> TokenPayload:
    """Validate a refresh token specifically."""
    payload = decode_token(token)
    if payload.type != "refresh":
        raise ValueError("Token is not a refresh token")
    # Check blacklist
    blacklist = get_token_blacklist()
    if blacklist.is_refresh_revoked(payload.jti):
        raise ValueError("Token has been revoked")
    return payload


# ---- Token revocation -------------------------------------------------------


def revoke_access_token(jti: str, exp: int) -> None:
    """Revoke an access token by JTI."""
    blacklist = get_token_blacklist()
    blacklist.revoke_access(jti, exp)


def revoke_refresh_token(jti: str, exp: int) -> None:
    """Revoke a refresh token by JTI."""
    blacklist = get_token_blacklist()
    blacklist.revoke_refresh(jti, exp)


def revoke_token_pair(access_jti: str, access_exp: int, refresh_jti: str, refresh_exp: int) -> None:
    """Revoke both tokens in a pair (used on logout)."""
    blacklist = get_token_blacklist()
    blacklist.revoke_token_pair(access_jti, access_exp, refresh_jti, refresh_exp)


def revoke_refresh_token_and_create_new(
    *,
    old_refresh_jti: str,
    old_refresh_exp: int,
    user_id: str,
    email: str,
    org_id: str | None = None,
) -> TokenPair:
    """Atomically revoke old refresh token and create new token pair.

    This is the secure rotation pattern: revoke FIRST, then create new.
    Uses Redis pipeline for atomicity.
    """
    settings = get_settings()
    client = _get_redis_client()

    # Atomic revoke + create using Redis pipeline
    blacklist = get_token_blacklist()

    # First, revoke the old refresh token
    blacklist.revoke_refresh(old_refresh_jti, old_refresh_exp)

    # Then create new token pair
    return create_token_pair(user_id=user_id, email=email, org_id=org_id)


# ---- Helpers ----------------------------------------------------------------


def _generate_jti() -> str:
    """Generate a unique token identifier."""
    import uuid

    return uuid.uuid4().hex


# Settings extensions --------------------------------------------------------


def _get_token_settings() -> dict[str, Any]:
    """Read token-related settings from config (with defaults)."""
    settings = get_settings()
    return {
        "access_token_expire_minutes": getattr(settings, "access_token_expire_minutes", 15),
        "refresh_token_expire_days": getattr(settings, "refresh_token_expire_days", 7),
        "secret_key": settings.secret_key,
        "algorithm": getattr(settings, "algorithm", "HS256"),
    }