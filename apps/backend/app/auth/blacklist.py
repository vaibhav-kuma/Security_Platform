"""Token blacklist using Redis for revocation.

Stores revoked token JTIs with TTL matching token expiry.
"""

from datetime import UTC, datetime

import redis

from app.config import get_settings


class TokenBlacklist:
    """Redis-backed token revocation list."""

    def __init__(self, redis_url: str | None = None, testing: bool = False) -> None:
        settings = get_settings()
        url = redis_url or settings.redis_url
        # Only use in-memory storage in test environment (APP_ENV=test)
        # Never use in-memory in development or production
        if testing or settings.app_env == "test":
            import fakeredis

            self._client = fakeredis.FakeRedis(decode_responses=True)
        else:
            self._client = redis.from_url(url, decode_responses=True)
        self._access_ttl = 15 * 60  # 15 minutes default
        self._refresh_ttl = 7 * 24 * 60 * 60  # 7 days default

    def _access_key(self, jti: str) -> str:
        return f"token_blacklist:access:{jti}"

    def _refresh_key(self, jti: str) -> str:
        return f"token_blacklist:refresh:{jti}"

    def revoke_access(self, jti: str, exp: int) -> None:
        """Revoke an access token by JTI with TTL based on expiry."""
        ttl = max(1, exp - int(datetime.now(UTC).timestamp()))
        if ttl > 0:
            self._client.setex(self._access_key(jti), ttl, "1")

    def revoke_refresh(self, jti: str, exp: int) -> None:
        """Revoke a refresh token by JTI with TTL based on expiry."""
        ttl = max(1, exp - int(datetime.now(UTC).timestamp()))
        if ttl > 0:
            self._client.setex(self._refresh_key(jti), ttl, "1")

    def is_access_revoked(self, jti: str) -> bool:
        """Check if access token JTI is revoked."""
        return bool(self._client.exists(self._access_key(jti)))

    def is_refresh_revoked(self, jti: str) -> bool:
        """Check if refresh token JTI is revoked."""
        return bool(self._client.exists(self._refresh_key(jti)))

    def revoke_token_pair(
        self, access_jti: str, access_exp: int, refresh_jti: str, refresh_exp: int
    ) -> None:
        """Revoke both tokens in a pair."""
        self.revoke_access(access_jti, access_exp)
        self.revoke_refresh(refresh_jti, refresh_exp)


# Module-level instance for dependency injection
_token_blacklist: TokenBlacklist | None = None


def get_token_blacklist() -> TokenBlacklist:
    """Get or create the token blacklist singleton."""
    global _token_blacklist
    if _token_blacklist is None:
        settings = get_settings()
        _token_blacklist = TokenBlacklist(testing=settings.app_env == "test")
    return _token_blacklist
