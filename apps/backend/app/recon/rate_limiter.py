"""Rate limiter for recon engine using Redis."""

import time
from dataclasses import dataclass

import redis


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    current_count: int
    limit: int
    window_seconds: int
    retry_after_seconds: float | None = None


class ReconRateLimiter:
    """Rate limiter for recon operations using Redis sliding window."""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        default_limit: int = 60,
        default_window: int = 60,
    ) -> None:
        self.redis_client = redis.from_url(redis_url, decode_responses=True)  # type: ignore[no-untyped-call]
        self.default_limit = default_limit
        self.default_window = default_window

    def _get_key(self, identifier: str, scope: str, window: int) -> str:
        """Generate Redis key for rate limiting."""
        current_window = int(time.time() // window)
        return f"ratelimit:{scope}:{identifier}:{current_window}"

    def check_limit(
        self,
        identifier: str,
        limit: int | None = None,
        window_seconds: int | None = None,
        scope: str = "target",
    ) -> RateLimitResult:
        """Check if request is within rate limit.

        Args:
            identifier: Unique identifier (project_id, target_id, etc.)
            limit: Max requests allowed in window
            window_seconds: Time window in seconds
            scope: Scope of rate limit (project, target, global)

        Returns:
            RateLimitResult with allowance decision
        """
        limit = limit or self.default_limit
        window_seconds = window_seconds or self.default_window
        key = self._get_key(identifier, scope, window_seconds)

        # Use Redis pipeline for atomic increment and expire
        pipe = self.redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = pipe.execute()

        current_count = int(results[0])

        if current_count > limit:
            # Get TTL for retry-after
            ttl = self.redis_client.ttl(key)
            retry_after = float(ttl) if ttl and ttl > 0 else float(window_seconds)
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                limit=limit,
                window_seconds=window_seconds,
                retry_after_seconds=retry_after,
            )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=limit,
            window_seconds=window_seconds,
        )

    def check_limit_sliding(
        self,
        identifier: str,
        limit: int | None = None,
        window_seconds: int | None = None,
        scope: str = "target",
    ) -> RateLimitResult:
        """Check rate limit using sliding window algorithm.

        More accurate but slightly more expensive than fixed window.
        """
        limit = limit or self.default_limit
        window_seconds = window_seconds or self.default_window
        now = time.time()
        window_start = now - window_seconds

        # Use sorted set for sliding window
        key = f"ratelimit:sliding:{scope}:{identifier}"

        pipe = self.redis_client.pipeline()
        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)
        # Count current entries
        pipe.zcard(key)
        # Add current request
        pipe.zadd(key, {str(now): now})
        # Set expiry
        pipe.expire(key, window_seconds + 1)
        results = pipe.execute()

        current_count = int(results[1]) + 1  # +1 for the request we just added

        if current_count > limit:
            # Get oldest entry to calculate retry-after
            oldest = self.redis_client.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = float(oldest[0][1]) + window_seconds - now
            else:
                retry_after = float(window_seconds)
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                limit=limit,
                window_seconds=window_seconds,
                retry_after_seconds=max(retry_after, 0.1),
            )

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=limit,
            window_seconds=window_seconds,
        )

    def reset_limit(self, identifier: str, scope: str = "target") -> None:
        """Reset rate limit for an identifier."""
        # Fixed window keys
        for window in [60, 3600]:  # minute, hour
            key = self._get_key(identifier, scope, window)
            self.redis_client.delete(key)
        # Sliding window key
        key = f"ratelimit:sliding:{scope}:{identifier}"
        self.redis_client.delete(key)

    def get_current_usage(
        self,
        identifier: str,
        window_seconds: int | None = None,
        scope: str = "target",
    ) -> int:
        """Get current usage count without incrementing."""
        window_seconds = window_seconds or self.default_window
        now = time.time()
        window_start = now - window_seconds

        # Check sliding window
        key = f"ratelimit:sliding:{scope}:{identifier}"
        count = self.redis_client.zcount(key, window_start, "+inf")

        # Also check fixed window (minute)
        key = self._get_key(identifier, scope, 60)
        fixed_count = int(self.redis_client.get(key) or 0)

        return max(int(count), fixed_count)

    def close(self) -> None:
        """Close Redis connection."""
        self.redis_client.close()


class InMemoryRateLimiter:
    """In-memory rate limiter for testing."""

    def __init__(
        self,
        default_limit: int = 60,
        default_window: int = 60,
    ) -> None:
        self.default_limit = default_limit
        self.default_window = default_window
        self._counters: dict[str, list[float]] = {}  # key -> list of timestamps

    def _cleanup_old(self, key: str, window_seconds: float) -> None:
        """Remove timestamps older than window."""
        now = time.time()
        cutoff = now - window_seconds
        if key in self._counters:
            self._counters[key] = [ts for ts in self._counters[key] if ts > cutoff]
            if not self._counters[key]:
                del self._counters[key]

    def check_limit(
        self,
        identifier: str,
        limit: int | None = None,
        window_seconds: int | None = None,
        scope: str = "target",
    ) -> RateLimitResult:
        """Check if request is within rate limit (sliding window)."""
        limit = limit or self.default_limit
        window_seconds = window_seconds or self.default_window
        now = time.time()

        key = f"{scope}:{identifier}"
        self._cleanup_old(key, window_seconds)

        current_count = len(self._counters.get(key, [])) + 1

        if current_count > limit:
            oldest = self._counters[key][0] if key in self._counters else now
            retry_after = oldest + window_seconds - now
            return RateLimitResult(
                allowed=False,
                current_count=current_count,
                limit=limit,
                window_seconds=window_seconds,
                retry_after_seconds=max(retry_after, 0.1),
            )

        # Add current request
        if key not in self._counters:
            self._counters[key] = []
        self._counters[key].append(now)

        return RateLimitResult(
            allowed=True,
            current_count=current_count,
            limit=limit,
            window_seconds=window_seconds,
        )

    def check_limit_sliding(
        self,
        identifier: str,
        limit: int | None = None,
        window_seconds: int | None = None,
        scope: str = "target",
    ) -> RateLimitResult:
        """Check rate limit using sliding window algorithm (alias for check_limit in memory)."""
        return self.check_limit(identifier, limit, window_seconds, scope)

    def reset_limit(self, identifier: str, scope: str = "target") -> None:
        """Reset rate limit for an identifier."""
        key = f"{scope}:{identifier}"
        if key in self._counters:
            del self._counters[key]

    def get_current_usage(
        self,
        identifier: str,
        window_seconds: int | None = None,
        scope: str = "target",
    ) -> int:
        """Get current usage count without incrementing."""
        window_seconds = window_seconds or self.default_window
        now = time.time()
        cutoff = now - window_seconds
        key = f"{scope}:{identifier}"
        if key in self._counters:
            return len([ts for ts in self._counters[key] if ts > cutoff])
        return 0
