"""Application configuration loaded from environment variables.

Settings are read once at import time; tests may construct ``Settings``
directly. Secrets must never be logged — the settings model is excluded
from default repr surfaces.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the backend service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: Literal["development", "test", "production"] = Field(
        default="development", alias="APP_ENV"
    )
    app_name: str = Field(default="security-assessment-platform", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    debug: bool = Field(default=False, alias="DEBUG")

    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_user: str = Field(default="platform", alias="POSTGRES_USER")
    postgres_password: str = Field(alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="platform", alias="POSTGRES_DB")

    redis_host: str = Field(default="localhost", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")

    minio_endpoint: str = Field(default="localhost:9000", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(alias="MINIO_SECRET_KEY")
    minio_secure: bool = Field(default=False, alias="MINIO_SECURE")

    # Auth / JWT settings
    secret_key: str = Field(alias="SECRET_KEY", min_length=32)
    algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=15, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")

    # Cookie settings
    cookie_secure: bool = Field(default=True, alias="COOKIE_SECURE")

    # Rate limiting settings
    rate_limit_requests_per_minute: int = Field(default=60, alias="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_auth_requests_per_minute: int = Field(default=5, alias="RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE")
    trusted_proxies: list[str] = Field(default=[], alias="TRUSTED_PROXIES")

    # CORS settings (production) - comma-separated string in env, parsed to list
    cors_origins_raw: str = Field(default="", alias="CORS_ORIGINS")

    @property
    def cors_origins(self) -> list[str]:
        """Parse CORS origins from comma-separated string and validate URLs."""
        if not self.cors_origins_raw:
            return []
        origins = [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]
        # Validate each origin is a valid URL with proper host
        import re

        from pydantic import HttpUrl
        validated = []
        for origin in origins:
            try:
                HttpUrl(origin)
                # Additional validation: host must have at least one dot (for domain) or be localhost
                host = origin.split("://")[1].split(":")[0].split("/")[0]
                if not (re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', host) or host == "localhost"):
                    import logging
                    logging.getLogger(__name__).warning(f"Invalid CORS origin host (no valid TLD): {origin}")
                    continue
                validated.append(origin)
            except Exception:
                import logging
                logging.getLogger(__name__).warning(f"Invalid CORS origin skipped: {origin}")
        return validated

    # Worker settings
    worker_max_concurrent_jobs: int = Field(default=4, alias="WORKER_MAX_CONCURRENT_JOBS")
    worker_concurrency: int = Field(default=4, alias="WORKER_CONCURRENCY")
    scan_job_timeout_minutes: int = Field(default=60, alias="SCAN_JOB_TIMEOUT_MINUTES")
    worker_heartbeat_interval_seconds: int = Field(default=30, alias="WORKER_HEARTBEAT_INTERVAL_SECONDS")
    worker_offline_timeout_seconds: int = Field(default=120, alias="WORKER_OFFLINE_TIMEOUT_SECONDS")

    # Observability settings
    otlp_endpoint: str | None = Field(default=None, alias="OTLP_ENDPOINT")
    prometheus_metrics_enabled: bool = Field(default=True, alias="PROMETHEUS_METRICS_ENABLED")
    tracing_enabled: bool = Field(default=True, alias="TRACING_ENABLED")
    log_json_format: bool = Field(default=False, alias="LOG_JSON_FORMAT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Artifact lifecycle settings
    artifact_retention_days: int = Field(default=30, alias="ARTIFACT_RETENTION_DAYS")
    artifact_cleanup_schedule_cron: str = Field(default="0 2 * * *", alias="ARTIFACT_CLEANUP_SCHEDULE_CRON")  # Daily at 2 AM

    # Rate limiting - per project/target
    max_concurrent_scans_per_project: int = Field(default=3, alias="MAX_CONCURRENT_SCANS_PER_PROJECT")
    max_concurrent_scans_per_target: int = Field(default=1, alias="MAX_CONCURRENT_SCANS_PER_TARGET")

    # Plugin settings
    plugin_enabled: bool = Field(default=True, alias="PLUGIN_ENABLED")
    plugin_directory: str = Field(default="./plugins/installed", alias="PLUGIN_DIRECTORY")
    plugin_permission_policy: str = Field(default="allow_safe", alias="PLUGIN_PERMISSION_POLICY")
    plugin_max_concurrent_executions: int = Field(default=10, alias="PLUGIN_MAX_CONCURRENT_EXECUTIONS")
    plugin_default_timeout_seconds: int = Field(default=300, alias="PLUGIN_DEFAULT_TIMEOUT_SECONDS")

    def __init__(self, **data):
        super().__init__(**data)
        if not self.secret_key or self.secret_key.strip() == "":
            raise ValueError("SECRET_KEY must be set and non-empty")

    @property
    def postgres_dsn(self) -> str:
        """PostgreSQL DSN built from settings."""
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/0"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
