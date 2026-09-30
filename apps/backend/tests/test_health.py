"""Unit tests: application factory and health endpoints."""

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_health_returns_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["app"] == "security-assessment-platform"


def test_readiness_returns_ready() -> None:
    client = TestClient(create_app())
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_openapi_served_at_custom_path() -> None:
    client = TestClient(create_app())
    response = client.get("/api/openapi.json")
    assert response.status_code == 200
    assert "paths" in response.json()


def test_settings_defaults_are_secure_for_ci() -> None:
    settings = Settings(_env_file=None)
    assert settings.app_env == "development"
    assert settings.debug is False
    assert settings.postgres_password == "change-me-dev-only"


def test_settings_builds_dsn() -> None:
    settings = Settings(_env_file=None)
    assert settings.postgres_dsn.startswith("postgresql+psycopg://platform:")
    assert settings.redis_url == "redis://localhost:6379/0"
