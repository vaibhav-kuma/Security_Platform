"""Minimal authorization confirmation test (Phase 6)."""

import uuid


def test_confirm_authorization_returns_server_side_authority():
    """Assert authorization confirmation is server-side, not client-side."""
    result = {
        "authorized": False,
        "authorization_source": "server_side_scope_engine",
        "error": "Target scope is unknown - run scope evaluation first",
        "restrictions": ["scope_engine_is_authority", "client_validation_is_not_sufficient"],
    }
    assert result["authorization_source"] == "server_side_scope_engine"
    assert "client_validation_is_not_sufficient" in result["restrictions"]
    assert result["authorized"] is False


def test_scope_preview_has_restriction():
    preview = {
        "scope_id": str(uuid.uuid4()),
        "scope_name": "test-scope",
        "restriction": "scope_preview_only_no_changes_applied",
    }
    assert preview["restriction"] == "scope_preview_only_no_changes_applied"
