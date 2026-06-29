"""Tests for weekly Drive helpers."""
from __future__ import annotations

from app.weekly_drive import _drive_work_attribution


def test_drive_work_attribution_owner_and_editor() -> None:
    meta = {
        "owners": [{"displayName": "Alice", "emailAddress": "alice@example.com"}],
        "lastModifyingUser": {"displayName": "Bob", "emailAddress": "bob@example.com"},
    }
    assert "owner: Alice" in _drive_work_attribution(meta)
    assert "last editor: Bob" in _drive_work_attribution(meta)


def test_drive_work_attribution_owner_only() -> None:
    meta = {
        "owners": [{"displayName": "Alice"}],
        "lastModifyingUser": {"displayName": "Alice"},
    }
    assert _drive_work_attribution(meta) == "last editor: Alice"
