"""Unit tests for model routing."""
from __future__ import annotations

import pytest

from app.model_routing import COMMERCIAL_ACTIONS, resolve_model, route_for_action


def test_commercial_actions_include_sales_prep_and_weekly() -> None:
    assert "sales_prep" in COMMERCIAL_ACTIONS
    assert "weekly_status" in COMMERCIAL_ACTIONS


def test_route_for_action_commercial() -> None:
    assert route_for_action("sales_prep") == "commercial"
    assert route_for_action("weekly_status") == "commercial"


def test_route_for_action_default() -> None:
    assert route_for_action("doc") == "default"
    assert route_for_action(None) == "default"


def test_resolve_model_commercial_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-default")
    monkeypatch.setenv("ANTHROPIC_COMMERCIAL_MODEL", "claude-commercial")
    assert resolve_model(action="sales_prep") == "claude-commercial"
    assert resolve_model(action="doc") == "claude-default"
