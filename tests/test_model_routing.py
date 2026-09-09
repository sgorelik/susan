"""Unit tests for model routing."""
from __future__ import annotations

import pytest

from app.model_routing import COMMERCIAL_ACTIONS, resolve_model, route_for_action


def test_commercial_actions_exclude_weekly() -> None:
    assert "sales_prep" in COMMERCIAL_ACTIONS
    assert "weekly_status" not in COMMERCIAL_ACTIONS


def test_route_for_action_commercial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUSAN_DEFAULT_MODEL_ROUTE", "sovereign")
    assert route_for_action("sales_prep") == "commercial"
    assert route_for_action("weekly_status") == "sovereign"


def test_route_for_action_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUSAN_DEFAULT_MODEL_ROUTE", raising=False)
    assert route_for_action("doc") == "default"
    assert route_for_action(None) == "default"


def test_resolve_model_sales_prep_defaults_to_opus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-default")
    monkeypatch.delenv("SALES_PREP_ANTHROPIC_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_COMMERCIAL_MODEL", raising=False)
    assert resolve_model(action="sales_prep", model_route="commercial") == "claude-opus-4-6"


def test_resolve_model_commercial_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-default")
    monkeypatch.setenv("ANTHROPIC_COMMERCIAL_MODEL", "claude-commercial")
    assert resolve_model(action="granola_cmd", model_route="commercial") == "claude-commercial"
    assert resolve_model(action="weekly_status", model_route="commercial") == "claude-commercial"
    assert resolve_model(action="doc") == "claude-default"
