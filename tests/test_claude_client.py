"""Tests for completion route reporting."""
from __future__ import annotations

import pytest

import app.claude_client as client


@pytest.mark.asyncio
async def test_call_claude_reports_sovereign_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUSAN_DEFAULT_MODEL_ROUTE", "sovereign")
    monkeypatch.setattr(client, "f1_model_active", lambda: True)

    async def fake_f1(system: str, user: str, max_tokens: int | None = None) -> str:
        return "sovereign response"

    monkeypatch.setattr(client, "_call_f1_sovereign", fake_f1)

    result = await client.call_claude("system", "user", action="weekly_status")

    assert result == "sovereign response"
    assert result.model_route == "sovereign"


@pytest.mark.asyncio
async def test_call_claude_reports_commercial_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SUSAN_DEFAULT_MODEL_ROUTE", "sovereign")
    monkeypatch.setattr(client, "f1_model_active", lambda: True)

    async def fake_anthropic(
        system: str,
        user: str,
        max_tokens: int | None,
        *,
        action: str | None = None,
        model_route: str | None = None,
    ) -> str:
        return "commercial response"

    monkeypatch.setattr(client, "_call_anthropic", fake_anthropic)

    result = await client.call_claude("system", "user", action="sales_prep")

    assert result == "commercial response"
    assert result.model_route == "commercial"
