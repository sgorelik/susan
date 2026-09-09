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

    async def fake_f1(
        system: str, user: str, max_tokens: int | None = None
    ) -> tuple[str, str]:
        return "sovereign response", "deepseek-ai-deepseek-v4-a05f5b"

    monkeypatch.setattr(client, "_call_f1_sovereign", fake_f1)

    result = await client.call_claude("system", "user", action="weekly_status")

    assert result == "sovereign response"
    assert result.model_route == "sovereign"
    assert result.model_name == "deepseek-ai-deepseek-v4-a05f5b"


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
    assert result.model_name == "claude-opus-4-6"


@pytest.mark.asyncio
async def test_sovereign_model_name_read_from_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Attribution names what answered, even if the endpoint swaps the model."""
    monkeypatch.setattr(client, "F1_MODEL_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setattr(client, "F1_MODEL_NAME", "requested-model")

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict:
            return {
                "model": "actually-served-model",
                "choices": [{"message": {"content": "hi"}}],
            }

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def post(self, *args: object, **kwargs: object) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(client.httpx, "AsyncClient", lambda **kw: FakeClient())

    text, served = await client._call_f1_sovereign("system", "user")

    assert text == "hi"
    assert served == "actually-served-model"
