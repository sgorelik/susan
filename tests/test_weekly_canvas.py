"""Tests for weekly status Canvas markdown conversion."""
from __future__ import annotations

import pytest

import app.weekly_canvas as weekly_canvas
from app.weekly_canvas import slack_mrkdwn_to_canvas_markdown, weekly_status_use_canvas


def test_slack_mrkdwn_to_canvas_markdown() -> None:
    src = "*Platform*\n- did <https://github.com/o/r/pull/1|PR #1> thing\n*1. Last week:*\n a. foo"
    out = slack_mrkdwn_to_canvas_markdown(src)
    assert "**Platform**" in out
    assert "[PR #1](https://github.com/o/r/pull/1)" in out
    assert "**1. Last week:**" in out


def test_weekly_status_use_canvas_default() -> None:
    assert weekly_status_use_canvas() is True


@pytest.mark.asyncio
async def test_canvas_announcement_preserves_completion_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(weekly_canvas, "weekly_status_use_canvas", lambda: True)

    async def fake_create(**kwargs: object) -> str:
        return "F123"

    async def fake_permalink(canvas_id: str) -> str:
        return "https://slack.example/canvas"

    posted: dict[str, object] = {}

    async def fake_post_message(channel: str, text: str, **kwargs: object) -> dict:
        posted.update(channel=channel, text=text, **kwargs)
        return {"ok": True}

    monkeypatch.setattr(weekly_canvas, "slack_api_canvases_create", fake_create)
    monkeypatch.setattr(weekly_canvas, "slack_api_files_permalink", fake_permalink)
    monkeypatch.setattr(weekly_canvas, "post_message", fake_post_message)

    await weekly_canvas.publish_weekly_status(
        "C123",
        None,
        "Weekly status",
        "Body",
        model_route="sovereign",
    )

    assert posted["model_route"] == "sovereign"
