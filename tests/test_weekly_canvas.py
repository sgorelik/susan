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


def test_model_emitted_horizontal_rules_are_dropped() -> None:
    src = "*Platform*\n- shipped it\n\n---\n\n*Onboarding*\n- new flow\n***\n___\n===\n"
    out = slack_mrkdwn_to_canvas_markdown(src)
    assert not any(
        line.strip() in ("---", "***", "___", "===") for line in out.splitlines()
    )
    assert "**Platform**" in out
    assert "**Onboarding**" in out
    assert "\n\n\n" not in out


def test_rule_directly_under_text_does_not_become_a_heading() -> None:
    # "latency down\n---" would parse as a setext H2 in the Canvas renderer.
    out = slack_mrkdwn_to_canvas_markdown("latency down\n---\n*Onboarding*")
    assert out == "latency down\n\n**Onboarding**"


def test_canvas_document_keeps_single_footer_rule() -> None:
    md = weekly_canvas._canvas_document_markdown("Weekly status", "*Platform*\n---\n- shipped")
    assert md.count("---") == 1
    assert md.endswith("---\n_Posted via Susan_")


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
