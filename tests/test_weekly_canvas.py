"""Tests for weekly status Canvas markdown conversion."""
from __future__ import annotations

from app.weekly_canvas import slack_mrkdwn_to_canvas_markdown, weekly_status_use_canvas


def test_slack_mrkdwn_to_canvas_markdown() -> None:
    src = "*Platform*\n- did <https://github.com/o/r/pull/1|PR #1> thing\n*1. Last week:*\n a. foo"
    out = slack_mrkdwn_to_canvas_markdown(src)
    assert "**Platform**" in out
    assert "[PR #1](https://github.com/o/r/pull/1)" in out
    assert "**1. Last week:**" in out


def test_weekly_status_use_canvas_default() -> None:
    assert weekly_status_use_canvas() is True
