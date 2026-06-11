"""Tests for action-items command parsing and formatting."""
from __future__ import annotations

import pytest

from app.action_items import (
    format_action_items_message,
    parse_action_items_command,
    parse_action_items_time_window,
)


def test_parse_action_items_command() -> None:
    assert parse_action_items_command("actions") == ""
    assert parse_action_items_command("actions last week") == "last week"
    assert parse_action_items_command("action items last 14 days") == "last 14 days"
    assert parse_action_items_command("todos") == ""
    assert parse_action_items_command("create issue") is None
    assert parse_action_items_command("interactions") is None


def test_format_action_items_message_mentions() -> None:
    items = [
        {
            "id": "abc",
            "text": "Fix login button",
            "assignee_slack_id": "U123ABC",
            "status": "open",
            "status_note": None,
        },
        {
            "id": "def",
            "text": "Write design doc",
            "assignee_slack_id": None,
            "status": "in_progress",
            "status_note": "started draft",
        },
    ]
    msg = format_action_items_message(items, "last 7 days", include_instructions=False)
    assert "<@U123ABC>" in msg
    assert "_unassigned_" in msg
    assert "in progress" in msg
    assert "Fix login button" in msg


def test_parse_action_items_time_window_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACTION_ITEMS_LOOKBACK_DAYS", "10")
    since, until, label = parse_action_items_time_window("")
    assert "10" in label
    assert since <= until
