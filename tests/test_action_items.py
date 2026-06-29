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
        {
            "id": "ghi",
            "text": "Ship feature",
            "assignee_slack_id": "U123ABC",
            "status": "open",
            "status_note": None,
        },
    ]
    msg = format_action_items_message(items, "last 7 days", include_instructions=False)
    assert "<@U123ABC> you have *2* outstanding:" in msg
    assert "*1.* Fix login button" in msg
    assert "*3.* Ship feature" in msg
    assert "*Unassigned*" in msg
    assert "*2.* Write design doc" in msg
    assert "in progress" in msg


def test_group_items_by_assignee() -> None:
    from app.action_items import _group_items_by_assignee

    items = [
        {"id": "a", "assignee_slack_id": "U2"},
        {"id": "b", "assignee_slack_id": "U1"},
        {"id": "c", "assignee_slack_id": None},
    ]
    groups = _group_items_by_assignee(items)
    assert groups[0][0] == "U1"
    assert groups[1][0] == "U2"
    assert groups[2][0] is None


def test_parse_action_items_time_window_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACTION_ITEMS_LOOKBACK_DAYS", "10")
    since, until, label = parse_action_items_time_window("")
    assert "10" in label
    assert since <= until


def test_drop_terminal_and_completed() -> None:
    from app.action_items import _drop_terminal_and_completed

    existing = [
        {"id": "done-1", "text": "Shipped feature", "status": "done", "assignee_slack_id": "U1"},
        {"id": "wont-1", "text": "Skip migration", "status": "wont_do", "assignee_slack_id": None},
    ]
    extracted = [
        {"id": "done-1", "text": "Shipped feature", "status": "open", "assignee_slack_id": "U1"},
        {"id": "new-1", "text": "Shipped feature", "status": "open", "assignee_slack_id": "U1"},
        {"id": "new-2", "text": "Fix bug", "status": "open", "assignee_slack_id": "U1"},
        {"id": "done-row", "text": "Old task", "status": "done", "assignee_slack_id": "U2"},
    ]
    out = _drop_terminal_and_completed(extracted, existing)
    texts = [it["text"] for it in out]
    assert "Shipped feature" not in texts
    assert "Old task" not in texts
    assert "Fix bug" in texts


def test_cap_items_per_assignee() -> None:
    from app.action_items import _cap_items_per_assignee

    items = [
        {"text": f"Task {i}", "status": "open", "assignee_slack_id": "U1"}
        for i in range(10)
    ] + [{"text": "Other", "status": "in_progress", "assignee_slack_id": "U2"}]
    capped = _cap_items_per_assignee(items, max_per=7)
    u1 = [it for it in capped if it["assignee_slack_id"] == "U1"]
    assert len(u1) == 7
    assert any(it["assignee_slack_id"] == "U2" for it in capped)
