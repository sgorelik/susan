"""Unit tests for Granola summarize command parsing (no external API calls)."""
from __future__ import annotations

import pytest

from app.config import ACTIONS
from app.slack_api import detect_action
from app.granola_summarize import parse_granola_slash_command, parse_granola_time_window


def test_parse_granola_slash_command_prefixes() -> None:
    assert parse_granola_slash_command("granola") == ""
    assert parse_granola_slash_command("granola last week") == "last week"
    assert parse_granola_slash_command("Granola last week") == "last week"
    assert parse_granola_slash_command("gn") == ""
    assert parse_granola_slash_command("gn last 14 days") == "last 14 days"
    assert parse_granola_slash_command("  gn  foo bar ") == "foo bar"
    assert parse_granola_slash_command("grocery list") is None
    assert parse_granola_slash_command("gnome") is None
    assert parse_granola_slash_command("") is None


def test_granola_cmd_not_matched_by_detect_action() -> None:
    assert ACTIONS["granola_cmd"][1] == []
    assert detect_action("granola last week") is None
    assert detect_action("gn") is None


def test_detect_action_doc_still_matches_notes_without_granola_prefix() -> None:
    assert detect_action("meeting notes for launch") == "doc"


def test_parse_granola_time_window_default_lookback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRANOLA_LOOKBACK_DAYS", "3")
    since, until, label = parse_granola_time_window("")
    assert "3" in label
    from datetime import datetime, timedelta, timezone

    today = datetime.now(timezone.utc).date()
    assert since == (today - timedelta(days=3)).isoformat()
    assert until == today.isoformat()


def test_parse_granola_time_window_delegates_to_weekly_parser() -> None:
    since, until, label = parse_granola_time_window("last calendar week")
    assert since <= until
    assert "calendar week" in label.lower() or "Calendar week" in label
