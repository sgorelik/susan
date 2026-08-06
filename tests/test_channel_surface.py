"""Unit tests for standup / failures / reviews surface parsers."""
from __future__ import annotations

from app.channel_surface import (
    _is_standup_parent,
    parse_failures_command,
    parse_reviews_command,
    parse_standup_command,
    parse_surface_time_window,
)
from app.config import ACTIONS
from app.model_routing import COMMERCIAL_ACTIONS
from app.slack_api import detect_action


def test_parse_standup_command() -> None:
    assert parse_standup_command("standups") == ""
    assert parse_standup_command("standups last week") == "last week"
    assert parse_standup_command("summary of standups last 7 days") == "last 7 days"
    assert parse_standup_command("summarize standups") == ""
    assert parse_standup_command("standup notes last calendar week") == "last calendar week"
    assert parse_standup_command("weekly status") is None
    assert parse_standup_command("create a doc") is None


def test_parse_failures_command() -> None:
    assert parse_failures_command("surface failures") == ""
    assert parse_failures_command("what's failing last 3 days") == "last 3 days"
    assert parse_failures_command("surface everything that is failing") == ""
    assert parse_failures_command("failures") == ""
    assert parse_failures_command("failing") == ""
    assert parse_failures_command("standups") is None


def test_parse_reviews_command() -> None:
    assert parse_reviews_command("needs my review") == ""
    assert parse_reviews_command("surface reviews last week") == "last week"
    assert parse_reviews_command(
        "surface everything that requires my review"
    ) == ""
    assert parse_reviews_command("prs to review") == ""
    assert parse_reviews_command("failures") is None


def test_surface_actions_not_matched_by_detect_action() -> None:
    assert ACTIONS["surface_standups"][1] == []
    assert ACTIONS["surface_failures"][1] == []
    assert ACTIONS["surface_reviews"][1] == []
    assert detect_action("standups last week") is None
    assert detect_action("surface failures") is None
    assert detect_action("needs my review") is None


def test_surface_actions_are_commercial() -> None:
    assert "surface_standups" in COMMERCIAL_ACTIONS
    assert "surface_failures" in COMMERCIAL_ACTIONS
    assert "surface_reviews" in COMMERCIAL_ACTIONS


def test_parse_surface_time_window_default(monkeypatch) -> None:
    monkeypatch.delenv("STANDUP_LOOKBACK_DAYS", raising=False)
    since, until, label = parse_surface_time_window("", default_days=7)
    assert "7" in label
    assert since <= until


def test_is_standup_parent() -> None:
    assert _is_standup_parent("July 13 Standup notes in :thread:")
    assert _is_standup_parent("Notes from standup in :thread:")
    assert _is_standup_parent("standup notes in :thread: , AIs:")
    assert not _is_standup_parent("Weekly status — …")
    assert not _is_standup_parent("PR ready for review")
