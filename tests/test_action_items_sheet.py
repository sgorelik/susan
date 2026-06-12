"""Unit tests for Google Sheets action-item helpers."""
from __future__ import annotations

from app.action_items_sheet import (
    _parse_sheet_row,
    sanitize_sheet_tab_title,
    spreadsheet_url,
)


def test_sanitize_sheet_tab_title() -> None:
    assert sanitize_sheet_tab_title("team-tech", "C123") == "team-tech"
    assert sanitize_sheet_tab_title("#general", "C999") == "general"
    assert sanitize_sheet_tab_title("weird [name]", "C1") == "weird name"
    assert sanitize_sheet_tab_title(None, "CABCDEF12") == "CABCDEF12"


def test_parse_sheet_row() -> None:
    assert _parse_sheet_row(["id", "task", "assignee_slack_id"]) is None
    row = _parse_sheet_row(
        ["uuid-1", "Ship feature", "U123", "open", "", "slack", "", "", ""]
    )
    assert row is not None
    assert row["id"] == "uuid-1"
    assert row["task"] == "Ship feature"
    assert row["status"] == "open"


def test_spreadsheet_url_with_gid() -> None:
    url = spreadsheet_url("abc123", 456)
    assert url == "https://docs.google.com/spreadsheets/d/abc123/edit#gid=456"
