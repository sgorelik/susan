"""Unit tests for Google Sheets action-item helpers."""
from __future__ import annotations

from app.action_items_sheet import (
    _parse_sheet_row,
    format_google_sheets_user_error,
    sanitize_sheet_tab_title,
    spreadsheet_url,
)


def test_sanitize_sheet_tab_title() -> None:
    assert sanitize_sheet_tab_title("team-tech", "C123") == "#team-tech"
    assert sanitize_sheet_tab_title("#general", "C999") == "#general"
    assert sanitize_sheet_tab_title("weird [name]", "C1") == "#weird name"
    assert sanitize_sheet_tab_title(None, "CABCDEF12") == "CABCDEF12"


def test_parse_sheet_row() -> None:
    assert _parse_sheet_row(["id", "task", "assignee"]) is None
    row = _parse_sheet_row(
        ["uuid-1", "Ship feature", "Alice Smith", "open", "", "slack", "", "", "Bob Jones"]
    )
    assert row is not None
    assert row["id"] == "uuid-1"
    assert row["task"] == "Ship feature"
    assert row["assignee"] == "Alice Smith"
    assert row["updated_by"] == "Bob Jones"
    assert row["status"] == "open"


def test_spreadsheet_url_with_gid() -> None:
    url = spreadsheet_url("abc123", 456)
    assert url == "https://docs.google.com/spreadsheets/d/abc123/edit#gid=456"


def test_format_google_sheets_user_error_service_disabled() -> None:
    err = Exception(
        "Google Sheets API 403: SERVICE_DISABLED sheets.googleapis.com project 44608097342"
    )
    msg = format_google_sheets_user_error(err)
    assert "Sheets API" in msg
    assert "sheets.googleapis.com" in msg
    assert "connect google" in msg
