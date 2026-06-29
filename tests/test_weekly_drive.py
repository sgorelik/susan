"""Tests for weekly Drive helpers."""
from __future__ import annotations

from app.weekly_drive import _drive_work_attribution


def test_drive_work_attribution_owner_and_editor() -> None:
    meta = {
        "owners": [{"displayName": "Alice", "emailAddress": "alice@example.com"}],
        "lastModifyingUser": {"displayName": "Bob", "emailAddress": "bob@example.com"},
    }
    assert "owner: Alice" in _drive_work_attribution(meta)
    assert "last editor: Bob" in _drive_work_attribution(meta)


def test_channel_google_urls_from_slack() -> None:
    from app.weekly_drive import channel_google_urls_from_slack, parse_google_drive_targets_from_urls

    digest = (
        "U123: Please review <https://docs.google.com/document/d/abc123XYZ/edit|Q3 plan>\n"
        "U456: see https://drive.google.com/file/d/file999/view"
    )
    urls = channel_google_urls_from_slack(digest)
    assert len(urls) == 2
    _, file_ids = parse_google_drive_targets_from_urls(urls)
    assert "abc123XYZ" in file_ids
    assert "file999" in file_ids


def test_format_drive_activity_line_shared_tag() -> None:
    from app.weekly_drive import _format_drive_activity_line

    line = _format_drive_activity_line(
        {
            "name": "Q3 Plan",
            "mimeType": "application/vnd.google-apps.document",
            "modifiedTime": "2025-01-01T12:00:00Z",
            "attribution": "owner: Alice",
            "webViewLink": "https://docs.google.com/document/d/abc/edit",
            "shared_in_channel": True,
            "modified_in_window": False,
        }
    )
    assert "shared in Slack this week" in line
    assert "Q3 Plan" in line
