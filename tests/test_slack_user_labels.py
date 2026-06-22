"""Tests for Slack user display labels used in action-item sheets."""
from __future__ import annotations

from app.slack_api import (
    resolve_slack_user_from_sheet_cell,
    slack_build_user_lookup,
    slack_user_label_from_member,
)


def test_slack_user_label_from_member_prefers_display_name() -> None:
    member = {
        "id": "U123ABC",
        "name": "alice",
        "profile": {"display_name": "Alice", "real_name": "Alice Smith"},
    }
    assert slack_user_label_from_member(member) == "Alice"


def test_resolve_slack_user_from_sheet_cell() -> None:
    members = [
        {
            "id": "U123ABC",
            "name": "alice",
            "profile": {"display_name": "Alice", "real_name": "Alice Smith"},
        }
    ]
    lookup = slack_build_user_lookup(members)
    assert resolve_slack_user_from_sheet_cell("U123ABC", lookup) == "U123ABC"
    assert resolve_slack_user_from_sheet_cell("Alice", lookup) == "U123ABC"
    assert resolve_slack_user_from_sheet_cell("Alice Smith", lookup) == "U123ABC"
    assert resolve_slack_user_from_sheet_cell("@alice", lookup) == "U123ABC"
    assert resolve_slack_user_from_sheet_cell("Unknown Person", lookup) is None
