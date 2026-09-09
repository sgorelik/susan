"""Tests for the /susan help overview and its topic pages."""
from __future__ import annotations

import json

from app.routes import parse_help_topic, susan_slash_help_response


def _text(topic: str = "") -> str:
    payload = json.loads(susan_slash_help_response(topic).body)
    return "\n".join(
        block.get("text", {}).get("text", "")
        for block in payload["blocks"]
        if block["type"] == "section"
    )


def test_parse_help_topic() -> None:
    assert parse_help_topic("help") == ""
    assert parse_help_topic("?") == ""
    assert parse_help_topic("help actions") == "actions"
    assert parse_help_topic("help me with actions") == "actions"
    assert parse_help_topic("help my actions") == "actions"
    assert parse_help_topic("commands roadmap") == "roadmap"
    assert parse_help_topic("help weekly status") == "status"
    assert parse_help_topic("help all") == "all"
    assert parse_help_topic("help something unknown") == ""


def test_overview_is_short_and_points_at_topics() -> None:
    body = _text()
    assert len(body) < 1800
    assert "/susan my actions" in body
    assert "/susan team actions" in body
    assert "help actions" in body


def test_overview_omits_server_configuration() -> None:
    """Env-var detail belongs on topic pages, not the first thing everyone reads."""
    body = _text()
    for noise in ("WEEKLY_DRIVE_MAX_FOLDERS", "GITHUB_OAUTH_SCOPE", "SUSAN_ROADMAP_ORG"):
        assert noise not in body


def test_actions_topic_distinguishes_personal_from_team() -> None:
    body = _text("actions")
    assert "my actions" in body
    assert "team actions" in body
    assert "Only you see it" in body
    assert "this one channel" in body


def test_all_topic_includes_every_section() -> None:
    body = _text("all")
    assert "team actions" in body
    assert "weekly status" in body
    assert "board status" in body
    assert "connect google" in body
    assert "schedule add" in body
    assert "Keywords Susan recognizes" in body


def test_every_section_fits_slack_block_limit() -> None:
    for topic in ("", "actions", "status", "roadmap", "connect", "schedule", "all"):
        payload = json.loads(susan_slash_help_response(topic).body)
        for block in payload["blocks"]:
            if block["type"] == "section":
                assert len(block["text"]["text"]) <= 3000


def test_topic_pages_link_back_to_overview() -> None:
    payload = json.loads(susan_slash_help_response("actions").body)
    assert any(block["type"] == "context" for block in payload["blocks"])
    overview = json.loads(susan_slash_help_response("").body)
    assert not any(block["type"] == "context" for block in overview["blocks"])
