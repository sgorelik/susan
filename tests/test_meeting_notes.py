"""Unit tests for meeting-notes intent detection and acknowledgement (Step 1)."""
from __future__ import annotations

import pytest

from app import meeting_notes
from app.meeting_notes import (
    MEETING_NOTES_ACK,
    acknowledge_meeting_notes_request,
    extract_mention_event,
    is_meeting_notes_request,
)
from app.slack_api import detect_action
from app.slack_events import handle_slack_event_callback


@pytest.mark.parametrize(
    "text",
    [
        "<@U0BOT> meeting notes",
        "<@U0BOT> share notes",
        "<@U0BOT> post notes",
        "<@U0BOT> notes from yesterday's standup",
        # Minor variations called out in the acceptance criteria.
        "<@U0BOT> share my meeting notes",
        "<@U0BOT> post the notes",
        # Case-insensitive matching.
        "<@U0BOT> MEETING NOTES please",
        "<@U0BOT> can you share the notes from our sync?",
    ],
)
def test_is_meeting_notes_request_matches(text: str) -> None:
    assert is_meeting_notes_request(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "<@U0BOT> create a doc",
        "<@U0BOT> what's on my calendar",
        "<@U0BOT> open a github issue",
        "<@U0BOT> summarize the prs",
        "<@U0BOT> hello there",
        # "notes" on its own must not trigger the flow.
        "<@U0BOT> take some notes please",
        "",
    ],
)
def test_is_meeting_notes_request_non_matches(text: str) -> None:
    assert is_meeting_notes_request(text) is False


def test_extract_mention_event_from_payload() -> None:
    event = {
        "type": "app_mention",
        "user": "U123USER",
        "channel": "C456CHAN",
        "text": "<@U0BOT> meeting notes",
        "ts": "1700000000.000100",
    }
    user_id, channel_id, text = extract_mention_event(event)
    assert user_id == "U123USER"
    assert channel_id == "C456CHAN"
    assert text == "<@U0BOT> meeting notes"


def test_extract_mention_event_missing_fields() -> None:
    assert extract_mention_event({}) == ("", "", "")


async def test_acknowledge_posts_ephemeral_and_hands_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posted: dict[str, str] = {}
    handed: dict[str, str] = {}

    async def fake_post_ephemeral(channel, user, text, blocks=None):
        posted.update(channel=channel, user=user, text=text)

    async def fake_handle(user_id, channel_id):
        handed.update(user_id=user_id, channel_id=channel_id)

    monkeypatch.setattr(meeting_notes, "post_ephemeral", fake_post_ephemeral)
    monkeypatch.setattr(meeting_notes, "handle_meeting_notes", fake_handle)

    await acknowledge_meeting_notes_request("U123USER", "C456CHAN")

    assert posted == {"channel": "C456CHAN", "user": "U123USER", "text": MEETING_NOTES_ACK}
    assert handed == {"user_id": "U123USER", "channel_id": "C456CHAN"}


async def test_app_mention_meeting_notes_triggers_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_ack(user_id, channel_id):
        calls.append((user_id, channel_id))

    monkeypatch.setattr("app.slack_events.acknowledge_meeting_notes_request", fake_ack)

    payload = {
        "type": "event_callback",
        "event": {
            "type": "app_mention",
            "user": "U1",
            "channel": "C1",
            "text": "<@U0BOT> share my meeting notes",
        },
    }
    await handle_slack_event_callback(payload)
    assert calls == [("U1", "C1")]


async def test_app_mention_unrecognised_does_not_trigger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_ack(user_id, channel_id):
        calls.append((user_id, channel_id))

    monkeypatch.setattr("app.slack_events.acknowledge_meeting_notes_request", fake_ack)

    payload = {
        "event": {
            "type": "app_mention",
            "user": "U1",
            "channel": "C1",
            "text": "<@U0BOT> what's the weather today",
        },
    }
    await handle_slack_event_callback(payload)
    assert calls == []


async def test_app_mention_from_bot_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    async def fake_ack(user_id, channel_id):
        calls.append((user_id, channel_id))

    monkeypatch.setattr("app.slack_events.acknowledge_meeting_notes_request", fake_ack)

    payload = {
        "event": {
            "type": "app_mention",
            "bot_id": "B999",
            "user": "U1",
            "channel": "C1",
            "text": "<@U0BOT> meeting notes",
        },
    }
    await handle_slack_event_callback(payload)
    assert calls == []


def test_existing_doc_intent_unaffected() -> None:
    # The slash-command intent layer is unchanged: "notes" still routes to "doc",
    # so existing handlers keep working alongside the new @mention flow.
    assert detect_action("meeting notes for launch") == "doc"
