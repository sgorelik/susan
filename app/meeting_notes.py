"""Meeting-notes intent: detect an @mention request and acknowledge it (Step 1).

Step 1 of a multi-phase feature. This module only recognises when a user is
asking Susan for meeting notes via an @mention, immediately acknowledges the
request to the triggering user, and hands ``(user_id, channel_id)`` off to the
meeting-notes handler.

The handler here is a placeholder: calendar lookup, Granola fetch, Drive
aggregation, and composing/posting the full summary are implemented in later
tickets.
"""
from __future__ import annotations

import re

from app.config import logger
from app.slack_api import post_ephemeral

# Phrases that signal a meeting-notes request. Matched case-insensitively as a
# substring after light normalisation (common determiners like "the"/"my" are
# dropped), so variations such as "post the notes" and "share my meeting notes"
# still match the listed phrases.
MEETING_NOTES_PHRASES: tuple[str, ...] = (
    "meeting notes",
    "share notes",
    "post notes",
    "notes from",
)

# Ephemeral acknowledgement posted to the user the moment intent is detected.
MEETING_NOTES_ACK = "Looking up your last meeting…"

# Determiners/possessives dropped before matching so an inserted filler word
# does not break a phrase (e.g. "post the notes" -> "post notes").
_FILLER_WORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "my",
        "our",
        "your",
        "their",
        "his",
        "her",
        "its",
        "this",
        "that",
        "these",
        "those",
    }
)


def _normalize_for_match(text: str) -> str:
    """Lowercase, drop punctuation and filler words, collapse to single spaces."""
    tokens = re.findall(r"[a-z0-9]+", (text or "").lower())
    return " ".join(t for t in tokens if t not in _FILLER_WORDS)


def is_meeting_notes_request(text: str) -> bool:
    """True when the @mention text asks Susan for meeting notes."""
    normalized = _normalize_for_match(text)
    if not normalized:
        return False
    return any(phrase in normalized for phrase in MEETING_NOTES_PHRASES)


def extract_mention_event(event: dict) -> tuple[str, str, str]:
    """Pull ``(user_id, channel_id, text)`` from a Slack app_mention payload."""
    user_id = (event.get("user") or "").strip()
    channel_id = (event.get("channel") or "").strip()
    text = (event.get("text") or "").strip()
    return user_id, channel_id, text


async def acknowledge_meeting_notes_request(user_id: str, channel_id: str) -> None:
    """Acknowledge the request to the user, then hand off to the handler."""
    await post_ephemeral(channel_id, user_id, MEETING_NOTES_ACK)
    await handle_meeting_notes(user_id, channel_id)


async def handle_meeting_notes(user_id: str, channel_id: str) -> None:
    """Downstream meeting-notes handler (placeholder for Step 1).

    Later tickets implement the pipeline (calendar lookup -> Granola fetch ->
    Drive aggregation -> summary). For now this only records the handoff.
    """
    logger.info(
        "Meeting-notes request accepted (user=%s channel=%s); pipeline pending.",
        user_id,
        channel_id,
    )
