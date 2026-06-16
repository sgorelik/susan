"""Slack Events API: thread replies on action-item digests update tracked status."""
from __future__ import annotations

import json

from db import get_digest_for_thread, list_active_action_items

from app.action_items import apply_status_reply_with_claude, format_status_ack
from app.config import logger
from app.meeting_notes import (
    acknowledge_meeting_notes_request,
    extract_mention_event,
    is_meeting_notes_request,
)
from app.slack_api import post_ephemeral


async def handle_app_mention(event: dict) -> None:
    """Route @mention events. Meeting-notes intent is acknowledged immediately;
    any other mention is left untouched (no-op) so existing handlers stay intact."""
    if event.get("bot_id"):
        return
    user_id, channel_id, text = extract_mention_event(event)
    if not user_id or not channel_id or not text:
        return
    if not is_meeting_notes_request(text):
        return
    try:
        await acknowledge_meeting_notes_request(user_id, channel_id)
    except Exception:
        logger.exception("Meeting-notes acknowledgement failed")


async def handle_slack_event_callback(payload: dict) -> None:
    event = payload.get("event") or {}
    event_type = event.get("type")
    if event_type == "app_mention":
        await handle_app_mention(event)
        return
    if event_type != "message":
        return
    if event.get("bot_id") or event.get("subtype"):
        return
    channel = (event.get("channel") or "").strip()
    user = (event.get("user") or "").strip()
    text = (event.get("text") or "").strip()
    thread_ts = (event.get("thread_ts") or "").strip()
    if not channel or not user or not text:
        return
    if not thread_ts:
        return

    digest = await get_digest_for_thread(channel, thread_ts)
    if not digest:
        return

    items = await list_active_action_items(channel)
    if not items:
        return

    try:
        updated = await apply_status_reply_with_claude(channel, user, text, items)
    except Exception as e:
        logger.exception("Action item status reply failed")
        try:
            await post_ephemeral(
                channel,
                user,
                f"Could not parse status update: {e}",
            )
        except Exception:
            pass
        return

    ack = format_status_ack(updated)
    if ack:
        try:
            await post_ephemeral(channel, user, ack)
        except Exception as e:
            logger.warning("Status ack ephemeral failed: %s", e)


def parse_events_body(body: bytes) -> dict:
    return json.loads(body.decode("utf-8"))
