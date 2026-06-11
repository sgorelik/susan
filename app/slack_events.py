"""Slack Events API: thread replies on action-item digests update tracked status."""
from __future__ import annotations

import json

from db import get_digest_for_thread, list_active_action_items

from app.action_items import apply_status_reply_with_claude, format_status_ack
from app.config import logger
from app.slack_api import post_ephemeral


async def handle_slack_event_callback(payload: dict) -> None:
    event = payload.get("event") or {}
    if event.get("type") != "message":
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
