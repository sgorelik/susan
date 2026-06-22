"""Publish weekly status to a Slack Canvas and announce with a short channel link."""
from __future__ import annotations

import os
import re

from app.config import logger
from app.slack_api import (
    post_message,
    post_pr_summary_to_channel,
    slack_api_canvases_create,
    slack_api_files_permalink,
)

_SLACK_LINK_RE = re.compile(r"<(https?://[^|>]+)\|([^>]+)>")
_SLACK_BARE_LINK_RE = re.compile(r"<(https?://[^>]+)>")
_SLACK_BOLD_RE = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")


def weekly_status_use_canvas() -> bool:
    raw = (os.environ.get("WEEKLY_STATUS_USE_CANVAS") or "true").strip().lower()
    return raw not in ("0", "false", "no", "off")


def slack_mrkdwn_to_canvas_markdown(text: str) -> str:
    """Best-effort Slack mrkdwn → Canvas markdown (Claude weekly output)."""
    s = (text or "").strip()
    if not s:
        return ""

    def link_sub(m: re.Match[str]) -> str:
        return f"[{m.group(2).strip()}]({m.group(1).strip()})"

    s = _SLACK_LINK_RE.sub(link_sub, s)
    s = _SLACK_BARE_LINK_RE.sub(lambda m: m.group(1), s)
    s = _SLACK_BOLD_RE.sub(r"**\1**", s)
    return s


def _canvas_document_markdown(title: str, body: str) -> str:
    converted = slack_mrkdwn_to_canvas_markdown(body)
    title_line = (title or "Weekly status").strip()
    parts = [f"# {title_line}", "", converted, "", "---", "_Posted via Susan_"]
    return "\n".join(p for p in parts if p is not None)


async def publish_weekly_status(
    channel: str,
    thread_ts: str | None,
    title: str,
    body: str,
) -> None:
    """Post weekly status to Canvas when enabled; otherwise fall back to long channel messages."""
    if weekly_status_use_canvas():
        try:
            await _publish_weekly_status_to_canvas(channel, thread_ts, title, body)
            return
        except Exception as e:
            logger.warning(
                "Weekly status canvas publish failed (%s); falling back to channel message",
                e,
            )
    await post_pr_summary_to_channel(channel, thread_ts, title, body)


async def _publish_weekly_status_to_canvas(
    channel: str,
    thread_ts: str | None,
    title: str,
    body: str,
) -> None:
    markdown = _canvas_document_markdown(title, body)
    canvas_id = await slack_api_canvases_create(
        title=(title or "Weekly status")[:150],
        markdown=markdown,
        channel_id=channel,
    )
    permalink = await slack_api_files_permalink(canvas_id)
    link_label = "Open weekly update in Canvas"
    announce = (
        f"*{title.strip()}*\n"
        f"<{permalink}|{link_label}> · _Posted via Susan_"
    )
    await post_message(
        channel,
        announce,
        thread_ts=thread_ts,
        unfurl_links=False,
        unfurl_media=False,
    )
