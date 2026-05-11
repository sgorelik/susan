"""Granola-only slash flow: fetch notes from the public API and summarize with Claude."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.claude_client import call_claude
from app.config import logger
from app.slack_api import notify_user_ephemeral
from app.weekly_context import parse_weekly_status_time_range
from db import get_granola_token


def parse_granola_slash_command(text: str) -> str | None:
    """If text is a Granola test command, return the remainder after the keyword; else None.

    Accepts ``granola …`` or short ``gn …`` (only when ``gn`` is the whole first token).
    """
    raw = (text or "").strip()
    if not raw:
        return None
    lower = raw.lower()
    if lower == "granola" or lower.startswith("granola "):
        return raw[len("granola") :].strip()
    if lower == "gn" or lower.startswith("gn "):
        return raw[2:].strip()
    return None


def parse_granola_time_window(remainder: str) -> tuple[str, str, str]:
    """Return ``(since_date, until_date, human_label)`` as YYYY-MM-DD (UTC dates, inclusive)."""
    r = (remainder or "").strip()
    if not r:
        days = int((os.environ.get("GRANOLA_LOOKBACK_DAYS") or "7").strip() or "7")
        days = max(1, min(366, days))
        today = datetime.now(timezone.utc).date()
        start = today - timedelta(days=days)
        label = f"last {days} day(s) (GRANOLA_LOOKBACK_DAYS default)"
        return start.isoformat(), today.isoformat(), label
    since_d, until_d, label = parse_weekly_status_time_range(r)
    return since_d, until_d, label


def granola_api_base() -> str:
    return (
        (os.environ.get("GRANOLA_API_BASE") or "https://public-api.granola.ai").strip().rstrip("/")
        or "https://public-api.granola.ai"
    )


def _granola_max_notes() -> int:
    n = int((os.environ.get("GRANOLA_SUMMARY_MAX_NOTES") or "12").strip() or "12")
    return max(1, min(40, n))


def _granola_max_list_pages() -> int:
    n = int((os.environ.get("GRANOLA_SUMMARY_MAX_LIST_PAGES") or "5").strip() or "5")
    return max(1, min(20, n))


def _include_transcript() -> bool:
    return (os.environ.get("GRANOLA_SUMMARY_INCLUDE_TRANSCRIPT") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


async def _granola_list_page(
    client: httpx.AsyncClient,
    bearer: str,
    *,
    created_after: str | None,
    created_before: str | None,
    cursor: str | None,
    page_size: int,
) -> dict[str, Any]:
    params: dict[str, str] = {"page_size": str(page_size)}
    if created_after:
        params["created_after"] = created_after
    if created_before:
        params["created_before"] = created_before
    if cursor:
        params["cursor"] = cursor
    r = await client.get(
        f"{granola_api_base()}/v1/notes",
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        params=params,
    )
    r.raise_for_status()
    return r.json()


async def _granola_get_note(
    client: httpx.AsyncClient, bearer: str, note_id: str, *, include_transcript: bool
) -> dict[str, Any]:
    params: dict[str, str] = {}
    if include_transcript:
        params["include"] = "transcript"
    r = await client.get(
        f"{granola_api_base()}/v1/notes/{note_id}",
        headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
        params=params or None,
    )
    r.raise_for_status()
    return r.json()


def _note_sort_key(n: dict[str, Any]) -> str:
    return (n.get("updated_at") or n.get("created_at") or "")[:32]


async def collect_granola_notes_for_window(
    bearer: str, since_d: str, until_d: str
) -> list[dict[str, Any]]:
    """List notes in the date window, then fetch detail (summary; optional transcript)."""
    until_date = datetime.strptime(until_d, "%Y-%m-%d").date()
    created_before = (until_date + timedelta(days=1)).isoformat()
    created_after = f"{since_d}T00:00:00Z"
    summaries: list[dict[str, Any]] = []
    cursor: str | None = None
    page_size = 30
    max_pages = _granola_max_list_pages()
    out: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=60) as client:
        for _ in range(max_pages):
            data = await _granola_list_page(
                client,
                bearer,
                created_after=created_after,
                created_before=created_before,
                cursor=cursor,
                page_size=page_size,
            )
            batch = data.get("notes") or []
            if isinstance(batch, list):
                summaries.extend([x for x in batch if isinstance(x, dict)])
            if not data.get("hasMore"):
                break
            cursor = data.get("cursor")
            if not cursor:
                break

        summaries.sort(key=_note_sort_key, reverse=True)
        cap = _granola_max_notes()
        picked = summaries[:cap]
        inc_t = _include_transcript()
        for s in picked:
            nid = s.get("id")
            if not isinstance(nid, str) or not nid.startswith("not_"):
                continue
            try:
                detail = await _granola_get_note(client, bearer, nid, include_transcript=inc_t)
                out.append(detail)
            except httpx.HTTPStatusError as e:
                logger.warning("Granola get note %s: HTTP %s", nid, e.response.status_code)
            except Exception as e:
                logger.warning("Granola get note %s: %s", nid, e)
    return out


def _format_notes_for_prompt(notes: list[dict[str, Any]], max_chars: int) -> str:
    parts: list[str] = []
    total = 0
    for i, n in enumerate(notes, 1):
        title = n.get("title") or "(untitled)"
        created = n.get("created_at") or ""
        sm = n.get("summary_markdown") or n.get("summary_text") or ""
        attendees = n.get("attendees") or []
        att_s = ""
        if isinstance(attendees, list):
            emails = [
                str(a.get("email", ""))
                for a in attendees
                if isinstance(a, dict) and a.get("email")
            ]
            att_s = ", ".join(emails[:20])
        block = (
            f"### Note {i}: {title}\n"
            f"- created: {created}\n"
            f"- attendees: {att_s or '(none listed)'}\n\n"
            f"{sm}\n"
        )
        tr = n.get("transcript")
        if isinstance(tr, list) and tr:
            lines = []
            for seg in tr[:200]:
                if not isinstance(seg, dict):
                    continue
                t = (seg.get("text") or "").strip()
                if t:
                    lines.append(t)
            if lines:
                block += "\n_Transcript (excerpt):_\n" + "\n".join(lines[:80]) + "\n"
        if total + len(block) > max_chars:
            parts.append(f"_…{len(notes) - i + 1} further note(s) omitted to fit context._")
            break
        parts.append(block)
        total += len(block)
    return "\n---\n".join(parts)


def _truncate_slack(s: str, limit: int = 3900) -> str:
    s = (s or "").strip()
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 20)] + "\n…_(truncated)_"


async def process_granola_summarize(
    remainder: str,
    channel_id: str,
    slack_user_id: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    """Fetch Granola notes for the parsed window and post a Claude summary (ephemeral)."""
    since_d, until_d, label = parse_granola_time_window(remainder)
    user_instr = (remainder or "").strip() or "Give a concise overview: themes, decisions, and follow-ups."

    try:
        token = await get_granola_token(slack_user_id)
    except ValueError as e:
        await notify_user_ephemeral(channel_id, slack_user_id, str(e), None, response_url)
        return

    try:
        notes = await collect_granola_notes_for_window(token, since_d, until_d)
    except httpx.HTTPStatusError as e:
        msg = f"Granola API error ({e.response.status_code}). If you just connected, try `/susan connect granola` again or check OAuth/API access."
        if e.response.status_code == 401:
            msg = (
                "Granola returned 401 (unauthorized). Your OAuth token may not include API access — "
                "check `GRANOLA_OAUTH_SCOPE` with Granola, or reconnect with `/susan connect granola`."
            )
        logger.warning("Granola list/get failed: %s", e)
        await notify_user_ephemeral(channel_id, slack_user_id, msg, None, response_url)
        return
    except Exception as e:
        logger.exception("Granola fetch failed")
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            f"Could not load Granola notes: {e}",
            None,
            response_url,
        )
        return

    if not notes:
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            f"No Granola notes found for *{label}*. Try a wider window (e.g. `last 30 days`) or check Granola for that period.",
            None,
            response_url,
        )
        return

    bundle = _format_notes_for_prompt(notes, max_chars=100_000)
    system = (
        "You are Susan. The user asked for a summary of their Granola meeting notes for a specific time window. "
        "Use only the note content provided. Be accurate; if something is not in the notes, say so. "
        "Structure with short sections (e.g. Overview, Key themes, Decisions, Action items / follow-ups). "
        "Use Slack mrkdwn: *bold* bullets, not **."
    )
    user_prompt = (
        f"Time window: {label} ({since_d} → {until_d} UTC, inclusive dates).\n"
        f"User request: {user_instr}\n\n"
        f"--- Granola notes ({len(notes)} meetings) ---\n{bundle}"
    )

    try:
        summary = await call_claude(system, user_prompt, max_tokens=8192)
    except Exception as e:
        logger.exception("Granola Claude summarize failed")
        await notify_user_ephemeral(
            channel_id,
            slack_user_id,
            f"Granola notes loaded ({len(notes)}), but summarization failed: {e}",
            None,
            response_url,
        )
        return

    header = f"*Granola summary* — {label} — {len(notes)} note(s)\n\n"
    await notify_user_ephemeral(
        channel_id,
        slack_user_id,
        _truncate_slack(header + summary),
        None,
        response_url,
    )
