"""Action-item digest: gather context, extract owners, post @mentions, track status from replies."""
from __future__ import annotations

import asyncio
import json
import os
import re
from inspect import cleandoc
from typing import Any

from db import (
    ACTION_ITEM_ACTIVE_STATUSES,
    create_action_item_digest,
    create_user_draft,
    get_github_token,
    get_granola_token,
    list_active_action_items,
    update_action_item_status,
    upsert_action_items,
    user_has_google_tokens,
    user_has_granola_tokens,
    user_has_github_tokens,
)

from app.claude_client import call_claude
from app.config import logger
from app.github_http import fetch_merged_prs_for_repo_range, fetch_opened_prs_for_repo_range
from app.action_items_sheet import sync_action_items_sheet, sync_sheet_after_status_updates
from app.granola_summarize import _format_notes_for_prompt, collect_granola_notes_for_window
from app.slack_api import (
    fetch_slack_channel_history_since,
    notify_user_ephemeral,
    post_message,
    slack_channel_bookmarks_for_weekly,
)
from app.weekly_context import (
    parse_weekly_status_time_range,
    resolve_github_repos_for_weekly_status,
    utc_date_start_slack_ts,
)
from app.weekly_drive import action_items_google_docs_block

_ACTION_PREFIXES = (
    "action items",
    "action item",
    "actions",
    "todos",
)

_STATUS_LABELS = {
    "open": "open",
    "in_progress": "in progress",
    "done": "done",
    "wont_do": "won't do",
}


def parse_action_items_command(text: str) -> str | None:
    """If text is an action-items command, return remainder after keyword; else None."""
    raw = (text or "").strip()
    if not raw:
        return None
    lower = raw.lower()
    for prefix in _ACTION_PREFIXES:
        if lower == prefix:
            return ""
        if lower.startswith(prefix + " "):
            return raw[len(prefix) :].strip()
    return None


def parse_action_items_time_window(remainder: str) -> tuple[str, str, str]:
    r = (remainder or "").strip()
    if not r or r.lower().startswith("--"):
        days = int((os.environ.get("ACTION_ITEMS_LOOKBACK_DAYS") or "14").strip() or "14")
        days = max(1, min(366, days))
        from datetime import datetime, timedelta, timezone

        today = datetime.now(timezone.utc).date()
        start = today - timedelta(days=days)
        return start.isoformat(), today.isoformat(), f"last {days} day(s)"
    since_d, until_d, label = parse_weekly_status_time_range(r)
    return since_d, until_d, label


def _strip_flags(remainder: str) -> tuple[str, bool]:
    """Return (text for date parsing, auto_publish). Reuses weekly --no-approval flags."""
    from app.weekly_context import strip_weekly_status_auto_post_flags

    return strip_weekly_status_auto_post_flags(remainder)


async def _gather_context_blocks(
    user: str,
    hist_channel: str,
    since_d: str,
    until_d: str,
    slack_digest: str,
) -> str:
    """Optional Google Drive, Granola, GitHub snippets appended to the Claude prompt."""
    blocks: list[str] = []
    bookmark_google, bookmark_md = await slack_channel_bookmarks_for_weekly(hist_channel)
    if bookmark_md:
        blocks.append(f"### Channel bookmarks\n{bookmark_md}")

    if await user_has_google_tokens(user):
        try:
            docs_block = await action_items_google_docs_block(
                user,
                slack_digest,
                extra_google_urls=bookmark_google,
            )
            if docs_block.strip():
                blocks.append(docs_block.strip())
            else:
                blocks.append(
                    "_(No Google Doc links in channel messages or bookmarks — "
                    "post or bookmark a doc URL to include outstanding tasks from Docs.)_"
                )
        except Exception as e:
            logger.warning("Action items Google Docs block failed: %s", e)
            blocks.append(f"_(Google Docs unavailable: {e})_")
    else:
        blocks.append("_(Google not connected — skipping Docs/Drive scan.)_")

    if await user_has_granola_tokens(user):
        try:
            bearer = await get_granola_token(user)
            notes = await collect_granola_notes_for_window(bearer, since_d, until_d)
            if notes:
                max_chars = max(
                    4000,
                    min(
                        80_000,
                        int(
                            (os.environ.get("ACTION_ITEMS_GRANOLA_MAX_CHARS") or "28000").strip()
                            or "28000"
                        ),
                    ),
                )
                blocks.append(
                    "### Granola meeting notes\n"
                    "_Extract action items, next steps, and owners from summaries and transcripts._\n\n"
                    + _format_notes_for_prompt(notes, max_chars)
                )
            else:
                blocks.append(
                    f"_(No Granola notes between {since_d} and {until_d} — widen the date window if needed.)_"
                )
        except Exception as e:
            logger.warning("Action items Granola fetch failed: %s", e)
            blocks.append(f"_(Granola unavailable: {e})_")
    else:
        blocks.append("_(Granola not connected — run `/susan connect granola` to include meeting notes.)_")

    if await user_has_github_tokens(user):
        repos, err = resolve_github_repos_for_weekly_status()
        if repos and not err:
            try:
                gh_token = await get_github_token(user)
                gh_lines: list[str] = []

                async def one_repo(r: str) -> str:
                    merged, opened = await asyncio.gather(
                        fetch_merged_prs_for_repo_range(r, since_d, until_d, gh_token),
                        fetch_opened_prs_for_repo_range(r, since_d, until_d, gh_token),
                    )
                    parts = [f"#### `{r}`"]
                    for it in merged[:20]:
                        t = (it.get("title") or "").replace("\n", " ")
                        url = (it.get("html_url") or "").strip()
                        parts.append(f"- merged: {url or t} — {t}")
                    for it in opened[:15]:
                        t = (it.get("title") or "").replace("\n", " ")
                        url = (it.get("html_url") or "").strip()
                        parts.append(f"- opened: {url or t} — {t}")
                    return "\n".join(parts)

                gh_lines = await asyncio.gather(*[one_repo(r) for r in repos[:8]])
                blocks.append("### GitHub PR activity\n" + "\n\n".join(gh_lines))
            except Exception as e:
                logger.warning("Action items GitHub fetch failed: %s", e)
                blocks.append(f"_(GitHub unavailable: {e})_")
        elif err:
            blocks.append(f"_(GitHub repos not configured: {err})_")
    else:
        blocks.append("_(GitHub not connected — run `/susan connect github` for PR context.)_")

    blocks.append(
        "_(Calendar read is not enabled; action items come from Slack, Drive, Granola, and GitHub when connected.)_"
    )
    return "\n\n".join(blocks)


def _format_items_for_claude(items: list[dict]) -> str:
    if not items:
        return "(none — first run for this channel)"
    lines = []
    for i, it in enumerate(items, 1):
        assignee = it.get("assignee_slack_id") or "unassigned"
        st = it.get("status") or "open"
        note = it.get("status_note") or ""
        lines.append(
            f"{i}. id={it['id']} status={st} assignee={assignee} text={it['text']!r}"
            + (f" note={note!r}" if note else "")
        )
    return "\n".join(lines)


def _parse_extraction_json(raw: str) -> list[dict]:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    data = json.loads(text)
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        t = (it.get("text") or "").strip()
        if not t:
            continue
        assignee = (it.get("assignee_slack_id") or "").strip() or None
        if assignee and not re.match(r"^U[A-Z0-9]{8,}$", assignee):
            assignee = None
        status = (it.get("status") or "open").strip().lower()
        if status not in ACTION_ITEM_ACTIVE_STATUSES | {"done", "wont_do"}:
            status = "open"
        out.append(
            {
                "id": (it.get("id") or "").strip() or None,
                "text": t[:500],
                "assignee_slack_id": assignee,
                "status": status,
                "source": (it.get("source") or "slack")[:16],
                "status_note": (it.get("status_note") or "").strip() or None,
            }
        )
    return out


def _build_item_numbers(items: list[dict]) -> dict[str, int]:
    """Stable global numbers for thread status replies (#1, #2, …)."""
    numbers: dict[str, int] = {}
    for i, it in enumerate(items, 1):
        iid = (it.get("id") or "").strip()
        if iid:
            numbers[iid] = i
    return numbers


def _group_items_by_assignee(items: list[dict]) -> list[tuple[str | None, list[dict]]]:
    """Return (assignee_slack_id, items) groups; unassigned last; stable within assignee."""
    buckets: dict[str | None, list[dict]] = {}
    for it in items:
        aid = (it.get("assignee_slack_id") or "").strip() or None
        buckets.setdefault(aid, []).append(it)

    def sort_key(aid: str | None) -> tuple[int, str]:
        if aid is None:
            return (1, "")
        return (0, aid.lower())

    out: list[tuple[str | None, list[dict]]] = []
    for aid in sorted(buckets.keys(), key=sort_key):
        out.append((aid, buckets[aid]))
    return out


def _format_item_line(it: dict, number: int) -> str:
    st = _STATUS_LABELS.get(it.get("status") or "open", "open")
    note = (it.get("status_note") or "").strip()
    note_part = f" — _{note}_" if note else ""
    return f"*{number}.* {it['text']} _({st}{note_part})_"


def format_action_items_header(
    range_label: str,
    *,
    include_instructions: bool = True,
    sheet_url: str | None = None,
    item_count: int = 0,
) -> str:
    """Short digest header (sheet link + thread instructions)."""
    if item_count:
        summary = f"*{item_count}* outstanding action item(s) — {range_label}"
    else:
        summary = f"*Outstanding action items* — {range_label}\n\n_No outstanding action items._"
    header = summary
    if sheet_url:
        header += (
            f"\n\n📎 *Ledger:* <{sheet_url}|Open Google Sheet> "
            "_(edit tasks/status here — Susan syncs on the next run)_"
        )
    if include_instructions and item_count:
        header += (
            "\n\n_Reply in this thread with status updates: `done`, `in progress`, or `won't do` "
            "(reference `#1` or describe the item). Susan remembers updates for the next roundup._"
        )
    return header


def format_assignee_action_items_message(
    assignee_slack_id: str | None,
    items: list[dict],
    item_numbers: dict[str, int],
) -> str:
    """One Slack message tagging a single assignee with their numbered items."""
    if not items:
        return ""
    count = len(items)
    if assignee_slack_id:
        lines = [f"<@{assignee_slack_id}> you have *{count}* outstanding:"]
    else:
        lines = [f"*Unassigned* — *{count}* item(s):"]
    for it in items:
        iid = (it.get("id") or "").strip()
        num = item_numbers.get(iid)
        if num is None:
            continue
        lines.append(_format_item_line(it, num))
    return "\n".join(lines)


def format_action_items_message(
    items: list[dict],
    range_label: str,
    *,
    include_instructions: bool = True,
    sheet_url: str | None = None,
) -> str:
    """Full preview text: header plus one block per assignee (same layout as channel posts)."""
    active = [it for it in items if it.get("status") in ACTION_ITEM_ACTIVE_STATUSES]
    if not active:
        return format_action_items_header(
            range_label,
            include_instructions=include_instructions,
            sheet_url=sheet_url,
            item_count=0,
        )
    item_numbers = _build_item_numbers(active)
    parts = [
        format_action_items_header(
            range_label,
            include_instructions=False,
            sheet_url=sheet_url,
            item_count=len(active),
        )
    ]
    for assignee_id, group in _group_items_by_assignee(active):
        block = format_assignee_action_items_message(assignee_id, group, item_numbers)
        if block:
            parts.append(block)
    body = "\n\n".join(parts)
    if include_instructions:
        body += (
            "\n\n_Reply in this thread with status updates: `done`, `in progress`, or `won't do` "
            "(reference `#1` or describe the item). Susan remembers updates for the next roundup._"
        )
    return body


async def _extract_action_items_with_claude(
    *,
    range_label: str,
    slack_digest: str,
    extra_context: str,
    existing_items: list[dict],
) -> list[dict]:
    system = cleandoc(
        """
        You are Susan. Extract actionable tasks with clear owners from ALL provided sources.

        Output ONLY valid JSON (no markdown outside the JSON):

        {
          "items": [
            {
              "id": "<existing uuid or null for new>",
              "text": "<short imperative task>",
              "assignee_slack_id": "<Slack user id U… from transcript, or null>",
              "status": "open|in_progress|done|wont_do",
              "source": "slack|granola|drive|github",
              "status_note": "<optional>"
            }
          ]
        }

        Where to look (scan every section — do not rely on Slack main messages alone):
        - **Slack channel**: top-level messages AND lines indented under `[thread replies on …]`.
          Commitments, "I'll …", "@mention please …", and numbered follow-ups in threads count.
        - **Google Docs**: unchecked checklist items, "Action items", "TODO", "Owner", tables with
          open tasks, and any line that implies someone still owes work. Use source "drive".
        - **Granola notes**: "Action items", "Next steps", "Follow-ups", and transcript commitments.
          Map owners to Slack U… ids only when the same person appears in the Slack transcript;
          otherwise assignee_slack_id is null but still include the task (source "granola").
        - **GitHub**: opened PRs that imply follow-up work (reviews, merges pending, TODO in title).

        Rules:
        - Merge with EXISTING TRACKED ITEMS: reuse `id` when the same task; preserve
          in_progress/done/wont_do unless sources clearly contradict.
        - Do not re-open done/wont_do items unless explicitly reopened in new sources.
        - Prefer Slack user ids (U…) seen anywhere in the Slack section for assignees.
        - Include important unassigned items rather than dropping them.
        - Deduplicate the same task across sources (one row, best source label).
        - Maximum 25 items; prefer still-open / outstanding work.
        """
    )
    user_prompt = (
        f"Window: {range_label}\n\n"
        f"--- EXISTING TRACKED ITEMS ---\n{_format_items_for_claude(existing_items)}\n\n"
        f"--- SLACK CHANNEL (main messages + thread replies; user ids are U…) ---\n{slack_digest}\n\n"
        f"--- OTHER SOURCES (Docs, Granola, GitHub) ---\n{extra_context}"
    )
    raw = await call_claude(system, user_prompt, max_tokens=4096)
    try:
        return _parse_extraction_json(raw)
    except json.JSONDecodeError as e:
        logger.error("Action items JSON parse failed: %s raw=%r", e, raw[:500])
        raise RuntimeError("Could not parse action items from Claude") from e


async def publish_action_items_digest(
    *,
    channel_id: str,
    thread_ts: str | None,
    user: str,
    range_label: str,
    since_d: str,
    until_d: str,
    items: list[dict],
    sheet_url: str | None = None,
) -> str:
    """Post digest to channel (header + one @mention message per assignee), persist items."""
    active_for_display = [
        it
        for it in items
        if it.get("status") in ACTION_ITEM_ACTIVE_STATUSES
    ]
    header = format_action_items_header(
        range_label,
        sheet_url=sheet_url,
        item_count=len(active_for_display),
    )
    title = f"Action items — {range_label}"
    post_thread = thread_ts
    if post_thread:
        data = await post_message(channel_id, header, thread_ts=post_thread)
        message_ts = str(data.get("ts") or "")
        thread_root_ts = post_thread
    else:
        data = await post_message(channel_id, header if active_for_display else f"*{title}*\n\n{header}")
        message_ts = str(data.get("ts") or "")
        thread_root_ts = message_ts
    if not message_ts:
        raise RuntimeError("Slack did not return message ts for action items digest")

    if active_for_display:
        item_numbers = _build_item_numbers(active_for_display)
        for assignee_id, group in _group_items_by_assignee(active_for_display):
            block = format_assignee_action_items_message(
                assignee_id, group, item_numbers
            )
            if block:
                await post_message(channel_id, block, thread_ts=thread_root_ts)

    digest_id = await create_action_item_digest(
        channel_id, message_ts, thread_root_ts, user, range_label, since_d, until_d
    )
    await upsert_action_items(channel_id, items, digest_id=digest_id)
    return message_ts


async def process_action_items(
    command_text: str,
    hist_channel: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
    *,
    auto_publish: bool = False,
) -> None:
    remainder, auto_publish_flag = _strip_flags(command_text)
    auto_publish = auto_publish or auto_publish_flag

    since_d, until_d, range_label = parse_action_items_time_window(remainder)
    oldest_ts = utc_date_start_slack_ts(since_d)

    sheet_url: str | None = None
    sheet_err: str | None = None
    if await user_has_google_tokens(user):
        try:
            sheet_url = await sync_action_items_sheet(user, hist_channel)
        except Exception as e:
            sheet_err = str(e)
            logger.warning("Action items sheet setup failed: %s", e)
    else:
        sheet_err = (
            "Google is not connected — action items will not be saved to a Sheet. "
            "Run `/susan connect google` to create the team ledger on first use."
        )

    try:
        slack_digest = await fetch_slack_channel_history_since(
            hist_channel, oldest_ts, user, include_thread_replies=True
        )
    except Exception as e:
        logger.exception("Action items Slack fetch failed")
        await notify_user_ephemeral(channel, user, f"Susan error (Slack): {e}", None, response_url)
        return

    extra = await _gather_context_blocks(user, hist_channel, since_d, until_d, slack_digest)
    existing = await list_active_action_items(hist_channel)

    try:
        extracted = await _extract_action_items_with_claude(
            range_label=range_label,
            slack_digest=slack_digest,
            extra_context=extra,
            existing_items=existing,
        )
    except Exception as e:
        logger.exception("Action items extraction failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    merged = await upsert_action_items(hist_channel, extracted)
    display_items = [it for it in merged if it.get("status") in ACTION_ITEM_ACTIVE_STATUSES]

    if await user_has_google_tokens(user):
        try:
            sheet_url = await sync_action_items_sheet(user, hist_channel) or sheet_url
        except Exception as e:
            logger.warning("Action items sheet export failed: %s", e)

    sheet_note = ""
    if sheet_url:
        sheet_note = f"\n\n📎 Ledger: {sheet_url}"
    elif sheet_err:
        sheet_note = f"\n\n⚠️ _Sheet ledger (optional): {sheet_err}_"

    if auto_publish:
        try:
            await publish_action_items_digest(
                channel_id=channel,
                thread_ts=thread_ts,
                user=user,
                range_label=range_label,
                since_d=since_d,
                until_d=until_d,
                items=display_items,
                sheet_url=sheet_url,
            )
        except Exception as e:
            logger.exception("Action items auto-publish failed")
            await notify_user_ephemeral(
                channel, user, f"Could not post action items: {e}", None, response_url
            )
            return
        await notify_user_ephemeral(
            channel,
            user,
            f"✓ Posted *{len(display_items)}* outstanding action item(s) to the channel (_no approval step_).{sheet_note}",
            None,
            response_url,
        )
        return

    body = format_action_items_message(display_items, range_label, sheet_url=sheet_url)
    title = f"Action items — {range_label}"
    meta = {
        "title": title,
        "body": body,
        "channel_id": channel,
        "thread_ts": thread_ts,
        "hist_channel": hist_channel,
        "range_label": range_label,
        "since_d": since_d,
        "until_d": until_d,
        "items": display_items,
        "sheet_url": sheet_url,
    }
    draft_id = await create_user_draft(user, "action_items", json.dumps(meta, ensure_ascii=False))
    preview = body[:2800] + ("..." if len(body) > 2800 else "")
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Susan preview — action items*\n_(Only visible to you)_\n"
                    "_Approve to post grouped @mention messages to the channel; team replies in the thread update status._"
                    f"{sheet_note}"
                ),
            },
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": preview}},
        {
            "type": "actions",
            "block_id": f"susan_actions_{channel}_{thread_ts or 'none'}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✓ Approve & post to channel"},
                    "style": "primary",
                    "action_id": "approve_action_items",
                    "value": draft_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✗ Cancel"},
                    "action_id": "cancel_susan",
                    "value": draft_id,
                },
            ],
        },
    ]
    await notify_user_ephemeral(
        channel,
        user,
        f"Action items preview ready ({len(display_items)} outstanding)",
        blocks,
        response_url,
    )


async def apply_status_reply_with_claude(
    channel_id: str,
    user_id: str,
    reply_text: str,
    items: list[dict],
) -> list[dict]:
    """Parse a thread reply into status updates; returns updated item dicts."""
    if not items or not (reply_text or "").strip():
        return []
    system = cleandoc(
        """
        You parse Slack replies about action-item status. Output ONLY JSON:

        {"updates": [{"item_id": "<uuid>", "status": "open|in_progress|done|wont_do", "note": "<optional short note>"}]}

        Map natural language: done/finished/complete -> done; won't do/cancelled -> wont_do;
        working on/wip/started -> in_progress. Match items by number (#1), quoted text, or meaning.
        If nothing matches, return {"updates": []}.
        """
    )
    numbered = "\n".join(
        f"{i}. id={it['id']} status={it['status']} text={it['text']!r}"
        for i, it in enumerate(items, 1)
        if it.get("status") in ACTION_ITEM_ACTIVE_STATUSES
    )
    user_prompt = f"Items:\n{numbered}\n\nReply from <@{user_id}>:\n{reply_text}"
    raw = await call_claude(system, user_prompt, max_tokens=1024)
    try:
        text = raw.strip()
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if fence:
            text = fence.group(1).strip()
        data = json.loads(text)
        updates = data.get("updates") or []
    except json.JSONDecodeError:
        logger.warning("Status reply JSON parse failed: %r", raw[:300])
        return []

    updated: list[dict] = []
    for u in updates:
        if not isinstance(u, dict):
            continue
        iid = (u.get("item_id") or "").strip()
        status = (u.get("status") or "").strip().lower()
        note = (u.get("note") or "").strip() or None
        if not iid:
            continue
        row = await update_action_item_status(
            iid, channel_id, status, note=note, updated_by=user_id
        )
        if row:
            updated.append(row)
    if updated:
        try:
            from db import get_action_items_registry

            reg = await get_action_items_registry()
            sync_user = (reg or {}).get("created_by_slack_user_id") or user_id
            await sync_sheet_after_status_updates(sync_user, channel_id)
        except Exception as e:
            logger.warning("Sheet sync after status reply failed: %s", e)
    return updated


def format_status_ack(updated: list[dict]) -> str:
    if not updated:
        return ""
    parts = []
    for it in updated:
        st = _STATUS_LABELS.get(it.get("status") or "", it.get("status") or "")
        parts.append(f"• _{it['text'][:80]}_ → *{st}*")
    return "Updated:\n" + "\n".join(parts)
