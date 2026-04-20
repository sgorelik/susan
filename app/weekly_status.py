"""Weekly team/repo status (Slack + optional GitHub + Drive)."""
from __future__ import annotations

import asyncio
import json
import os
from collections import Counter
from inspect import cleandoc

from db import create_user_draft, get_github_token

from app.claude_client import call_claude
from app.config import ACTIONS, logger
from app.github_http import (
    _pr_turnaround_hours,
    fetch_dependabot_alert_stats,
    fetch_merged_prs_for_repo_range,
    fetch_opened_prs_for_repo_range,
)
from app.slack_api import (
    fetch_slack_channel_history_since,
    notify_user_ephemeral,
    post_pr_summary_to_channel,
    slack_channel_bookmarks_for_weekly,
)
from app.weekly_context import parse_weekly_status_time_range, utc_date_start_slack_ts
from app.weekly_drive import weekly_status_drive_activity_block

_WEEKLY_SLACK_MRKDN = cleandoc(
    """
    Slack Block Kit *mrkdwn* rules (not GitHub/CommonMark): use *single asterisks* for bold
    only — never **double-asterisk** bold. Do not use # or ## headings. Links must use
    Slack syntax: <https://example.com/path|short visible label>. Prefer real URLs from
    the prompt (GitHub PR/issue links, Google Doc/Drive links, bookmark links); do not invent URLs.
    """
)

_WEEKLY_STRUCTURE = cleandoc(
    """
    **Output shape** (match a structured team update people can post as-is):

    - First line: *Tech team update — <plain-language reporting window>* (use *Weekly update — …*
      if the channel is not engineering-focused).

    - Split the body into **workstream / project sections**. Each section starts with a bold title line:
      *<Short workstream or initiative> (<owners>)* — owners may be Slack user ids from the transcript
      (e.g. U01…), @mentions if they appear in the thread, or names you infer; use `<@U123>` when you have a user id.

    - Under **each** workstream use exactly this pattern (Slack mrkdwn):
      *1. Last week:*
      a. …
      b. …
      *2. Next steps:*
      a. …
      b. …

    - Use sub-bullets **a. b. c.** under each numbered block. Keep lines scannable. Where a fact comes from
      GitHub, Drive, or a linked doc, include a Slack link `<url|short label>` on that line.
    - Optional short status hints in parentheses are fine when supported by the data, e.g. _(in progress)_
      or _(next week)_.

    - Close with nothing that says the message is a private draft or ephemeral.
    """
)


def _weekly_status_title_line(
    repos: list[str], range_label: str, *, include_github: bool
) -> str:
    if not include_github:
        return f"Weekly status — {range_label} — Slack"
    if len(repos) == 1:
        return f"Weekly status — {range_label} — `{repos[0]}`"
    shown = ", ".join(f"`{r}`" for r in repos[:5])
    if len(repos) > 5:
        shown += f", … (+{len(repos) - 5} more)"
    return f"Weekly status — {range_label} — {shown}"


async def process_weekly_status(
    repos: list[str],
    command_text: str,
    hist_channel: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
    *,
    include_github: bool,
    auto_publish: bool = False,
) -> None:
    since_d, until_d, range_label = parse_weekly_status_time_range(command_text)
    oldest_ts = utc_date_start_slack_ts(since_d)
    try:
        slack_digest = await fetch_slack_channel_history_since(
            hist_channel, oldest_ts, user
        )
    except Exception as e:
        logger.exception("Weekly status Slack fetch failed")
        await notify_user_ephemeral(
            channel, user, f"Susan error (Slack): {e}", None, response_url
        )
        return

    bookmark_google, bookmark_md = await slack_channel_bookmarks_for_weekly(hist_channel)
    drive_block = await weekly_status_drive_activity_block(
        user,
        since_d,
        until_d,
        slack_digest,
        extra_google_urls=bookmark_google,
    )
    bookmark_section = f"\n---\n{bookmark_md}\n" if bookmark_md else ""

    if include_github:
        if not repos:
            await notify_user_ephemeral(
                channel, user, "No repositories configured.", None, response_url
            )
            return

        try:
            token = await get_github_token(user)
        except ValueError as e:
            await notify_user_ephemeral(channel, user, str(e), None, response_url)
            return

        async def one_repo(r: str) -> tuple[str, list[dict], list[dict], dict]:
            merged, opened, dep = await asyncio.gather(
                fetch_merged_prs_for_repo_range(r, since_d, until_d, token),
                fetch_opened_prs_for_repo_range(r, since_d, until_d, token),
                fetch_dependabot_alert_stats(r, since_d, until_d, token),
            )
            return r, merged, opened, dep

        try:
            per_repo = await asyncio.gather(*[one_repo(r) for r in repos])
        except Exception as e:
            logger.exception("Weekly status GitHub fetch failed")
            await notify_user_ephemeral(
                channel, user, f"Susan error (GitHub): {e}", None, response_url
            )
            return

        github_sections: list[str] = []
        for r, merged, opened, dep in per_repo:
            authors = Counter()
            hours: list[float] = []
            titles: list[str] = []
            for it in merged:
                login = (it.get("user") or {}).get("login") or "?"
                authors[login] += 1
                th = _pr_turnaround_hours(it)
                if th is not None:
                    hours.append(th)
                titles.append((it.get("title") or "").replace("\n", " "))
            avg_h = sum(hours) / len(hours) if hours else None
            top_authors = authors.most_common(6)
            if dep.get("ok"):
                dep_lines = (
                    f"Dependabot: {dep['open_total']} open alerts now; "
                    f"fixed in window {dep['fixed_in_window']}, dismissed in window "
                    f"{dep['dismissed_in_window']}, newly opened in window {dep['new_open_in_window']}."
                )
            else:
                dep_lines = f"Dependabot: unavailable — {dep.get('hint', 'unknown')}"

            merged_lines: list[str] = []
            for it in merged[:45]:
                num = it.get("number")
                pr_title = ((it.get("title") or "") or "").replace("\n", " ")[:220]
                url = ((it.get("html_url") or "") or "").strip()
                if url:
                    merged_lines.append(f"- {url} — #{num} {pr_title}")
                elif num is not None:
                    merged_lines.append(f"- #{num} {pr_title}")
            opened_lines: list[str] = []
            for x in opened[:30]:
                num = x.get("number")
                t = ((x.get("title") or "") or "").replace("\n", " ")[:220]
                url = ((x.get("html_url") or "") or "").strip()
                if url:
                    opened_lines.append(f"- {url} — #{num} {t}")
                elif num is not None:
                    opened_lines.append(f"- #{num} {t}")
            avg_part = (
                f"{avg_h:.1f}"
                if avg_h is not None
                else "n/a (no merged PRs with created+merged timestamps)"
            )
            merged_block = "\n".join(merged_lines) if merged_lines else "(none)"
            opened_block = "\n".join(opened_lines) if opened_lines else "(none)"
            github_sections.append(
                f"### `{r}`\n"
                f"{dep_lines}\n"
                f"PRs opened in window: {len(opened)}; merged in window: {len(merged)}.\n"
                f"Average merge turnaround (hours): {avg_part}.\n"
                f"Top merged-PR authors: {', '.join(f'@{a} ({c})' for a, c in top_authors) or 'none'}.\n"
                f"Merged PRs (titles also as quick scan): {'; '.join(titles[:50])}\n"
                f"Merged PRs with `html_url` (use for Slack links):\n{merged_block}\n"
                f"Opened PRs with `html_url`:\n{opened_block}\n"
            )

        facts = "\n\n".join(github_sections)
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            "Sources (use all that apply — synthesize into the workstream sections, do not dump raw tables):\n"
            f"1) Slack channel messages in the window.\n"
            f"2) GitHub metrics and PR titles per repo (below).\n"
            f"3) Google Drive file activity (below), including links from channel bookmarks when present.\n\n"
            f"---\n### Slack transcript (opaque user ids U…; infer roles from content)\n{slack_digest}\n"
            f"{bookmark_section}"
            f"---\n### GitHub (all configured repos for this weekly run)\n{facts}"
            f"{drive_block}"
        )
        system = "\n\n".join(
            [
                cleandoc(
                    """
                    You are Susan, writing for an **engineering / tech** channel. Ground the update in:
                    - Slack conversation and bookmark links,
                    - GitHub merged/opened PR lines (each includes `html_url` when available), authors, Dependabot
                      posture, and turnaround hints from the data,
                    - Google Drive lines (files modified in the window under linked folders/files).

                    Weave GitHub facts into the *1. Last week* / *2. Next steps* bullets under the relevant workstreams.
                    Turn each provided GitHub `html_url` into a Slack mrkdwn link `<url|#123 short title>` in the final text.
                    If a repo does not map to a workstream, you may add one short *GitHub — misc* section.
                    If Dependabot data was unavailable for a repo, note it briefly in place.
                    If the Drive block is empty, skip inventing Drive content.
                    """
                ),
                _WEEKLY_SLACK_MRKDN,
                _WEEKLY_STRUCTURE,
            ]
        )
    else:
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            "This channel does not use the full GitHub metrics bundle; rely on Slack, bookmarks, and Drive only.\n\n"
            f"---\n### Slack transcript\n{slack_digest}\n"
            f"{bookmark_section}"
            f"{drive_block}"
        )
        system = "\n\n".join(
            [
                cleandoc(
                    """
                    You are Susan, writing for a **general team** channel. **Do not** lead with pull requests or
                    repo lists unless the transcript clearly discusses them. Still use the same
                    *workstream → 1. Last week / 2. Next steps* structure and Slack links.
                    Use Google Drive facts only from the provided Drive block; use bookmark links from the prompt when relevant.
                    """
                ),
                _WEEKLY_SLACK_MRKDN,
                _WEEKLY_STRUCTURE,
            ]
        )

    max_tok = max(1500, min(32000, int(os.environ.get("WEEKLY_STATUS_MAX_TOKENS", "8192"))))
    try:
        summary = await call_claude(system, user_prompt, max_tokens=max_tok)
    except Exception as e:
        logger.exception("Weekly status Claude failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    title = _weekly_status_title_line(repos, range_label, include_github=include_github)
    if auto_publish:
        try:
            await post_pr_summary_to_channel(channel, thread_ts, title, summary)
        except Exception as e:
            logger.exception("Weekly status auto-publish failed")
            await notify_user_ephemeral(
                channel,
                user,
                f"Susan could not post weekly status to the channel: {e}",
                None,
                response_url,
            )
            return
        await notify_user_ephemeral(
            channel,
            user,
            "✓ Weekly status was posted to the channel (_no approval step_).",
            None,
            response_url,
        )
        return

    meta = {
        "title": title,
        "body": summary,
        "channel_id": channel,
        "thread_ts": thread_ts,
        "repos": repos if include_github else [],
        "include_github": include_github,
    }
    draft_id = await create_user_draft(
        user, "weekly_status", json.dumps(meta, ensure_ascii=False)
    )
    display_truncated = summary[:2800] + ("..." if len(summary) > 2800 else "")
    hint = (
        "_Use *Approve & post to channel* to publish this for everyone in this conversation, "
        "or *Cancel*._"
    )
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Susan preview — {ACTIONS['weekly_status'][0]}*\n_(Only visible to you)_\n{hint}",
            },
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{display_truncated}```"}},
        {
            "type": "actions",
            "block_id": f"susan_weekly_{channel}_{thread_ts or 'none'}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✓ Approve & post to channel"},
                    "style": "primary",
                    "action_id": "approve_weekly_status",
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
    if include_github:
        repo_hint = (
            f"`{repos[0]}`"
            if len(repos) == 1
            else f"{len(repos)} repos ({', '.join(repos[:3])}{'…' if len(repos) > 3 else ''})"
        )
        preview_note = f"Susan weekly status preview ready ({repo_hint})"
    else:
        preview_note = "Susan weekly status preview ready (Slack only — not a tech channel)"
    await notify_user_ephemeral(
        channel,
        user,
        preview_note,
        blocks,
        response_url,
    )
