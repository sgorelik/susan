"""Weekly team/repo status (Slack + optional GitHub + Drive)."""
from __future__ import annotations

import asyncio
import json
import os
from collections import Counter

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
)
from app.weekly_context import parse_weekly_status_time_range, utc_date_start_slack_ts
from app.weekly_drive import weekly_status_drive_activity_block

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
    from collections import Counter

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

    drive_block = await weekly_status_drive_activity_block(
        user, since_d, until_d, slack_digest
    )

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

            opened_titles = [(x.get("title") or "").replace("\n", " ") for x in opened[:40]]
            avg_part = (
                f"{avg_h:.1f}"
                if avg_h is not None
                else "n/a (no merged PRs with created+merged timestamps)"
            )
            github_sections.append(
                f"### `{r}`\n"
                f"{dep_lines}\n"
                f"PRs opened in window: {len(opened)}; merged in window: {len(merged)}.\n"
                f"Average merge turnaround (hours): {avg_part}.\n"
                f"Top merged-PR authors: {', '.join(f'@{a} ({c})' for a, c in top_authors) or 'none'}.\n"
                f"Merged PR titles (up to 50): {'; '.join(titles[:50])}\n"
                f"Opened PR titles (up to 40): {'; '.join(opened_titles)}\n"
            )

        facts = "\n\n".join(github_sections)
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            f"Slack channel transcript (user ids are opaque U…; infer roles from content only):\n"
            f"{slack_digest}\n\n"
            f"---\nGitHub metrics and PR titles per repo:\n{facts}"
            f"{drive_block}"
        )
        system = (
            "You are Susan. Write a weekly status for Slack Block Kit *mrkdwn* (not CommonMark).\n"
            "Use *single asterisks* for bold only; never **double-asterisk** bold. "
            "Do not use # or ## — use bold title lines instead (e.g. *Channel (Slack)*, *GitHub*, *f1-asgardos*).\n"
            "Slack section: very high level — notable updates from teammates, decisions, risks, "
            "open questions; do not quote long messages.\n"
            "GitHub section: summarize Dependabot/vulnerability posture, PR volume, average turnaround, "
            "main themes of merged work, and who was most active (authors you infer from the data).\n"
            "If a Google Drive block is included, add a concise *Google Drive* section: what files or docs "
            "under linked folders or linked files were updated in the window (use the list; do not invent files).\n"
            "If Dependabot data was unavailable for a repo, say so briefly.\n"
            "Keep it executive-readable. Do not say the draft is private or ephemeral."
        )
    else:
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            "This is a non-engineering Slack channel: produce a weekly status from the transcript only "
            "(no GitHub or code repository data).\n"
            f"Slack channel transcript (user ids are opaque U…; infer roles from content only):\n"
            f"{slack_digest}\n"
            f"{drive_block}"
        )
        system = (
            "You are Susan. Write a weekly status for Slack Block Kit *mrkdwn* for a general team channel.\n"
            "Use *single asterisks* for bold; never **double-asterisk** bold. No # or ## headings — "
            "use bold lines (e.g. *Highlights*, *Decisions*, *Risks & blockers*, *Open questions*).\n"
            "Stay very high level — notable updates, decisions, and open threads; do not quote long messages.\n"
            "If a Google Drive block is included, add a concise *Google Drive* section from that data only.\n"
            "Do not mention GitHub, pull requests, or repositories unless the transcript explicitly does.\n"
            "Keep it executive-readable. Do not say the draft is private or ephemeral."
        )

    max_tok = max(1500, min(32000, int(os.environ.get("WEEKLY_STATUS_MAX_TOKENS", "4096"))))
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
