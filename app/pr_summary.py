"""Merged PR summary flow (Claude + approve-to-post)."""
from __future__ import annotations

import asyncio
import json

from db import create_user_draft, get_github_token

from app.claude_client import call_claude
from app.config import ACTIONS, logger
from app.github_http import (
    build_pr_summary_engagement_appendix,
    fetch_merged_prs_for_repo_range,
)
from app.github_repos import parse_pr_summary_time_range
from app.slack_api import notify_user_ephemeral, post_pr_summary_to_channel

def _pr_summary_title_line(repos: list[str], since_d: str, until_d: str) -> str:
    if len(repos) == 1:
        return f"PR summary — `{repos[0]}` ({since_d} → {until_d})"
    shown = ", ".join(f"`{r}`" for r in repos[:5])
    if len(repos) > 5:
        shown += f", … (+{len(repos) - 5} more)"
    return f"PR summary — {shown} ({since_d} → {until_d})"


async def process_pr_summary(
    repos: list[str],
    command_text: str,
    convo: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    if not repos:
        await notify_user_ephemeral(
            channel, user, "No repositories to summarize.", None, response_url
        )
        return
    since_d, until_d = parse_pr_summary_time_range(command_text)
    try:
        token = await get_github_token(user)
    except ValueError as e:
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return
    try:
        batches = await asyncio.gather(
            *[
                fetch_merged_prs_for_repo_range(r, since_d, until_d, token)
                for r in repos
            ]
        )
    except Exception as e:
        logger.exception("GitHub PR fetch failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return
    sections: list[str] = []
    total = 0
    for repo, items in zip(repos, batches):
        total += len(items)
        lines: list[str] = []
        for it in items:
            num = it.get("number")
            pr_title = (it.get("title") or "").replace("\n", " ")
            url = it.get("html_url") or ""
            pr_meta = it.get("pull_request") or {}
            merged = pr_meta.get("merged_at") or it.get("closed_at") or ""
            login = (it.get("user") or {}).get("login") or "?"
            lines.append(
                f"#{num} | repo=`{repo}` | {merged[:10] if merged else '?'} | @{login} | {pr_title} | {url}"
            )
        raw_list = "\n".join(lines) if lines else "(No merged PRs in this window.)"
        sections.append(
            f"### Repository `{repo}`\nMerged PRs ({len(items)}):\n{raw_list}"
        )
    engagement = await build_pr_summary_engagement_appendix(repos, batches, token)
    prompt = (
        f"Repositories ({len(repos)}): {', '.join(f'`{r}`' for r in repos)}\n"
        f"Merged date range (UTC, inclusive): {since_d} through {until_d}.\n"
        f"Total merged PRs in range: {total}\n\n" + "\n\n".join(sections)
    )
    prompt += f"\n\n{engagement}\n"
    if (convo or "").strip():
        prompt += f"\nSlack thread context (optional):\n{convo.strip()[:6000]}\n"
    system = (
        "You are Susan. Write a concise summary for Slack Block Kit *mrkdwn* (not GitHub/CommonMark). "
        "Rules: use *single asterisks* for bold (e.g. *Major updates*); never use **double-asterisk** bold. "
        "Do not use # or ## headings — use a short bold title on its own line instead (e.g. *Contributors*). "
        "Use bullets with leading hyphen (-). Italic uses _underscores_ if needed. "
        "Merged pull requests across one or more repositories. "
        "Whenever you mention a specific PR in the body, include its repository slug in parentheses "
        "using the exact `owner/repo` from the data, e.g. `#35 Model deployment UI cleanup (frontier-one/f1-asgardos)`. "
        "If you use Slack link syntax, put the same slug in the visible text, e.g. "
        "<https://github.com/…|#35 Model deployment UI cleanup (frontier-one/f1-asgardos)>. "
        "Group by theme or area when it helps; you may group by repository or combine cross-repo themes. "
        "State the date range and repo list at the top. "
        "Always end with a *Contributors & commenters* section (bold title line): briefly highlight who merged the most PRs "
        "(contributors / authors) and who was most active commenting or reviewing, informed by the "
        "aggregated participation block in the prompt; use @login handles. "
        "If there were zero PRs everywhere, say so and suggest widening the time range. "
        "Do not say the summary is private, ephemeral, or “only visible to you” — the app handles visibility."
    )
    try:
        summary = await call_claude(system, prompt)
    except Exception as e:
        logger.exception("PR summary Claude failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return
    title = _pr_summary_title_line(repos, since_d, until_d)
    meta = {
        "title": title,
        "body": summary,
        "channel_id": channel,
        "thread_ts": thread_ts,
        "repos": repos,
    }
    draft_id = await create_user_draft(
        user, "pr_summary", json.dumps(meta, ensure_ascii=False)
    )
    display_truncated = summary[:2800] + ("..." if len(summary) > 2800 else "")
    hint = (
        "_Use *Approve & post to channel* to publish this summary for everyone in this conversation, "
        "or *Cancel*._"
    )
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Susan preview — {ACTIONS['pr_summary'][0]}*\n_(Only visible to you)_\n{hint}",
            },
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{display_truncated}```"}},
        {
            "type": "actions",
            "block_id": f"susan_pr_summary_{channel}_{thread_ts or 'none'}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✓ Approve & post to channel"},
                    "style": "primary",
                    "action_id": "approve_pr_summary",
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
    repo_hint = (
        f"`{repos[0]}`"
        if len(repos) == 1
        else f"{len(repos)} repos ({', '.join(repos[:3])}{'…' if len(repos) > 3 else ''})"
    )
    await notify_user_ephemeral(
        channel,
        user,
        f"Susan PR summary preview ready for {repo_hint}",
        blocks,
        response_url,
    )
