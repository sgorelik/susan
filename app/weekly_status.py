"""Weekly team/repo status (Slack + optional GitHub + Drive)."""
from __future__ import annotations

import asyncio
import json
import os
from collections import Counter
from inspect import cleandoc

from db import create_user_draft, get_github_token

from app.claude_client import call_claude
from app.config import ACTIONS, SUSAN_VOICE, logger
from app.github_http import (
    _pr_turnaround_hours,
    fetch_dependabot_alert_stats,
    fetch_merged_prs_for_repo_range,
    fetch_opened_prs_for_repo_range,
)
from app.slack_api import (
    fetch_slack_channel_history_since,
    notify_user_ephemeral,
    slack_channel_bookmarks_for_weekly,
)
from app.weekly_canvas import publish_weekly_status
from app.weekly_context import parse_weekly_status_time_range, utc_date_start_slack_ts
from app.weekly_drive import weekly_status_drive_activity_block

_WEEKLY_SLACK_MRKDN = cleandoc(
    """
    Slack Block Kit *mrkdwn* rules (not GitHub/CommonMark): use *single asterisks* for bold
    only — never **double-asterisk** bold. Do not use # or ## headings. Links must use
    Slack syntax: <https://example.com/path|short visible label>. Prefer real URLs from
    the prompt (GitHub PR/issue links, Google Doc/Drive links, bookmark links); do not invent URLs.
    Group related people with `<@U123>` mentions on the same theme line.
    """
)

_WEEKLY_ATTRIBUTION = cleandoc(
    """
    **Attribution rules** (who gets credit on each theme line):
    - **GitHub:** credit the **PR author/opener** (`@login` on each PR line in the data).
      Do **not** credit reviewers, commenters, or merge-by users unless they also opened PRs on that theme.
    - **Google Drive:** credit the **owner or last editor** shown on each Drive line (`by owner: …`).
      Do **not** credit people who only commented in Slack about a doc.
    - **Slack:** use `<@U…>` for people who posted substantive updates or decisions in the transcript.
    - Map GitHub `@login` or Drive names to `<@U…>` only when the same person clearly appears in the Slack transcript.
    """
)

_WEEKLY_STRUCTURE = cleandoc(
    """
    **Output shape** — concise, founder-ready (Jesse should be able to forward this as-is):

    - First line: *Tech team update — <plain-language reporting window>*
      (or *Weekly update — …* for non-engineering channels).

    - **3–6 theme sections** (not per-repo dumps). Group PRs, Slack topics, and Drive work
      by initiative/theme (e.g. *Inference platform*, *Customer onboarding*, *Infra & reliability*).
      Order sections by business impact — highest priority first.

    - Each section format:
      *<Theme> (<@U123> @github-login — people who **shipped** this work)>*
      - *Shipped / progress:* 2–4 outcome bullets in plain language (impact first, not implementation detail).
        For PRs: state the count (*12 PRs merged*) and name the theme — do **not** list every PR.
        At most 1–2 example PR links per theme when a specific change is worth calling out.
      - *Next:* 1–3 bullets only.

    - Skip low-signal noise, stale threads, and deep technical internals unless they affect
      delivery or customers. Translate engineering work into outcomes a non-engineer founder understands.

    - Optional one-line *GitHub snapshot* at the end: total merged PRs, top **PR authors (openers)** — no PR-by-PR list.

    - Target length: ~800–1200 words. Scannable on one Slack screen.

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
                login = (it.get("user") or {}).get("login") or "?"
                if url:
                    merged_lines.append(f"- {url} — #{num} opener=@{login} | {pr_title}")
                elif num is not None:
                    merged_lines.append(f"- #{num} opener=@{login} | {pr_title}")
            opened_lines: list[str] = []
            for x in opened[:30]:
                num = x.get("number")
                t = ((x.get("title") or "") or "").replace("\n", " ")[:220]
                url = ((x.get("html_url") or "") or "").strip()
                login = (x.get("user") or {}).get("login") or "?"
                if url:
                    opened_lines.append(f"- {url} — #{num} opener=@{login} | {t}")
                elif num is not None:
                    opened_lines.append(f"- #{num} opener=@{login} | {t}")
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
                f"Top merged-PR authors (openers — use for attribution, not reviewers): "
                f"{', '.join(f'@{a} ({c})' for a, c in top_authors) or 'none'}.\n"
                f"Merged PRs (titles also as quick scan): {'; '.join(titles[:50])}\n"
                f"Merged PRs with `html_url` (use for Slack links):\n{merged_block}\n"
                f"Opened PRs with `html_url`:\n{opened_block}\n"
            )

        facts = "\n\n".join(github_sections)
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            "Sources (synthesize into themed sections — do not dump raw tables or list every PR):\n"
            f"1) Slack channel messages in the window.\n"
            f"2) GitHub metrics and PR data per repo (below) — group by theme, cite counts not full lists.\n"
            f"3) Google Drive file activity (below), including links from channel bookmarks when present.\n\n"
            f"---\n### Slack transcript (opaque user ids U…; infer roles from content)\n{slack_digest}\n"
            f"{bookmark_section}"
            f"---\n### GitHub (all configured repos for this weekly run)\n{facts}"
            f"{drive_block}"
        )
        system = "\n\n".join(
            [
                cleandoc(
                    f"""
                    You are Susan, writing a weekly update for an **engineering / tech** channel
                    that leadership will read. {SUSAN_VOICE}

                    Ground the update in Slack, GitHub, and Drive data provided — but **synthesize**:
                    - Group merged/opened PRs by **theme**, not repository. Mention PR *counts* per theme;
                      link at most 1–2 exemplar PRs per theme.
                    - Credit **PR openers** (`opener=@login` on each PR line) on theme headers — not reviewers.
                    - Credit **Drive owners/editors** (`by owner: …` on each Drive line) — not Slack commenters.
                    - Weave Dependabot posture and turnaround hints into relevant themes only when material.
                    - Tag shippers per theme with `@github-login` and `<@U…>` when mappable from Slack.
                    - Outcomes and customer/delivery impact first; trim implementation jargon.
                    If a repo does not map to a theme, fold it into the closest theme or one short bullet.
                    If Dependabot data was unavailable, note briefly. If Drive block is empty, skip Drive content.
                    """
                ),
                _WEEKLY_ATTRIBUTION,
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
                    f"""
                    You are Susan, writing a weekly update for a **general team** channel
                    that leadership may forward to founders. {SUSAN_VOICE}

                    **Do not** lead with pull requests or repo lists unless the transcript clearly discusses them.
                    Group topics by theme; credit **Drive owners/editors** and people who **posted** substantive
                    Slack updates — not passive commenters. Use `<@U…>` for Slack; map Drive names when clear.
                    Outcomes and decisions first — minimal jargon. Use Drive/bookmark links only from provided data.
                    """
                ),
                _WEEKLY_ATTRIBUTION,
                _WEEKLY_SLACK_MRKDN,
                _WEEKLY_STRUCTURE,
            ]
        )

    max_tok = max(1500, min(32000, int(os.environ.get("WEEKLY_STATUS_MAX_TOKENS", "8192"))))
    try:
        summary = await call_claude(
            system,
            user_prompt,
            max_tokens=max_tok,
            action="weekly_status",
            model_route="commercial",
        )
    except Exception as e:
        logger.exception("Weekly status Claude failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    title = _weekly_status_title_line(repos, range_label, include_github=include_github)
    if auto_publish:
        try:
            await publish_weekly_status(channel, thread_ts, title, summary)
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
            "✓ Weekly status was posted to the channel (_Canvas link; no approval step_).",
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
        "_Use *Approve & post to channel* to publish a Canvas link for everyone in this conversation, "
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
                    "text": {"type": "plain_text", "text": "✓ Approve & post Canvas link"},
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
