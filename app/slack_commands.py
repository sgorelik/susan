"""Slash command continuation: Claude previews, modals, OAuth resume."""
from __future__ import annotations

import json
import os
import re
import uuid

from db import create_user_draft

from app.claude_client import call_claude
from app.config import ACTIONS, logger, REPO_PREFIX, SYSTEM_PROMPTS
from app.github_pickers import (
    post_github_repo_multi_summary_picker_ephemeral,
    post_github_repo_picker_ephemeral,
    resolve_github_repo_for_issue,
)
from app.github_repos import (
    _issue_allowlist,
    _pr_allowlist,
    resolve_github_repo_for_pr,
    resolve_github_repos_for_pr_summary,
)
from app.pr_summary import process_pr_summary
from app.slack_api import (
    extract_slack_archives_link,
    fetch_slack_history,
    notify_user_ephemeral,
    post_ephemeral,
    slack_views_open,
)
from app.weekly_context import (
    resolve_github_repos_for_weekly_status,
    strip_weekly_status_auto_post_flags,
    weekly_status_auto_post_user_allowed,
    weekly_status_include_github,
)
from app.weekly_status import process_weekly_status

def _sanitize_repo_rel_path(path: str) -> str | None:
    p = path.strip().strip("/").replace("\\", "/")
    if not p or any(seg == ".." for seg in p.split("/")):
        return None
    return p


def _parse_pr_files_changed(content: str) -> list[tuple[str, str]]:
    """Parse Claude PR output after 'Files changed:' — path line then ``` fenced code."""
    m = re.search(r"(?is)Files changed:\s*", content)
    if not m:
        return []
    s = content[m.end() :]
    out: list[tuple[str, str]] = []
    pos = 0
    n = len(s)
    while pos < n:
        while pos < n and s[pos] in " \t\r\n":
            pos += 1
        if pos >= n:
            break
        line_end = s.find("\n", pos)
        if line_end == -1:
            break
        line = s[pos:line_end].strip()
        pos = line_end + 1
        if not line or line.startswith("#"):
            continue
        path = line.strip("`").strip()
        if not path:
            continue
        while pos < n and s[pos] in " \t\r\n":
            pos += 1
        if pos >= n or not s.startswith("```", pos):
            break
        pos += 3
        nl = s.find("\n", pos)
        if nl == -1:
            break
        pos = nl + 1
        end_fence = s.find("```", pos)
        if end_fence == -1:
            break
        body = s[pos:end_fence]
        out.append((path, body))
        pos = end_fence + 3
    return out



def split_repo_prefix_from_approve_value(value: str) -> tuple[str | None, str]:
    """Approve button value may start with REPO_PREFIX line from process_command."""
    if value.startswith(REPO_PREFIX):
        nl = value.find("\n")
        if nl != -1:
            line = value[:nl]
            rest = value[nl + 1 :]
            slug = line[len(REPO_PREFIX) :].strip().lower()
            return slug or None, rest
    return None, value


SLACK_CB_EMAIL_MODAL = "susan_submit_email"
SLACK_CB_INVITE_MODAL = "susan_submit_invite"


def _looks_like_draft_id(value: str) -> bool:
    v = (value or "").strip()
    if len(v) != 36:
        return False
    try:
        uuid.UUID(v)
        return True
    except ValueError:
        return False


def parse_email_draft(text: str) -> dict[str, str]:
    """Parse To:/Subject:/body from Claude email output."""
    raw = text.strip()
    to_m = re.search(r"(?im)^To:\s*(.+)$", raw)
    subj_m = re.search(r"(?im)^Subject:\s*(.+)$", raw)
    to_val = (to_m.group(1).strip() if to_m else "")[:4000]
    subj = (subj_m.group(1).strip() if subj_m else "Email from Susan")[:2000]
    body = raw
    body = re.sub(r"(?im)^To:\s*.+$", "", body, count=1)
    body = re.sub(r"(?im)^Subject:\s*.+$", "", body, count=1)
    body = body.strip()
    return {"to": to_val, "subject": subj, "body": body[:12000]}


def parse_invite_draft(text: str) -> dict[str, str]:
    """Parse structured invite from Claude output."""
    raw = text.strip()

    def one(name: str) -> str | None:
        m = re.search(rf"(?im)^{name}:\s*(.+)$", raw)
        return m.group(1).strip() if m else None

    title = (one("Title") or "Meeting")[:2000]
    attendees = (one("Attendees") or "")[:2000]
    start = (one("Start") or "2026-04-01T10:00:00Z")[:500]
    end = (one("End") or "2026-04-01T11:00:00Z")[:500]
    tz = (one("TimeZone") or one("Timezone") or "UTC")[:100]
    desc = ""
    if re.search(r"(?im)^Description:\s*", raw):
        desc = re.split(r"(?im)^Description:\s*", raw, maxsplit=1)[-1].strip()[:12000]
    return {
        "title": title,
        "attendees": attendees,
        "start": start,
        "end": end,
        "timezone": tz,
        "description": desc,
    }


def format_email_content(parsed: dict[str, str]) -> str:
    return f"To: {parsed['to']}\nSubject: {parsed['subject']}\n\n{parsed['body']}"


def format_invite_content(parsed: dict[str, str]) -> str:
    return (
        f"Title: {parsed['title']}\n"
        f"Attendees: {parsed['attendees']}\n"
        f"Start: {parsed['start']}\n"
        f"End: {parsed['end']}\n"
        f"TimeZone: {parsed['timezone']}\n"
        f"Description:\n{parsed['description']}"
    )


def _slack_block_input_value(values: dict, block_id: str, action_id: str) -> str:
    try:
        el = (values.get(block_id) or {}).get(action_id) or {}
        return (el.get("value") or "").strip()
    except (AttributeError, TypeError):
        return ""


def build_email_modal_view(draft_id: str, channel_id: str, parsed: dict[str, str]) -> dict:
    meta = json.dumps({"draft_id": draft_id, "channel_id": channel_id})
    return {
        "type": "modal",
        "callback_id": SLACK_CB_EMAIL_MODAL,
        "private_metadata": meta[:3000],
        "title": {"type": "plain_text", "text": "Send email"},
        "submit": {"type": "plain_text", "text": "Send"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "input",
                "block_id": "em_to",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "em_to_val",
                    "initial_value": (parsed.get("to") or "")[:2000],
                    "placeholder": {"type": "plain_text", "text": "a@x.com, b@y.com"},
                },
                "label": {"type": "plain_text", "text": "To (comma-separated)"},
            },
            {
                "type": "input",
                "block_id": "em_sub",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "em_sub_val",
                    "initial_value": (parsed.get("subject") or "")[:2000],
                },
                "label": {"type": "plain_text", "text": "Subject"},
            },
            {
                "type": "input",
                "block_id": "em_body",
                "element": {
                    "type": "plain_text_input",
                    "multiline": True,
                    "action_id": "em_body_val",
                    "initial_value": (parsed.get("body") or "")[:3000],
                },
                "label": {"type": "plain_text", "text": "Body"},
            },
        ],
    }


def build_invite_modal_view(draft_id: str, channel_id: str, parsed: dict[str, str]) -> dict:
    meta = json.dumps({"draft_id": draft_id, "channel_id": channel_id})
    return {
        "type": "modal",
        "callback_id": SLACK_CB_INVITE_MODAL,
        "private_metadata": meta[:3000],
        "title": {"type": "plain_text", "text": "Calendar invite"},
        "submit": {"type": "plain_text", "text": "Create invite"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "input",
                "block_id": "in_tt",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "in_tt_val",
                    "initial_value": (parsed.get("title") or "")[:2000],
                },
                "label": {"type": "plain_text", "text": "Title"},
            },
            {
                "type": "input",
                "block_id": "in_att",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "in_att_val",
                    "initial_value": (parsed.get("attendees") or "")[:2000],
                    "placeholder": {"type": "plain_text", "text": "emails, comma-separated"},
                },
                "label": {"type": "plain_text", "text": "Attendees"},
            },
            {
                "type": "input",
                "block_id": "in_st",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "in_st_val",
                    "initial_value": (parsed.get("start") or "")[:2000],
                    "placeholder": {"type": "plain_text", "text": "2026-04-15T14:00:00"},
                },
                "label": {"type": "plain_text", "text": "Start (ISO8601)"},
            },
            {
                "type": "input",
                "block_id": "in_en",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "in_en_val",
                    "initial_value": (parsed.get("end") or "")[:2000],
                },
                "label": {"type": "plain_text", "text": "End (ISO8601)"},
            },
            {
                "type": "input",
                "block_id": "in_tz",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "in_tz_val",
                    "initial_value": (parsed.get("timezone") or "UTC")[:2000],
                },
                "label": {"type": "plain_text", "text": "Time zone (IANA)"},
            },
            {
                "type": "input",
                "block_id": "in_de",
                "element": {
                    "type": "plain_text_input",
                    "multiline": True,
                    "action_id": "in_de_val",
                    "initial_value": (parsed.get("description") or "")[:3000],
                },
                "label": {"type": "plain_text", "text": "Description"},
            },
        ],
    }


async def process_command(
    action: str,
    convo: str,
    instructions: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None = None,
    github_repo: str | None = None,
):
    try:
        repo_line = ""
        if action == "pr":
            if not github_repo:
                await notify_user_ephemeral(
                    channel,
                    user,
                    "Internal error: missing GitHub repo for PR. Run `/susan` again.",
                    None,
                    response_url,
                )
                return
            repo_line = f"{REPO_PREFIX}{github_repo}\n"
        elif action == "issue":
            if not github_repo:
                await notify_user_ephemeral(
                    channel,
                    user,
                    "Internal error: missing GitHub repo for issue. Run `/susan` again.",
                    None,
                    response_url,
                )
                return
            repo_line = f"{REPO_PREFIX}{github_repo}\n"

        preview = await call_claude(
            SYSTEM_PROMPTS[action],
            f"Slack conversation:\n{convo}\n\nExtra instructions: {instructions}",
        )
        display_truncated = preview[:2800] + ("..." if len(preview) > 2800 else "")

        if action in ("email", "invite"):
            draft_id = await create_user_draft(user, action, preview)
            hint = (
                "_Use *Edit & send* to change recipients and wording, or *Approve & send* to send this draft as-is._"
            )
            blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Susan preview — {ACTIONS[action][0]}*\n_(Only visible to you)_\n{hint}",
                    },
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```{display_truncated}```"}},
                {
                    "type": "actions",
                    "block_id": f"susan_{action}_{channel}_{thread_ts or 'none'}",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✏️ Edit & send"},
                            "action_id": f"open_modal_{action}",
                            "value": draft_id,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✓ Approve & send"},
                            "style": "primary",
                            "action_id": f"approve_{action}",
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
        else:
            max_val = 2000 - len(repo_line)
            if max_val < 200:
                max_val = 200
            value_truncated = preview[:max_val] + ("..." if len(preview) > max_val else "")
            approve_value = f"{repo_line}{value_truncated}"
            blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Susan preview — {ACTIONS[action][0]}*\n_(Only visible to you)_",
                    },
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```{display_truncated}```"}},
                {
                    "type": "actions",
                    "block_id": f"susan_{action}_{channel}_{thread_ts or 'none'}",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✓ Approve & execute"},
                            "style": "primary",
                            "action_id": f"approve_{action}",
                            "value": approve_value[:2000],
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✗ Cancel"},
                            "action_id": "cancel_susan",
                        },
                    ],
                },
            ]
        await notify_user_ephemeral(
            channel, user, f"Susan preview ready for: {ACTIONS[action][0]}", blocks, response_url
        )
    except Exception as e:
        logger.exception("process_command failed")
        try:
            await notify_user_ephemeral(channel, user, f"Susan error: {str(e)}", None, response_url)
        except Exception as e2:
            logger.error("Could not notify user in Slack: %s", e2)


async def resume_slash_after_oauth(row: dict) -> None:
    """Re-run the same logic as the /susan background task after OAuth completes."""
    text = row["command_text"]
    channel = row["channel_id"]
    user = row["slack_user_id"]
    thread_ts = row["thread_ts"]
    action = row["action"]
    response_url = None
    try:
        await post_ephemeral(
            channel,
            user,
            f"Resuming your *{ACTIONS[action][0]}* request after sign-in…",
        )
    except Exception as e:
        logger.warning("resume_slash_after_oauth intro ephemeral: %s", e)
    try:
        weekly_command_text = text
        weekly_auto_post = False
        if action == "weekly_status":
            weekly_command_text, weekly_auto_post = strip_weekly_status_auto_post_flags(text)
            if weekly_auto_post and not weekly_status_auto_post_user_allowed(user):
                await notify_user_ephemeral(
                    channel,
                    user,
                    "Auto-publish (`--no-approval`) is not allowed for your user. Run `/susan weekly status` "
                    "without the flag, or add your user id to `SUSAN_WEEKLY_AUTO_POST_USER_IDS`.",
                    None,
                    response_url,
                )
                return
        link_ch, link_ts = extract_slack_archives_link(
            weekly_command_text if action == "weekly_status" else text
        )
        hist_channel = link_ch or channel
        hist_thread_ts = thread_ts or link_ts
        if action == "weekly_status":
            tech = await weekly_status_include_github(hist_channel, channel, None)
            if not tech:
                await process_weekly_status(
                    [],
                    weekly_command_text,
                    hist_channel,
                    channel,
                    user,
                    thread_ts,
                    response_url,
                    include_github=False,
                    auto_publish=weekly_auto_post,
                )
                return
            repos_w, err_w = resolve_github_repos_for_weekly_status()
            if err_w:
                await notify_user_ephemeral(channel, user, err_w, None, response_url)
                return
            await process_weekly_status(
                repos_w,
                weekly_command_text,
                hist_channel,
                channel,
                user,
                thread_ts,
                response_url,
                include_github=True,
                auto_publish=weekly_auto_post,
            )
            return
        convo = await fetch_slack_history(hist_channel, hist_thread_ts, user)
        if action in GITHUB_ACTIONS:
            if action == "issue":
                repo, err, need_pick = resolve_github_repo_for_issue(text)
                if need_pick:
                    await post_github_repo_picker_ephemeral(
                        channel,
                        user,
                        action,
                        text,
                        thread_ts,
                        response_url,
                        _issue_allowlist(),
                    )
                    return
                if err:
                    await notify_user_ephemeral(channel, user, err, None, response_url)
                    return
                await process_command(
                    action,
                    convo,
                    text,
                    channel,
                    user,
                    thread_ts,
                    response_url,
                    github_repo=repo,
                )
            elif action == "pr_summary":
                repos, err, need_pick = resolve_github_repos_for_pr_summary(text)
                if need_pick:
                    await post_github_repo_multi_summary_picker_ephemeral(
                        channel,
                        user,
                        text,
                        thread_ts,
                        response_url,
                        _pr_allowlist(),
                    )
                    return
                if err:
                    await notify_user_ephemeral(channel, user, err, None, response_url)
                    return
                await process_pr_summary(
                    repos, text, convo, channel, user, thread_ts, response_url
                )
            else:
                repo, err, need_pick = resolve_github_repo_for_pr(text)
                if need_pick:
                    await post_github_repo_picker_ephemeral(
                        channel,
                        user,
                        "pr",
                        text,
                        thread_ts,
                        response_url,
                        _pr_allowlist(),
                    )
                    return
                if err:
                    await notify_user_ephemeral(channel, user, err, None, response_url)
                    return
                await process_command(
                    action,
                    convo,
                    text,
                    channel,
                    user,
                    thread_ts,
                    response_url,
                    github_repo=repo,
                )
        else:
            await process_command(action, convo, text, channel, user, thread_ts, response_url)
    except Exception as e:
        logger.exception("resume_slash_after_oauth failed")
        try:
            await notify_user_ephemeral(
                channel,
                user,
                f"Could not resume your command after sign-in: {e}",
                None,
                response_url,
            )
        except Exception as e2:
            logger.error("resume_slash_after_oauth notify: %s", e2)
