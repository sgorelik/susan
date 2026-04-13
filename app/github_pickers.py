"""GitHub repo pickers and issue/PR resolution for slash flows."""
from __future__ import annotations

import json
import os

from db import create_repo_pick_pending

from app.github_repos import (
    _issue_allowlist,
    _pr_allowlist,
    parse_repo_slug_from_text,
)
from app.slack_api import notify_user_ephemeral

def resolve_github_repo_for_issue(text: str) -> tuple[str | None, str | None, bool]:
    allow = _issue_allowlist()
    parsed = parse_repo_slug_from_text(text)
    default = (
        os.environ.get("GITHUB_ISSUES_REPO") or os.environ.get("GITHUB_REPO") or ""
    ).strip().lower()
    if parsed:
        if allow and parsed not in allow:
            return None, f"Repo `{parsed}` is not allowed for issues. Allowed: {', '.join(allow)}.", False
        return parsed, None, False
    if default:
        if allow and default not in allow:
            return None, f"Default issues repo (`{default}`) is not in the allowlist: {', '.join(allow)}.", False
        return default, None, False
    if len(allow) == 1:
        return allow[0], None, False
    if len(allow) > 1:
        return None, None, True
    return None, (
        "No repo for issues. Set `GITHUB_REPO` or `GITHUB_ISSUES_REPO`, or `GITHUB_REPOS` (allowlist), "
        "or include `owner/repo` in your command."
    ), False


async def post_github_repo_picker_ephemeral(
    channel: str,
    user: str,
    kind: str,
    text: str,
    thread_ts: str | None,
    response_url: str | None,
    allow: list[str],
) -> None:
    """Ephemeral blocks: buttons (≤8 repos) or dropdown (>8). Uses DB-backed session id."""
    if kind == "pr":
        label = "PR"
    elif kind == "summary":
        label = "PR summary"
    else:
        label = "issue"
    pick_id = await create_repo_pick_pending(user, channel, thread_ts, kind, text)
    blocks: list[dict] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Choose a GitHub repo* for this {label} (from `GITHUB_REPOS`):",
            },
        }
    ]
    if len(allow) <= 8:
        # Slack requires unique action_id per interactive element in one message.
        btn_idx = 0
        for i in range(0, len(allow), 5):
            chunk = allow[i : i + 5]
            elements = []
            for repo in chunk:
                payload = json.dumps({"i": pick_id, "r": repo}, separators=(",", ":"))
                elements.append(
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": repo[:75]},
                        "action_id": f"github_repo_pick_{btn_idx}",
                        "value": payload[:2000],
                    }
                )
                btn_idx += 1
            blocks.append({"type": "actions", "elements": elements})
    else:
        options = []
        for r in allow[:100]:
            options.append(
                {
                    "text": {"type": "plain_text", "text": r[:75]},
                    "value": r[:75],
                }
            )
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "static_select",
                        "action_id": f"github_repo_menu_{pick_id}",
                        "placeholder": {"type": "plain_text", "text": "Select repository"},
                        "options": options,
                    }
                ],
            }
        )
    await notify_user_ephemeral(
        channel, user, f"Pick a repo for this {label}", blocks, response_url
    )


def _slack_multi_summary_selected_repos(payload: dict, pick_id: str) -> list[str]:
    """Read multi_static_select choices from block_actions `state` (values are allowlist indices)."""
    nid = pick_id.replace("-", "")
    blk_section = f"s{nid}"
    act_id = f"grms_{nid}"
    state = payload.get("state") or {}
    values = state.get("values") or {}
    inner = values.get(blk_section) or {}
    sel_el = inner.get(act_id) or {}
    opts = sel_el.get("selected_options") or []
    out = [o.get("value", "").strip().lower() for o in opts if o.get("value")]
    if out:
        return out
    found: list[str] = []
    for _bid, actions in values.items():
        if not isinstance(actions, dict):
            continue
        for _aid, el in actions.items():
            if not isinstance(el, dict):
                continue
            if el.get("type") != "multi_static_select":
                continue
            for o in el.get("selected_options") or []:
                v = (o.get("value") or "").strip().lower()
                if v:
                    found.append(v)
            if found:
                return found
    return []


async def post_github_repo_multi_summary_picker_ephemeral(
    channel: str,
    user: str,
    text: str,
    thread_ts: str | None,
    response_url: str | None,
    allow: list[str],
) -> None:
    """Ephemeral multi-select + confirm for PR summary when several repos are allowed."""
    pick_id = await create_repo_pick_pending(user, channel, thread_ts, "summary", text)
    nid = pick_id.replace("-", "")
    blk_section = f"s{nid}"
    blk_go = f"g{nid}"
    act_sel = f"grms_{nid}"
    # Slack option `value` must be ≤75 chars; long owner/repo breaks validation (invalid_blocks).
    picked_allow = [
        x.strip().lower() for x in allow[:100] if (x or "").strip()
    ]
    if not picked_allow:
        await notify_user_ephemeral(
            channel,
            user,
            "`GITHUB_REPOS` is empty on the server — set it (comma-separated owner/repo) and try again.",
            None,
            response_url,
        )
        return
    options = [
        {
            "text": {"type": "plain_text", "text": r[:75] if r else "?"},
            "value": str(i),
        }
        for i, r in enumerate(picked_allow)
    ]
    # multi_static_select in an actions block often yields invalid_blocks on chat.postEphemeral;
    # use a section accessory instead.
    blocks: list[dict] = [
        {
            "type": "section",
            "block_id": blk_section,
            "text": {
                "type": "plain_text",
                "text": (
                    "Choose one or more repositories for this PR summary, "
                    "then click Run PR summary."
                ),
                "emoji": True,
            },
            "accessory": {
                "type": "multi_static_select",
                "action_id": act_sel,
                "placeholder": {"type": "plain_text", "text": "Repositories"},
                "options": options,
            },
        },
        {
            "type": "actions",
            "block_id": blk_go,
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Run PR summary"},
                    "style": "primary",
                    "action_id": f"github_repo_multi_summary_go_{pick_id}",
                    "value": "go",
                }
            ],
        },
    ]
    await notify_user_ephemeral(
        channel, user, "Select repos for PR summary", blocks, response_url
    )
