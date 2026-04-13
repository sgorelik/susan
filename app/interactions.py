"""Slack interactive payloads: modals and block actions."""
from __future__ import annotations

import json
import urllib.parse

from fastapi import BackgroundTasks
from fastapi.responses import JSONResponse

from db import consume_repo_pick_pending, consume_user_draft, get_user_draft

from app.config import APPROVE_ACTION_TYPES, logger
from app.github_actions import create_github_issue, create_github_pr
from app.github_pickers import _slack_multi_summary_selected_repos
from app.github_repos import _issue_allowlist, _pr_allowlist
from app.google_workspace import create_calendar_invite, create_google_doc, send_gmail
from app.pr_summary import process_pr_summary
from app.slack_commands import (
    SLACK_CB_EMAIL_MODAL,
    SLACK_CB_INVITE_MODAL,
    build_email_modal_view,
    build_invite_modal_view,
    format_email_content,
    format_invite_content,
    parse_email_draft,
    parse_invite_draft,
    process_command,
    _looks_like_draft_id,
    _slack_block_input_value,
)
from app.slack_api import (
    _slack_form_fields,
    fetch_slack_history,
    post_ephemeral,
    post_pr_summary_to_channel,
    post_slack_delayed_response,
    slack_views_open,
    verify_slack,
)

def slack_interaction_user_id(payload: dict) -> str:
    """Slack user id from interaction payload (handles typical and enterprise-shaped user objects)."""
    u = payload.get("user")
    if not isinstance(u, dict):
        return ""
    uid = (u.get("id") or "").strip()
    if uid:
        return uid
    eu = u.get("enterprise_user")
    if isinstance(eu, dict):
        return (eu.get("id") or "").strip()
    return ""


def slack_interaction_channel_id(payload: dict) -> str:
    """Best-effort channel id for block_actions (ephemeral previews often omit container.channel_id)."""
    c = payload.get("container") or {}
    cid = (c.get("channel_id") or "").strip()
    if cid:
        return cid
    ch = payload.get("channel")
    if isinstance(ch, dict):
        cid = (ch.get("id") or "").strip()
        if cid:
            return cid
    msg = payload.get("message") or {}
    mc = msg.get("channel")
    if isinstance(mc, str) and mc.strip():
        return mc.strip()
    if isinstance(mc, dict):
        cid = (mc.get("id") or "").strip()
        if cid:
            return cid
    return ""

async def handle_slack_view_submission(payload: dict, background_tasks: BackgroundTasks) -> JSONResponse:
    """Modal submit for editable email / calendar drafts."""
    user = slack_interaction_user_id(payload)
    view = payload.get("view") or {}
    callback_id = view.get("callback_id") or ""
    values = (view.get("state") or {}).get("values") or {}
    meta: dict = {}
    try:
        meta = json.loads(view.get("private_metadata") or "{}")
    except json.JSONDecodeError:
        meta = {}
    draft_id = (meta.get("draft_id") or "").strip()
    channel_id = (meta.get("channel_id") or "").strip()

    async def notify_done(text: str) -> None:
        if channel_id and user:
            try:
                await post_ephemeral(channel_id, user, text)
            except Exception as e:
                logger.error("view_submission notify: %s", e)

    if callback_id == SLACK_CB_EMAIL_MODAL:
        to = _slack_block_input_value(values, "em_to", "em_to_val")
        subj = _slack_block_input_value(values, "em_sub", "em_sub_val")
        body = _slack_block_input_value(values, "em_body", "em_body_val")
        content = format_email_content({"to": to, "subject": subj, "body": body})

        async def run_email():
            if draft_id:
                await consume_user_draft(draft_id, user)
            try:
                result = await send_gmail(content, user)
                await notify_done(f"✓ Susan done: {result}")
            except Exception as e:
                logger.exception("Modal send email failed")
                await notify_done(f"Susan error: {e}")

        background_tasks.add_task(run_email)
        return JSONResponse({"response_action": "clear"})

    if callback_id == SLACK_CB_INVITE_MODAL:
        parsed = {
            "title": _slack_block_input_value(values, "in_tt", "in_tt_val"),
            "attendees": _slack_block_input_value(values, "in_att", "in_att_val"),
            "start": _slack_block_input_value(values, "in_st", "in_st_val"),
            "end": _slack_block_input_value(values, "in_en", "in_en_val"),
            "timezone": _slack_block_input_value(values, "in_tz", "in_tz_val") or "UTC",
            "description": _slack_block_input_value(values, "in_de", "in_de_val"),
        }
        content = format_invite_content(parsed)

        async def run_inv():
            if draft_id:
                await consume_user_draft(draft_id, user)
            try:
                result = await create_calendar_invite(content, user)
                await notify_done(f"✓ Susan done: {result}")
            except Exception as e:
                logger.exception("Modal calendar invite failed")
                await notify_done(f"Susan error: {e}")

        background_tasks.add_task(run_inv)
        return JSONResponse({"response_action": "clear"})

    return JSONResponse({"response_action": "clear"})

async def handle_action(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    ts = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    if not verify_slack(body, ts, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    form = _slack_form_fields(body)
    payload_raw = form.get("payload", "{}")
    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        payload = json.loads(urllib.parse.unquote(payload_raw))

    ptype = payload.get("type")
    if ptype == "view_submission":
        return await handle_slack_view_submission(payload, background_tasks)

    if ptype and ptype != "block_actions":
        logger.info("Ignoring Slack interaction type=%s", ptype)
        return JSONResponse({})

    actions = payload.get("actions") or []
    if not actions:
        logger.warning("block_actions with empty actions payload keys=%s", list(payload.keys()))
        return JSONResponse({})

    user = slack_interaction_user_id(payload)
    if not user:
        logger.warning("block_actions missing user: payload keys=%s", list(payload.keys()))
        return JSONResponse({})

    channel = slack_interaction_channel_id(payload)
    if not channel:
        logger.warning(
            "block_actions channel unresolved (ephemeral quirks); keys=%s container=%s message.ch=%s",
            list(payload.keys()),
            payload.get("container"),
            (payload.get("message") or {}).get("channel"),
        )

    action_type: str | None = None
    value = ""
    for a in actions:
        aid = (a.get("action_id") or "").strip()
        if not aid:
            continue
        if aid in ("open_modal_email", "open_modal_invite"):
            draft_id = (a.get("value") or "").strip()
            trigger_id = (payload.get("trigger_id") or "").strip()
            row = await get_user_draft(draft_id, user)
            if not row:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": "That draft expired. Run `/susan` again.",
                    }
                )
            kind = row["kind"]
            content = row["content"]
            if kind == "email":
                view = build_email_modal_view(draft_id, channel, parse_email_draft(content))
            elif kind == "invite":
                view = build_invite_modal_view(draft_id, channel, parse_invite_draft(content))
            elif kind == "pr_summary":
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": "PR summaries don’t use the editor — use *Approve & post to channel* on the preview.",
                    }
                )
            else:
                return JSONResponse(
                    {"response_type": "ephemeral", "text": "Unknown draft type."}
                )
            ok, err = await slack_views_open(trigger_id, view)
            if not ok:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": (
                            f"Could not open the editor (`{err}`). "
                            "Try *Approve & send* or run `/susan` again. "
                            "If this persists, confirm the app has **interactivity** enabled for `/susan/actions`."
                        ),
                    }
                )
            return JSONResponse({})
        if aid.startswith("github_repo_multi_summary_go_"):
            pick_id = aid.removeprefix("github_repo_multi_summary_go_").strip()
            if not pick_id:
                return JSONResponse(
                    {"response_type": "ephemeral", "text": "Invalid PR summary picker."}
                )
            repos_sel = _slack_multi_summary_selected_repos(payload, pick_id)
            if not repos_sel:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": (
                            "Select one or more repositories in the dropdown, then click "
                            "*Run PR summary* again."
                        ),
                    }
                )
            row = await consume_repo_pick_pending(pick_id, user)
            if not row or row["kind"] != "summary":
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": "Picker expired. Run `/susan` again.",
                    }
                )
            allow_now = _pr_allowlist()
            # Indices match post_github_repo_multi_summary_picker_ephemeral's picked_allow order.
            picked_now = [
                x.strip().lower() for x in allow_now[:100] if (x or "").strip()
            ]
            seen_idx: set[int] = set()
            repos_ordered: list[str] = []
            for v in repos_sel:
                vs = (v or "").strip()
                if not vs.isdigit():
                    continue
                idx = int(vs)
                if idx in seen_idx or idx < 0 or idx >= len(picked_now):
                    continue
                seen_idx.add(idx)
                repos_ordered.append(picked_now[idx])
            if not repos_ordered:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": (
                            "Could not resolve the selected repositories "
                            "(try again or run `/susan summarize prs …`)."
                        ),
                    }
                )

            async def run_pr_summary_multi():
                try:
                    convo = await fetch_slack_history(
                        row["channel_id"], row["thread_ts"], user
                    )
                    await process_pr_summary(
                        repos_ordered,
                        row["command_text"],
                        convo,
                        row["channel_id"],
                        user,
                        row["thread_ts"],
                        None,
                    )
                except Exception as e:
                    logger.exception("PR summary multi-repo follow-up failed")
                    await post_ephemeral(channel, user, f"Susan error: {e}")

            background_tasks.add_task(run_pr_summary_multi)
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "text": f"Using {len(repos_ordered)} repo(s) — fetching merged PRs…",
                }
            )
        # Buttons use github_repo_pick_0, github_repo_pick_1, … (unique action_ids).
        if aid.startswith("github_repo_pick"):
            try:
                pdata = json.loads(a.get("value") or "{}")
            except json.JSONDecodeError:
                return JSONResponse(
                    {"response_type": "ephemeral", "text": "Invalid picker payload."}
                )
            pick_id = pdata.get("i")
            repo = (pdata.get("r") or "").strip().lower()
            if not pick_id or not repo:
                return JSONResponse({"response_type": "ephemeral", "text": "Invalid picker."})
            row = await consume_repo_pick_pending(pick_id, user)
            if not row:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": "Picker expired. Run `/susan` again.",
                    }
                )
            if row["kind"] not in ("pr", "issue", "summary"):
                return JSONResponse({})
            allow = (
                _pr_allowlist() if row["kind"] in ("pr", "summary") else _issue_allowlist()
            )
            if allow and repo not in allow:
                return JSONResponse(
                    {"response_type": "ephemeral", "text": f"Repo `{repo}` is not allowed."}
                )

            async def run_repo_pick():
                try:
                    convo = await fetch_slack_history(row["channel_id"], row["thread_ts"], user)
                    if row["kind"] == "summary":
                        await process_pr_summary(
                            [repo],
                            row["command_text"],
                            convo,
                            row["channel_id"],
                            user,
                            row["thread_ts"],
                            None,
                        )
                    else:
                        await process_command(
                            row["kind"],
                            convo,
                            row["command_text"],
                            row["channel_id"],
                            user,
                            row["thread_ts"],
                            None,
                            github_repo=repo,
                        )
                except Exception as e:
                    logger.exception("GitHub repo pick follow-up failed")
                    await post_ephemeral(channel, user, f"Susan error: {e}")

            background_tasks.add_task(run_repo_pick)
            pick_msg = (
                f"Using `{repo}` — fetching merged PRs…"
                if row["kind"] == "summary"
                else f"Using `{repo}` — preparing preview…"
            )
            return JSONResponse({"response_type": "ephemeral", "text": pick_msg})

        if aid.startswith("github_repo_menu_"):
            pick_id = aid.removeprefix("github_repo_menu_")
            sel = a.get("selected_option") or {}
            repo = (sel.get("value") or "").strip().lower()
            if not pick_id or not repo:
                return JSONResponse(
                    {"response_type": "ephemeral", "text": "No repository selected."}
                )
            row = await consume_repo_pick_pending(pick_id, user)
            if not row:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": "Picker expired. Run `/susan` again.",
                    }
                )
            if row["kind"] not in ("pr", "issue", "summary"):
                return JSONResponse({})
            allow = (
                _pr_allowlist() if row["kind"] in ("pr", "summary") else _issue_allowlist()
            )
            if allow and repo not in allow:
                return JSONResponse(
                    {"response_type": "ephemeral", "text": f"Repo `{repo}` is not allowed."}
                )

            async def run_repo_select():
                try:
                    convo = await fetch_slack_history(row["channel_id"], row["thread_ts"], user)
                    if row["kind"] == "summary":
                        await process_pr_summary(
                            [repo],
                            row["command_text"],
                            convo,
                            row["channel_id"],
                            user,
                            row["thread_ts"],
                            None,
                        )
                    else:
                        await process_command(
                            row["kind"],
                            convo,
                            row["command_text"],
                            row["channel_id"],
                            user,
                            row["thread_ts"],
                            None,
                            github_repo=repo,
                        )
                except Exception as e:
                    logger.exception("GitHub repo menu follow-up failed")
                    await post_ephemeral(channel, user, f"Susan error: {e}")

            background_tasks.add_task(run_repo_select)
            sel_msg = (
                f"Using `{repo}` — fetching merged PRs…"
                if row["kind"] == "summary"
                else f"Using `{repo}` — preparing preview…"
            )
            return JSONResponse({"response_type": "ephemeral", "text": sel_msg})

        if aid == "cancel_susan":
            val = (a.get("value") or "").strip()

            async def consume_cancel_draft() -> None:
                try:
                    if _looks_like_draft_id(val):
                        await consume_user_draft(val, user)
                except Exception:
                    logger.exception("consume_user_draft on cancel")

            background_tasks.add_task(consume_cancel_draft)

            # Ephemeral + sync JSON often ignores invalid combos (e.g. response_type + delete_original).
            # response_url is the documented path to delete the source message (including ephemeral).
            ru = (payload.get("response_url") or "").strip()
            if ru:
                try:
                    await post_slack_delayed_response(ru, {"delete_original": True})
                except Exception:
                    logger.exception("cancel: response_url delete failed; falling back to sync body")
                    return JSONResponse({"delete_original": True})
                return JSONResponse({})
            return JSONResponse({"delete_original": True})
        if aid.startswith("approve_"):
            suffix = aid[len("approve_") :].strip().casefold()
            value = a.get("value") or ""
            if suffix in APPROVE_ACTION_TYPES:
                action_type = suffix
                break
            logger.warning(
                "Unknown approve button: action_id=%r normalized=%r user=%s",
                aid,
                suffix,
                user,
            )

    if action_type is None:
        # Wrong [0], link-only quirks, or stale payload — do not post "Unknown action."
        logger.warning("No recognized approve/cancel in actions: %s", actions)
        return JSONResponse({})

    async def execute():
        notify_ch = (channel or "").strip()
        try:
            if action_type == "doc":
                result = await create_google_doc(value, user)
            elif action_type == "email":
                text = value
                if _looks_like_draft_id(value):
                    row = await consume_user_draft(value, user)
                    if not row:
                        await post_ephemeral(
                            channel,
                            user,
                            "That draft expired. Run `/susan send email …` again.",
                        )
                        return
                    text = row["content"]
                result = await send_gmail(text, user)
            elif action_type == "invite":
                text = value
                if _looks_like_draft_id(value):
                    row = await consume_user_draft(value, user)
                    if not row:
                        await post_ephemeral(
                            channel,
                            user,
                            "That draft expired. Run `/susan create invite …` again.",
                        )
                        return
                    text = row["content"]
                result = await create_calendar_invite(text, user)
            elif action_type == "issue":
                result = await create_github_issue(value, user)
            elif action_type == "pr_summary":
                if not _looks_like_draft_id(value):
                    await post_ephemeral(
                        channel,
                        user,
                        "Invalid PR summary draft. Run `/susan summarize prs …` again.",
                    )
                    return
                row = await consume_user_draft(value, user)
                if not row or row.get("kind") != "pr_summary":
                    await post_ephemeral(
                        channel,
                        user,
                        "That PR summary draft expired. Run `/susan summarize prs …` again.",
                    )
                    return
                try:
                    meta = json.loads(row["content"])
                    title = (meta.get("title") or "PR summary").strip()
                    body = meta.get("body") or ""
                    post_ch = (meta.get("channel_id") or channel or "").strip()
                    th = meta.get("thread_ts")
                    if not isinstance(th, str) or not th.strip():
                        th = None
                    if not post_ch:
                        result = "Could not post — missing channel."
                    else:
                        notify_ch = notify_ch or post_ch
                        await post_pr_summary_to_channel(post_ch, th, title, body)
                        result = "Posted the PR summary to the channel."
                except (json.JSONDecodeError, TypeError, RuntimeError) as e:
                    logger.exception("pr_summary post failed")
                    result = f"Susan error posting summary: {e}"
            elif action_type == "weekly_status":
                if not _looks_like_draft_id(value):
                    await post_ephemeral(
                        channel,
                        user,
                        "Invalid weekly status draft. Run `/susan weekly status` again.",
                    )
                    return
                row = await consume_user_draft(value, user)
                if not row or row.get("kind") != "weekly_status":
                    await post_ephemeral(
                        channel,
                        user,
                        "That weekly status draft expired. Run `/susan weekly status` again.",
                    )
                    return
                try:
                    meta = json.loads(row["content"])
                    title = (meta.get("title") or "Weekly status").strip()
                    body = meta.get("body") or ""
                    post_ch = (meta.get("channel_id") or channel or "").strip()
                    th = meta.get("thread_ts")
                    if not isinstance(th, str) or not th.strip():
                        th = None
                    if not post_ch:
                        result = "Could not post — missing channel."
                    else:
                        notify_ch = notify_ch or post_ch
                        await post_pr_summary_to_channel(post_ch, th, title, body)
                        result = "Posted the weekly status to the channel."
                except (json.JSONDecodeError, TypeError, RuntimeError) as e:
                    logger.exception("weekly_status post failed")
                    result = f"Susan error posting weekly status: {e}"
            elif action_type == "pr":
                result = await create_github_pr(value, user)
            else:
                logger.error("Unhandled approve action_type=%s", action_type)
                await post_ephemeral(
                    channel,
                    user,
                    "Susan internal error: unknown approve action.",
                )
                return
            if notify_ch:
                await post_ephemeral(notify_ch, user, f"✓ Susan done: {result}")
            else:
                logger.warning(
                    "No channel for approve ack user=%s action=%s", user, action_type
                )
        except Exception as e:
            await post_ephemeral(channel, user, f"Susan error during execution: {str(e)}")

    background_tasks.add_task(execute)
    return JSONResponse({"response_type": "ephemeral", "text": "Susan is executing..."})
