"""HTTP routes and FastAPI application factory."""
from __future__ import annotations

import html
import logging
import os
import re
import urllib.parse
from contextlib import asynccontextmanager

from db import (
    consume_oauth_resume_pending,
    create_oauth_resume_pending,
    exchange_code_for_tokens,
    exchange_github_code_for_token,
    init_db,
    upsert_github_token,
    upsert_tokens,
    user_has_github_tokens,
    user_has_google_tokens,
)
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.config import ACTIONS, GITHUB_ACTIONS, GOOGLE_ACTIONS, logger
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
from app.interactions import handle_action
from app.oauth import (
    _github_oauth_configured,
    _google_oauth_configured,
    github_authorize_url,
    google_authorize_url,
    make_oauth_state,
    parse_oauth_state,
    public_base_url,
)
from app.pr_summary import process_pr_summary
from app.slack_commands import process_command, resume_slash_after_oauth
from app.slack_api import (
    _slack_form_fields,
    detect_action,
    extract_slack_archives_link,
    fetch_slack_history,
    notify_user_ephemeral,
    post_ephemeral,
    verify_slack,
)
from app.weekly_context import (
    resolve_github_repos_for_weekly_status,
    strip_weekly_status_auto_post_flags,
    weekly_status_auto_post_user_allowed,
    weekly_status_include_github,
)
from app.weekly_status import process_weekly_status

@asynccontextmanager
async def lifespan(app: FastAPI):
    susan_log = logging.getLogger("susan")
    susan_log.setLevel(logging.INFO)
    if not susan_log.handlers:
        _h = logging.StreamHandler()
        _h.setFormatter(logging.Formatter("%(levelname)s [susan] %(message)s"))
        susan_log.addHandler(_h)
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/auth/google")
async def auth_google_start(state: str):
    parsed = parse_oauth_state(state)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    try:
        _ = os.environ["GOOGLE_CLIENT_ID"]
        _ = os.environ["GOOGLE_CLIENT_SECRET"]
        _ = os.environ["GOOGLE_REDIRECT_URI"]
    except KeyError:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    return RedirectResponse(google_authorize_url(state))


@app.get("/auth/google/callback")
async def auth_google_callback(
    code: str, state: str, background_tasks: BackgroundTasks
):
    parsed = parse_oauth_state(state)
    if not parsed:
        return HTMLResponse(
            "<html><body><p>Invalid or expired session. Close this window and run <code>/susan connect</code> again in Slack.</p></body></html>",
            status_code=400,
        )
    uid, slack_channel_id, resume_id = parsed
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "")
    resumed = False
    try:
        data = await exchange_code_for_tokens(code, redirect_uri)
        access = data["access_token"]
        refresh = data.get("refresh_token")
        if not refresh:
            return HTMLResponse(
                "<html><body><p>Google did not return a refresh token. Revoke Susan's access in your Google account settings and try <code>/susan connect</code> again (use the same Google account).</p></body></html>",
                status_code=400,
            )
        expires_in = int(data.get("expires_in", 3600))
        await upsert_tokens(uid, access, refresh, expires_in)
        logger.info(
            "Google OAuth tokens stored for Slack user=%s channel_in_state=%s",
            uid,
            slack_channel_id or "(none)",
        )
        if resume_id:
            row = await consume_oauth_resume_pending(resume_id, uid, "google")
            if row:
                background_tasks.add_task(resume_slash_after_oauth, row)
                resumed = True
    except Exception as e:
        logger.exception("Google OAuth callback failed for user=%s", uid)
        return HTMLResponse(
            "<html><body><p>Could not complete Google sign-in: "
            f"{html.escape(str(e))}</p></body></html>",
            status_code=400,
        )

    if slack_channel_id:
        try:
            if resumed:
                msg = "✓ *Google connected.* Continuing your previous `/susan` command in this channel…"
            else:
                msg = "✓ *Google connected.* You can use `/susan` anytime."
            await post_ephemeral(
                slack_channel_id,
                uid,
                msg,
            )
            logger.info("Posted Google connect confirmation to Slack channel=%s user=%s", slack_channel_id, uid)
        except Exception as e:
            logger.warning("Could not post Slack confirmation after Google OAuth: %s", e)

    html_note = (
        "Susan is continuing your request in Slack."
        if resumed
        else "You can close this tab."
    )
    return HTMLResponse(
        f"<html><body><p><strong>Google connected.</strong> {html_note}</p></body></html>"
    )


@app.get("/auth/github")
async def auth_github_start(state: str):
    parsed = parse_oauth_state(state)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    try:
        _ = os.environ["GITHUB_CLIENT_ID"]
        _ = os.environ["GITHUB_CLIENT_SECRET"]
        _ = os.environ["GITHUB_REDIRECT_URI"]
    except KeyError:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    return RedirectResponse(github_authorize_url(state))


@app.get("/auth/github/callback")
async def auth_github_callback(
    code: str, state: str, background_tasks: BackgroundTasks
):
    parsed = parse_oauth_state(state)
    if not parsed:
        return HTMLResponse(
            "<html><body><p>Invalid or expired session. Close this window and run <code>/susan connect github</code> again in Slack.</p></body></html>",
            status_code=400,
        )
    uid, slack_channel_id, resume_id = parsed
    redirect_uri = os.environ.get("GITHUB_REDIRECT_URI", "")
    resumed = False
    try:
        data = await exchange_github_code_for_token(code, redirect_uri)
        access = data.get("access_token")
        if not access:
            return HTMLResponse(
                "<html><body><p>GitHub did not return an access token. Try <code>/susan connect github</code> again.</p></body></html>",
                status_code=400,
            )
        await upsert_github_token(uid, access)
        logger.info(
            "GitHub OAuth token stored for Slack user=%s channel_in_state=%s",
            uid,
            slack_channel_id or "(none)",
        )
        if resume_id:
            row = await consume_oauth_resume_pending(resume_id, uid, "github")
            if row:
                background_tasks.add_task(resume_slash_after_oauth, row)
                resumed = True
    except Exception as e:
        logger.exception("GitHub OAuth callback failed for user=%s", uid)
        return HTMLResponse(
            "<html><body><p>Could not complete GitHub sign-in: "
            f"{html.escape(str(e))}</p></body></html>",
            status_code=400,
        )

    if slack_channel_id:
        try:
            if resumed:
                msg = "✓ *GitHub connected.* Continuing your previous `/susan` command in this channel…"
            else:
                msg = "✓ *GitHub connected.* You can use `/susan` anytime."
            await post_ephemeral(
                slack_channel_id,
                uid,
                msg,
            )
            logger.info("Posted GitHub connect confirmation to Slack channel=%s user=%s", slack_channel_id, uid)
        except Exception as e:
            logger.warning("Could not post Slack confirmation after GitHub OAuth: %s", e)

    html_note = (
        "Susan is continuing your request in Slack."
        if resumed
        else "You can close this tab."
    )
    return HTMLResponse(
        f"<html><body><p><strong>GitHub connected.</strong> {html_note}</p></body></html>"
    )

def connect_google_slack_response(
    user: str,
    intro: str | None = None,
    channel_id: str | None = None,
    resume_id: str | None = None,
) -> JSONResponse:
    """Ephemeral message with link to Google OAuth. Pass channel_id so we can notify Slack after connect.
    Optional resume_id continues the same /susan command after OAuth (embedded in signed state)."""
    base = public_base_url()
    if not base:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Set PUBLIC_BASE_URL (e.g. https://your-app.up.railway.app) or set GOOGLE_REDIRECT_URI to https://…/auth/google/callback so the Connect link works.",
            }
        )
    try:
        _ = os.environ["GOOGLE_CLIENT_ID"]
        _ = os.environ["GOOGLE_CLIENT_SECRET"]
        _ = os.environ["GOOGLE_REDIRECT_URI"]
    except KeyError:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Google OAuth is not configured. Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI.",
            }
        )
    intro = intro or "Connect your Google account so Susan uses *your* Docs, Gmail, and Calendar."
    state = make_oauth_state(
        user, channel_id=channel_id or None, resume_id=resume_id
    )
    auth_path = f"{base}/auth/google?state={urllib.parse.quote(state, safe='')}"
    # Use a mrkdwn link, not a Block Kit url button: Slack often treats url-less or
    # invalid-url buttons as interactive (random action_id → POST /susan/actions).
    link = f"<{auth_path}|Connect Google Account>"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{intro}\n\n{link}",
            },
        },
    ]
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": "Google connection (only visible to you).",
            "blocks": blocks,
        }
    )


def connect_github_slack_response(
    user: str,
    intro: str | None = None,
    channel_id: str | None = None,
    resume_id: str | None = None,
) -> JSONResponse:
    """Ephemeral message with link to GitHub OAuth. Optional resume_id continues the command after OAuth."""
    base = public_base_url()
    if not base:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Set PUBLIC_BASE_URL or GITHUB_REDIRECT_URI (e.g. https://your-app.up.railway.app/auth/github/callback) so the Connect link works.",
            }
        )
    if not _github_oauth_configured():
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "GitHub OAuth is not configured. Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and GITHUB_REDIRECT_URI.",
            }
        )
    intro = intro or "Connect your GitHub account so Susan can open **issues** and **PRs**. Repos: `GITHUB_REPO` / `GITHUB_REPOS` (allowlist) on the server, or type `owner/repo` in the command."
    state = make_oauth_state(
        user, channel_id=channel_id or None, resume_id=resume_id
    )
    auth_path = f"{base}/auth/github?state={urllib.parse.quote(state, safe='')}"
    link = f"<{auth_path}|Connect GitHub Account>"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{intro}\n\n{link}",
            },
        },
    ]
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": "GitHub connection (only visible to you).",
            "blocks": blocks,
        }
    )


def connect_slack_response_combined(user: str, channel_id: str | None = None) -> JSONResponse:
    """Ephemeral with Google and/or GitHub connect links."""
    base = public_base_url()
    g_ok = _google_oauth_configured()
    h_ok = _github_oauth_configured()
    if not g_ok and not h_ok:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "OAuth is not configured. Set Google (`GOOGLE_*`) and/or GitHub (`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`) env vars.",
            }
        )
    if not base:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Set PUBLIC_BASE_URL or a redirect URI so OAuth links work.",
            }
        )
    parts: list[str] = ["*Link your accounts* (only visible to you):\n"]
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": ""}}]
    if g_ok:
        state = make_oauth_state(user, channel_id=channel_id or None)
        gurl = f"{base}/auth/google?state={urllib.parse.quote(state, safe='')}"
        parts.append(f"• *Google* (Docs, Gmail, Calendar): <{gurl}|Connect Google>")
    if h_ok:
        state = make_oauth_state(user, channel_id=channel_id or None)
        hurl = f"{base}/auth/github?state={urllib.parse.quote(state, safe='')}"
        parts.append(f"• *GitHub* (create PRs): <{hurl}|Connect GitHub>")
    blocks[0]["text"]["text"] = "\n".join(parts)
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": "Connect Google and/or GitHub (only visible to you).",
            "blocks": blocks,
        }
    )


def normalize_slack_command_text(raw: str) -> str:
    """Strip Slack/client quirks (NBSP, ZWSP, BOM) from slash command text before matching."""
    s = (raw or "").strip()
    for ch in ("\u00a0", "\u200b", "\u200c", "\ufeff"):
        s = s.replace(ch, "")
    return s.strip()


def is_susan_help_command(text_lower: str) -> bool:
    t = text_lower.strip()
    if not t:
        return False
    if t == "?":
        return True
    # Word boundary so "helpful" is not treated as help; allows "help", "help me", "commands …"
    return bool(re.match(r"^(help|commands|usage)\b", t))


def susan_slash_help_response() -> JSONResponse:
    """Ephemeral Block Kit help; command keywords mirror detect_action / ACTIONS."""
    action_lines: list[str] = []
    for _key, (label, kws) in ACTIONS.items():
        kw_str = ", ".join(f"`{k}`" for k in kws)
        action_lines.append(f"• *{label}* — include one of: {kw_str}")
    actions_body = "\n".join(action_lines)

    body_how = (
        "*How it works*\n"
        "Run `/susan` *in a thread* so Susan reads that thread, or paste a *Slack message link* "
        "(⋯ → Copy link) if you’re not in the thread. You’ll get a *private preview*; then *Approve*, "
        "*Edit* (email & calendar), or *Cancel*. "
        "For *summarize merged PRs* and *weekly status*, approving posts to the *channel* "
        "(everyone can see it)."
    )
    body_connect = (
        "*Connect accounts*\n"
        "• `/susan connect` — Google + GitHub (whatever is configured on the server)\n"
        "• `/susan connect google` — Docs, Gmail, Calendar, Drive metadata (weekly status: linked folders/files)\n"
        "• `/susan connect github` — issues, PRs, PR summaries; *tech-channel* weekly status (see below)"
    )
    body_what = "*What to ask*\n" + actions_body
    body_ex = (
        "*Examples*\n"
        "`/susan create a doc summarizing this thread for the launch notes`\n"
        "`/susan send email to the team thanking them for the release`\n"
        "`/susan create invite for a 30m design review next Tuesday`\n"
        "`/susan create issue in org/repo login button is misaligned`\n"
        "`/susan create pr in org/repo fixing the typo we discussed`\n"
        "`/susan summarize merged prs for org/repo last 30 days`\n"
        "`/susan summarize merged prs for org/a org/b org/c last 14 days`\n"
        "`/susan weekly status` · `/susan weekly report last 14 days` · `/susan team status last calendar week`\n"
        "`/susan weekly status --no-approval` — generate and *post immediately* to the channel (for schedules / Mondays); "
        "same with `-no-approval`. Optional: set `SUSAN_WEEKLY_AUTO_POST_USER_IDS` to comma-separated Slack user ids "
        "to restrict who may use that flag."
    )
    body_pr = (
        "*PR summaries & weekly status — time ranges* (optional; default is last 7 days)\n"
        "`last 14 days` · `past week` · `past month` · `since 2026-01-01` · `from 2026-01-01 to 2026-03-01` · "
        "`last calendar week` (Mon–Sun UTC, previous week)"
    )
    body_repo = (
        "*Repos*\n"
        "Name `owner/repo` in the message (several: `org/a org/b` or `repos: org/a, org/b`), "
        "or use `GITHUB_REPO` / `GITHUB_REPOS` on the server. "
        "For *PR summaries* with multiple entries in `GITHUB_REPOS` and no repos in the text, "
        "Susan shows a *multi-select* — choose repos, then *Run PR summary*. "
        "*Weekly status*: in *tech* Slack channels (default names: `team-tech`, `software`, `security` — set "
        "`SUSAN_TECH_WEEKLY_CHANNEL_NAMES` to override), Susan includes **every** repo in `GITHUB_REPOS` "
        "(or `GITHUB_REPO` if the list is empty) and needs GitHub connected. In *other* channels, weekly status is "
        "**Slack-only** (no GitHub). The digest follows the channel you run `/susan` in, or a pasted archives link.\n"
        "For *PRs/issues*, if several repos are allowed she still asks you to pick one.\n\n"
        "*Dependabot / vulnerabilities* (tech weekly status only): set `GITHUB_OAUTH_SCOPE` to include **`security_events`** "
        "(for example `repo security_events`) and reconnect GitHub; otherwise Susan will note that alerts are unavailable.\n\n"
        "*Google Drive & bookmarks* (weekly status): Google Docs/Drive URLs from **channel messages and channel bookmarks** "
        "(needs `bookmarks:read`) seed a Drive scan; Susan lists files in linked folders (recursive) and linked files whose "
        "`modifiedTime` falls in the date window — using the **Google account** of the user who runs `/susan`. Enable the "
        "**Google Drive API** in GCP and reconnect Google after "
        "deploy (new `drive.metadata.readonly` scope). Caps: `WEEKLY_DRIVE_MAX_FOLDERS`, `WEEKLY_DRIVE_MAX_DEPTH`, "
        "`WEEKLY_DRIVE_MAX_FILES_REPORTED`, `WEEKLY_DRIVE_MAX_API_CALLS`."
    )
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Susan — commands & examples", "emoji": True},
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": body_how}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": body_connect}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": body_what}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": body_ex}},
        {"type": "section", "text": {"type": "mrkdwn", "text": body_pr}},
        {"type": "section", "text": {"type": "mrkdwn", "text": body_repo}},
    ]
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": "Susan — commands & examples (see the full message).",
            "blocks": blocks,
        }
    )


@app.get("/susan")
async def slash_susan_get():
    """Slack invokes POST /susan with a form body; GET is probes/browsers only."""
    return {
        "message": "This URL is for Slack slash commands only (POST from Slack). Use /susan in Slack.",
        "method": "POST",
    }


@app.post("/susan")
async def slash_susan(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    ts = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    logger.info(
        "Slack POST /susan: %d bytes, X-Slack-Signature=%s, X-Slack-Request-Timestamp=%s",
        len(body),
        "set" if sig else "MISSING",
        "set" if ts else "MISSING",
    )
    if not verify_slack(body, ts, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    form = _slack_form_fields(body)
    text = normalize_slack_command_text(form.get("text", ""))
    channel = form.get("channel_id", "")
    user = form.get("user_id", "")
    thread_ts = form.get("thread_ts") or None
    response_url = form.get("response_url") or None
    text_lower = text.lower()
    logger.info("Slack slash verified: user=%s channel=%s text=%r", user, channel, text[:120] if text else "")

    if text_lower == "connect" or text_lower.startswith("connect "):
        rest = text_lower[len("connect") :].strip()
        if rest in ("github", "gh"):
            return connect_github_slack_response(user, channel_id=channel or None)
        if rest in ("google",):
            return connect_google_slack_response(user, channel_id=channel or None)
        if rest == "":
            return connect_slack_response_combined(user, channel_id=channel or None)
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Unknown `connect` subcommand. Use `connect`, `connect google`, or `connect github`.",
            }
        )

    if is_susan_help_command(text_lower):
        return susan_slash_help_response()

    action = detect_action(text)
    if not action:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Susan doesn’t understand that command. Try `/susan help` for examples, "
                    "or keywords like `connect`, `doc`, `email`, `invite`, `issue`, `pr`, "
                    "`summarize prs`, or `weekly status`."
                ),
            }
        )

    weekly_command_text = text
    weekly_auto_post = False
    if action == "weekly_status":
        weekly_command_text, weekly_auto_post = strip_weekly_status_auto_post_flags(text)
        if weekly_auto_post and not weekly_status_auto_post_user_allowed(user):
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "Auto-publish (`--no-approval` / `-no-approval`) is restricted for your user. "
                        "Remove the flag for a normal preview, or ask an admin to add your Slack user id to "
                        "`SUSAN_WEEKLY_AUTO_POST_USER_IDS` on the server."
                    ),
                }
            )

    if action in GOOGLE_ACTIONS and not await user_has_google_tokens(user):
        resume_id = await create_oauth_resume_pending(
            user, channel, thread_ts, text, action, "google"
        )
        return connect_google_slack_response(
            user,
            intro="*Google isn’t connected yet.* Use the link below to sign in — Susan will continue this command when you’re done (or use `/susan connect google` anytime).",
            channel_id=channel or None,
            resume_id=resume_id,
        )

    link_ch_digest, _ = extract_slack_archives_link(
        weekly_command_text if action == "weekly_status" else text
    )
    digest_channel_for_weekly = link_ch_digest or channel
    weekly_wants_github = False
    if action == "weekly_status":
        weekly_wants_github = await weekly_status_include_github(
            digest_channel_for_weekly, channel, form.get("channel_name")
        )
        if weekly_wants_github and not await user_has_github_tokens(user):
            resume_id = await create_oauth_resume_pending(
                user, channel, thread_ts, text, action, "github"
            )
            return connect_github_slack_response(
                user,
                intro=(
                    "*GitHub isn’t connected yet.* Weekly status in *tech channels* includes repo metrics "
                    "(PRs, Dependabot). Use the link below to sign in — Susan will continue when you’re done "
                    "(or use `/susan connect github` anytime)."
                ),
                channel_id=channel or None,
                resume_id=resume_id,
            )

    if action in GITHUB_ACTIONS and not await user_has_github_tokens(user):
        resume_id = await create_oauth_resume_pending(
            user, channel, thread_ts, text, action, "github"
        )
        return connect_github_slack_response(
            user,
            intro="*GitHub isn’t connected yet.* Use the link below to sign in — Susan will continue this command when you’re done (or use `/susan connect github` anytime).",
            channel_id=channel or None,
            resume_id=resume_id,
        )

    async def run():
        try:
            link_ch, link_ts = extract_slack_archives_link(
                weekly_command_text if action == "weekly_status" else text
            )
            hist_channel = link_ch or channel
            hist_thread_ts = thread_ts or link_ts
            logger.info(
                "Susan background: fetch history channel=%s thread_ts=%s (from_link channel=%s ts=%s)",
                hist_channel,
                hist_thread_ts,
                link_ch,
                link_ts,
            )
            if action == "weekly_status":
                if not weekly_wants_github:
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
            logger.exception("Susan background task failed: %s", e)
            try:
                await notify_user_ephemeral(channel, user, f"Susan error: {str(e)}", None, response_url)
            except Exception as e2:
                logger.error("Could not notify user in Slack: %s", e2)

    background_tasks.add_task(run)
    if action == "pr_summary":
        ack = (
            "Got it — Susan is fetching *merged PRs* from GitHub for the chosen repo(s) and date range, "
            "then drafting a summary (only visible to you)."
        )
    elif action == "weekly_status":
        if weekly_auto_post:
            if weekly_wants_github:
                ack = (
                    "Got it — Susan is generating *weekly status* with *GitHub* metrics and will *post it "
                    "to this channel* (`--no-approval`). You’ll get a short confirmation when done."
                )
            else:
                ack = (
                    "Got it — Susan is generating *Slack-only weekly status* and will *post it to this channel* "
                    "(`--no-approval`). You’ll get a short confirmation when done."
                )
        elif weekly_wants_github:
            ack = (
                "Got it — Susan is loading *channel history* and *GitHub* metrics (PRs, Dependabot) for "
                "all repos in `GITHUB_REPOS`, then drafting a *weekly status* preview (only visible to you)."
            )
        else:
            ack = (
                "Got it — Susan is drafting a *weekly status* from *Slack only* (this channel isn’t a tech "
                "channel — no GitHub). Preview is only visible to you."
            )
    else:
        ack = f"Got it — Susan is reading the channel and preparing a *{ACTIONS[action][0]}* preview..."
    return JSONResponse({"response_type": "ephemeral", "text": ack})

@app.get("/")
async def root():
    """Avoid 404 noise from bots and uptime probes hitting the base URL."""
    return {"service": "susan", "docs": "POST /susan (Slack slash), GET /health"}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "susan"}


@app.post("/susan/actions")
async def susan_slack_actions(request: Request, background_tasks: BackgroundTasks):
    return await handle_action(request, background_tasks)
