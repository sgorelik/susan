"""HTTP routes and FastAPI application factory."""
from __future__ import annotations

import asyncio
import html
import json
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
    exchange_granola_code_for_token,
    init_db,
    upsert_github_token,
    upsert_granola_token,
    upsert_tokens,
    user_has_github_tokens,
    user_has_google_tokens,
    user_has_granola_tokens,
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
    _granola_oauth_configured,
    github_authorize_url,
    google_authorize_url,
    granola_authorize_url,
    granola_client_credentials_set,
    granola_redirect_uri,
    make_oauth_state,
    parse_oauth_state,
    public_base_url,
    public_origin_for_connect_links,
)
from app.pr_summary import process_pr_summary
from app.roadmap import (
    ROADMAP_ACKS,
    parse_roadmap_command,
    process_roadmap,
    process_roadmap_add,
)
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
from app.granola_summarize import parse_granola_slash_command, process_granola_summarize
from app.action_items import (
    _strip_all_channels_scope,
    is_personal_actions_command,
    is_team_actions_command,
    parse_action_items_command,
    process_action_items,
)
from app.channel_surface import (
    parse_failures_command,
    parse_reviews_command,
    parse_standup_command,
    process_channel_surface,
)
from app.standup_digest import parse_daily_standup_command, process_standup_digest

from app.sales_prep import parse_sales_prep_command, process_sales_prep
from app.slack_events import handle_slack_event_callback, parse_events_body
from app.scheduler import handle_schedule_slash, parse_schedule_command, start_scheduler, stop_scheduler
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
    scheduler_task = await start_scheduler()
    yield
    await stop_scheduler(scheduler_task)

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


@app.get("/auth/granola")
async def auth_granola_start(state: str):
    """Initiate the Granola OAuth flow for the signed Slack-user state."""
    parsed = parse_oauth_state(state)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    if not _granola_oauth_configured():
        raise HTTPException(status_code=500, detail="Granola OAuth not configured")
    return RedirectResponse(granola_authorize_url(state))


@app.get("/auth/granola/callback")
async def auth_granola_callback(
    code: str, state: str, background_tasks: BackgroundTasks
):
    """Granola OAuth callback: exchanges ``code`` for an access token, stores it,
    and resumes any pending ``/susan`` command via ``oauth_resume_pending``."""
    parsed = parse_oauth_state(state)
    if not parsed:
        return HTMLResponse(
            "<html><body><p>Invalid or expired session. Close this window and run <code>/susan connect granola</code> again in Slack.</p></body></html>",
            status_code=400,
        )
    uid, slack_channel_id, resume_id = parsed
    redirect_uri = granola_redirect_uri()
    resumed = False
    try:
        data = await exchange_granola_code_for_token(code, redirect_uri)
        access = data.get("access_token")
        if not access:
            return HTMLResponse(
                "<html><body><p>Granola did not return an access token. Try <code>/susan connect granola</code> again.</p></body></html>",
                status_code=400,
            )
        await upsert_granola_token(uid, access)
        logger.info(
            "Granola OAuth token stored for Slack user=%s channel_in_state=%s",
            uid,
            slack_channel_id or "(none)",
        )
        if resume_id:
            row = await consume_oauth_resume_pending(resume_id, uid, "granola")
            if row:
                background_tasks.add_task(resume_slash_after_oauth, row)
                resumed = True
    except Exception as e:
        logger.exception("Granola OAuth callback failed for user=%s", uid)
        return HTMLResponse(
            "<html><body><p>Could not complete Granola sign-in: "
            f"{html.escape(str(e))}</p></body></html>",
            status_code=400,
        )

    if slack_channel_id:
        try:
            if resumed:
                msg = "✓ *Granola connected.* Continuing your previous `/susan` command in this channel…"
            else:
                msg = "✓ *Granola connected.* You can use `/susan` anytime."
            await post_ephemeral(
                slack_channel_id,
                uid,
                msg,
            )
            logger.info("Posted Granola connect confirmation to Slack channel=%s user=%s", slack_channel_id, uid)
        except Exception as e:
            logger.warning("Could not post Slack confirmation after Granola OAuth: %s", e)

    html_note = (
        "Susan is continuing your request in Slack."
        if resumed
        else "You can close this tab."
    )
    return HTMLResponse(
        f"<html><body><p><strong>Granola connected.</strong> {html_note}</p></body></html>"
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


def connect_granola_slack_response(
    user: str,
    intro: str | None = None,
    channel_id: str | None = None,
    resume_id: str | None = None,
) -> JSONResponse:
    """Report shared API access or offer per-user Granola OAuth."""
    if (os.environ.get("GRANOLA_API_KEY") or "").strip():
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Granola is already connected through Susan’s shared workspace API key. "
                    "Try `/susan granola last week` (or `/susan gn last week`)."
                ),
            }
        )
    granola_redir = granola_redirect_uri()
    if not granola_redir:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Granola OAuth needs a **callback URL** registered with Granola and on this server. Set "
                    "`PUBLIC_BASE_URL` to your deploy’s HTTPS origin (e.g. `https://your-service.up.railway.app`) "
                    "so Susan uses `…/auth/granola/callback`, *or* set `GRANOLA_REDIRECT_URI` to the full callback "
                    "URL (must match what you registered with Granola)."
                ),
            }
        )
    if not granola_client_credentials_set():
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Set **`GRANOLA_CLIENT_ID`** and **`GRANOLA_CLIENT_SECRET`** in Railway (or `.env`). "
                    "Susan uses a normal OAuth *authorization_code* flow. If Granola hasn’t given you a static "
                    "client id/secret for your app, ask them at **hey@granola.so** — their MCP docs describe "
                    "dynamic registration for some clients: "
                    "https://docs.granola.ai/help-center/sharing/integrations/mcp"
                ),
            }
        )
    base = public_origin_for_connect_links()
    if not base:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Could not determine your app’s public **origin** for the Connect link. Set `PUBLIC_BASE_URL` "
                    "or a full `GRANOLA_REDIRECT_URI` URL."
                ),
            }
        )
    intro = intro or "Connect your Granola account so Susan can use *your* meeting notes to inform responses."
    state = make_oauth_state(
        user, channel_id=channel_id or None, resume_id=resume_id
    )
    auth_path = f"{base}/auth/granola?state={urllib.parse.quote(state, safe='')}"
    link = f"<{auth_path}|Connect Granola Account>"
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
            "text": "Granola connection (only visible to you).",
            "blocks": blocks,
        }
    )


def connect_slack_response_combined(user: str, channel_id: str | None = None) -> JSONResponse:
    """Ephemeral with Google, GitHub, and/or Granola connect links."""
    base = public_base_url()
    g_ok = _google_oauth_configured()
    h_ok = _github_oauth_configured()
    n_ok = _granola_oauth_configured()
    if not g_ok and not h_ok and not n_ok:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "OAuth is not configured. Set Google (`GOOGLE_*`), GitHub (`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`), and/or Granola (`GRANOLA_CLIENT_ID`, `GRANOLA_CLIENT_SECRET`) env vars.",
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
    if n_ok:
        state = make_oauth_state(user, channel_id=channel_id or None)
        nurl = f"{base}/auth/granola?state={urllib.parse.quote(state, safe='')}"
        parts.append(f"• *Granola* (meeting notes): <{nurl}|Connect Granola>")
    blocks[0]["text"]["text"] = "\n".join(parts)
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": "Connect Google, GitHub, and/or Granola (only visible to you).",
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


_HELP_TOPICS = ("actions", "status", "roadmap", "connect", "schedule", "all")


def parse_help_topic(text: str) -> str:
    """Return the topic after `help`/`commands`/`usage`, or "" for the overview."""
    t = (text or "").strip().lower()
    if t == "?":
        return ""
    remainder = re.sub(r"^(help|commands|usage)\b", "", t).strip()
    remainder = re.sub(
        r"^(me\s+with|me|with|on|for|about|the|my|team)\b", "", remainder
    ).strip()
    for topic in _HELP_TOPICS:
        if remainder == topic or remainder.startswith(topic):
            return topic
    if remainder.startswith("action") or remainder.startswith("todo"):
        return "actions"
    if remainder.startswith("weekly") or remainder.startswith("pr"):
        return "status"
    if remainder.startswith("board"):
        return "roadmap"
    return ""


def _help_overview() -> list[str]:
    return [
        "*How it works*\n"
        "Run `/susan` *in a thread* so Susan reads that thread, or paste a *Slack message link* "
        "(⋯ → Copy link). You get a *private preview* — then *Approve*, *Edit*, or *Cancel*. "
        "Weekly status and PR summaries post to the *channel* once approved; everything else "
        "stays private unless you say otherwise.",
        "*Most used*\n"
        "• `/susan my actions` — *your* tasks across every channel, Gmail, Drive, and Granola (private)\n"
        "• `/susan team actions` — *everyone's* open tasks in *this* channel\n"
        "• `/susan daily status` — standup digest from Granola: updates, blockers, decisions\n"
        "• `/susan weekly status` — team digest for this channel\n"
        "• `/susan granola` — summarize your recent meetings\n"
        "• `/susan needs my review` — PRs and asks waiting on you\n"
        "• `/susan surface failures` — failing CI, promote, and cost alerts\n"
        "• `/susan board status` — roadmap digest from the GitHub Projects board\n"
        "• `/susan create issue in org/repo …` · `create a doc …` · `send email …`",
        "*More detail*\n"
        "`/susan help actions` · `help status` · `help roadmap` · `help connect` · "
        "`help schedule` · `help all`\n"
        "_Most commands take a time range: `last 14 days`, `past week`, `last calendar week`, "
        "`since 2026-01-01`. Default is the last 7 days._",
    ]


def _help_actions() -> list[str]:
    return [
        "*Actions — two different commands*\n"
        "• `/susan my actions` — *your own* inbox: commitments you made, direct asks, mentions, "
        "and pending replies. Reads *every channel Susan can see* plus Gmail, Drive comments, "
        "and Granola. *Only you see it*, and it is never posted to a channel.\n"
        "• `/susan team actions` — *everyone's* outstanding tasks in *this one channel*, with "
        "*@mentions*. Posts to the channel after you approve. `/susan actions` does the same thing.",
        "*Options*\n"
        "• Add a range: `/susan my actions last 14 days` · `/susan team actions past month`\n"
        "• `/susan team actions --no-approval` — post straight to the channel (for schedules). "
        "Restrict who may use it with `SUSAN_WEEKLY_AUTO_POST_USER_IDS`.\n"
        "• Team actions are kept in a *Google Sheet* (one tab per channel) so you can edit tasks "
        "and status; Susan syncs on the next run.\n"
        "• Reply in the digest thread with `done`, `in progress`, or `won't do` (reference `#1`) "
        "and Susan remembers it for the next roundup.",
    ]


def _help_status() -> list[str]:
    return [
        "*Daily standup digest* (from Granola notes)\n"
        "`/susan daily status` — reads today's standup meeting from Granola and posts "
        "*Updates*, *Blockers*, *Decisions*, *Parking lot*, *Discussion*, and *Next steps*. "
        "Empty sections are dropped.\n"
        "• `/susan daily status yesterday` · `/susan daily status last 3 days`\n"
        "• `--no-approval` (or just `no approval`) posts straight to the channel for everyone; "
        "without it you get a private preview. A *scheduled* daily status always posts to the channel.\n"
        "• Post it automatically: "
        "`/susan schedule add daily status every weekday at 10:00 in #team-tech`\n"
        "• Susan finds the meeting by title. If yours isn't called \"standup\", set "
        "`SUSAN_STANDUP_MEETING_TERMS` to a comma-separated list of title words.",
        "*Weekly status*\n"
        "`/susan weekly status` · `/susan weekly report last 14 days` · `/susan team status last calendar week`\n"
        "In *tech* channels (`team-tech`, `software`, `security` by default — override with "
        "`SUSAN_TECH_WEEKLY_CHANNEL_NAMES`) Susan includes every repo in `GITHUB_REPOS` and needs "
        "GitHub connected. In other channels the digest is *Slack-only*. It follows the channel you "
        "run `/susan` in, or a pasted archives link.\n"
        "`--no-approval` generates and posts immediately (for Monday schedules).",
        "*PR summaries*\n"
        "`/susan summarize merged prs for org/repo last 30 days` · "
        "`/susan summarize merged prs for org/a org/b last 14 days`\n"
        "Name `owner/repo` in the message (several: `org/a org/b` or `repos: org/a, org/b`), or set "
        "`GITHUB_REPO` / `GITHUB_REPOS` on the server. With several repos configured and none named, "
        "Susan shows a *multi-select*. For PRs and issues she still asks you to pick one repo.",
        "*Time ranges* (optional; default last 7 days)\n"
        "`last 14 days` · `past week` · `past month` · `since 2026-01-01` · "
        "`from 2026-01-01 to 2026-03-01` · `last calendar week` (Mon–Sun UTC)",
        "*Extra data sources* (weekly status)\n"
        "• *Dependabot / vulnerabilities* — set `GITHUB_OAUTH_SCOPE` to include `security_events` "
        "and reconnect GitHub, or Susan notes that alerts are unavailable.\n"
        "• *Drive & bookmarks* — Google Doc/Drive URLs in channel messages and bookmarks seed a Drive "
        "scan, using the Google account of whoever runs `/susan`. Enable the Drive API in GCP and "
        "reconnect Google. Caps: `WEEKLY_DRIVE_MAX_FOLDERS`, `WEEKLY_DRIVE_MAX_DEPTH`, "
        "`WEEKLY_DRIVE_MAX_FILES_REPORTED`, `WEEKLY_DRIVE_MAX_API_CALLS`.",
    ]


def _help_roadmap() -> list[str]:
    return [
        "*Roadmap board* (GitHub Projects — the plan of record)\n"
        "• `/susan board status` — what shipped, what only moved status, what's blocked and on whom\n"
        "• `/susan board pack` — the board/investor update, honest about *Partial* and *Done (dev)*\n"
        "• `/susan board risks` — P0/P1 items that would stop a pilot handover, ranked\n"
        "• `/susan board claims` — what you can tell a customer is live today\n"
        "• `/susan customer ask Augur` — what we owe a customer and what we're waiting on\n"
        "• `/susan roadmap can we promise streaming responses in the UK?` — any question, answered "
        "from the board with issue numbers\n"
        "• `/susan roadmap add <idea>` — checks for duplicates, drafts an issue, shows it before filing",
        "Susan quotes the *Status* word verbatim and treats *Partial* and *Done (dev)* as *not done*. "
        "Every claim carries an issue number. She can file issues and open PRs — she never merges.\n"
        "_Needs GitHub connected with `read:project`, plus `SUSAN_ROADMAP_ORG` and "
        "`SUSAN_ROADMAP_PROJECT` on the server._",
    ]


def _help_connect() -> list[str]:
    return [
        "*Connect accounts*\n"
        "• `/susan connect` — everything configured on the server\n"
        "• `/susan connect google` — Docs, Gmail, Calendar, Drive metadata\n"
        "• `/susan connect github` — issues, PRs, PR summaries, tech-channel weekly status\n"
        "• `/susan connect granola` — meeting notes\n"
        "_Reconnect after Susan gains a new scope; she'll tell you when that's needed._",
    ]


def _help_schedule() -> list[str]:
    return [
        "*Schedules*\n"
        "`/susan schedule add weekly status last calendar week every monday at 9:00 in #team-tech`\n"
        "See `/susan schedule help` for the full syntax, listing, and removal.",
    ]


def _help_keywords() -> list[str]:
    lines = [
        f"• *{label}* — include one of: " + ", ".join(f"`{k}`" for k in kws)
        for _key, (label, kws) in ACTIONS.items()
    ]
    return ["*Keywords Susan recognizes in free text*\n" + "\n".join(lines)]


def susan_slash_help_response(topic: str = "") -> JSONResponse:
    """Ephemeral Block Kit help; `topic` selects a focused page, "" is the overview."""
    pages: dict[str, tuple[str, list[str]]] = {
        "": ("Susan — help", _help_overview()),
        "actions": ("Susan — actions", _help_actions()),
        "status": ("Susan — weekly status & PR summaries", _help_status()),
        "roadmap": ("Susan — roadmap board", _help_roadmap()),
        "connect": ("Susan — connect accounts", _help_connect()),
        "schedule": ("Susan — schedules", _help_schedule()),
    }
    if topic == "all":
        title = "Susan — all commands"
        bodies = (
            _help_overview()[:1]
            + _help_actions()
            + _help_status()
            + _help_roadmap()
            + _help_connect()
            + _help_schedule()
            + _help_keywords()
        )
    else:
        title, bodies = pages.get(topic, pages[""])

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": title, "emoji": True}}
    ]
    for i, body in enumerate(bodies):
        if i:
            blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}})
    if topic:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "`/susan help` for the overview"}
                ],
            }
        )
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": f"{title} (see the full message).",
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
        if rest in ("granola",):
            return connect_granola_slack_response(user, channel_id=channel or None)
        if rest == "":
            return connect_slack_response_combined(user, channel_id=channel or None)
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Unknown `connect` subcommand. Use `connect`, `connect google`, `connect github`, or `connect granola`.",
            }
        )

    if is_susan_help_command(text_lower):
        return susan_slash_help_response(parse_help_topic(text_lower))

    schedule_remainder = parse_schedule_command(text)
    if schedule_remainder is not None:
        return await handle_schedule_slash(
            schedule_remainder,
            user=user,
            channel=channel,
            channel_name=form.get("channel_name"),
        )

    granola_remainder = parse_granola_slash_command(text)
    if granola_remainder is not None:
        if not await user_has_granola_tokens(user):
            resume_id = await create_oauth_resume_pending(
                user, channel, thread_ts, text, "granola_cmd", "granola"
            )
            return connect_granola_slack_response(
                user,
                intro="*Granola isn’t connected yet.* Use the link below to sign in — Susan will run your Granola summary when you’re done (or use `/susan connect granola` anytime).",
                channel_id=channel or None,
                resume_id=resume_id,
            )

        async def run_granola():
            try:
                await process_granola_summarize(
                    granola_remainder,
                    channel,
                    user,
                    thread_ts,
                    response_url,
                )
            except Exception as e:
                logger.exception("Granola summarize task failed")
                try:
                    await notify_user_ephemeral(
                        channel,
                        user,
                        f"Susan error (Granola): {str(e)}",
                        None,
                        response_url,
                    )
                except Exception as e2:
                    logger.error("Could not notify user after Granola error: %s", e2)

        background_tasks.add_task(run_granola)
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Got it — Susan is pulling *your Granola notes* for the requested window and will post "
                    "a private summary here when ready."
                ),
            }
        )

    actions_remainder = parse_action_items_command(text)
    if actions_remainder is not None:
        _, explicit_all_channels = _strip_all_channels_scope(actions_remainder)
        actions_all_channels = is_personal_actions_command(text) or (
            explicit_all_channels and not is_team_actions_command(text)
        )
        _, actions_auto_post = strip_weekly_status_auto_post_flags(text)
        if actions_all_channels:
            actions_auto_post = False
        if actions_auto_post and not weekly_status_auto_post_user_allowed(user):
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

        link_ch_a, link_ts_a = extract_slack_archives_link(text)
        hist_channel_a = link_ch_a or channel

        async def run_action_items():
            try:
                await process_action_items(
                    text,
                    hist_channel_a,
                    channel,
                    user,
                    thread_ts or link_ts_a,
                    response_url,
                    auto_publish=actions_auto_post,
                )
            except Exception as e:
                logger.exception("Action items task failed")
                try:
                    await notify_user_ephemeral(
                        channel,
                        user,
                        f"Susan error (action items): {str(e)}",
                        None,
                        response_url,
                    )
                except Exception as e2:
                    logger.error("Could not notify user after action items error: %s", e2)

        background_tasks.add_task(run_action_items)
        if actions_all_channels:
            ack = (
                "Got it — Susan is building *My Actions*, your private inbox, from "
                "all accessible Slack channels, Gmail, Drive comments, Granola, and GitHub."
            )
        elif actions_auto_post:
            ack = (
                "Got it — Susan is scanning *this channel* (and connected Drive, Granola, GitHub) for "
                "*team actions* and will *post a roundup with @mentions* when ready (`--no-approval`)."
            )
        else:
            ack = (
                "Got it — Susan is gathering *team actions* for *this channel* from Slack and connected "
                "sources; you'll get a preview with @mentions to approve. "
                "_For your own cross-channel inbox, use `/susan my actions`._"
            )
        if explicit_all_channels and is_team_actions_command(text):
            ack += (
                "\n\n_Note: team actions are always scoped to one channel, so the all-channels part was "
                "ignored. Use `/susan my actions` for a cross-channel view._"
            )
        return JSONResponse({"response_type": "ephemeral", "text": ack})

    sales_prep_target = parse_sales_prep_command(text)
    if sales_prep_target is not None:
        if not await user_has_google_tokens(user):
            resume_id = await create_oauth_resume_pending(
                user, channel, thread_ts, text, "sales_prep", "google"
            )
            return connect_google_slack_response(
                user,
                intro=(
                    "*Google isn’t connected yet.* Sales prep scans your Google Drive for "
                    "sales/GTM and F1 docs. Sign in below — Susan will continue when you’re done."
                ),
                channel_id=channel or None,
                resume_id=resume_id,
            )

        async def run_sales_prep():
            timeout_s = int((os.environ.get("SALES_PREP_TIMEOUT_SECONDS") or "480").strip() or "480")
            timeout_s = max(120, min(900, timeout_s))
            try:
                await asyncio.wait_for(
                    process_sales_prep(
                        sales_prep_target,
                        channel,
                        user,
                        thread_ts,
                        response_url,
                    ),
                    timeout=timeout_s,
                )
            except asyncio.TimeoutError:
                logger.error("Sales prep timed out after %ss", timeout_s)
                try:
                    await notify_user_ephemeral(
                        channel,
                        user,
                        (
                            f"Sales prep for *{sales_prep_target}* timed out after {timeout_s}s. "
                            "Susan may still be waiting on Drive, Granola, or Claude Opus — try again, "
                            "or ask an admin to raise `SALES_PREP_TIMEOUT_SECONDS`."
                        ),
                        None,
                        response_url,
                        skip_sovereign_attribution=True,
                    )
                except Exception as e2:
                    logger.error("Could not notify user after sales prep timeout: %s", e2)
            except Exception as e:
                logger.exception("Sales prep task failed")
                try:
                    await notify_user_ephemeral(
                        channel,
                        user,
                        f"Susan error (sales prep): {str(e)}",
                        None,
                        response_url,
                        skip_sovereign_attribution=True,
                    )
                except Exception as e2:
                    logger.error("Could not notify user after sales prep error: %s", e2)

        background_tasks.add_task(run_sales_prep)
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    f"Got it — Susan is preparing a *sales call brief* for *{sales_prep_target}* "
                    "(internal docs, Granola, and company research). You'll get a concise TLDR in "
                    "Slack with a link to the full Google Doc when ready."
                ),
            }
        )

    # Before parse_standup_command: "standup digest" also matches its bare "standup" prefix.
    if parse_daily_standup_command(text) is not None:
        _, standup_auto_post = strip_weekly_status_auto_post_flags(text)
        if standup_auto_post and not weekly_status_auto_post_user_allowed(user):
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "Auto-publish (`--no-approval`) is restricted for your user. Remove the flag "
                        "for a private preview, or ask an admin to add your Slack user id to "
                        "`SUSAN_WEEKLY_AUTO_POST_USER_IDS`."
                    ),
                }
            )

        async def run_standup_digest():
            try:
                await process_standup_digest(
                    text, channel, user, thread_ts, response_url
                )
            except Exception as e:
                logger.exception("Standup digest task failed")
                try:
                    await notify_user_ephemeral(
                        channel, user, f"Susan error (standup): {e}", None, response_url
                    )
                except Exception as e2:
                    logger.error("Could not notify user after standup error: %s", e2)

        background_tasks.add_task(run_standup_digest)
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Got it — Susan is building the *standup digest* from Granola notes "
                    "(updates, blockers, decisions, parking lot, next steps)."
                    + ("" if standup_auto_post else " You'll get a private preview first.")
                ),
            }
        )

    surface_kind = None
    if parse_standup_command(text) is not None:
        surface_kind = "standups"
    elif parse_failures_command(text) is not None:
        surface_kind = "failures"
    elif parse_reviews_command(text) is not None:
        surface_kind = "reviews"

    if surface_kind is not None:

        async def run_surface():
            kind = surface_kind
            try:
                await process_channel_surface(
                    kind,  # type: ignore[arg-type]
                    text,
                    channel,
                    user,
                    thread_ts,
                    response_url,
                )
            except Exception as e:
                logger.exception("Channel surface task failed kind=%s", kind)
                try:
                    await notify_user_ephemeral(
                        channel,
                        user,
                        f"Susan error ({kind}): {str(e)}",
                        None,
                        response_url,
                    )
                except Exception as e2:
                    logger.error("Could not notify user after surface error: %s", e2)

        background_tasks.add_task(run_surface)
        ack_by_kind = {
            "standups": (
                "Got it — Susan is reading *standup notes* in #team-tech for the requested window "
                "and will send you a private summary."
            ),
            "failures": (
                "Got it — Susan is scanning *alert channels* for failures and will send you a "
                "private digest of what's failing."
            ),
            "reviews": (
                "Got it — Susan is scanning alerts + #team-tech for items that need *your* review "
                "and will send you a private list."
            ),
        }
        return JSONResponse(
            {"response_type": "ephemeral", "text": ack_by_kind[surface_kind]}
        )

    roadmap_cmd = parse_roadmap_command(text)
    if roadmap_cmd is not None:
        roadmap_kind, roadmap_remainder = roadmap_cmd
        _, roadmap_auto_post = strip_weekly_status_auto_post_flags(text)
        if roadmap_auto_post and not weekly_status_auto_post_user_allowed(user):
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "text": (
                        "Posting straight to the channel (`--no-approval`) is restricted for your user. "
                        "Remove the flag to get the answer privately, or ask an admin to add your Slack "
                        "user id to `SUSAN_WEEKLY_AUTO_POST_USER_IDS`."
                    ),
                }
            )
        if not await user_has_github_tokens(user):
            resume_id = await create_oauth_resume_pending(
                user, channel, thread_ts, text, "roadmap_cmd", "github"
            )
            return connect_github_slack_response(
                user,
                intro=(
                    "*GitHub isn’t connected yet.* The roadmap board lives in GitHub, so Susan needs "
                    "your account to read it. Use the link below — Susan will answer when you’re done "
                    "(or use `/susan connect github` anytime)."
                ),
                channel_id=channel or None,
                resume_id=resume_id,
            )

        async def run_roadmap():
            try:
                if roadmap_kind == "add":
                    await process_roadmap_add(
                        roadmap_remainder, channel, user, thread_ts, response_url
                    )
                else:
                    await process_roadmap(
                        roadmap_kind, roadmap_remainder, channel, user, thread_ts, response_url
                    )
            except Exception as e:
                logger.exception("Roadmap task failed kind=%s", roadmap_kind)
                try:
                    await notify_user_ephemeral(
                        channel, user, f"Susan error (roadmap): {str(e)}", None, response_url
                    )
                except Exception as e2:
                    logger.error("Could not notify user after roadmap error: %s", e2)

        background_tasks.add_task(run_roadmap)
        return JSONResponse(
            {"response_type": "ephemeral", "text": ROADMAP_ACKS[roadmap_kind]}
        )

    action = detect_action(text)
    if not action:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    "Susan doesn’t understand that command. Try `/susan help` for examples, "
                    "or keywords like `connect`, `schedule`, `doc`, `email`, `invite`, `issue`, `pr`, "
                    "`summarize prs`, `weekly status`, `prep me for a sales call with …`, "
                    "`standups`, `surface failures`, `needs my review`, "
                    "`board status`, `customer ask <name>`, `roadmap add …`, "
                    "`actions` / `action items`, or Granola-only: `granola` / `gn`."
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


@app.post("/susan/events")
async def slack_events(request: Request, background_tasks: BackgroundTasks):
    """Slack Events API (action-item status replies in digest threads)."""
    body = await request.body()
    ts = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    if not verify_slack(body, ts, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    try:
        payload = parse_events_body(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    if payload.get("type") == "url_verification":
        return JSONResponse({"challenge": payload.get("challenge", "")})
    if payload.get("type") == "event_callback":
        background_tasks.add_task(handle_slack_event_callback, payload)
    return JSONResponse({"ok": True})


@app.post("/susan/actions")
async def susan_slack_actions(request: Request, background_tasks: BackgroundTasks):
    return await handle_action(request, background_tasks)
