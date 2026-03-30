import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env before db (engine) or os.environ reads — uvicorn does not load .env by itself.
load_dotenv(Path(__file__).resolve().parent / ".env")

import httpx
from db import (
    exchange_code_for_tokens,
    get_valid_access_token,
    init_db,
    upsert_tokens,
)
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].strip()
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"].strip()
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
]


def oauth_state_secret() -> str:
    return os.environ.get("OAUTH_STATE_SECRET", SLACK_SIGNING_SECRET).strip()


def make_oauth_state(slack_user_id: str) -> str:
    exp = int(time.time()) + 3600
    payload = {"u": slack_user_id, "exp": exp}
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(oauth_state_secret().encode(), body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + sig).decode()


def parse_oauth_state(state: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(state.encode())
        body, sig = raw[:-32], raw[-32:]
        expected = hmac.new(oauth_state_secret().encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(body.decode())
        if payload["exp"] < time.time():
            return None
        return payload["u"]
    except Exception:
        return None


def public_base_url() -> str:
    explicit = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    if explicit:
        return explicit
    redir = os.environ.get("GOOGLE_REDIRECT_URI", "")
    if redir.endswith("/auth/google/callback"):
        return redir[: -len("/auth/google/callback")]
    return ""


def google_authorize_url(state: str) -> str:
    redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]
    params = {
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


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

logger = logging.getLogger("susan")


def _slack_form_fields(body: bytes) -> dict[str, str]:
    """Parse application/x-www-form-urlencoded body into single string per key (Slack sends one value each)."""
    q = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    return {k: v[0] for k, v in q.items() if v}


ACTIONS = {
    "doc": ("create a doc", ["doc", "document", "notes"]),
    "email": ("send email", ["email", "mail"]),
    "invite": ("create invite", ["invite", "calendar", "meeting", "event"]),
    "pr": ("create pr", ["pr", "pull request", "github"]),
}


def verify_slack(req_body: bytes, timestamp: str, signature: str) -> bool:
    if not timestamp or not signature:
        logger.warning("Slack verify: missing X-Slack-Request-Timestamp or X-Slack-Signature")
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        logger.warning("Slack verify: timestamp is not an integer")
        return False
    now = time.time()
    if abs(now - ts) > 60 * 5:
        logger.warning(
            "Slack verify: request too old or clock skew (server_time=%s slack_ts=%s)",
            int(now),
            ts,
        )
        return False
    try:
        raw = req_body.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Slack verify: body is not valid UTF-8")
        return False
    sig_base = f"v0:{timestamp}:{raw}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_base.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning(
            "Slack verify: HMAC mismatch — copy Signing Secret from api.slack.com → "
            "Your App → Basic Information (must be the same app that owns /susan)"
        )
        return False
    return True


def detect_action(text: str) -> str | None:
    lower = text.lower()
    for key, (_, keywords) in ACTIONS.items():
        if any(k in lower for k in keywords):
            return key
    return None


def extract_slack_archives_link(text: str) -> tuple[str | None, str | None]:
    """Parse (channel_id, message_ts) from a message permalink (⋯ → Copy link).

    Use when /susan is run in the main channel (no thread_ts): pass any message
    in the thread as a link so we can call conversations.replies.
    """
    m = re.search(
        r"(?:https?://)?(?:[\w-]+\.)?slack\.com/archives/([CGD][A-Z0-9]+)/p([0-9]+)(?:\?|[\s>]|$)",
        text,
        re.IGNORECASE,
    )
    if not m:
        return None, None
    channel_id = m.group(1).upper()
    digits = m.group(2)
    if len(digits) < 10:
        return None, None
    ts = f"{digits[:10]}.{digits[10:]}" if len(digits) > 10 else digits
    return channel_id, ts


def _is_public_slack_channel(channel_id: str) -> bool:
    """conversations.join is only valid for public channels (ids start with C)."""
    return bool(channel_id) and channel_id.upper().startswith("C")


def _history_error_hint(channel_id: str) -> str:
    c = (channel_id or "").upper()
    if c.startswith("D"):
        return (
            "For a *group DM*: add **Susan** to the conversation (⋮ or header → *Add people* / include the app like a member). "
            "For *1:1* with the bot, open **Messages** → Susan. "
            "The app needs `im:history` + `mpim:history` (and reinstall after scope changes)."
        )
    if c.startswith("G"):
        return (
            "Private channel or *multi-person DM* (often `G…`): add **Susan** under channel details → *Integrations* or participants. "
            "Use `groups:history` / `mpim:history` on the app as appropriate."
        )
    return (
        "This is a *public channel*: the bot must be a member. In the channel, run **`/invite @Susan`** "
        "(or *Channel details → Integrations → Add apps*). That works **without** the `channels:join` scope. "
        "Optional: add Bot scope **`channels:join`** in api.slack.com → *reinstall app* so Susan can auto-join public channels. "
        "For a thread, paste a message permalink (⋯ → Copy link) in your `/susan` command."
    )


async def _try_slack_join_channel(channel: str) -> None:
    """Join public channels so history + ephemerals work (requires channels:join scope)."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://slack.com/api/conversations.join",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json={"channel": channel},
        )
    data = r.json()
    if data.get("ok"):
        logger.info("Slack: joined channel %s", channel)
        return
    err = data.get("error", "")
    if err == "already_in_channel":
        return
    if err == "missing_scope" and "channels:join" in str(data.get("needed", "")):
        logger.error(
            "Slack: token is missing channels:join. In api.slack.com → Your App → "
            "OAuth & Permissions → Scopes → Bot Token Scopes → add channels:join → "
            "Save, then reinstall the app to your workspace (Install to Workspace)."
        )
    else:
        logger.warning("Slack: conversations.join failed: %s", data)


async def _fetch_slack_history_once(channel: str, thread_ts: str | None) -> dict:
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    params = {"channel": channel, "limit": 50}
    endpoint = (
        "https://slack.com/api/conversations.replies"
        if thread_ts
        else "https://slack.com/api/conversations.history"
    )
    if thread_ts:
        params["ts"] = thread_ts
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(endpoint, headers=headers, params=params)
    return r.json()


async def fetch_slack_history(channel: str, thread_ts: str | None) -> str:
    data = await _fetch_slack_history_once(channel, thread_ts)
    if not data.get("ok"):
        err = data.get("error", "unknown_error")
        if err in ("channel_not_found", "not_in_channel") and _is_public_slack_channel(channel):
            await _try_slack_join_channel(channel)
            data = await _fetch_slack_history_once(channel, thread_ts)
        elif err in ("channel_not_found", "not_in_channel"):
            logger.info(
                "Slack: skip conversations.join (DM/private/mpim — not a public C… channel): %s",
                channel[:12] if channel else "",
            )
    if not data.get("ok"):
        err = data.get("error", "unknown_error")
        logger.error("Slack conversations API failed: %s full=%s", err, data)
        raise RuntimeError(
            f"Could not load channel history ({err}). {_history_error_hint(channel)}"
        )
    msgs = data.get("messages", [])
    lines = []
    for m in reversed(msgs):
        user = m.get("user", "unknown")
        text = m.get("text", "")
        lines.append(f"{user}: {text}")
    return "\n".join(lines)


async def call_claude(system: str, user: str) -> str:
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
    data = r.json()
    if r.status_code >= 400:
        logger.error("Anthropic HTTP %s: %s", r.status_code, data)
        raise RuntimeError(data.get("error", {}).get("message", r.text) if isinstance(data.get("error"), dict) else str(data))
    if data.get("type") == "error":
        logger.error("Anthropic error payload: %s", data)
        raise RuntimeError(str(data.get("error", data)))
    content = data.get("content") or []
    if not content or content[0].get("type") != "text":
        logger.error("Unexpected Anthropic response: %s", data)
        raise RuntimeError("Unexpected response from Claude API")
    return content[0]["text"]


async def post_ephemeral(channel: str, user: str, text: str, blocks: list | None = None):
    payload = {"channel": channel, "user": user, "text": text}
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://slack.com/api/chat.postEphemeral",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json=payload,
        )
    data = r.json()
    if not data.get("ok"):
        logger.error("chat.postEphemeral failed: %s", data)
        raise RuntimeError(data.get("error", "chat.postEphemeral failed"))


async def post_slack_delayed_response(response_url: str, payload: dict) -> None:
    """Follow-up message for slash commands (same payload shape as slash JSON response)."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(response_url, json=payload)
    if r.status_code >= 400:
        logger.error("response_url POST failed: %s %s", r.status_code, r.text)
        raise RuntimeError(f"response_url failed: HTTP {r.status_code}")


async def notify_user_ephemeral(
    channel: str,
    user: str,
    text: str,
    blocks: list | None = None,
    response_url: str | None = None,
) -> None:
    """Prefer chat.postEphemeral; if channel is not visible to the bot, use slash response_url."""
    try:
        await post_ephemeral(channel, user, text, blocks)
    except Exception as e:
        logger.warning("post_ephemeral failed (%s), trying response_url", e)
        if not response_url:
            raise
        payload: dict = {"response_type": "ephemeral", "text": text}
        if blocks:
            payload["blocks"] = blocks
        await post_slack_delayed_response(response_url, payload)


async def post_message(channel: str, text: str, thread_ts: str | None = None):
    payload = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json=payload,
        )


SYSTEM_PROMPTS = {
    "doc": "You are Susan. Given a Slack conversation, write a structured document with sections: ## Summary, ## Key Decisions, ## Action Items, ## Open Questions. Be concise and professional.",
    "email": "You are Susan. Given a Slack conversation, draft a professional email. Output ONLY:\nSubject: <subject>\n\n<body>",
    "invite": "You are Susan. Given a Slack conversation, draft a calendar invite. Output ONLY:\nTitle: ...\nDate/Time: ...\nDuration: ...\nAttendees: ...\nAgenda: ...\nInfer details from context.",
    "pr": "You are Susan. Given a Slack conversation about code, draft a GitHub PR. Output ONLY:\nTitle: ...\n\nDescription:\n...\n\nFiles changed:\n<filename>\n```\n<code>\n```",
}


async def process_command(
    action: str,
    convo: str,
    instructions: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None = None,
):
    try:
        preview = await call_claude(
            SYSTEM_PROMPTS[action],
            f"Slack conversation:\n{convo}\n\nExtra instructions: {instructions}",
        )
        truncated = preview[:2800] + ("..." if len(preview) > 2800 else "")
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Susan preview — {ACTIONS[action][0]}*\n_(Only visible to you)_",
                },
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"```{truncated}```"}},
            {
                "type": "actions",
                "block_id": f"susan_{action}_{channel}_{thread_ts or 'none'}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✓ Approve & execute"},
                        "style": "primary",
                        "action_id": f"approve_{action}",
                        "value": preview[:2000],
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


@app.get("/auth/google")
async def auth_google_start(state: str):
    uid = parse_oauth_state(state)
    if not uid:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    try:
        _ = os.environ["GOOGLE_CLIENT_ID"]
        _ = os.environ["GOOGLE_CLIENT_SECRET"]
        _ = os.environ["GOOGLE_REDIRECT_URI"]
    except KeyError:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    return RedirectResponse(google_authorize_url(state))


@app.get("/auth/google/callback")
async def auth_google_callback(code: str, state: str):
    uid = parse_oauth_state(state)
    if not uid:
        return HTMLResponse(
            "<html><body><p>Invalid or expired session. Close this window and run <code>/susan connect</code> again in Slack.</p></body></html>",
            status_code=400,
        )
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "")
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
    except Exception as e:
        return HTMLResponse(
            f"<html><body><p>Could not complete Google sign-in: {e!s}</p></body></html>",
            status_code=400,
        )
    return HTMLResponse(
        "<html><body><p>Google connected. You can close this tab and return to Slack.</p></body></html>"
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
    text = form.get("text", "").strip()
    channel = form.get("channel_id", "")
    user = form.get("user_id", "")
    thread_ts = form.get("thread_ts") or None
    response_url = form.get("response_url") or None
    text_lower = text.lower()
    logger.info("Slack slash verified: user=%s channel=%s text=%r", user, channel, text[:120] if text else "")

    if text_lower == "connect" or text_lower.startswith("connect "):
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
        state = make_oauth_state(user)
        auth_path = f"{base}/auth/google?state={urllib.parse.quote(state, safe='')}"
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Connect your Google account so Susan uses *your* Docs, Gmail, and Calendar.",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Connect Google Account"},
                        "url": auth_path,
                    }
                ],
            },
        ]
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Connect your Google account (only visible to you).",
                "blocks": blocks,
            }
        )

    action = detect_action(text)
    if not action:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Susan doesn't understand that command. Try: `connect`, `create a doc`, `send email`, `create invite`, or `create pr`.",
            }
        )

    async def run():
        try:
            link_ch, link_ts = extract_slack_archives_link(text)
            hist_channel = link_ch or channel
            hist_thread_ts = thread_ts or link_ts
            logger.info(
                "Susan background: fetch history channel=%s thread_ts=%s (from_link channel=%s ts=%s)",
                hist_channel,
                hist_thread_ts,
                link_ch,
                link_ts,
            )
            convo = await fetch_slack_history(hist_channel, hist_thread_ts)
            await process_command(action, convo, text, channel, user, thread_ts, response_url)
        except Exception as e:
            logger.exception("Susan background task failed: %s", e)
            try:
                await notify_user_ephemeral(channel, user, f"Susan error: {str(e)}", None, response_url)
            except Exception as e2:
                logger.error("Could not notify user in Slack: %s", e2)

    background_tasks.add_task(run)
    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": f"Got it — Susan is reading the channel and preparing a *{ACTIONS[action][0]}* preview...",
        }
    )


@app.post("/susan/actions")
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
    action_id = payload["actions"][0]["action_id"]
    value = payload["actions"][0].get("value", "")
    channel = payload["container"]["channel_id"]
    user = payload["user"]["id"]
    if action_id == "cancel_susan":
        return JSONResponse({"response_type": "ephemeral", "text": "Susan cancelled. No action taken."})
    action_type = action_id.replace("approve_", "")

    async def execute():
        try:
            if action_type == "doc":
                result = await create_google_doc(value, user)
            elif action_type == "email":
                result = await send_gmail(value, user)
            elif action_type == "invite":
                result = await create_calendar_invite(value, user)
            elif action_type == "pr":
                result = await create_github_pr(value)
            else:
                result = "Unknown action."
            await post_ephemeral(channel, user, f"✓ Susan done: {result}")
        except Exception as e:
            await post_ephemeral(channel, user, f"Susan error during execution: {str(e)}")

    background_tasks.add_task(execute)
    return JSONResponse({"response_type": "ephemeral", "text": "Susan is executing..."})


async def create_google_doc(content: str, slack_user_id: str) -> str:
    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://docs.googleapis.com/v1/documents",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"title": "Susan — Meeting Notes"},
        )
        doc = r.json()
        if r.status_code >= 400:
            hint = (
                " Enable **Google Docs API** for the same GCP project as your OAuth client "
                "(APIs & Services → Library → Google Docs API). "
                "Then revoke Susan at https://myaccount.google.com/permissions and run `/susan connect` again."
            )
            if r.status_code in (401, 403):
                return f"Google Docs rejected this token ({r.status_code}).{hint} Raw: {doc}"
            return f"Failed to create doc: {doc}"
        doc_id = doc.get("documentId")
        if not doc_id:
            return f"Failed to create doc: {doc}"
        await client.post(
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"requests": [{"insertText": {"location": {"index": 1}, "text": content}}]},
        )
    return f"Google Doc created: https://docs.google.com/document/d/{doc_id}"


async def send_gmail(content: str, slack_user_id: str) -> str:
    import base64
    from email.mime.text import MIMEText

    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    lines = content.split("\n")
    subj_line = next((l for l in lines if l.lower().startswith("subject:")), "Subject: Update from Susan")
    subject = subj_line.split(":", 1)[1].strip()
    body = "\n".join(lines[lines.index(subj_line) + 2 :]) if subj_line in lines else content
    to_addr = os.environ.get("DEFAULT_EMAIL_TO", "")
    if not to_addr:
        return "Email not sent — DEFAULT_EMAIL_TO not set."
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["To"] = to_addr
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {token}"},
            json={"raw": raw},
        )
    return "Email sent via Gmail." if r.status_code == 200 else f"Gmail error: {r.text}"


async def create_calendar_invite(content: str, slack_user_id: str) -> str:
    import re

    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    title = re.search(r"Title:\s*(.+)", content)
    title = title.group(1).strip() if title else "Meeting"
    event = {
        "summary": title,
        "description": content,
        "start": {"dateTime": "2026-04-01T10:00:00Z", "timeZone": "UTC"},
        "end": {"dateTime": "2026-04-01T11:00:00Z", "timeZone": "UTC"},
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            headers={"Authorization": f"Bearer {token}"},
            json=event,
        )
    data = r.json()
    link = data.get("htmlLink", "")
    return f"Calendar invite created: {link}" if link else f"Calendar error: {data}"


async def create_github_pr(content: str) -> str:
    import re

    token = GITHUB_TOKEN
    repo = os.environ.get("GITHUB_REPO", "")
    base = os.environ.get("GITHUB_BASE_BRANCH", "main")
    if not token or not repo:
        return "PR not created — GITHUB_TOKEN or GITHUB_REPO not set."
    title_m = re.search(r"^Title:\s*(.+)", content, re.M)
    desc_m = re.search(r"Description:\s*([\s\S]+?)(?=Files changed:|$)", content)
    title = title_m.group(1).strip() if title_m else "Susan: changes from Slack"
    desc = desc_m.group(1).strip() if desc_m else content
    branch = f"susan/slack-{int(time.time())}"
    hdrs = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        sha_r = await client.get(f"https://api.github.com/repos/{repo}/git/refs/heads/{base}", headers=hdrs)
        sha = sha_r.json().get("object", {}).get("sha")
        if not sha:
            return f"Could not find base branch '{base}' in {repo}."
        await client.post(
            f"https://api.github.com/repos/{repo}/git/refs",
            headers=hdrs,
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )
        pr_r = await client.post(
            f"https://api.github.com/repos/{repo}/pulls",
            headers=hdrs,
            json={"title": title, "body": desc, "head": branch, "base": base},
        )
    pr = pr_r.json()
    return f"PR created: {pr.get('html_url', pr)}"


@app.get("/")
async def root():
    """Avoid 404 noise from bots and uptime probes hitting the base URL."""
    return {"service": "susan", "docs": "POST /susan (Slack slash), GET /health"}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "susan"}
