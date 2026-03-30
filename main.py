import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from contextlib import asynccontextmanager

import httpx
from db import (
    exchange_code_for_tokens,
    get_valid_access_token,
    init_db,
    upsert_tokens,
)
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
]


def oauth_state_secret() -> str:
    return os.environ.get("OAUTH_STATE_SECRET", os.environ["SLACK_SIGNING_SECRET"])


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
    await init_db()
    yield


app = FastAPI(lifespan=lifespan)

ACTIONS = {
    "doc": ("create a doc", ["doc", "document", "notes"]),
    "email": ("send email", ["email", "mail"]),
    "invite": ("create invite", ["invite", "calendar", "meeting", "event"]),
    "pr": ("create pr", ["pr", "pull request", "github"]),
}


def verify_slack(req_body: bytes, timestamp: str, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    sig_base = f"v0:{timestamp}:{req_body.decode()}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_base.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def detect_action(text: str) -> str | None:
    lower = text.lower()
    for key, (_, keywords) in ACTIONS.items():
        if any(k in lower for k in keywords):
            return key
    return None


async def fetch_slack_history(channel: str, thread_ts: str | None) -> str:
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    params = {"channel": channel, "limit": 50}
    endpoint = (
        "https://slack.com/api/conversations.replies"
        if thread_ts
        else "https://slack.com/api/conversations.history"
    )
    if thread_ts:
        params["ts"] = thread_ts
    async with httpx.AsyncClient() as client:
        r = await client.get(endpoint, headers=headers, params=params)
    data = r.json()
    msgs = data.get("messages", [])
    lines = []
    for m in reversed(msgs):
        user = m.get("user", "unknown")
        text = m.get("text", "")
        lines.append(f"{user}: {text}")
    return "\n".join(lines)


async def call_claude(system: str, user: str) -> str:
    async with httpx.AsyncClient(timeout=30) as client:
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
    return data["content"][0]["text"]


async def post_ephemeral(channel: str, user: str, text: str, blocks: list | None = None):
    payload = {"channel": channel, "user": user, "text": text}
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://slack.com/api/chat.postEphemeral",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json=payload,
        )


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
    action: str, convo: str, instructions: str, channel: str, user: str, thread_ts: str | None
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
        await post_ephemeral(channel, user, f"Susan preview ready for: {ACTIONS[action][0]}", blocks)
    except Exception as e:
        await post_ephemeral(channel, user, f"Susan error: {str(e)}")


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


@app.post("/susan")
async def slash_susan(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    ts = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    if not verify_slack(body, ts, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    form = await request.form()
    text = form.get("text", "").strip()
    channel = form.get("channel_id", "")
    user = form.get("user_id", "")
    thread_ts = form.get("thread_ts")
    text_lower = text.lower()

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
        convo = await fetch_slack_history(channel, thread_ts)
        await process_command(action, convo, text, channel, user, thread_ts)

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
    form = await request.form()
    payload = json.loads(urllib.parse.unquote(form.get("payload", "{}")))
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "susan"}
