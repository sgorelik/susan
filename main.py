import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load .env before db (engine) or os.environ reads — uvicorn does not load .env by itself.
load_dotenv(Path(__file__).resolve().parent / ".env")

import httpx
from db import (
    consume_oauth_resume_pending,
    consume_user_draft,
    consume_repo_pick_pending,
    create_oauth_resume_pending,
    create_repo_pick_pending,
    create_user_draft,
    exchange_code_for_tokens,
    exchange_github_code_for_token,
    get_github_token,
    get_user_draft,
    get_valid_access_token,
    init_db,
    upsert_github_token,
    upsert_tokens,
    user_has_github_tokens,
    user_has_google_tokens,
)
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].strip()
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"].strip()
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
]


def oauth_state_secret() -> str:
    return os.environ.get("OAUTH_STATE_SECRET", SLACK_SIGNING_SECRET).strip()


def oauth_state_ttl_seconds() -> int:
    """How long the OAuth link stays valid (default 24h). Override with OAUTH_STATE_TTL_SECONDS."""
    try:
        return max(300, int(os.environ.get("OAUTH_STATE_TTL_SECONDS", "86400")))
    except ValueError:
        return 86400


def make_oauth_state(
    slack_user_id: str,
    channel_id: str | None = None,
    resume_id: str | None = None,
) -> str:
    """Signed state for OAuth (Google/GitHub). Optional resume_id continues a /susan command after connect."""
    exp = int(time.time()) + oauth_state_ttl_seconds()
    payload: dict = {"u": slack_user_id, "exp": exp}
    if channel_id:
        payload["ch"] = channel_id
    if resume_id:
        payload["rid"] = resume_id
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(oauth_state_secret().encode(), body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + sig).decode()


def parse_oauth_state(state: str) -> tuple[str, str | None, str | None] | None:
    """Returns (slack_user_id, channel_id_or_none, resume_id_or_none)."""
    try:
        raw = base64.urlsafe_b64decode(state.encode())
        body, sig = raw[:-32], raw[-32:]
        expected = hmac.new(oauth_state_secret().encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(body.decode())
        if payload["exp"] < time.time():
            return None
        uid = payload["u"]
        ch = payload.get("ch")
        if not isinstance(ch, str) or not ch.strip():
            ch = None
        rid = payload.get("rid")
        if not isinstance(rid, str) or not rid.strip():
            rid = None
        return uid, ch, rid
    except Exception:
        return None


def _ensure_url_with_scheme(base: str) -> str:
    """Slack link buttons and mrkdwn links need an absolute URL with a scheme."""
    u = base.strip().rstrip("/")
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u.lstrip("/")
    return u


def public_base_url() -> str:
    explicit = _ensure_url_with_scheme(os.environ.get("PUBLIC_BASE_URL", ""))
    if explicit:
        return explicit
    redir = os.environ.get("GOOGLE_REDIRECT_URI", "")
    if redir.endswith("/auth/google/callback"):
        return _ensure_url_with_scheme(redir[: -len("/auth/google/callback")])
    redir = os.environ.get("GITHUB_REDIRECT_URI", "")
    if redir.endswith("/auth/github/callback"):
        return _ensure_url_with_scheme(redir[: -len("/auth/github/callback")])
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


def _google_oauth_configured() -> bool:
    try:
        _ = os.environ["GOOGLE_CLIENT_ID"]
        _ = os.environ["GOOGLE_CLIENT_SECRET"]
        _ = os.environ["GOOGLE_REDIRECT_URI"]
        return True
    except KeyError:
        return False


def _github_oauth_configured() -> bool:
    try:
        _ = os.environ["GITHUB_CLIENT_ID"]
        _ = os.environ["GITHUB_CLIENT_SECRET"]
        _ = os.environ["GITHUB_REDIRECT_URI"]
        return True
    except KeyError:
        return False


def github_authorize_url(state: str) -> str:
    redirect_uri = os.environ["GITHUB_REDIRECT_URI"]
    scope = (os.environ.get("GITHUB_OAUTH_SCOPE") or "repo").strip() or "repo"
    params = {
        "client_id": os.environ["GITHUB_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
    }
    return "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)


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
    # "issue" before "pr" — keywords like "github issue" must match issue, not bare "github" on pr.
    "issue": (
        "open a GitHub issue",
        ["github issue", "open issue", "file issue", "create issue", "issue"],
    ),
    # Before "pr" so "summarize prs …" does not match the bare "pr" keyword.
    "pr_summary": (
        "summarize merged GitHub PRs",
        [
            "summarize pull requests",
            "summarize prs",
            "summarize merged pr",
            "pr summary",
            "pull request summary",
            "github pr summary",
            "prs summary",
            "pr summaries",
        ],
    ),
    "pr": ("create a GitHub PR", ["pull request", "create pr", "open pr", "pr"]),
}

GOOGLE_ACTIONS = frozenset({"doc", "email", "invite"})
GITHUB_ACTIONS = frozenset({"pr", "issue", "pr_summary"})

APPROVE_ACTION_TYPES = frozenset({"doc", "email", "invite", "pr", "issue"})


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


def _is_dm_slack_channel(channel_id: str) -> bool:
    """1:1 direct message with a user (incl. bot DM)."""
    return bool(channel_id) and channel_id.upper().startswith("D")


def _is_private_or_mpim_slack_channel(channel_id: str) -> bool:
    """Private channel or multi-person DM — ids start with G."""
    return bool(channel_id) and channel_id.upper().startswith("G")


def _history_error_hint(channel_id: str) -> str:
    c = (channel_id or "").strip().upper()
    if not c:
        return (
            "Slack did not send a channel id. Try `/susan` again from the channel or DM, "
            "or reinstall the app so bot scopes include `im:history` and `im:write` for DMs."
        )
    if _is_dm_slack_channel(c):
        return (
            "Susan could not read this DM. The app needs **`im:history`** and **`im:write`** (so the bot can open/resume the DM via the Slack API). "
            "In [api.slack.com](https://api.slack.com/apps) → your app → *OAuth & Permissions* → add those Bot scopes → **reinstall** the app. "
            "Then open **Messages** with Susan and run `/susan` again."
        )
    if _is_private_or_mpim_slack_channel(c):
        return (
            "For a *private channel* or *group DM* (`G…`): add **Susan** (*Channel details* → *Integrations* / *Add apps*, or add the app to the group DM). "
            "The app needs `groups:history` / `mpim:history` (and `mpim:write` can help for some group DMs). "
            "For a *thread in another channel*, paste a message permalink in `/susan`."
        )
    return (
        "This is a *public channel*: the bot must be a member. In the channel, run **`/invite @Susan`** "
        "(or *Channel details → Integrations → Add apps*). That works **without** the `channels:join` scope. "
        "Optional: add Bot scope **`channels:join`** in api.slack.com → *reinstall app* so Susan can auto-join public channels. "
        "For a thread, paste a message permalink (⋯ → Copy link) in your `/susan` command."
    )


async def _try_slack_open_im_with_user(slack_user_id: str) -> str | None:
    """Open or resume 1:1 DM so conversations.history has a valid channel id (needs im:write)."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://slack.com/api/conversations.open",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json={"users": slack_user_id},
        )
    data = r.json()
    if data.get("ok") and data.get("channel", {}).get("id"):
        cid = data["channel"]["id"]
        logger.info("Slack: conversations.open(users) resolved DM channel=%s for user=%s", cid, slack_user_id)
        return cid
    logger.warning("Slack: conversations.open(users) failed: %s", data)
    return None


async def _try_slack_open_by_channel_id(channel: str) -> str | None:
    """Resume an existing DM/mpim by id (helps some G… group DMs)."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://slack.com/api/conversations.open",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json={"channel": channel},
        )
    data = r.json()
    if data.get("ok") and data.get("channel", {}).get("id"):
        cid = data["channel"]["id"]
        logger.info("Slack: conversations.open(channel) resolved channel=%s", cid)
        return cid
    logger.warning("Slack: conversations.open(channel) failed: %s", data)
    return None


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


async def fetch_slack_history(
    channel: str, thread_ts: str | None, slack_user_id: str | None = None
) -> str:
    data = await _fetch_slack_history_once(channel, thread_ts)
    if not data.get("ok"):
        err = data.get("error", "unknown_error")
        if err in ("channel_not_found", "not_in_channel") and _is_public_slack_channel(channel):
            await _try_slack_join_channel(channel)
            data = await _fetch_slack_history_once(channel, thread_ts)
        elif (
            err in ("channel_not_found", "not_in_channel")
            and _is_dm_slack_channel(channel)
            and slack_user_id
        ):
            new_ch = await _try_slack_open_im_with_user(slack_user_id)
            if new_ch:
                data = await _fetch_slack_history_once(new_ch, thread_ts)
        elif err in ("channel_not_found", "not_in_channel") and _is_private_or_mpim_slack_channel(
            channel
        ):
            new_ch = await _try_slack_open_by_channel_id(channel)
            if new_ch:
                data = await _fetch_slack_history_once(new_ch, thread_ts)
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


def _anthropic_error_payload(data: dict) -> str:
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or err.get("type") or err)
    if err is not None:
        return str(err)
    return str(data)


def _anthropic_is_overloaded(status: int, data: dict) -> bool:
    if status in (503, 529):
        return True
    msg = _anthropic_error_payload(data).lower()
    if "overload" in msg:
        return True
    err = data.get("error")
    if isinstance(err, dict) and "overload" in (err.get("type") or "").lower():
        return True
    return False


def _anthropic_should_retry(status: int, data: dict) -> bool:
    """Transient capacity / rate limits — safe to backoff and retry."""
    if status == 429:
        return True
    if status in (503, 529):
        return True
    if status >= 500:
        return True
    if data.get("type") == "error":
        err = data.get("error")
        if isinstance(err, dict):
            et = (err.get("type") or "").lower()
            em = (err.get("message") or "").lower()
            if "overloaded" in em or "overloaded" in et or "rate_limit" in et:
                return True
    return False


async def call_claude(system: str, user: str) -> str:
    max_attempts = max(1, min(8, int(os.environ.get("ANTHROPIC_MAX_RETRIES", "5"))))
    base_delay = max(1.0, float(os.environ.get("ANTHROPIC_RETRY_DELAY_SECONDS", "2")))
    last_data: dict = {}
    last_status = 0
    last_text = ""

    for attempt in range(max_attempts):
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
        last_status = r.status_code
        last_text = r.text
        try:
            data = r.json()
        except json.JSONDecodeError:
            data = {}
        last_data = data

        if r.status_code < 400 and data.get("type") != "error":
            content = data.get("content") or []
            if content and content[0].get("type") == "text":
                return content[0]["text"]
            logger.error("Unexpected Anthropic response: %s", data)
            raise RuntimeError("Unexpected response from Claude API")

        logger.error("Anthropic HTTP %s: %s", r.status_code, data or last_text)
        if not _anthropic_should_retry(r.status_code, data) or attempt >= max_attempts - 1:
            break
        delay = min(base_delay * (2**attempt), 60.0)
        logger.warning(
            "Anthropic retry %s/%s in %.1fs (transient error)",
            attempt + 2,
            max_attempts,
            delay,
        )
        await asyncio.sleep(delay)

    if _anthropic_is_overloaded(last_status, last_data):
        raise RuntimeError(
            "Claude is temporarily overloaded. Please try again in a minute or two."
        )
    if last_status == 429:
        raise RuntimeError(
            "Claude API rate limit — please wait a bit and try again."
        )
    raise RuntimeError(_anthropic_error_payload(last_data) if last_data else last_text or "Claude API error")


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


def _strip_blank_modal_initial_values(view: dict) -> None:
    """Slack rejects some modals when plain_text_input has initial_value: \"\"."""
    for block in view.get("blocks") or []:
        el = block.get("element")
        if isinstance(el, dict) and el.get("type") == "plain_text_input":
            if not (el.get("initial_value") or "").strip():
                el.pop("initial_value", None)


async def slack_views_open(trigger_id: str, view: dict) -> tuple[bool, str]:
    """Open a modal; required for buttons on *ephemeral* messages (response_action push often does nothing)."""
    if not trigger_id:
        return False, "missing_trigger_id"
    _strip_blank_modal_initial_values(view)
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            "https://slack.com/api/views.open",
            headers={
                "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                "Content-Type": "application/json",
            },
            json={"trigger_id": trigger_id, "view": view},
        )
    try:
        data = r.json()
    except json.JSONDecodeError:
        return False, r.text[:200]
    if data.get("ok"):
        return True, ""
    err = str(data.get("error", data))
    logger.error("views.open failed: %s", data)
    return False, err


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
    "email": "You are Susan. Given a Slack conversation, draft a professional email. Output ONLY this structure:\nTo: email1@domain.com, email2@domain.com\nSubject: <subject>\n\n<body>\n\nPut every recipient in To: (comma-separated). If the user names people or gives addresses in their instructions, use those addresses in To:. If they give no recipients, use To: with DEFAULT_EMAIL_TO from the server only if you know it; otherwise leave To: empty and they will set it in Slack.",
    "invite": "You are Susan. Given a Slack conversation, draft a calendar invite. Output ONLY:\nTitle: <short title>\nAttendees: email1@..., email2@... (comma-separated)\nStart: <ISO8601 e.g. 2026-04-15T14:00:00>\nEnd: <ISO8601>\nTimeZone: <IANA e.g. America/New_York or UTC>\nDescription:\n<agenda / notes>\n\nInfer date/time from the thread. If the user names attendees or emails, use them in Attendees:.",
    "issue": "You are Susan. Given a Slack conversation, draft a GitHub issue. Output ONLY:\nTitle: <short title>\n\nDescription:\n<markdown body with context, steps to reproduce, expected vs actual, or acceptance criteria as appropriate>\n",
    "pr": "You are Susan. Given a Slack conversation about code, draft a GitHub PR. Output ONLY:\nTitle: ...\n\nDescription:\n...\n\nFiles changed:\nFor each file: one repo-relative path on its own line, then a fenced code block with the full file contents. Example:\nsrc/foo.py\n```python\n...\n```\nRepeat for more files.",
}

REPO_PREFIX = "__REPO__:"


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


async def _github_put_file_on_branch(
    client: httpx.AsyncClient,
    repo: str,
    path: str,
    file_body: str,
    branch: str,
    message: str,
    hdrs: dict,
) -> str | None:
    """Create or update a file on ``branch``. Returns None on success, else an error message."""
    enc = urllib.parse.quote(path, safe="/")
    url = f"https://api.github.com/repos/{repo}/contents/{enc}"
    gr = await client.get(url, headers=hdrs, params={"ref": branch})
    existing_sha = None
    if gr.status_code == 200:
        existing_sha = gr.json().get("sha")
    b64 = base64.b64encode(file_body.encode("utf-8")).decode("ascii")
    payload: dict = {"message": message, "content": b64, "branch": branch}
    if existing_sha:
        payload["sha"] = existing_sha
    put_r = await client.put(url, headers=hdrs, json=payload)
    if put_r.status_code not in (200, 201):
        return f"Could not commit `{path}`: {put_r.status_code} {put_r.text}"
    return None


def _comma_repo_list(raw: str) -> list[str]:
    if not (raw or "").strip():
        return []
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def _pr_allowlist() -> list[str]:
    return _comma_repo_list(os.environ.get("GITHUB_REPOS", ""))


def _issue_allowlist() -> list[str]:
    """GITHUB_ISSUES_REPOS if set, else same allowlist as PR (GITHUB_REPOS)."""
    raw = (os.environ.get("GITHUB_ISSUES_REPOS") or "").strip()
    if raw:
        return _comma_repo_list(raw)
    return _pr_allowlist()


def is_plausible_github_repo_slug(slug: str) -> bool:
    """Reject Slack URLs and other false positives (e.g. frontier-one.slack.com/archives)."""
    if not slug or "/" not in slug:
        return False
    parts = slug.split("/", 1)
    if len(parts) != 2:
        return False
    owner, name = parts[0].strip(), parts[1].strip()
    if not owner or not name:
        return False
    low = slug.lower()
    if "slack.com" in low or "archives" in name.lower():
        return False
    if "http://" in low or "https://" in low:
        return False
    if "." in owner:
        return False
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,38}[a-zA-Z0-9])?/[a-zA-Z0-9._-]+$", slug):
        return False
    return True


def parse_repo_slug_from_text(text: str) -> str | None:
    """Extract owner/repo from slash text; validated so Slack links are never treated as repos."""
    m = re.search(r"\b(?:repo|in)\s*:?\s*([^\s]+/[^\s]+)", text, re.I)
    if m:
        cand = m.group(1).strip().rstrip(".,;)")
        if is_plausible_github_repo_slug(cand):
            return cand.lower()
    m = re.search(r"github\.com/([^/\s]+)/([^/\s?#]+)", text, re.I)
    if m:
        cand = f"{m.group(1)}/{m.group(2)}"
        if is_plausible_github_repo_slug(cand):
            return cand.lower()
    m = re.search(r"\b([a-zA-Z0-9][a-zA-Z0-9-]{0,38}/[a-zA-Z0-9._-]+)\b", text)
    if m:
        cand = m.group(1)
        if is_plausible_github_repo_slug(cand):
            return cand.lower()
    return None


def resolve_github_repo_for_pr(text: str) -> tuple[str | None, str | None, bool]:
    """Returns (repo, error_ephemeral, needs_interactive_picker)."""
    allow = _pr_allowlist()
    parsed = parse_repo_slug_from_text(text)
    default = (os.environ.get("GITHUB_REPO") or "").strip().lower()
    if parsed:
        if allow and parsed not in allow:
            return None, f"Repo `{parsed}` is not allowed. Allowed: {', '.join(allow)}.", False
        return parsed, None, False
    if default:
        if allow and default not in allow:
            return None, f"Default `GITHUB_REPO` (`{default}`) is not in `GITHUB_REPOS`: {', '.join(allow)}.", False
        return default, None, False
    if len(allow) == 1:
        return allow[0], None, False
    if len(allow) > 1:
        return None, None, True
    return None, (
        "No GitHub repo configured. Set `GITHUB_REPO` (default) or `GITHUB_REPOS` (comma-separated allowlist) "
        "on the server, or include `owner/repo` in your command."
    ), False


def parse_pr_summary_time_range(text: str) -> tuple[str, str]:
    """Return inclusive merged-date range as YYYY-MM-DD (UTC) for GitHub search."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    today = now.date()
    lower = text.lower()

    m = re.search(r"last\s+(\d+)\s+days?", lower)
    if m:
        n = max(1, min(365, int(m.group(1))))
        start = today - timedelta(days=n)
        return start.isoformat(), today.isoformat()

    if re.search(r"\b(last|past)\s+week\b", lower):
        start = today - timedelta(days=7)
        return start.isoformat(), today.isoformat()

    if re.search(r"\b(last|past)\s+month\b", lower):
        start = today - timedelta(days=30)
        return start.isoformat(), today.isoformat()

    m = re.search(r"\bsince\s+(\d{4}-\d{2}-\d{2})\b", lower)
    if m:
        return m.group(1), today.isoformat()

    m = re.search(
        r"\b(?:between|from)\s+(\d{4}-\d{2}-\d{2})\s+(?:and|to)\s+(\d{4}-\d{2}-\d{2})\b",
        lower,
    )
    if m:
        return m.group(1), m.group(2)

    m = re.search(r"\bin\s+(?:the\s+)?last\s+(\d+)\s+weeks?\b", lower)
    if m:
        w = max(1, min(52, int(m.group(1))))
        start = today - timedelta(weeks=w)
        return start.isoformat(), today.isoformat()

    start = today - timedelta(days=7)
    return start.isoformat(), today.isoformat()


async def fetch_merged_prs_for_repo_range(
    repo: str, since_d: str, until_d: str, token: str
) -> list[dict]:
    """GitHub search API: merged PRs in repo between since_d and until_d (YYYY-MM-DD)."""
    q = f"repo:{repo} is:pr is:merged merged:>={since_d} merged:<={until_d}"
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    items: list[dict] = []
    async with httpx.AsyncClient(timeout=60) as client:
        for page in range(1, 11):
            r = await client.get(
                "https://api.github.com/search/issues",
                headers=hdrs,
                params={"q": q, "per_page": 100, "page": page},
            )
            data = r.json()
            if r.status_code != 200:
                raise RuntimeError(
                    f"GitHub search failed ({r.status_code}): {data.get('message', data)}"
                )
            batch = data.get("items") or []
            items.extend(batch)
            if len(batch) < 100:
                break
    return items


async def post_long_ephemeral(
    channel: str,
    user: str,
    title: str,
    body: str,
    response_url: str | None = None,
) -> None:
    """Slack mrkdwn sections are limited ~3000 chars; split long summaries."""
    chunk = 2800
    parts: list[str] = []
    s = body.strip()
    while s:
        parts.append(s[:chunk])
        s = s[chunk:]
    if not parts:
        parts = ["_(empty)_"]
    blocks: list[dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{title}*\n_(only visible to you)_"},
        }
    ]
    for p in parts:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": p[:2900]}})
    await notify_user_ephemeral(channel, user, title, blocks, response_url)


async def process_pr_summary(
    repo: str,
    command_text: str,
    convo: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    since_d, until_d = parse_pr_summary_time_range(command_text)
    try:
        token = await get_github_token(user)
    except ValueError as e:
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return
    try:
        items = await fetch_merged_prs_for_repo_range(repo, since_d, until_d, token)
    except Exception as e:
        logger.exception("GitHub PR fetch failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return
    lines: list[str] = []
    for it in items:
        num = it.get("number")
        title = (it.get("title") or "").replace("\n", " ")
        url = it.get("html_url") or ""
        pr_meta = it.get("pull_request") or {}
        merged = pr_meta.get("merged_at") or it.get("closed_at") or ""
        login = (it.get("user") or {}).get("login") or "?"
        lines.append(f"#{num} | {merged[:10] if merged else '?'} | @{login} | {title} | {url}")
    raw_list = "\n".join(lines) if lines else "(No merged PRs in this window.)"
    prompt = (
        f"Repository `{repo}`.\n"
        f"Merged date range (UTC, inclusive): {since_d} through {until_d}.\n"
        f"Merged PRs ({len(items)}):\n{raw_list}\n"
    )
    if (convo or "").strip():
        prompt += f"\nSlack thread context (optional):\n{convo.strip()[:6000]}\n"
    system = (
        "You are Susan. Write a concise Slack-ready summary (mrkdwn) of merged pull requests. "
        "Use short ## headings, bullets, and link PRs as <url|#123 short title>. "
        "Group by theme or area if obvious. Note the date range and repo at the top. "
        "If there were zero PRs, say so and suggest widening the time range."
    )
    try:
        summary = await call_claude(system, prompt)
    except Exception as e:
        logger.exception("PR summary Claude failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return
    await post_long_ephemeral(
        channel,
        user,
        f"PR summary — `{repo}` ({since_d} → {until_d})",
        summary,
        response_url,
    )


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
        link_ch, link_ts = extract_slack_archives_link(text)
        hist_channel = link_ch or channel
        hist_thread_ts = thread_ts or link_ts
        convo = await fetch_slack_history(hist_channel, hist_thread_ts, user)
        if action in GITHUB_ACTIONS:
            if action == "issue":
                repo, err, need_pick = resolve_github_repo_for_issue(text)
            else:
                repo, err, need_pick = resolve_github_repo_for_pr(text)
            if need_pick:
                pick_kind = "summary" if action == "pr_summary" else action
                allow = _pr_allowlist() if action in ("pr", "pr_summary") else _issue_allowlist()
                await post_github_repo_picker_ephemeral(
                    channel, user, pick_kind, text, thread_ts, response_url, allow
                )
                return
            if err:
                await notify_user_ephemeral(channel, user, err, None, response_url)
                return
            if action == "pr_summary":
                await process_pr_summary(
                    repo, text, convo, channel, user, thread_ts, response_url
                )
            else:
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
            f"<html><body><p>Could not complete Google sign-in: {e!s}</p></body></html>",
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
            f"<html><body><p>Could not complete GitHub sign-in: {e!s}</p></body></html>",
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

    action = detect_action(text)
    if not action:
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": "Susan doesn't understand that command. Try: `connect`, `create a doc`, `send email`, `create invite`, `create issue`, `create pr`, or `summarize prs …` (GitHub merged PRs for a repo + time range).",
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
            convo = await fetch_slack_history(hist_channel, hist_thread_ts, user)
            if action in GITHUB_ACTIONS:
                if action == "issue":
                    repo, err, need_pick = resolve_github_repo_for_issue(text)
                else:
                    repo, err, need_pick = resolve_github_repo_for_pr(text)
                if need_pick:
                    pick_kind = "summary" if action == "pr_summary" else action
                    allow = _pr_allowlist() if action in ("pr", "pr_summary") else _issue_allowlist()
                    await post_github_repo_picker_ephemeral(
                        channel, user, pick_kind, text, thread_ts, response_url, allow
                    )
                    return
                if err:
                    await notify_user_ephemeral(channel, user, err, None, response_url)
                    return
                if action == "pr_summary":
                    await process_pr_summary(
                        repo, text, convo, channel, user, thread_ts, response_url
                    )
                else:
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
    ack = (
        "Got it — Susan is fetching *merged PRs* from GitHub for that repo and date range, then drafting a summary (only visible to you)."
        if action == "pr_summary"
        else f"Got it — Susan is reading the channel and preparing a *{ACTIONS[action][0]}* preview..."
    )
    return JSONResponse({"response_type": "ephemeral", "text": ack})


EMAIL_IN_TEXT_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


async def handle_slack_view_submission(payload: dict, background_tasks: BackgroundTasks) -> JSONResponse:
    """Modal submit for editable email / calendar drafts."""
    user = (payload.get("user") or {}).get("id") or ""
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

    channel = (payload.get("container") or {}).get("channel_id") or (payload.get("channel") or {}).get("id") or ""
    user = (payload.get("user") or {}).get("id") or ""
    if not channel or not user:
        logger.warning("block_actions missing channel or user: container=%s", payload.get("container"))
        return JSONResponse({})

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
                            repo,
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
                            repo,
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
            return JSONResponse({"response_type": "ephemeral", "text": "Susan cancelled. No action taken."})
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
            else:
                result = await create_github_pr(value, user)
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
    parsed = parse_email_draft(content)
    to_raw = (parsed.get("to") or "").strip()
    if not to_raw:
        to_raw = (os.environ.get("DEFAULT_EMAIL_TO") or "").strip()
    if not to_raw:
        return (
            "Email not sent — add *To:* recipients in the draft (or set DEFAULT_EMAIL_TO on the server)."
        )
    recipients = [x.strip() for x in to_raw.replace(";", ",").split(",") if x.strip()]
    subject = (parsed.get("subject") or "Email from Susan").strip()
    body = parsed.get("body") or ""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["To"] = ", ".join(recipients)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {token}"},
            json={"raw": raw},
        )
    if r.status_code == 200:
        return "Email sent via Gmail."
    try:
        err = r.json()
    except json.JSONDecodeError:
        err = r.text
    return f"Gmail error ({r.status_code}): {err}"


async def create_calendar_invite(content: str, slack_user_id: str) -> str:
    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    p = parse_invite_draft(content)
    title = p["title"]
    tz = p["timezone"] or "UTC"
    start = p["start"]
    end = p["end"]
    desc = p["description"]
    att_raw = p["attendees"]
    emails: list[str] = []
    for part in att_raw.replace(";", ",").split(","):
        part = part.strip()
        if part:
            emails.extend(EMAIL_IN_TEXT_RE.findall(part))
    if not emails:
        fallback = (os.environ.get("DEFAULT_EMAIL_TO") or "").strip()
        if fallback:
            emails = EMAIL_IN_TEXT_RE.findall(fallback) or ([fallback] if "@" in fallback else [])
    event: dict = {
        "summary": title,
        "description": desc or content,
        "start": {"dateTime": start, "timeZone": tz},
        "end": {"dateTime": end, "timeZone": tz},
    }
    if emails:
        event["attendees"] = [{"email": e} for e in emails]
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    if emails:
        url = f"{url}?sendUpdates=all"
    async with httpx.AsyncClient() as client:
        r = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=event,
        )
    data = r.json()
    if r.status_code >= 400:
        return f"Calendar error ({r.status_code}): {data}"
    link = data.get("htmlLink", "")
    return f"Calendar invite created: {link}" if link else f"Calendar error: {data}"


async def create_github_issue(content: str, slack_user_id: str) -> str:
    import re

    try:
        token = await get_github_token(slack_user_id)
    except ValueError as e:
        return str(e)
    repo_meta, body = split_repo_prefix_from_approve_value(content)
    repo = repo_meta or (os.environ.get("GITHUB_ISSUES_REPO") or os.environ.get("GITHUB_REPO") or "").strip()
    if not repo:
        return "Issue not created — no repo (approve payload missing `__REPO__` line)."
    content = body
    title_m = re.search(r"^Title:\s*(.+)", content, re.M)
    title = title_m.group(1).strip() if title_m else "Susan: issue from Slack"
    desc_m = re.search(r"^Description:\s*", content, re.M)
    body = content[desc_m.end() :].strip() if desc_m else content
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers=hdrs,
            json={"title": title, "body": body},
        )
    data = r.json()
    if r.status_code >= 400:
        return f"GitHub issue error ({r.status_code}): {data}"
    return f"Issue created: {data.get('html_url', data)}"


async def create_github_pr(content: str, slack_user_id: str) -> str:
    try:
        token = await get_github_token(slack_user_id)
    except ValueError as e:
        return str(e)
    repo_meta, body = split_repo_prefix_from_approve_value(content)
    repo = repo_meta or (os.environ.get("GITHUB_REPO") or "").strip()
    if not repo:
        return "PR not created — no repo (approve payload missing `__REPO__` line)."
    content = body
    base = os.environ.get("GITHUB_BASE_BRANCH", "main")
    title_m = re.search(r"^Title:\s*(.+)", content, re.M)
    desc_m = re.search(r"Description:\s*([\s\S]+?)(?=Files changed:|$)", content)
    title = title_m.group(1).strip() if title_m else "Susan: changes from Slack"
    desc = desc_m.group(1).strip() if desc_m else content

    parsed: list[tuple[str, str]] = []
    for raw_path, file_body in _parse_pr_files_changed(content):
        sp = _sanitize_repo_rel_path(raw_path)
        if sp:
            parsed.append((sp, file_body))
    by_path: dict[str, str] = {}
    for p, b in parsed:
        by_path[p] = b
    file_list = list(by_path.items())
    ts = int(time.time())
    if not file_list:
        file_list = [
            (
                f"docs/susan/slack-pr-{ts}.md",
                f"# {title}\n\n{desc}\n\n"
                "_*(No `Files changed:` block was parsed; add real file edits in this branch or adjust the preview format.)*_\n",
            )
        ]

    branch = f"susan/slack-{ts}-{uuid.uuid4().hex[:8]}"
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=120) as client:
        sha_r = await client.get(
            f"https://api.github.com/repos/{repo}/git/refs/heads/{base}",
            headers=hdrs,
        )
        if sha_r.status_code >= 400:
            return f"Could not read base branch `{base}` in `{repo}`: {sha_r.status_code} {sha_r.text}"
        sha = sha_r.json().get("object", {}).get("sha")
        if not sha:
            return f"Could not find base branch '{base}' in {repo}."
        ref_r = await client.post(
            f"https://api.github.com/repos/{repo}/git/refs",
            headers=hdrs,
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )
        if ref_r.status_code not in (201,):
            return f"Could not create branch `{branch}`: {ref_r.status_code} {ref_r.text}"

        nfiles = len(file_list)
        for i, (path, file_body) in enumerate(file_list):
            msg = f"susan: {title[:60]}"
            if nfiles > 1:
                msg = f"{msg} ({path})"
            err = await _github_put_file_on_branch(
                client, repo, path, file_body, branch, msg, hdrs
            )
            if err:
                return err

        pr_r = await client.post(
            f"https://api.github.com/repos/{repo}/pulls",
            headers=hdrs,
            json={"title": title, "body": desc, "head": branch, "base": base},
        )
        pr_status = pr_r.status_code
        pr_data = pr_r.json()

    if pr_status >= 400:
        return f"PR not created ({pr_status}): {pr_data}"
    return f"PR created: {pr_data.get('html_url', pr_data)}"


@app.get("/")
async def root():
    """Avoid 404 noise from bots and uptime probes hitting the base URL."""
    return {"service": "susan", "docs": "POST /susan (Slack slash), GET /health"}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "susan"}
