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
    # Before "pr"; distinct from PR summary ("weekly", "status report").
    "weekly_status": (
        "weekly team & repo status",
        [
            "weekly status",
            "week status",
            "weekly report",
            "status report",
            "team status",
            "engineering status",
        ],
    ),
    "pr": ("create a GitHub PR", ["pull request", "create pr", "open pr", "pr"]),
}

GOOGLE_ACTIONS = frozenset({"doc", "email", "invite"})
# weekly_status is not listed here: non-tech channels get Slack-only weekly status without GitHub OAuth.
GITHUB_ACTIONS = frozenset({"pr", "issue", "pr_summary"})

APPROVE_ACTION_TYPES = frozenset(
    {"doc", "email", "invite", "pr", "issue", "pr_summary", "weekly_status"}
)


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


async def _slack_conversations_history_page(
    channel: str, oldest_ts: str | None, cursor: str | None
) -> dict:
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    params: dict[str, str] = {"channel": channel, "limit": "200"}
    if oldest_ts:
        params["oldest"] = oldest_ts
    if cursor:
        params["cursor"] = cursor
    async with httpx.AsyncClient(timeout=45) as client:
        r = await client.get(
            "https://slack.com/api/conversations.history",
            headers=headers,
            params=params,
        )
    return r.json()


async def fetch_slack_channel_history_since(
    channel: str,
    oldest_slack_ts: str,
    slack_user_id: str | None,
) -> str:
    """Paginated channel messages at or after oldest_slack_ts (Slack epoch string)."""
    max_msgs = max(50, min(2000, int(os.environ.get("WEEKLY_STATUS_MAX_SLACK_MESSAGES", "800"))))
    max_chars = max(5000, min(500_000, int(os.environ.get("WEEKLY_STATUS_MAX_SLACK_CHARS", "120000"))))

    work_channel = channel

    async def fetch_all() -> list[dict]:
        nonlocal work_channel
        collected: list[dict] = []
        cursor: str | None = None
        first = True
        while len(collected) < max_msgs:
            data = await _slack_conversations_history_page(
                work_channel, oldest_slack_ts if first else None, cursor
            )
            if not data.get("ok"):
                err = data.get("error", "unknown_error")
                if err in ("channel_not_found", "not_in_channel") and _is_public_slack_channel(
                    work_channel
                ):
                    await _try_slack_join_channel(work_channel)
                    data = await _slack_conversations_history_page(
                        work_channel, oldest_slack_ts if first else None, cursor
                    )
                elif (
                    err in ("channel_not_found", "not_in_channel")
                    and _is_dm_slack_channel(work_channel)
                    and slack_user_id
                ):
                    new_ch = await _try_slack_open_im_with_user(slack_user_id)
                    if new_ch:
                        work_channel = new_ch
                        data = await _slack_conversations_history_page(
                            work_channel, oldest_slack_ts if first else None, cursor
                        )
                elif err in ("channel_not_found", "not_in_channel") and _is_private_or_mpim_slack_channel(
                    work_channel
                ):
                    new_ch = await _try_slack_open_by_channel_id(work_channel)
                    if new_ch:
                        work_channel = new_ch
                        data = await _slack_conversations_history_page(
                            work_channel, oldest_slack_ts if first else None, cursor
                        )
            if not data.get("ok"):
                err = data.get("error", "unknown_error")
                logger.error("Slack conversations.history failed: %s full=%s", err, data)
                raise RuntimeError(
                    f"Could not load channel history ({err}). {_history_error_hint(work_channel)}"
                )
            batch = data.get("messages") or []
            collected.extend(batch)
            cursor = (data.get("response_metadata") or {}).get("next_cursor") or None
            first = False
            if not cursor or not batch:
                break
        return collected

    msgs = await fetch_all()
    msgs.sort(key=lambda m: float(m.get("ts", "0") or 0))
    lines: list[str] = []
    total_len = 0
    truncated = False
    for m in msgs:
        uid = m.get("user", "unknown")
        text = m.get("text", "")
        line = f"{uid}: {text}"
        if total_len + len(line) + 1 > max_chars:
            truncated = True
            break
        lines.append(line)
        total_len += len(line) + 1
    out = "\n".join(lines)
    if truncated:
        out += (
            f"\n\n… ({len(msgs) - len(lines)} more messages omitted; cap WEEKLY_STATUS_MAX_SLACK_CHARS)"
        )
    if not out.strip():
        return "(No channel messages in this time window.)"
    return out


def utc_date_start_slack_ts(iso_date: str) -> str:
    """First instant of YYYY-MM-DD in UTC as Slack message ts."""
    from datetime import datetime, timezone

    d = datetime.strptime(iso_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return f"{d.timestamp():.6f}"


_WEEKLY_AUTO_POST_FLAG_RE = re.compile(
    r"(?i)(?:^|\s)(?:--no-approval|-no-approval)(?:\s|$)"
)


def strip_weekly_status_auto_post_flags(text: str) -> tuple[str, bool]:
    """Remove --no-approval / -no-approval; return (text for date/link parsing, auto_publish)."""
    raw = (text or "").strip()
    auto = bool(_WEEKLY_AUTO_POST_FLAG_RE.search(raw))
    cleaned = _WEEKLY_AUTO_POST_FLAG_RE.sub(" ", raw)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned, auto


def weekly_status_auto_post_user_allowed(slack_user_id: str) -> bool:
    """If SUSAN_WEEKLY_AUTO_POST_USER_IDS is set, only those Slack user ids may use --no-approval."""
    raw = (os.environ.get("SUSAN_WEEKLY_AUTO_POST_USER_IDS") or "").strip()
    if not raw:
        return True
    allowed = {p.strip() for p in raw.split(",") if p.strip()}
    return (slack_user_id or "").strip() in allowed


def parse_weekly_status_time_range(text: str) -> tuple[str, str, str]:
    """Return (since_d, until_d, human_label) in UTC dates for GitHub + Slack window."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    today = now.date()
    lower = (text or "").lower()

    if re.search(r"\b(last|previous)\s+calendar\s+week\b", lower):
        # Previous ISO week Mon–Sun (UTC).
        this_monday = today - timedelta(days=today.weekday())
        prev_sun = this_monday - timedelta(days=1)
        prev_mon = prev_sun - timedelta(days=6)
        label = f"Calendar week {prev_mon.isoformat()} → {prev_sun.isoformat()} (UTC)"
        return prev_mon.isoformat(), prev_sun.isoformat(), label

    since_d, until_d = parse_pr_summary_time_range(text)
    label = f"{since_d} → {until_d} (UTC, inclusive dates)"
    return since_d, until_d, label


def resolve_github_repos_for_weekly_status() -> tuple[list[str] | None, str | None]:
    """All repos from GITHUB_REPOS, or GITHUB_REPO if the list is empty."""
    allow = _pr_allowlist()
    default = (os.environ.get("GITHUB_REPO") or "").strip().lower()
    if allow:
        return list(allow), None
    if default:
        return [default], None
    return None, (
        "No GitHub repos configured. Set `GITHUB_REPOS` or `GITHUB_REPO` for weekly status "
        "(Dependabot + PR metrics need at least one repo)."
    )


def _tech_weekly_channel_names() -> frozenset[str]:
    """Slack channel name slugs (lowercase) that get GitHub data in weekly status."""
    raw = (
        os.environ.get("SUSAN_TECH_WEEKLY_CHANNEL_NAMES", "").strip()
        or "team-tech,software,security"
    )
    return frozenset(p.strip().lower() for p in raw.split(",") if p.strip())


def normalize_slack_command_channel_name(raw: str | None) -> str:
    return (raw or "").strip().lstrip("#").lower()


async def slack_api_conversation_channel_name(channel_id: str) -> str | None:
    """Resolve channel name slug via conversations.info (lowercase), or None."""
    if not (channel_id or "").strip():
        return None
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(
            "https://slack.com/api/conversations.info",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            params={"channel": channel_id},
        )
    try:
        data = r.json()
    except json.JSONDecodeError:
        return None
    if not data.get("ok"):
        logger.warning(
            "Slack conversations.info failed for weekly tech check: %s", data.get("error")
        )
        return None
    ch = data.get("channel") or {}
    name = ch.get("name")
    return str(name).strip().lower() if name else None


async def weekly_status_include_github(
    digest_channel_id: str,
    slash_channel_id: str,
    slash_channel_name: str | None,
) -> bool:
    """True when weekly status should pull GitHub metrics (tech channels only)."""
    tech = _tech_weekly_channel_names()
    if digest_channel_id == slash_channel_id:
        n = normalize_slack_command_channel_name(slash_channel_name)
        if n and n not in ("directmessage", "mpim", "group"):
            return n in tech
    api_name = await slack_api_conversation_channel_name(digest_channel_id)
    return (api_name or "") in tech


def _pr_turnaround_hours(item: dict) -> float | None:
    from datetime import datetime

    created = item.get("created_at")
    pr = item.get("pull_request") or {}
    merged = pr.get("merged_at")
    if not created or not merged:
        return None
    try:
        c = datetime.fromisoformat(created.replace("Z", "+00:00"))
        m = datetime.fromisoformat(merged.replace("Z", "+00:00"))
        return (m - c).total_seconds() / 3600.0
    except (ValueError, TypeError):
        return None


async def fetch_opened_prs_for_repo_range(
    repo: str, since_d: str, until_d: str, token: str
) -> list[dict]:
    q = f"repo:{repo} is:pr created:>={since_d} created:<={until_d}"
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


async def fetch_dependabot_alert_stats(
    repo: str, since_d: str, until_d: str, token: str
) -> dict:
    """Counts open alerts + fixed/dismissed in date window. On 403, returns error hint."""
    from datetime import datetime, timezone

    hdrs = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    since_dt = datetime.strptime(since_d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    until_dt = datetime.strptime(until_d, "%Y-%m-%d").replace(
        hour=23, minute=59, second=59, tzinfo=timezone.utc
    )

    open_count = 0
    fixed_in_window = 0
    dismissed_in_window = 0
    new_open_in_window = 0
    url = f"https://api.github.com/repos/{repo}/dependabot/alerts"
    async with httpx.AsyncClient(timeout=60) as client:
        page = 1
        while page <= 20:
            r = await client.get(
                url, headers=hdrs, params={"state": "all", "per_page": 100, "page": page}
            )
            if r.status_code == 403:
                return {
                    "ok": False,
                    "hint": (
                        "Dependabot alerts unavailable (403). Add scope **`security_events`** to "
                        "`GITHUB_OAUTH_SCOPE` (e.g. `repo security_events`) and reconnect GitHub."
                    ),
                }
            if r.status_code != 200:
                return {
                    "ok": False,
                    "hint": f"Dependabot API error {r.status_code}: {r.text[:200]}",
                }
            batch = r.json()
            if not isinstance(batch, list):
                return {"ok": False, "hint": f"Unexpected Dependabot response: {batch!s}"[:300]}
            if not batch:
                break
            for a in batch:
                st = (a.get("state") or "").lower()
                created_s = a.get("created_at") or ""
                fixed_s = a.get("fixed_at") or ""
                dismissed_s = a.get("dismissed_at") or ""
                try:
                    created = (
                        datetime.fromisoformat(created_s.replace("Z", "+00:00"))
                        if created_s
                        else None
                    )
                except ValueError:
                    created = None
                in_created_window = (
                    created is not None and since_dt <= created <= until_dt
                )
                if st == "open":
                    open_count += 1
                    if in_created_window:
                        new_open_in_window += 1
                if st == "fixed" and fixed_s:
                    try:
                        fx = datetime.fromisoformat(fixed_s.replace("Z", "+00:00"))
                        if since_dt <= fx <= until_dt:
                            fixed_in_window += 1
                    except ValueError:
                        pass
                if st == "dismissed" and dismissed_s:
                    try:
                        ds = datetime.fromisoformat(dismissed_s.replace("Z", "+00:00"))
                        if since_dt <= ds <= until_dt:
                            dismissed_in_window += 1
                    except ValueError:
                        pass
            if len(batch) < 100:
                break
            page += 1

    return {
        "ok": True,
        "open_total": open_count,
        "fixed_in_window": fixed_in_window,
        "dismissed_in_window": dismissed_in_window,
        "new_open_in_window": new_open_in_window,
    }


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


async def call_claude(system: str, user: str, max_tokens: int | None = None) -> str:
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
                    "max_tokens": max_tokens if max_tokens is not None else 1500,
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


SLACK_JSON_HEADERS = {
    "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
    "Content-Type": "application/json; charset=utf-8",
}


async def post_ephemeral(channel: str, user: str, text: str, blocks: list | None = None):
    payload = {"channel": channel, "user": user, "text": text}
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://slack.com/api/chat.postEphemeral",
            headers=SLACK_JSON_HEADERS,
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


async def post_message(
    channel: str,
    text: str,
    thread_ts: str | None = None,
    blocks: list[dict] | None = None,
) -> dict:
    payload: dict = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://slack.com/api/chat.postMessage",
            headers=SLACK_JSON_HEADERS,
            json=payload,
        )
    try:
        data = r.json()
    except json.JSONDecodeError:
        data = {}
    if not data.get("ok"):
        logger.error("chat.postMessage failed: %s", data)
        raise RuntimeError(str(data.get("error", "chat.postMessage failed")))
    return data


async def post_pr_summary_to_channel(
    channel: str,
    thread_ts: str | None,
    title: str,
    body: str,
) -> None:
    """Publish PR summary as channel/thread messages (splits long bodies; ≤48 sections per message)."""
    chunk_size = 2800
    max_sections = 48
    s = (body or "").strip()
    parts: list[str] = []
    while s:
        parts.append(s[:chunk_size])
        s = s[chunk_size:]
    if not parts:
        parts = ["_(empty)_"]
    reply_thread_ts = thread_ts
    i = 0
    first_message = True
    while i < len(parts):
        batch = parts[i : i + max_sections]
        i += len(batch)
        blk: list[dict] = []
        if first_message:
            blk.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{title}*\n_Posted via Susan_"},
                }
            )
            blk.append({"type": "divider"})
            first_message = False
        for p in batch:
            blk.append({"type": "section", "text": {"type": "mrkdwn", "text": p[:2900]}})
        is_last = i >= len(parts)
        fallback = (title[:200] if is_last else f"{title[:80]}… (continued)") or "PR summary"
        data = await post_message(channel, fallback, thread_ts=reply_thread_ts, blocks=blk)
        ts = data.get("ts")
        if reply_thread_ts is None and ts and not is_last:
            reply_thread_ts = ts


EMAIL_IN_TEXT_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Slack mention: <@U123ABC> or <@U123ABC|display name> (also W for workflows in some workspaces)
SLACK_USER_MENTION_RE = re.compile(r"<@([UW][A-Z0-9]+)(?:\|[^>]+)?>")


def _slack_unresolved_recipients_help(user_ids: str) -> str:
    json_example = '{"U08MYEN0NS0":"you@company.com"}'
    return (
        f"Slack user(s) `{user_ids}` have no email the bot can use.\n\n"
        "*Fixes:* Reinstall Susan after adding **`users:read.email`** (the install/OAuth screen must list that scope). "
        "Some workspaces **hide member emails from apps** (Enterprise: org security / email visibility). "
        "**Guests** and **Slack Connect** users often cannot be resolved.\n\n"
        "*Override:* set **`SLACK_USER_EMAIL_MAP`** on the server — e.g. `U08MYEN0NS0:you@company.com` "
        f"or JSON `{json_example}`. "
        "Or type plain **`email@domain`** in To:/Attendees:."
    )


def _slack_user_email_overrides() -> dict[str, str]:
    """Optional env SLACK_USER_EMAIL_MAP when Slack does not expose emails (policy, guests, etc.)."""
    raw = (os.environ.get("SLACK_USER_EMAIL_MAP") or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return {
                    str(k).strip().upper(): str(v).strip()
                    for k, v in data.items()
                    if str(k).strip() and str(v).strip()
                }
        except json.JSONDecodeError:
            pass
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if ":" not in part:
            continue
        sid, em = part.split(":", 1)
        sid, em = sid.strip().upper(), em.strip()
        if sid and em:
            out[sid] = em
    return out


async def slack_users_lookup_email(user_id: str) -> str | None:
    """Uses users.info (needs users:read.email) or SLACK_USER_EMAIL_MAP override."""
    uid = user_id.strip().upper()
    if not uid:
        return None
    ov = _slack_user_email_overrides()
    if uid in ov:
        return ov[uid]
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://slack.com/api/users.info",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            params={"user": uid},
        )
    data = r.json()
    if not data.get("ok"):
        logger.warning("users.info %s: %s", uid, data.get("error"))
        return None
    profile = (data.get("user") or {}).get("profile") or {}
    email = (profile.get("email") or "").strip()
    if not email:
        logger.info(
            "users.info %s: ok but no profile.email (needs users:read.email + reinstall, "
            "or workspace hides emails from apps; use SLACK_USER_EMAIL_MAP to override)",
            uid,
        )
    return email or None


async def resolve_slack_recipients_to_emails(raw: str) -> tuple[str, list[str]]:
    """Replace <@U…> mentions and bare Slack user ids (U…/W…) in a To/Attendees line with workspace emails."""
    if not (raw or "").strip():
        return "", []
    cache: dict[str, str | None] = {}

    async def lookup(uid: str) -> str | None:
        k = uid.strip().upper()
        if k not in cache:
            cache[k] = await slack_users_lookup_email(k)
        return cache[k]

    text = raw.strip()
    unresolved: list[str] = []

    if "<@" in text:
        seen_full: set[str] = set()
        pairs: list[tuple[str, str]] = []
        for m in SLACK_USER_MENTION_RE.finditer(text):
            full, uid = m.group(0), m.group(1)
            if full not in seen_full:
                seen_full.add(full)
                pairs.append((full, uid))
        for full, uid in pairs:
            em = await lookup(uid)
            if em:
                text = text.replace(full, em)
            else:
                text = text.replace(full, "")
                unresolved.append(uid.upper())

    resolved_parts: list[str] = []
    for chunk in re.split(r"[,;]", text):
        chunk = chunk.strip()
        if not chunk:
            continue
        found_addrs = EMAIL_IN_TEXT_RE.findall(chunk)
        if found_addrs:
            resolved_parts.extend(found_addrs)
            continue
        uid_m = re.fullmatch(r"([uw][a-z0-9]{8,12})", chunk, re.I)
        if uid_m:
            uid = uid_m.group(1).upper()
            em = await lookup(uid)
            if em:
                resolved_parts.append(em)
            else:
                unresolved.append(uid)
            continue
        resolved_parts.append(chunk)

    out = ", ".join(resolved_parts)
    out = re.sub(r",\s*,+", ", ", out)
    out = re.sub(r"^\s*,\s*|\s*,\s*$", "", out)
    out = re.sub(r"\s{2,}", " ", out).strip()
    un = list(dict.fromkeys(unresolved))
    return out, un


SYSTEM_PROMPTS = {
    "doc": "You are Susan. Given a Slack conversation, write a structured document with sections: ## Summary, ## Key Decisions, ## Action Items, ## Open Questions. Be concise and professional.",
    "email": "You are Susan. Given a Slack conversation, draft a professional email. Output ONLY this structure:\nTo: …\nSubject: <subject>\n\n<body>\n\nRecipients in To: must be comma-separated. Use real email@domain when known. When the thread shows Slack user ids before each message (e.g. U01ABC2XYZ3: hello), you may put those people in To: as Slack mentions: <@U01ABC2XYZ3> (one per person Susan should email). Susan will resolve mentions to workspace emails. If the user types @mentions in Slack, the thread text may already contain <@U…> — keep those in To:. If no recipients, leave To: empty.",
    "invite": "You are Susan. Given a Slack conversation, draft a calendar invite. Output ONLY:\nTitle: <short title>\nAttendees: … (comma-separated emails and/or <@SLACK_USER_ID> mentions as in the thread)\nStart: <ISO8601 e.g. 2026-04-15T14:00:00>\nEnd: <ISO8601>\nTimeZone: <IANA e.g. America/New_York or UTC>\nDescription:\n<agenda / notes>\n\nInfer date/time from the thread. For people only identified by Slack user id in the thread (U01…), use <@U01…> in Attendees: so Susan can resolve emails.",
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
    all_slugs = parse_all_repo_slugs_from_text(text)
    return all_slugs[0] if all_slugs else None


def parse_all_repo_slugs_from_text(text: str) -> list[str]:
    """All distinct owner/repo slugs from slash text (order preserved)."""
    if not (text or "").strip():
        return []
    seen: set[str] = set()
    out: list[str] = []

    def add_slug(cand: str) -> None:
        if not is_plausible_github_repo_slug(cand):
            return
        c = cand.strip().lower()
        if c not in seen:
            seen.add(c)
            out.append(c)

    m_list = re.search(r"(?i)\b(?:repos?|in)\s*:\s*([^\n]+)", text)
    if m_list:
        for part in m_list.group(1).split(","):
            p = part.strip()
            if p:
                add_slug(p)

    for m in re.finditer(r"github\.com/([^/\s]+)/([^/\s?#]+)", text, re.I):
        add_slug(f"{m.group(1)}/{m.group(2)}")

    for m in re.finditer(
        r"\b([a-zA-Z0-9][a-zA-Z0-9-]{0,38}/[a-zA-Z0-9._-]+)\b", text
    ):
        add_slug(m.group(1))

    return out


def resolve_github_repos_for_pr_summary(
    text: str,
) -> tuple[list[str] | None, str | None, bool]:
    """Returns (repos, error_ephemeral, needs_multi_picker)."""
    allow = _pr_allowlist()
    parsed = parse_all_repo_slugs_from_text(text)
    if parsed:
        if allow:
            bad = [r for r in parsed if r not in allow]
            if bad:
                return None, (
                    f"Repo(s) not allowed: {', '.join(f'`{b}`' for b in bad)}. "
                    f"Allowed: {', '.join(allow)}."
                ), False
        return parsed, None, False
    default = (os.environ.get("GITHUB_REPO") or "").strip().lower()
    if default:
        if allow and default not in allow:
            return None, (
                f"Default `GITHUB_REPO` (`{default}`) is not in `GITHUB_REPOS`: {', '.join(allow)}."
            ), False
        return [default], None, False
    if len(allow) == 1:
        return [allow[0]], None, False
    if len(allow) > 1:
        return None, None, True
    return None, (
        "No GitHub repo configured. Set `GITHUB_REPO` or `GITHUB_REPOS`, "
        "or name repos in your command (e.g. `org/a org/b` or `repos: org/a, org/b`)."
    ), False


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


_PR_SUMMARY_PARTICIPANT_SEM = asyncio.Semaphore(10)


async def _github_list_all_pages(
    client: httpx.AsyncClient, url: str, headers: dict, max_pages: int = 15
) -> list[dict]:
    out: list[dict] = []
    for page in range(1, max_pages + 1):
        r = await client.get(url, headers=headers, params={"per_page": 100, "page": page})
        if r.status_code != 200:
            break
        batch = r.json()
        if not isinstance(batch, list):
            break
        out.extend(batch)
        if len(batch) < 100:
            break
    return out


async def fetch_merged_pr_participant_logins(repo: str, pr_number: int, token: str) -> set[str]:
    """Logins from issue comments, pull review comments, and submitted reviews (non-bot)."""
    hdrs = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    base = f"https://api.github.com/repos/{repo}"
    urls = [
        f"{base}/issues/{pr_number}/comments",
        f"{base}/pulls/{pr_number}/comments",
        f"{base}/pulls/{pr_number}/reviews",
    ]
    logins: set[str] = set()
    async with _PR_SUMMARY_PARTICIPANT_SEM:
        async with httpx.AsyncClient(timeout=45) as client:
            batches = await asyncio.gather(
                _github_list_all_pages(client, urls[0], hdrs),
                _github_list_all_pages(client, urls[1], hdrs),
                _github_list_all_pages(client, urls[2], hdrs),
            )
            for batch in batches:
                for item in batch:
                    u = item.get("user")
                    if isinstance(u, dict):
                        lg = u.get("login")
                        if lg and not str(lg).endswith("[bot]"):
                            logins.add(lg)
    return logins


def _pr_merged_sort_key(pair: tuple[str, dict]) -> float:
    from datetime import datetime

    it = pair[1]
    pr_meta = it.get("pull_request") or {}
    m = pr_meta.get("merged_at") or it.get("closed_at") or ""
    if not m:
        return 0.0
    try:
        return datetime.fromisoformat(m.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


async def build_pr_summary_engagement_appendix(
    repos: list[str], batches: list[list[dict]], token: str
) -> str:
    """Authors + comment/review participation for the Claude prompt (caps GitHub fan-out)."""
    from collections import Counter

    author_counts: Counter[str] = Counter()
    for _repo, items in zip(repos, batches):
        for it in items:
            login = (it.get("user") or {}).get("login") or "?"
            author_counts[login] += 1

    flat: list[tuple[str, dict]] = []
    for repo, items in zip(repos, batches):
        for it in items:
            flat.append((repo, it))
    flat.sort(key=_pr_merged_sort_key, reverse=True)

    max_fetch = max(0, min(500, int(os.environ.get("PR_SUMMARY_MAX_PARTICIPANT_FETCH", "80"))))
    slice_pairs = flat[:max_fetch] if max_fetch else []

    commenter_pr_touch: Counter[str] = Counter()
    if slice_pairs:
        try:

            async def _participants(repo: str, it: dict) -> set[str]:
                n = it.get("number")
                if n is None:
                    return set()
                return await fetch_merged_pr_participant_logins(repo, int(n), token)

            results = await asyncio.gather(
                *[_participants(repo, it) for repo, it in slice_pairs],
                return_exceptions=True,
            )
            for pair, res in zip(slice_pairs, results):
                if isinstance(res, Exception):
                    logger.warning(
                        "PR participant fetch failed for %s #%s: %s",
                        pair[0],
                        pair[1].get("number"),
                        res,
                    )
                    continue
                for lg in res:
                    commenter_pr_touch[lg] += 1
        except Exception as e:
            logger.exception("PR participant gather failed: %s", e)

    lines = [
        "### Aggregated participation (from GitHub: issue comments, review comments, reviews)",
    ]
    if author_counts:
        lines.append(
            "Merged-PR authors (@login → count of merged PRs they opened in this window): "
            + ", ".join(f"@{k} ({v})" for k, v in author_counts.most_common())
        )
    else:
        lines.append("(No merged PRs in window.)")

    if commenter_pr_touch:
        lines.append(
            "Commenters & reviewers (@login → number of merged PRs in this window they commented on "
            "or reviewed; bots excluded): "
            + ", ".join(f"@{k} ({v})" for k, v in commenter_pr_touch.most_common(40))
        )
    elif flat and max_fetch == 0:
        lines.append(
            "(Comment/review participation not fetched: PR_SUMMARY_MAX_PARTICIPANT_FETCH is 0.)"
        )
    elif slice_pairs:
        lines.append(
            "(No non-bot issue/review activity found on the sampled PRs, or GitHub returned errors.)"
        )

    if len(flat) > max_fetch and max_fetch > 0:
        lines.append(
            f"_Note: comment/review data was fetched for the {max_fetch} most recently merged PRs only "
            f"({len(flat)} total in window); authors above include all merged PRs._"
        )

    return "\n".join(lines)


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
        "You are Susan. Write a concise Slack-ready summary (mrkdwn) of merged pull requests "
        "across one or more repositories. "
        "Use short ## headings and bullets. "
        "Whenever you mention a specific PR in the body, include its repository slug in parentheses "
        "using the exact `owner/repo` from the data, e.g. `#35 Model deployment UI cleanup (frontier-one/f1-asgardos)`. "
        "If you use Slack link syntax, put the same slug in the visible text, e.g. "
        "<https://github.com/…|#35 Model deployment UI cleanup (frontier-one/f1-asgardos)>. "
        "Group by theme or area when it helps; you may group by repository or combine cross-repo themes. "
        "State the date range and repo list at the top. "
        "Always end with a ## Contributors & commenters section: briefly highlight who merged the most PRs "
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
    from collections import Counter

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

            opened_titles = [(x.get("title") or "").replace("\n", " ") for x in opened[:40]]
            avg_part = (
                f"{avg_h:.1f}"
                if avg_h is not None
                else "n/a (no merged PRs with created+merged timestamps)"
            )
            github_sections.append(
                f"### `{r}`\n"
                f"{dep_lines}\n"
                f"PRs opened in window: {len(opened)}; merged in window: {len(merged)}.\n"
                f"Average merge turnaround (hours): {avg_part}.\n"
                f"Top merged-PR authors: {', '.join(f'@{a} ({c})' for a, c in top_authors) or 'none'}.\n"
                f"Merged PR titles (up to 50): {'; '.join(titles[:50])}\n"
                f"Opened PR titles (up to 40): {'; '.join(opened_titles)}\n"
            )

        facts = "\n\n".join(github_sections)
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            f"Slack channel transcript (user ids are opaque U…; infer roles from content only):\n"
            f"{slack_digest}\n\n"
            f"---\nGitHub metrics and PR titles per repo:\n{facts}"
        )
        system = (
            "You are Susan. Write a weekly status report as Slack mrkdwn.\n"
            "Use clear ## headings, e.g. ## Channel (Slack) and ## GitHub (or per-repo ## lines).\n"
            "Slack section: very high level — notable updates from teammates, decisions, risks, "
            "open questions; do not quote long messages.\n"
            "GitHub section: summarize Dependabot/vulnerability posture, PR volume, average turnaround, "
            "main themes of merged work, and who was most active (authors you infer from the data).\n"
            "If Dependabot data was unavailable for a repo, say so briefly.\n"
            "Keep it executive-readable. Do not say the draft is private or ephemeral."
        )
    else:
        user_prompt = (
            f"Reporting window: {range_label}.\n"
            "This is a non-engineering Slack channel: produce a weekly status from the transcript only "
            "(no GitHub or code repository data).\n"
            f"Slack channel transcript (user ids are opaque U…; infer roles from content only):\n"
            f"{slack_digest}\n"
        )
        system = (
            "You are Susan. Write a weekly status report as Slack mrkdwn for a general team channel.\n"
            "Use clear ## headings focused on the conversation (e.g. ## Highlights, ## Decisions, "
            "## Risks & blockers, ## Open questions).\n"
            "Stay very high level — notable updates, decisions, and open threads; do not quote long messages.\n"
            "Do not mention GitHub, pull requests, or repositories unless the transcript explicitly does.\n"
            "Keep it executive-readable. Do not say the draft is private or ephemeral."
        )

    max_tok = max(1500, min(32000, int(os.environ.get("WEEKLY_STATUS_MAX_TOKENS", "4096"))))
    try:
        summary = await call_claude(system, user_prompt, max_tokens=max_tok)
    except Exception as e:
        logger.exception("Weekly status Claude failed")
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    title = _weekly_status_title_line(repos, range_label, include_github=include_github)
    if auto_publish:
        try:
            await post_pr_summary_to_channel(channel, thread_ts, title, summary)
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
            "✓ Weekly status was posted to the channel (_no approval step_).",
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
        "_Use *Approve & post to channel* to publish this for everyone in this conversation, "
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
                    "text": {"type": "plain_text", "text": "✓ Approve & post to channel"},
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
        "• `/susan connect google` — Docs, Gmail, Calendar\n"
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
        "(for example `repo security_events`) and reconnect GitHub; otherwise Susan will note that alerts are unavailable."
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
    to_raw, slack_unres = await resolve_slack_recipients_to_emails(to_raw)
    if slack_unres and not EMAIL_IN_TEXT_RE.findall(to_raw):
        return "Email not sent — " + _slack_unresolved_recipients_help(", ".join(slack_unres))
    if not to_raw:
        return (
            "Email not sent — add *To:* recipients in the draft (or set DEFAULT_EMAIL_TO on the server)."
        )
    recipients = list(dict.fromkeys(EMAIL_IN_TEXT_RE.findall(to_raw)))
    if not recipients:
        return (
            "Email not sent — no valid email addresses in *To:* after resolving Slack mentions. "
            "Use emails or <@USER_ID> with **users:read.email** scope."
        )
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
    att_raw, att_unres = await resolve_slack_recipients_to_emails(p["attendees"])
    emails = list(dict.fromkeys(EMAIL_IN_TEXT_RE.findall(att_raw)))
    if not emails and att_unres:
        return "Calendar invite not created — " + _slack_unresolved_recipients_help(
            ", ".join(att_unres)
        )
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
