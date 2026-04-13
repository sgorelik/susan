"""Slack signing verification, history, posting, and recipient resolution."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse

import httpx

from app.config import ACTIONS, EMAIL_IN_TEXT_RE, logger, SLACK_BOT_TOKEN, SLACK_SIGNING_SECRET

def _slack_form_fields(body: bytes) -> dict[str, str]:
    """Parse application/x-www-form-urlencoded body into single string per key (Slack sends one value each)."""
    q = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    return {k: v[0] for k, v in q.items() if v}


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


def _md_double_star_to_slack_bold(s: str) -> str:
    """Turn **commonmark bold** into Slack mrkdwn *bold* (non-nested segments)."""
    out: list[str] = []
    i = 0
    while True:
        a = s.find("**", i)
        if a == -1:
            out.append(s[i:])
            break
        out.append(s[i:a])
        b = s.find("**", a + 2)
        if b == -1:
            out.append(s[a:])
            break
        inner = s[a + 2 : b].replace("*", "")
        out.append(f"*{inner}*")
        i = b + 2
    return "".join(out)


def _atx_headers_to_slack_bold(s: str) -> str:
    """Turn ## ATX headings into a single Slack *bold* line (Slack has no # headings in mrkdwn)."""
    lines = s.split("\n")
    out: list[str] = []
    for line in lines:
        m = re.match(r"^(\s*)(#{1,6})\s+(.+?)\s*$", line)
        if not m:
            out.append(line)
            continue
        indent, content = m.group(1), m.group(3).strip()
        content = re.sub(r"\s+#+\s*$", "", content)
        content = _md_double_star_to_slack_bold(content)
        if "*" in content:
            out.append(indent + content)
        else:
            out.append(f"{indent}*{content}*")
    return "\n".join(out)


def markdownish_to_slack_mrkdwn(text: str) -> str:
    """Claude often emits CommonMark (**bold**, ## headers). Slack Block Kit mrkdwn needs *bold* and no # headings."""
    if not (text or "").strip():
        return text or ""

    def convert_segment(seg: str) -> str:
        seg = _atx_headers_to_slack_bold(seg)
        seg = _md_double_star_to_slack_bold(seg)
        return seg

    parts = re.split(r"(```[\s\S]*?```)", text)
    buf: list[str] = []
    for i, p in enumerate(parts):
        if p.startswith("```") and p.endswith("```") and len(p) >= 6:
            buf.append(p)
        else:
            buf.append(convert_segment(p))
    return "".join(buf)


async def post_pr_summary_to_channel(
    channel: str,
    thread_ts: str | None,
    title: str,
    body: str,
) -> None:
    """Publish PR summary as channel/thread messages (splits long bodies; ≤48 sections per message)."""
    chunk_size = 2800
    max_sections = 48
    s = markdownish_to_slack_mrkdwn((body or "").strip())
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
