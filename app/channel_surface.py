"""Personal digests from #team-tech standups and alert channels.

Skills (slash phrasing):
  /susan standups [last week]
  /susan surface failures [last 7 days]
  /susan surface reviews / needs my review
"""
from __future__ import annotations

import os
import re
from inspect import cleandoc
from typing import Any, Literal

import httpx

from app.claude_client import call_claude
from app.config import SLACK_BOT_TOKEN, SUSAN_VOICE, logger
from app.slack_api import (
    fetch_slack_channel_history_since,
    notify_user_ephemeral,
    post_message,
)
from app.weekly_context import (
    parse_weekly_status_time_range,
    strip_weekly_status_auto_post_flags,
    utc_date_start_slack_ts,
)

SurfaceKind = Literal["standups", "failures", "reviews"]

_STANDUP_PARENT_RE = re.compile(
    r"(?i)\b(standup|stand-up|stand\s*up)\b.*\bnotes\b|\bnotes\b.*\b(standup|stand-up|stand\s*up)\b|"
    r"^\s*\w[\w\s,]*standup notes\b|\bnotes from standup\b"
)

_FAILURE_HINT_RE = re.compile(
    r"(?i)(:red_circle:|\bfailed\b|\bfailure\b|\berror\b|\bburst\b|\bbudget\b|"
    r":warning:|\balert\b|\bdown\b|\bunhealthy\b|\btimeout\b|\bcrash)"
)

_SUCCESS_ONLY_RE = re.compile(
    r"(?i)^[^:]*:white_check_mark:.*\b(passed|success|live \+ verified|ok)\b"
)

_REVIEW_HINT_RE = re.compile(
    r"(?i)(:eyes:|\bready for review\b|\bneeds? review\b|\bplease review\b|"
    r"\bcan you (have a )?review\b|\bfor review\b|\bcode review\b|\bPR ready\b)"
)

# Phrase parsers — longer / more specific first.
_STANDUP_PREFIXES = (
    "summary of standups",
    "summarize standups",
    "summarise standups",
    "standup summary",
    "standup notes",
    "standups summary",
    "stand-up summary",
    "standups",
    "standup",
    "stand-ups",
    "stand-up",
)

_FAILURE_PREFIXES = (
    "surface everything that is failing",
    "surface everything failing",
    "surface failures",
    "surface alerts",
    "what's failing",
    "whats failing",
    "what is failing",
    "failures",
    "failing",
    "alerts digest",
    "alert summary",
    "alert digest",
)

_REVIEW_PREFIXES = (
    "surface everything that requires my review",
    "surface everything that needs my review",
    "surface everything requiring my review",
    "surface reviews",
    "requires my review",
    "require my review",
    "needs my review",
    "need my review",
    "my reviews",
    "pending reviews",
    "prs to review",
    "pr to review",
    "reviews for me",
)


def _match_prefix(text: str, prefixes: tuple[str, ...]) -> str | None:
    raw = (text or "").strip()
    if not raw:
        return None
    lower = raw.lower()
    for prefix in prefixes:
        if lower == prefix:
            return ""
        if lower.startswith(prefix + " "):
            return raw[len(prefix) :].strip()
    return None


def parse_standup_command(text: str) -> str | None:
    return _match_prefix(text, _STANDUP_PREFIXES)


def parse_failures_command(text: str) -> str | None:
    return _match_prefix(text, _FAILURE_PREFIXES)


def parse_reviews_command(text: str) -> str | None:
    return _match_prefix(text, _REVIEW_PREFIXES)


def parse_surface_time_window(remainder: str, *, default_days: int) -> tuple[str, str, str]:
    r = (remainder or "").strip()
    if not r or r.lower().startswith("--"):
        days = max(1, min(366, default_days))
        from datetime import datetime, timedelta, timezone

        today = datetime.now(timezone.utc).date()
        start = today - timedelta(days=days)
        return start.isoformat(), today.isoformat(), f"last {days} day(s)"
    return parse_weekly_status_time_range(r)


def default_standup_channel_id() -> str:
    return (os.environ.get("SUSAN_STANDUP_CHANNEL") or "C0ANY6ASRB5").strip()


def _alias_map() -> dict[str, str]:
    """name slug → channel id from SUSAN_SCHEDULE_CHANNEL_ALIASES + surface defaults."""
    out: dict[str, str] = {"team-tech": default_standup_channel_id()}
    raw = (os.environ.get("SUSAN_SCHEDULE_CHANNEL_ALIASES") or "").strip()
    if raw:
        for part in raw.split(","):
            part = part.strip()
            if ":" not in part:
                continue
            name, cid = part.split(":", 1)
            name = name.strip().lstrip("#").lower()
            cid = cid.strip()
            if name and cid:
                out[name] = cid
    extra = (os.environ.get("SUSAN_CHANNEL_ALIASES") or "").strip()
    if extra:
        for part in extra.split(","):
            part = part.strip()
            if ":" not in part:
                continue
            name, cid = part.split(":", 1)
            name = name.strip().lstrip("#").lower()
            cid = cid.strip()
            if name and cid:
                out[name] = cid
    return out


def _alert_channel_specs() -> list[str]:
    """Configured alert channel ids or names (comma-separated)."""
    raw = (os.environ.get("SUSAN_ALERT_CHANNELS") or "").strip()
    if raw:
        return [p.strip().lstrip("#") for p in raw.split(",") if p.strip()]
    return ["team-tech-alerts", "team-tech-dev-alerts"]


_CHANNEL_ID_RE = re.compile(r"^C[A-Z0-9]{8,}$", re.IGNORECASE)

_channel_name_cache: dict[str, str] | None = None


async def _list_public_channel_name_map() -> dict[str, str]:
    """name → id via conversations.list (needs channels:read). Cached per process."""
    global _channel_name_cache
    if _channel_name_cache is not None:
        return _channel_name_cache
    mapping: dict[str, str] = {}
    cursor: str | None = None
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            while True:
                params: dict[str, str] = {
                    "types": "public_channel,private_channel",
                    "limit": "200",
                    "exclude_archived": "true",
                }
                if cursor:
                    params["cursor"] = cursor
                r = await client.get(
                    "https://slack.com/api/conversations.list",
                    headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
                    params=params,
                )
                data = r.json()
                if not data.get("ok"):
                    logger.warning(
                        "conversations.list failed (need channels:read?): %s",
                        data.get("error"),
                    )
                    break
                for ch in data.get("channels") or []:
                    name = (ch.get("name") or "").strip().lower()
                    cid = ch.get("id")
                    if name and cid:
                        mapping[name] = str(cid)
                cursor = (data.get("response_metadata") or {}).get("next_cursor") or None
                if not cursor:
                    break
    except Exception:
        logger.exception("conversations.list failed")
    _channel_name_cache = mapping
    return mapping


async def resolve_channel_ref(spec: str) -> str | None:
    """Resolve a channel id or #name to a channel id."""
    s = (spec or "").strip().lstrip("#")
    if not s:
        return None
    if _CHANNEL_ID_RE.match(s):
        return s.upper()
    aliases = _alias_map()
    if s.lower() in aliases:
        return aliases[s.lower()]
    names = await _list_public_channel_name_map()
    return names.get(s.lower())


async def resolve_alert_channel_ids() -> tuple[list[str], list[str]]:
    """Return (resolved_ids, unresolved_specs)."""
    resolved: list[str] = []
    missing: list[str] = []
    seen: set[str] = set()
    for spec in _alert_channel_specs():
        cid = await resolve_channel_ref(spec)
        if not cid:
            missing.append(spec)
            continue
        if cid not in seen:
            seen.add(cid)
            resolved.append(cid)
    return resolved, missing


def _is_standup_parent(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    if _STANDUP_PARENT_RE.search(t):
        return True
    # Dated "July 13 Standup notes in :thread:" style
    if re.search(r"(?i)\bstandup notes\b", t):
        return True
    return False


async def _fetch_filtered_channel_digest(
    channel: str,
    oldest_ts: str,
    user: str,
    *,
    keep_line,
    include_thread_replies: bool,
    label: str,
) -> str:
    """Fetch history+optional threads, keep only lines matching keep_line(text)."""
    # Pull a fuller digest then filter — reuse existing helper.
    raw = await fetch_slack_channel_history_since(
        channel,
        oldest_ts,
        user,
        include_thread_replies=include_thread_replies,
    )
    if raw.startswith("(No channel messages"):
        return f"### #{label}\n_(no messages in window)_"

    kept: list[str] = []
    keep_block = False
    for line in raw.splitlines():
        # Thread reply lines are indented; keep them if we're inside a kept parent.
        if line.startswith("  ") or line.startswith("  ["):
            if keep_block:
                kept.append(line)
            continue
        # Parent line: "U123: text" or "B123: text"
        text = line.split(":", 1)[-1] if ":" in line else line
        if keep_line(text):
            keep_block = True
            kept.append(line)
        else:
            keep_block = False

    if not kept:
        return f"### #{label}\n_(no matching messages in window)_"
    return f"### #{label}\n" + "\n".join(kept)


async def _gather_standup_digest(user: str, oldest_ts: str) -> str:
    cid = default_standup_channel_id()
    return await _fetch_filtered_channel_digest(
        cid,
        oldest_ts,
        user,
        keep_line=_is_standup_parent,
        include_thread_replies=True,
        label="team-tech standups",
    )


async def _gather_failures_digest(user: str, oldest_ts: str) -> tuple[str, list[str]]:
    ids, missing = await resolve_alert_channel_ids()
    parts: list[str] = []
    errors: list[str] = []
    if missing:
        errors.append(
            "Could not resolve alert channel(s): "
            + ", ".join(f"`#{m}`" for m in missing)
            + ". Set `SUSAN_ALERT_CHANNELS` to channel ids (e.g. `C0…,C0…`) or add "
            "`channels:read` + reinstall so Susan can resolve names, and "
            "`/invite @Susan` into those channels."
        )
    if not ids:
        return "\n".join(errors) or "_(no alert channels configured)_", errors

    def keep(text: str) -> bool:
        if _SUCCESS_ONLY_RE.search(text or "") and not _FAILURE_HINT_RE.search(text or ""):
            return False
        return bool(_FAILURE_HINT_RE.search(text or ""))

    for cid in ids:
        try:
            parts.append(
                await _fetch_filtered_channel_digest(
                    cid,
                    oldest_ts,
                    user,
                    keep_line=keep,
                    include_thread_replies=False,
                    label=cid,
                )
            )
        except Exception as e:
            logger.warning("Alert channel fetch failed %s: %s", cid, e)
            errors.append(f"Could not read `{cid}`: {e}")
    body = "\n\n".join(parts) if parts else "_(no failure alerts in window)_"
    if errors:
        body = "\n".join(f"⚠️ _{e}_" for e in errors) + "\n\n" + body
    return body, errors


async def _gather_reviews_digest(user: str, oldest_ts: str) -> str:
    parts: list[str] = []

    # Alert channels: :eyes: PR ready pings
    ids, missing = await resolve_alert_channel_ids()
    if missing:
        parts.append(
            "⚠️ _Unresolved alert channels: "
            + ", ".join(f"`#{m}`" for m in missing)
            + " — set `SUSAN_ALERT_CHANNELS` or add `channels:read`._"
        )

    def keep_review(text: str) -> bool:
        if not _REVIEW_HINT_RE.search(text or ""):
            return False
        # Prefer items that tag the requester; still keep untagged "ready for review"
        # so Claude can filter to this user.
        return True

    for cid in ids:
        try:
            parts.append(
                await _fetch_filtered_channel_digest(
                    cid,
                    oldest_ts,
                    user,
                    keep_line=keep_review,
                    include_thread_replies=False,
                    label=f"alerts:{cid}",
                )
            )
        except Exception as e:
            logger.warning("Review alert fetch failed %s: %s", cid, e)
            parts.append(f"⚠️ _Could not read `{cid}`: {e}_")

    # team-tech: @mentions / explicit review asks (with threads)
    try:
        tech = default_standup_channel_id()

        def keep_tech(text: str) -> bool:
            t = text or ""
            if f"<@{user}>" in t and _REVIEW_HINT_RE.search(t):
                return True
            if _REVIEW_HINT_RE.search(t):
                return True
            return False

        parts.append(
            await _fetch_filtered_channel_digest(
                tech,
                oldest_ts,
                user,
                keep_line=keep_tech,
                include_thread_replies=True,
                label="team-tech review asks",
            )
        )
    except Exception as e:
        logger.warning("team-tech review fetch failed: %s", e)
        parts.append(f"⚠️ _Could not read team-tech: {e}_")

    return "\n\n".join(parts) if parts else "_(nothing found)_"


def _system_prompt(kind: SurfaceKind) -> str:
    common = cleandoc(
        f"""
        You are Susan. {SUSAN_VOICE}
        Output Slack mrkdwn only (single *asterisks* for bold). Use <@U…> when tagging people.
        Lead with what matters. Omit empty sections. No preamble like "Here is…".
        """
    )
    if kind == "standups":
        return common + "\n\n" + cleandoc(
            """
            Summarize daily standup notes for the requested window.

            Structure:
            *Standups — <range>*
            • One short bullet per standup day (date + headline themes)
            *Open threads / decisions*
            • Carry-forward decisions and open questions
            *Action items still open*
            • Owner <@U…> — task (skip clearly done items)

            Use only the standup transcript. If none, say so in one line.
            """
        )
    if kind == "failures":
        return common + "\n\n" + cleandoc(
            """
            Surface what is failing or unhealthy from CI / promote / cost / red-team alerts.

            Structure:
            *Failing now — <range>*
            • Group by system/repo (cloud-infra, f1, costs, redteam, …)
            • Each bullet: what failed + link if present + date
            *Recurring / noisy*
            • Patterns that failed more than once (optional; omit if none)
            *Ignore*
            Do **not** list pure successes (:white_check_mark: passed). Focus on :red_circle:, FAILED, errors, budget bursts, warnings that need action.

            If nothing is failing, say so in one line.
            """
        )
    return common + "\n\n" + cleandoc(
        """
        Surface items that require **this Slack user's** review or response.

        The requesting user's Slack id is given in the prompt — prioritize:
        - Messages that <@mention> them
        - ":eyes: … PR ready for review" pings that include them
        - Explicit "please review" / "can you review" asks aimed at them

        Structure:
        *Needs your review — <range>*
        • Bullets with PR/doc links when present
        *Also awaiting review (team)*
        • Optional short list of review asks that don't tag them but look unblockable — omit if none

        If nothing needs them, say so in one line.
        """
    )


async def _summarize(
    kind: SurfaceKind,
    *,
    range_label: str,
    digest: str,
    user: str,
) -> str:
    system = _system_prompt(kind)
    user_prompt = (
        f"Window: {range_label}\n"
        f"Requesting Slack user: <@{user}> ({user})\n\n"
        f"--- SOURCE TRANSCRIPT ---\n{digest}"
    )
    action = f"surface_{kind}"
    return await call_claude(system, user_prompt, max_tokens=4096, action=action)


async def process_channel_surface(
    kind: SurfaceKind,
    command_text: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    remainder, post_to_channel = strip_weekly_status_auto_post_flags(command_text)
    # Strip the skill prefix for date parsing
    if kind == "standups":
        rem = parse_standup_command(remainder) or remainder
        default_days = int((os.environ.get("STANDUP_LOOKBACK_DAYS") or "7").strip() or "7")
    elif kind == "failures":
        rem = parse_failures_command(remainder) or remainder
        default_days = int((os.environ.get("FAILURES_LOOKBACK_DAYS") or "7").strip() or "7")
    else:
        rem = parse_reviews_command(remainder) or remainder
        default_days = int((os.environ.get("REVIEWS_LOOKBACK_DAYS") or "7").strip() or "7")

    since_d, until_d, range_label = parse_surface_time_window(rem, default_days=default_days)
    oldest_ts = utc_date_start_slack_ts(since_d)

    try:
        if kind == "standups":
            digest = await _gather_standup_digest(user, oldest_ts)
        elif kind == "failures":
            digest, _ = await _gather_failures_digest(user, oldest_ts)
        else:
            digest = await _gather_reviews_digest(user, oldest_ts)
    except Exception as e:
        logger.exception("channel surface Slack gather failed kind=%s", kind)
        await notify_user_ephemeral(
            channel, user, f"Susan error (Slack): {e}", None, response_url
        )
        return

    try:
        summary = await _summarize(kind, range_label=range_label, digest=digest, user=user)
    except Exception as e:
        logger.exception("channel surface Claude failed kind=%s", kind)
        await notify_user_ephemeral(channel, user, f"Susan error: {e}", None, response_url)
        return

    summary = (summary or "").strip()
    if not summary:
        summary = f"_No {kind} digest for {range_label}._"

    if post_to_channel:
        try:
            await post_message(channel, summary, thread_ts=thread_ts)
            await notify_user_ephemeral(
                channel,
                user,
                f"✓ Posted *{kind}* digest to the channel (`--no-approval`).",
                None,
                response_url,
            )
        except Exception as e:
            logger.exception("channel surface post failed")
            await notify_user_ephemeral(
                channel, user, f"Could not post digest: {e}", None, response_url
            )
        return

    # Personal ephemeral (default)
    await notify_user_ephemeral(channel, user, summary, None, response_url)
