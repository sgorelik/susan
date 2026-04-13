"""Weekly status: flags, date windows, tech-channel detection."""
from __future__ import annotations

import os
import re

from app.github_repos import parse_pr_summary_time_range
from app.slack_api import slack_api_conversation_channel_name

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
