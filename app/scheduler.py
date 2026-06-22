"""Slack-configured recurring jobs: parse `/susan schedule`, run on a minute tick."""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from db import (
    create_scheduled_job,
    delete_scheduled_job,
    find_scheduled_job_by_prefix,
    list_due_scheduled_jobs,
    list_scheduled_jobs,
    set_scheduled_job_enabled,
    update_scheduled_job_after_run,
)
from fastapi.responses import JSONResponse

from app.action_items import process_action_items
from app.config import logger
from app.slack_api import _try_slack_open_im_with_user, post_message
from app.weekly_context import resolve_github_repos_for_weekly_status, weekly_status_include_github
from app.weekly_status import process_weekly_status

_DAY_NAMES: dict[str, int] = {
    "mon": 0,
    "monday": 0,
    "tue": 1,
    "tues": 1,
    "tuesday": 1,
    "wed": 2,
    "wednesday": 2,
    "thu": 3,
    "thur": 3,
    "thurs": 3,
    "thursday": 3,
    "fri": 4,
    "friday": 4,
    "sat": 5,
    "saturday": 5,
    "sun": 6,
    "sunday": 6,
}

_WEEKDAY_LABELS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

_SCHEDULE_TAIL_RE = re.compile(
    r"\s+every\s+(?P<days>daily|weekdays?|(?:(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|"
    r"thu(?:rs(?:day)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)(?:\s*,\s*"
    r"(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|"
    r"sat(?:urday)?|sun(?:day)?))*))\s+at\s+(?P<time>\d{1,2}(?::\d{2})?\s*(?:am|pm)?|\d{1,2}:\d{2})"
    r"(?:\s+in\s+(?P<channel>.+))?$",
    re.IGNORECASE,
)

_QUOTED_TEXT_RE = re.compile(r"""^["'](.+?)["']\s*(.*)$""", re.DOTALL)

_SLACK_CHANNEL_ID_RE = re.compile(r"^C[A-Z0-9]{8,}$", re.IGNORECASE)

_scheduler_task: asyncio.Task | None = None
_running_jobs: set[str] = set()


def default_schedule_timezone() -> str:
    return (os.environ.get("SUSAN_SCHEDULE_TIMEZONE") or "America/Los_Angeles").strip()


def default_schedule_channel_id() -> str:
    return (os.environ.get("SUSAN_DEFAULT_SCHEDULE_CHANNEL") or "C0ANY6ASRB5").strip()


def _schedule_channel_aliases() -> dict[str, str]:
    raw = (os.environ.get("SUSAN_SCHEDULE_CHANNEL_ALIASES") or "").strip()
    if not raw:
        return {"team-tech": default_schedule_channel_id()}
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        name, cid = part.split(":", 1)
        out[name.strip().lower().lstrip("#")] = cid.strip()
    return out


def parse_schedule_command(text: str) -> str | None:
    raw = (text or "").strip()
    if not raw:
        return None
    lower = raw.lower()
    if lower == "schedule":
        return ""
    if lower.startswith("schedule "):
        return raw[len("schedule") :].strip()
    return None


def _parse_time_of_day(raw: str) -> tuple[int, int]:
    s = (raw or "").strip().lower().replace(" ", "")
    m = re.match(r"^(\d{1,2})(?::(\d{2}))?(am|pm)?$", s)
    if not m:
        raise ValueError(f"Could not parse time {raw!r}. Use e.g. `9:00`, `9am`, or `17:30`.")
    hour = int(m.group(1))
    minute = int(m.group(2) or "0")
    meridiem = m.group(3)
    if meridiem == "pm" and hour < 12:
        hour += 12
    elif meridiem == "am" and hour == 12:
        hour = 0
    if hour > 23 or minute > 59:
        raise ValueError(f"Invalid time {raw!r}.")
    return hour, minute


def _parse_days_of_week(raw: str) -> list[int]:
    token = (raw or "").strip().lower()
    if token in ("daily", "everyday", "every day"):
        return list(range(7))
    if token in ("weekday", "weekdays"):
        return [0, 1, 2, 3, 4]
    days: list[int] = []
    for piece in re.split(r"\s*,\s*|\s+", token):
        piece = piece.strip()
        if not piece:
            continue
        if piece not in _DAY_NAMES:
            raise ValueError(
                f"Unknown day {piece!r}. Use `daily`, `weekdays`, or names like `monday`, `mon,wed`."
            )
        d = _DAY_NAMES[piece]
        if d not in days:
            days.append(d)
    if not days:
        raise ValueError("No days of week parsed.")
    return sorted(days)


def _format_days(days: list[int]) -> str:
    if days == list(range(7)):
        return "daily"
    if days == [0, 1, 2, 3, 4]:
        return "weekdays"
    return ",".join(_WEEKDAY_LABELS[d] for d in days)


def _format_time(hour: int, minute: int) -> str:
    h12 = hour % 12 or 12
    suffix = "am" if hour < 12 else "pm"
    if minute:
        return f"{h12}:{minute:02d}{suffix}"
    return f"{h12}{suffix}"


def resolve_schedule_channel(
    channel_clause: str | None,
    *,
    slash_channel_id: str,
    slash_channel_name: str | None,
) -> str:
    if not (channel_clause or "").strip():
        if slash_channel_id and _SLACK_CHANNEL_ID_RE.match(slash_channel_id):
            return slash_channel_id.upper()
        return default_schedule_channel_id()

    clause = channel_clause.strip()
    lower = clause.lower()
    if lower in ("this channel", "here", "this"):
        return slash_channel_id

    if _SLACK_CHANNEL_ID_RE.match(clause):
        return clause.upper()

    name = clause.lstrip("#").lower()
    aliases = _schedule_channel_aliases()
    if name in aliases:
        return aliases[name]

    slash_name = (slash_channel_name or "").strip().lstrip("#").lower()
    if slash_name and name == slash_name and slash_channel_id:
        return slash_channel_id

    raise ValueError(
        f"Unknown channel {clause!r}. Use `in this channel`, a channel id (e.g. `C0ANY6ASRB5`), "
        f"or a configured alias like `#team-tech`."
    )


def compute_next_run_at(
    *,
    hour: int,
    minute: int,
    days_of_week: list[int],
    tz_name: str,
    after: datetime | None = None,
) -> datetime:
    tz = ZoneInfo(tz_name)
    now_local = (after or datetime.now(timezone.utc)).astimezone(tz)
    dow_set = set(days_of_week)
    for offset in range(8):
        day = now_local.date() + timedelta(days=offset)
        if day.weekday() not in dow_set:
            continue
        candidate = datetime(
            day.year, day.month, day.day, hour, minute, tzinfo=tz
        )
        if candidate <= now_local:
            continue
        return candidate.astimezone(timezone.utc)
    raise RuntimeError("Could not compute next run time within 7 days.")


@dataclass
class ParsedScheduleAdd:
    job_type: str
    job_params: dict[str, Any]
    hour: int
    minute: int
    days_of_week: list[int]
    channel_id: str


def parse_schedule_add(
    remainder: str,
    *,
    slash_channel_id: str,
    slash_channel_name: str | None,
) -> ParsedScheduleAdd:
    raw = (remainder or "").strip()
    if not raw.lower().startswith("add "):
        raise ValueError("Use `schedule add …` (see `/susan help`).")

    body = raw[4:].strip()
    m_tail = _SCHEDULE_TAIL_RE.search(body)
    if not m_tail:
        raise ValueError(
            "Missing schedule tail. Example: `every monday at 9:00 in #team-tech` "
            "or `every weekday at 9am in C0ANY6ASRB5`."
        )

    head = body[: m_tail.start()].strip()
    hour, minute = _parse_time_of_day(m_tail.group("time"))
    days = _parse_days_of_week(m_tail.group("days"))
    channel_id = resolve_schedule_channel(
        m_tail.group("channel"),
        slash_channel_id=slash_channel_id,
        slash_channel_name=slash_channel_name,
    )

    lower_head = head.lower()
    if lower_head.startswith("message "):
        msg_body = head[len("message") :].strip()
        qm = _QUOTED_TEXT_RE.match(msg_body)
        if not qm:
            raise ValueError('Message jobs need quoted text, e.g. `message "Good morning team"`.')
        text, extra = qm.group(1), qm.group(2).strip()
        if extra:
            raise ValueError("Unexpected text after message quote.")
        return ParsedScheduleAdd(
            job_type="slack_message",
            job_params={"text": text},
            hour=hour,
            minute=minute,
            days_of_week=days,
            channel_id=channel_id,
        )

    if lower_head.startswith("weekly status"):
        command_text = head[len("weekly status") :].strip()
        return ParsedScheduleAdd(
            job_type="weekly_status",
            job_params={"command_text": command_text},
            hour=hour,
            minute=minute,
            days_of_week=days,
            channel_id=channel_id,
        )

    if lower_head.startswith("actions") or lower_head.startswith("action items"):
        prefix = "action items" if lower_head.startswith("action items") else "actions"
        command_text = head[len(prefix) :].strip()
        return ParsedScheduleAdd(
            job_type="action_items",
            job_params={"command_text": command_text},
            hour=hour,
            minute=minute,
            days_of_week=days,
            channel_id=channel_id,
        )

    raise ValueError(
        "Unknown job type. Supported: `message \"…\"`, `weekly status …`, `actions …`."
    )


def _job_summary(job: dict) -> str:
    params = json.loads(job["job_params"])
    jt = job["job_type"]
    if jt == "slack_message":
        detail = params.get("text", "")[:60]
        if len(params.get("text", "")) > 60:
            detail += "…"
        kind = f'message "{detail}"'
    elif jt == "weekly_status":
        extra = (params.get("command_text") or "").strip() or "(default window)"
        kind = f"weekly status ({extra})"
    elif jt == "action_items":
        extra = (params.get("command_text") or "").strip() or "(default lookback)"
        kind = f"actions ({extra})"
    else:
        kind = jt
    days = json.loads(job["days_of_week"])
    when = f"{_format_days(days)} at {_format_time(job['hour'], job['minute'])} {job['timezone']}"
    status = "on" if job["enabled"] else "paused"
    err = f" — last error: {job['last_error'][:80]}" if job.get("last_error") else ""
    return (
        f"• `{job['short_id']}` *{kind}* → <#{job['channel_id']}> — {when} ({status}){err}"
    )


async def handle_schedule_slash(
    remainder: str,
    *,
    user: str,
    channel: str,
    channel_name: str | None,
) -> JSONResponse:
    sub = (remainder or "").strip()
    lower = sub.lower()

    if not sub or lower == "help":
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": _schedule_help_text(),
            }
        )

    if lower == "list":
        jobs = await list_scheduled_jobs()
        if not jobs:
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "text": "No scheduled jobs yet. Example:\n" + _schedule_examples(),
                }
            )
        lines = ["*Scheduled jobs*\n"] + [_job_summary(j) for j in jobs]
        return JSONResponse({"response_type": "ephemeral", "text": "\n".join(lines)})

    if lower.startswith("add "):
        try:
            spec = parse_schedule_add(
                sub,
                slash_channel_id=channel,
                slash_channel_name=channel_name,
            )
        except ValueError as e:
            return JSONResponse({"response_type": "ephemeral", "text": str(e)})

        tz_name = default_schedule_timezone()
        next_run = compute_next_run_at(
            hour=spec.hour,
            minute=spec.minute,
            days_of_week=spec.days_of_week,
            tz_name=tz_name,
        )
        job = await create_scheduled_job(
            created_by_slack_user_id=user,
            run_as_slack_user_id=user,
            channel_id=spec.channel_id,
            job_type=spec.job_type,
            job_params=spec.job_params,
            hour=spec.hour,
            minute=spec.minute,
            days_of_week=spec.days_of_week,
            tz_name=tz_name,
            next_run_at=next_run,
        )
        nxt = job["next_run_at"]
        nxt_s = nxt.astimezone(ZoneInfo(tz_name)).strftime("%a %Y-%m-%d %H:%M %Z") if nxt else "?"
        return JSONResponse(
            {
                "response_type": "ephemeral",
                "text": (
                    f"Scheduled `{job['short_id']}` — {_job_summary(job)}\n"
                    f"Next run: *{nxt_s}* (runs as you; connect Google/GitHub if the job needs them)."
                ),
            }
        )

    for verb, enabled in (("pause", False), ("enable", True), ("remove", None), ("run", "run")):
        if lower.startswith(verb + " "):
            job_id = sub[len(verb) :].strip()
            job = await find_scheduled_job_by_prefix(job_id)
            if not job:
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": f"No job matching id `{job_id}`. Use `schedule list`.",
                    }
                )
            if enabled is None:
                await delete_scheduled_job(job["id"])
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": f"Removed schedule `{job['short_id']}`.",
                    }
                )
            if enabled == "run":
                asyncio.create_task(_run_job_once(job["id"], force=True))
                return JSONResponse(
                    {
                        "response_type": "ephemeral",
                        "text": f"Running `{job['short_id']}` now…",
                    }
                )
            await set_scheduled_job_enabled(job["id"], enabled)
            state = "enabled" if enabled else "paused"
            return JSONResponse(
                {
                    "response_type": "ephemeral",
                    "text": f"Schedule `{job['short_id']}` is *{state}*.",
                }
            )

    return JSONResponse(
        {
            "response_type": "ephemeral",
            "text": "Unknown `schedule` subcommand. Try `schedule help`.",
        }
    )


def _schedule_examples() -> str:
    ch = default_schedule_channel_id()
    return (
        f'`/susan schedule add message "☀️ Good morning" every weekday at 9:00 in {ch}`\n'
        f'`/susan schedule add weekly status last calendar week every monday at 9:00 in #team-tech`\n'
        "`/susan schedule list` · `schedule pause abc12345` · `schedule run abc12345`"
    )


def _schedule_help_text() -> str:
    return (
        "*Susan schedules* — recurring jobs Susan runs for you (auto-post, no approval step).\n\n"
        "*Commands*\n"
        "• `schedule list` — show all jobs\n"
        "• `schedule add message \"…\" every weekday at 9:00 in #team-tech`\n"
        "• `schedule add weekly status last calendar week every monday at 9:00 in #team-tech`\n"
        "• `schedule add actions last 14 days every friday at 16:00 in this channel`\n"
        "• `schedule pause <id>` · `schedule enable <id>` · `schedule remove <id>` · `schedule run <id>`\n\n"
        "*Channel:* `in this channel`, `#team-tech`, or a channel id (default `#team-tech` → "
        f"`{default_schedule_channel_id()}`).\n\n"
        "*Examples*\n" + _schedule_examples()
    )


async def execute_scheduled_job(job: dict) -> None:
    params = json.loads(job["job_params"])
    user = job["run_as_slack_user_id"]
    channel = job["channel_id"]
    jt = job["job_type"]

    if jt == "slack_message":
        await post_message(channel, params.get("text", ""))
        return

    if jt == "weekly_status":
        command_text = params.get("command_text", "")
        repos, err = resolve_github_repos_for_weekly_status()
        include_github = await weekly_status_include_github(channel, channel, None)
        if include_github and not repos:
            raise RuntimeError(err or "No GitHub repos configured.")
        await process_weekly_status(
            repos or [],
            command_text,
            channel,
            channel,
            user,
            None,
            None,
            include_github=include_github,
            auto_publish=True,
        )
        return

    if jt == "action_items":
        remainder = (params.get("command_text") or "").strip()
        command_text = f"actions {remainder}".strip()
        await process_action_items(
            command_text,
            channel,
            channel,
            user,
            None,
            None,
            auto_publish=True,
        )
        return

    raise RuntimeError(f"Unknown job type {jt!r}.")


async def _notify_scheduler_user(user_id: str, text: str) -> None:
    dm = await _try_slack_open_im_with_user(user_id)
    if not dm:
        logger.warning("Could not DM scheduler user %s: %s", user_id, text[:120])
        return
    try:
        await post_message(dm, text)
    except Exception:
        logger.exception("Failed to notify scheduler user %s", user_id)


async def _run_job_once(job_id: str, *, force: bool = False) -> None:
    if job_id in _running_jobs:
        return
    _running_jobs.add(job_id)
    try:
        from db import get_scheduled_job

        job = await get_scheduled_job(job_id)
        if not job:
            return
        if not job["enabled"] and not force:
            return
        try:
            await execute_scheduled_job(job)
        except Exception as e:
            logger.exception("Scheduled job %s failed", job_id)
            err = str(e)
            tz_name = job["timezone"]
            days = json.loads(job["days_of_week"])
            next_run = compute_next_run_at(
                hour=job["hour"],
                minute=job["minute"],
                days_of_week=days,
                tz_name=tz_name,
            )
            await update_scheduled_job_after_run(
                job_id,
                last_run_at=datetime.now(timezone.utc),
                next_run_at=next_run,
                last_error=err,
            )
            await _notify_scheduler_user(
                job["created_by_slack_user_id"],
                f"⚠️ Susan schedule `{job['short_id']}` failed: {err}",
            )
            return

        tz_name = job["timezone"]
        days = json.loads(job["days_of_week"])
        next_run = compute_next_run_at(
            hour=job["hour"],
            minute=job["minute"],
            days_of_week=days,
            tz_name=tz_name,
        )
        await update_scheduled_job_after_run(
            job_id,
            last_run_at=datetime.now(timezone.utc),
            next_run_at=next_run,
            last_error=None,
        )
        logger.info("Scheduled job %s completed; next run %s", job_id, next_run.isoformat())
    finally:
        _running_jobs.discard(job_id)


async def _scheduler_loop() -> None:
    while True:
        try:
            now = datetime.now(timezone.utc)
            due = await list_due_scheduled_jobs(now)
            for job in due:
                asyncio.create_task(_run_job_once(job["id"]))
        except Exception:
            logger.exception("Scheduler tick failed")
        await asyncio.sleep(60)


async def start_scheduler() -> asyncio.Task:
    global _scheduler_task
    if _scheduler_task and not _scheduler_task.done():
        return _scheduler_task
    _scheduler_task = asyncio.create_task(_scheduler_loop())
    logger.info("Susan scheduler started (60s tick)")
    return _scheduler_task


async def stop_scheduler(task: asyncio.Task | None = None) -> None:
    global _scheduler_task
    t = task or _scheduler_task
    if t and not t.done():
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    _scheduler_task = None
