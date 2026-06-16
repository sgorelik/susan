"""Meeting notes flow: find the user's most recent meeting, fetch Granola notes, post a summary.

Triggered conversationally from the ``/susan`` message routing layer (phrases like
``meeting notes`` / ``share notes`` / ``post notes`` / ``notes from``). The flow:

1. Resolve the Slack user to their Google account and list recent Calendar events.
2. Pick the most recent *qualifying* meeting (past, >=2 attendees, the user RSVP'd
   accepted/tentative).
3. Look up the matching Granola notes record (by calendar event id, else title + time).
4. Aggregate Google Drive docs from the calendar event (description + attachments) and
   from Granola, deduplicated by Drive **file id**, and resolve each title via Drive.
5. Post a Block Kit summary to the channel and delete the ephemeral acknowledgement.

External-API boundaries (Calendar ``events.list``, Granola ``/v1/notes``, Drive
``files.get``, Slack posting) are isolated in small functions so tests can mock them.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from db import get_granola_token, get_valid_access_token, user_has_granola_tokens

from app.config import logger
from app.granola_summarize import _granola_list_page, _granola_max_list_pages
from app.slack_api import (
    notify_user_ephemeral,
    post_message,
    post_slack_delayed_response,
    slack_users_lookup_email,
)

# --- Tunables -----------------------------------------------------------------

NOTES_TRUNCATE_LIMIT = 2800
GRANOLA_TITLE_TIME_WINDOW_MIN = 15

NO_MEETING_MESSAGE = "I couldn't find a recent meeting on your calendar."
ACK_MESSAGE = "Looking up your last meeting…"


def _meeting_lookback_days() -> int:
    """How far back the Calendar scan looks (default 30). Bounds the recent-events query."""
    try:
        n = int((os.environ.get("MEETING_NOTES_LOOKBACK_DAYS") or "30").strip() or "30")
    except ValueError:
        n = 30
    return max(1, min(180, n))


# --- Intent parsing -----------------------------------------------------------

_MEETING_NOTES_RE = re.compile(
    r"\b(meeting notes|share notes|post notes|notes from)\b", re.IGNORECASE
)


def parse_meeting_notes_command(text: str) -> str | None:
    """Return the command text if it contains a meeting-notes trigger phrase, else None.

    Matching is conversational: any of ``meeting notes`` / ``share notes`` /
    ``post notes`` / ``notes from`` anywhere in the text triggers the flow. The returned
    remainder is currently informational only — the flow always auto-selects the most
    recent qualifying meeting.
    """
    raw = (text or "").strip()
    if not raw:
        return None
    if _MEETING_NOTES_RE.search(raw):
        return raw
    return None


# --- Datetime helpers ---------------------------------------------------------

def _rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_dt(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def _parse_event_dt(node: Any) -> datetime | None:
    """Parse a Calendar event ``start``/``end`` node ({"dateTime": …} or {"date": …})."""
    if not isinstance(node, dict):
        return None
    dt = _parse_iso_dt(node.get("dateTime"))
    if dt:
        return dt
    date_s = node.get("date")
    if isinstance(date_s, str) and date_s.strip():
        try:
            return datetime.strptime(date_s.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _event_start_dt(event: dict) -> datetime | None:
    return _parse_event_dt(event.get("start"))


def _event_end_dt(event: dict) -> datetime | None:
    return _parse_event_dt(event.get("end"))


# --- Calendar filtering -------------------------------------------------------

def _attendee_list(event: dict) -> list[dict]:
    return [a for a in (event.get("attendees") or []) if isinstance(a, dict)]


def _find_self_attendee(attendees: list[dict], user_email: str | None) -> dict | None:
    """Locate the triggering user's attendee row by ``self: true`` or matching email."""
    email = (user_email or "").strip().lower()
    for a in attendees:
        if a.get("self") is True:
            return a
    if email:
        for a in attendees:
            if (a.get("email") or "").strip().lower() == email:
                return a
    return None


def is_qualifying_event(event: dict, user_email: str | None, now: datetime) -> bool:
    """Qualifying = past, >=2 attendees (user + one other), user RSVP accepted/tentative."""
    attendees = _attendee_list(event)
    if len(attendees) < 2:
        return False
    end_dt = _event_end_dt(event)
    if end_dt is None or end_dt >= now:
        return False
    me = _find_self_attendee(attendees, user_email)
    if me is None:
        return False
    return (me.get("responseStatus") or "").strip().lower() in ("accepted", "tentative")


def store_event_fields(event: dict) -> dict:
    """Keep only the fields the downstream flow needs."""
    return {
        "id": (event.get("id") or "").strip(),
        "summary": (event.get("summary") or "").strip() or "(untitled meeting)",
        "start": event.get("start") or {},
        "end": event.get("end") or {},
        "attendees": _attendee_list(event),
        "description": event.get("description") or "",
        "attachments": [a for a in (event.get("attachments") or []) if isinstance(a, dict)],
    }


def select_recent_qualifying_event(
    events: list[dict], user_email: str | None, now: datetime
) -> dict | None:
    """Return stored fields for the most recent (latest-ending) qualifying event, or None."""
    qualifying = [e for e in events if isinstance(e, dict) and is_qualifying_event(e, user_email, now)]
    if not qualifying:
        return None

    def sort_key(e: dict) -> datetime:
        return _event_end_dt(e) or _event_start_dt(e) or datetime.min.replace(tzinfo=timezone.utc)

    qualifying.sort(key=sort_key, reverse=True)
    return store_event_fields(qualifying[0])


async def fetch_recent_calendar_events(token: str) -> list[dict]:
    """Calendar ``events.list``: recent past events, expanded and ordered by start time.

    The Calendar API only sorts ascending, so we bound the scan with ``timeMin`` and let
    :func:`select_recent_qualifying_event` pick the most recent (latest-ending) match.
    """
    now = datetime.now(timezone.utc)
    params = {
        "timeMax": _rfc3339(now),
        "timeMin": _rfc3339(now - timedelta(days=_meeting_lookback_days())),
        "singleEvents": "true",
        "orderBy": "startTime",
        "maxResults": "10",
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
    if r.status_code >= 400:
        raise RuntimeError(f"Calendar events.list failed ({r.status_code}): {(r.text or '')[:300]}")
    return r.json().get("items") or []


# --- Granola matching ---------------------------------------------------------

def _normalize_title(title: str | None) -> str:
    return re.sub(r"\s+", " ", (title or "").strip().lower())


def granola_note_event_id(note: dict) -> str | None:
    """Best-effort extraction of a linked Google Calendar event id from a Granola note."""
    for key in (
        "calendar_event_id",
        "google_calendar_event_id",
        "gcal_event_id",
        "event_id",
    ):
        v = note.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for container in ("calendar", "google_calendar", "calendar_event", "event"):
        c = note.get(container)
        if isinstance(c, dict):
            for key in ("event_id", "google_event_id", "id"):
                v = c.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return None


def _granola_note_time(note: dict) -> datetime | None:
    for key in ("start_time", "started_at", "scheduled_at", "meeting_start", "start", "created_at"):
        v = note.get(key)
        if isinstance(v, dict):
            dt = _parse_event_dt(v)
            if dt:
                return dt
        elif isinstance(v, str):
            dt = _parse_iso_dt(v)
            if dt:
                return dt
    return None


def match_granola_by_event_id(notes: list[dict], event_id: str | None) -> dict | None:
    eid = (event_id or "").strip()
    if not eid:
        return None
    for n in notes:
        if isinstance(n, dict) and granola_note_event_id(n) == eid:
            return n
    return None


def match_granola_by_title_time(
    notes: list[dict],
    title: str | None,
    start: datetime | None,
    end: datetime | None = None,
    window_minutes: int = GRANOLA_TITLE_TIME_WINDOW_MIN,
) -> dict | None:
    """Fallback match: same (normalized) title and a note time within ±window of the event."""
    norm = _normalize_title(title)
    if not norm or start is None:
        return None
    window = timedelta(minutes=window_minutes)
    for n in notes:
        if not isinstance(n, dict):
            continue
        if _normalize_title(n.get("title")) != norm:
            continue
        n_time = _granola_note_time(n)
        if n_time is None:
            continue
        if abs((n_time - start).total_seconds()) <= window.total_seconds():
            return n
        if end is not None and abs((n_time - end).total_seconds()) <= window.total_seconds():
            return n
    return None


def select_granola_record(notes: list[dict], event: dict) -> tuple[dict | None, str | None]:
    """Pick the Granola note for an event: by calendar event id first, then title + time."""
    by_id = match_granola_by_event_id(notes, event.get("id"))
    if by_id is not None:
        return by_id, "event_id"
    by_tt = match_granola_by_title_time(
        notes, event.get("summary"), _event_start_dt(event), _event_end_dt(event)
    )
    if by_tt is not None:
        return by_tt, "title_time"
    return None, None


async def fetch_granola_candidates_for_event(bearer: str, event: dict) -> list[dict]:
    """List Granola notes created around the meeting time (candidates for matching)."""
    start = _event_start_dt(event)
    end = _event_end_dt(event)
    anchor = start or end
    if anchor is None:
        return []
    created_after = _rfc3339(anchor - timedelta(hours=6))
    created_before = _rfc3339((end or anchor) + timedelta(hours=6))
    out: list[dict] = []
    cursor: str | None = None
    async with httpx.AsyncClient(timeout=60) as client:
        for _ in range(_granola_max_list_pages()):
            data = await _granola_list_page(
                client,
                bearer,
                created_after=created_after,
                created_before=created_before,
                cursor=cursor,
                page_size=30,
            )
            batch = data.get("notes") or []
            if isinstance(batch, list):
                out.extend([n for n in batch if isinstance(n, dict)])
            if not data.get("hasMore"):
                break
            cursor = data.get("cursor")
            if not cursor:
                break
    return out


def extract_granola_payload(note: dict) -> dict:
    """Pull the notes body text and the Granola meeting URL out of a note record."""
    body = (
        note.get("summary_markdown")
        or note.get("summary_text")
        or note.get("notes_markdown")
        or note.get("notes_plain")
        or note.get("content")
        or ""
    )
    url = ""
    for key in ("url", "share_url", "granola_url", "public_url", "web_url"):
        v = note.get(key)
        if isinstance(v, str) and v.strip():
            url = v.strip()
            break
    return {"body": body if isinstance(body, str) else "", "url": url}


# --- Drive doc aggregation ----------------------------------------------------

DRIVE_URL_RE = re.compile(
    r"https?://(?:docs|drive)\.google\.com/[^\s<>()\[\]\"'|]+", re.IGNORECASE
)
_DRIVE_FILE_ID_PATH_RE = re.compile(r"/d/([a-zA-Z0-9_-]+)")
_DRIVE_FILE_ID_QUERY_RE = re.compile(r"[?&]id=([a-zA-Z0-9_-]+)")


def extract_drive_urls_from_text(text: str) -> list[str]:
    """All Google Docs/Drive URLs found in free text (e.g. a calendar description)."""
    seen: set[str] = set()
    out: list[str] = []
    for m in DRIVE_URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;)]}>")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_drive_file_id(url: str) -> str | None:
    """Drive file id from a Docs/Drive URL (``/d/<id>`` or ``?id=<id>``)."""
    if not url:
        return None
    m = _DRIVE_FILE_ID_PATH_RE.search(url)
    if m:
        return m.group(1)
    m = _DRIVE_FILE_ID_QUERY_RE.search(url)
    if m:
        return m.group(1)
    return None


def extract_drive_docs_from_attachments(attachments: list[dict]) -> list[dict]:
    """Drive docs from a Calendar event ``attachments`` array (uses ``fileId``/``fileUrl``)."""
    out: list[dict] = []
    for a in attachments or []:
        if not isinstance(a, dict):
            continue
        fid = (a.get("fileId") or "").strip()
        url = (a.get("fileUrl") or "").strip()
        if not fid and url:
            fid = extract_drive_file_id(url) or ""
        if not fid:
            continue
        if not url:
            url = f"https://drive.google.com/file/d/{fid}/view"
        out.append({"file_id": fid, "url": url, "title": (a.get("title") or "").strip() or None})
    return out


def extract_drive_docs_from_granola(note: dict | None) -> list[dict]:
    """Drive docs referenced by a Granola note (structured fields + URLs in the body text)."""
    if not isinstance(note, dict):
        return []
    out: list[dict] = []
    for container in ("documents", "google_docs", "attachments", "links", "files"):
        items = note.get(container)
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            url = (it.get("url") or it.get("fileUrl") or it.get("link") or "").strip()
            fid = (it.get("file_id") or it.get("fileId") or "").strip()
            if not fid and url:
                fid = extract_drive_file_id(url) or ""
            if not fid:
                continue
            if not url:
                url = f"https://drive.google.com/file/d/{fid}/view"
            out.append(
                {"file_id": fid, "url": url, "title": (it.get("title") or it.get("name") or "").strip() or None}
            )
    payload = extract_granola_payload(note)
    text_blob = " ".join(
        s for s in (payload.get("body"), note.get("notes_markdown"), note.get("summary_markdown")) if isinstance(s, str)
    )
    for url in extract_drive_urls_from_text(text_blob):
        fid = extract_drive_file_id(url)
        if fid:
            out.append({"file_id": fid, "url": url, "title": None})
    return out


def aggregate_drive_docs(
    calendar_description: str,
    attachments: list[dict],
    granola_note: dict | None,
) -> list[dict]:
    """Merge Drive docs from the calendar description, attachments, and Granola.

    Deduplicated by Drive **file id** (not URL string), preserving first-seen order.
    """
    by_id: dict[str, dict] = {}

    def add(file_id: str | None, url: str, title: str | None = None) -> None:
        if not file_id or file_id in by_id:
            return
        by_id[file_id] = {"file_id": file_id, "url": url, "title": title}

    for url in extract_drive_urls_from_text(calendar_description or ""):
        add(extract_drive_file_id(url), url)
    for d in extract_drive_docs_from_attachments(attachments or []):
        add(d["file_id"], d["url"], d.get("title"))
    for d in extract_drive_docs_from_granola(granola_note):
        add(d["file_id"], d["url"], d.get("title"))
    return list(by_id.values())


async def fetch_drive_file_title(token: str, file_id: str) -> tuple[str | None, str | None]:
    """Drive ``files.get`` for a single file → (name, webViewLink). Returns (None, None) on error."""
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"https://www.googleapis.com/drive/v3/files/{file_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"fields": "id,name,webViewLink", "supportsAllDrives": "true"},
        )
    if r.status_code >= 400:
        logger.warning("Drive files.get failed for %s: %s", file_id, r.status_code)
        return None, None
    data = r.json()
    return (data.get("name") or None), (data.get("webViewLink") or None)


async def resolve_drive_doc_titles(token: str, docs: list[dict]) -> list[dict]:
    """Call ``files.get`` for each unique doc to fetch its title; tolerate per-file errors."""
    resolved: list[dict] = []
    for d in docs:
        title: str | None = None
        web_link: str | None = None
        try:
            title, web_link = await fetch_drive_file_title(token, d["file_id"])
        except Exception as e:  # noqa: BLE001 - one bad file shouldn't drop the rest
            logger.warning("Drive title lookup failed for %s: %s", d.get("file_id"), e)
        resolved.append(
            {
                "file_id": d["file_id"],
                "url": web_link or d["url"],
                "title": title or d.get("title") or "Document",
            }
        )
    return resolved


# --- Message composition ------------------------------------------------------

def format_meeting_date(start: Any) -> str:
    dt = _parse_event_dt(start)
    if dt is not None:
        return f"{dt.strftime('%b')} {dt.day}, {dt.year}"
    if isinstance(start, dict) and isinstance(start.get("date"), str):
        return start["date"]
    return "unknown date"


def format_attendees(attendees: list[dict]) -> str:
    names: list[str] = []
    for a in attendees or []:
        if not isinstance(a, dict):
            continue
        names.append((a.get("displayName") or a.get("email") or "guest").strip())
    return ", ".join(n for n in names if n)


def truncate_notes_body(body: str, granola_url: str | None, limit: int = NOTES_TRUNCATE_LIMIT) -> str:
    """Truncate the notes body to ``limit`` chars; append a Granola link if truncated."""
    body = (body or "").strip()
    if len(body) <= limit:
        return body
    truncated = body[:limit].rstrip()
    if granola_url:
        return f"{truncated}…\n\n<{granola_url}|View full notes in Granola>"
    return f"{truncated}…\n\n_View full notes in Granola_"


def build_documents_section(docs: list[dict]) -> dict | None:
    """Bulleted Documents section (titles hyperlinked). None if there are no docs."""
    if not docs:
        return None
    lines = ["*Documents*"]
    for d in docs:
        title = (d.get("title") or "Document").replace("\n", " ")
        lines.append(f"• <{d['url']}|{title}>")
    return {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}


def build_meeting_notes_blocks(
    meeting: dict,
    notes_body: str,
    granola_url: str | None,
    docs: list[dict],
) -> tuple[list[dict], str]:
    """Block Kit message: meeting header, (truncated) notes, optional Documents section."""
    title = meeting.get("summary") or "(untitled meeting)"
    date_s = format_meeting_date(meeting.get("start"))
    attendees_s = format_attendees(meeting.get("attendees") or [])

    header = f"*{title}*\n_{date_s}_"
    if attendees_s:
        header += f"\n*Attendees:* {attendees_s}"

    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": header}}]
    notes_text = truncate_notes_body(notes_body, granola_url)
    if notes_text:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": notes_text}})
    docs_section = build_documents_section(docs)
    if docs_section:
        blocks.append(docs_section)
    return blocks, f"{title} — {date_s}"


def no_granola_notes_message(meeting: dict) -> str:
    title = meeting.get("summary") or "(untitled meeting)"
    date_s = format_meeting_date(meeting.get("start"))
    return f"I found your last meeting ({title}, {date_s}) but couldn't find Granola notes for it."


# --- Orchestration ------------------------------------------------------------

async def _delete_ack(response_url: str | None) -> None:
    """Remove the ephemeral acknowledgement posted as the slash response (best effort)."""
    if not response_url:
        return
    try:
        await post_slack_delayed_response(response_url, {"delete_original": True})
    except Exception as e:  # noqa: BLE001
        logger.warning("Could not delete meeting-notes acknowledgement: %s", e)


async def _post_final(
    channel: str,
    response_url: str | None,
    text: str,
    *,
    blocks: list[dict] | None = None,
    thread_ts: str | None = None,
) -> None:
    """Delete the ack first (never leave a stale 'looking up…'), then post to the channel."""
    await _delete_ack(response_url)
    await post_message(channel, text, thread_ts=thread_ts, blocks=blocks)


async def process_meeting_notes(
    remainder: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    """Full flow: calendar lookup → Granola fetch → Drive aggregation → Slack post."""
    try:
        token = await get_valid_access_token(user)
    except ValueError as e:
        await _delete_ack(response_url)
        await notify_user_ephemeral(channel, user, str(e), None, response_url)
        return

    user_email = None
    try:
        user_email = await slack_users_lookup_email(user)
    except Exception as e:  # noqa: BLE001 - email is only used to find the user's RSVP
        logger.warning("Could not resolve Slack user email for meeting notes: %s", e)

    now = datetime.now(timezone.utc)
    try:
        events = await fetch_recent_calendar_events(token)
    except Exception as e:  # noqa: BLE001
        logger.exception("Meeting notes calendar lookup failed")
        await _delete_ack(response_url)
        await notify_user_ephemeral(
            channel, user, f"Susan couldn't read your calendar: {e}", None, response_url
        )
        return

    meeting = select_recent_qualifying_event(events, user_email, now)
    if meeting is None:
        await _post_final(channel, response_url, NO_MEETING_MESSAGE)
        return

    if not await user_has_granola_tokens(user):
        await _delete_ack(response_url)
        await notify_user_ephemeral(
            channel,
            user,
            "Granola isn't connected, so Susan can't fetch notes. Run `/susan connect granola` and try again.",
            None,
            response_url,
        )
        return

    granola_note: dict | None = None
    try:
        bearer = await get_granola_token(user)
        candidates = await fetch_granola_candidates_for_event(bearer, meeting)
        granola_note, match_kind = select_granola_record(candidates, meeting)
        if granola_note is not None:
            logger.info(
                "Meeting notes: matched Granola record by %s for event %s",
                match_kind,
                meeting.get("id"),
            )
    except Exception as e:  # noqa: BLE001 - treat Granola failures as "no notes found"
        logger.warning("Meeting notes Granola lookup failed: %s", e)
        granola_note = None

    if granola_note is None:
        await _post_final(channel, response_url, no_granola_notes_message(meeting))
        return

    payload = extract_granola_payload(granola_note)
    docs = aggregate_drive_docs(
        meeting.get("description") or "", meeting.get("attachments") or [], granola_note
    )
    try:
        docs = await resolve_drive_doc_titles(token, docs)
    except Exception as e:  # noqa: BLE001 - don't fail the whole post over Drive titles
        logger.warning("Meeting notes Drive title resolution failed: %s", e)
        docs = [{"file_id": d["file_id"], "url": d["url"], "title": d.get("title") or "Document"} for d in docs]

    blocks, fallback = build_meeting_notes_blocks(
        meeting, payload.get("body") or "", payload.get("url") or "", docs
    )
    await _post_final(channel, response_url, fallback, blocks=blocks, thread_ts=thread_ts)
