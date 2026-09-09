"""Daily standup digest built from Granola meeting notes.

Skills (slash phrasing):
  /susan daily status [today|yesterday|<range>] [--no-approval]
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from inspect import cleandoc
from typing import Any

import httpx

from app.claude_client import call_claude
from app.config import SUSAN_VOICE, logger
from app.granola_summarize import collect_granola_notes_matching_terms
from app.slack_api import notify_user_ephemeral, post_message
from app.weekly_context import parse_weekly_status_time_range, strip_weekly_status_auto_post_flags
from db import get_granola_token, user_has_granola_tokens

# Longer phrases first so "daily standup" is not consumed by "daily".
_DAILY_PREFIXES = (
    "daily standup digest",
    "daily standup",
    "daily status",
    "daily digest",
    "standup digest",
    "standup status",
)


def parse_daily_standup_command(text: str) -> str | None:
    """If text is a daily-standup-digest command, return the remainder; else None."""
    raw = (text or "").strip()
    if not raw:
        return None
    lower = raw.lower()
    for prefix in _DAILY_PREFIXES:
        if lower == prefix:
            return ""
        if lower.startswith(prefix + " "):
            return raw[len(prefix) :].strip()
    return None


def standup_meeting_terms() -> list[str]:
    """Title/summary terms that identify the standup meeting in Granola."""
    raw = (os.environ.get("SUSAN_STANDUP_MEETING_TERMS") or "standup,stand-up,stand up").strip()
    terms = [t.strip() for t in raw.split(",") if t.strip()]
    return terms or ["standup"]


def _max_standup_notes() -> int:
    n = int((os.environ.get("SUSAN_STANDUP_MAX_NOTES") or "3").strip() or "3")
    return max(1, min(10, n))


def _max_transcript_chars() -> int:
    """Transcript budget per run. F1_MODEL_MAX_PROMPT_CHARS is the real ceiling."""
    n = int((os.environ.get("SUSAN_STANDUP_MAX_TRANSCRIPT_CHARS") or "120000").strip() or "120000")
    return max(5_000, min(300_000, n))


def _standup_max_tokens() -> int:
    n = int((os.environ.get("SUSAN_STANDUP_MAX_TOKENS") or "8192").strip() or "8192")
    return max(1024, min(32_000, n))


def _note_attendee_names(note: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for a in note.get("attendees") or []:
        if isinstance(a, dict):
            name = (a.get("name") or a.get("email") or "").strip()
            if name:
                out.append(name)
    return out


def _transcript_speaker_names(note: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for seg in note.get("transcript") or []:
        if not isinstance(seg, dict):
            continue
        sp = seg.get("speaker")
        if isinstance(sp, dict) and (sp.get("name") or "").strip():
            names.add(sp["name"].strip())
    return names


def _recording_user_name(note: dict[str, Any]) -> str:
    """Granola labels the recorder's own audio as `attribution: me` with no name.

    The recorder is the attendee who never appears as a named speaker.
    """
    named = _transcript_speaker_names(note)
    unmatched = [
        a
        for a in _note_attendee_names(note)
        if not any(a.split()[0].lower() in n.lower() for n in named if n)
    ]
    return unmatched[0] if len(unmatched) == 1 else "Meeting host"


def format_standup_transcript(note: dict[str, Any], max_chars: int) -> str:
    """Speaker-labelled transcript, consecutive turns merged, oldest first."""
    segments = note.get("transcript") or []
    if not isinstance(segments, list) or not segments:
        return ""
    me = _recording_user_name(note)
    turns: list[tuple[str, list[str]]] = []
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        text = (seg.get("text") or "").strip()
        if not text:
            continue
        sp = seg.get("speaker") if isinstance(seg.get("speaker"), dict) else {}
        if (sp or {}).get("attribution") == "me":
            speaker = me
        else:
            speaker = ((sp or {}).get("name") or "Unknown speaker").strip()
        if turns and turns[-1][0] == speaker:
            turns[-1][1].append(text)
        else:
            turns.append((speaker, [text]))

    lines: list[str] = []
    total = 0
    dropped = 0
    for speaker, parts in turns:
        line = f"{speaker}: {' '.join(parts)}"
        if total + len(line) > max_chars:
            dropped += 1
            continue
        lines.append(line)
        total += len(line)
    if dropped:
        lines.append(f"_…{dropped} further turn(s) omitted (transcript budget)._")
    return "\n".join(lines)


def standup_notes_for_prompt(notes: list[dict[str, Any]], max_chars: int) -> str:
    """Granola's own summary plus the full speaker-labelled transcript per meeting."""
    budget = max_chars // max(1, len(notes))
    blocks: list[str] = []
    for i, n in enumerate(notes, 1):
        title = n.get("title") or "(untitled)"
        created = n.get("created_at") or ""
        attendees = ", ".join(_note_attendee_names(n)) or "(none listed)"
        summary = n.get("summary_markdown") or n.get("summary_text") or ""
        block = (
            f"### Meeting {i}: {title}\n"
            f"- created: {created}\n"
            f"- attendees: {attendees}\n\n"
            f"#### Granola's own summary\n{summary}\n"
        )
        transcript = format_standup_transcript(n, max(1000, budget - len(block)))
        if transcript:
            block += (
                "\n#### Full transcript (authoritative — the summary above may omit things)\n"
                f"{transcript}\n"
            )
        blocks.append(block)
    return "\n---\n".join(blocks)


def parse_standup_digest_window(remainder: str) -> tuple[str, str, str]:
    """Return (since, until, label). Defaults to today, since this runs after standup."""
    r = (remainder or "").strip().lower()
    today = datetime.now(timezone.utc).date()
    if not r or r in ("today", "this morning"):
        return today.isoformat(), today.isoformat(), "today"
    if r == "yesterday":
        d = today - timedelta(days=1)
        return d.isoformat(), d.isoformat(), "yesterday"
    return parse_weekly_status_time_range(r)


def _standup_system_prompt() -> str:
    return cleandoc(
        f"""
        You are Susan. {SUSAN_VOICE}
        Turn standup meeting notes into a digest the whole team reads in the channel.

        Slack mrkdwn only: *single asterisks* for bold, never **double**. No # headings.
        Refer to people by the names used in the notes.

        *Completeness comes first, brevity second.* Write tersely, but never drop a
        substantive item to save space. It is a failure to omit an update, a blocker,
        or a decision because the digest was getting long. Every person who spoke gets
        an entry. Cut words, never content.

        Sections, in this order. *Omit any section with nothing real to report* — never
        emit a heading followed by "none" or "n/a":

        *Updates*
        • `*<Name>* — what they reported`. One bullet per person; add a second or third
          bullet under that person when they covered genuinely separate workstreams.
          Cover *every* person who gave an update. Lead with the outcome, not the process.

        *Blockers*
        • `*<Name>* — what is blocked, and who or what is needed to unblock it`.
          Anything waiting on another person, an access request, a review, a decision,
          or an external party. Include every one mentioned, even in passing.

        *Decisions*
        • What was decided and by whom. Include every decision reached, including small
          ones and ones reversing an earlier plan. Not opinions still being weighed.

        *Parking lot*
        • Topics raised and deliberately deferred, or that ran out of time. Note who
          raised each so it can be picked up.

        *Discussion*
        • Substantive discussion that reached no decision. Skip small talk and status
          chatter already covered under Updates.

        *Next steps*
        • `*<Name>* — action`. Concrete commitments with an owner. Skip vague intentions.

        Rules:
        - The transcript is authoritative. Granola's own summary is a starting point and
          routinely omits things — mine the transcript for updates, blockers, and
          decisions the summary missed.
        - Ignore greetings, scheduling chatter, and audio problems.
        - Use only what the notes contain. Never invent an update for someone who did not speak.
        - If the notes are too thin for a real digest, say so in one line instead of padding.
        - No preamble, no sign-off, no "here is".
        """
    )


async def build_standup_digest(
    notes: list[dict[str, Any]],
    range_label: str,
) -> str:
    """Summarize standup notes into the channel-facing digest body."""
    bundle = standup_notes_for_prompt(notes, max_chars=_max_transcript_chars())
    attendees = sorted({a for n in notes for a in _note_attendee_names(n)})
    roster = ", ".join(attendees) if attendees else "(not listed)"
    user_prompt = (
        f"Standup window: {range_label}.\n"
        f"Attendees across these meetings: {roster}.\n"
        "Every attendee who spoke must appear under Updates.\n\n"
        f"--- Granola standup notes ({len(notes)} meeting(s)) ---\n{bundle}"
    )
    summary = await call_claude(
        _standup_system_prompt(),
        user_prompt,
        max_tokens=_standup_max_tokens(),
        action="standup_digest",
    )
    return summary


def _no_notes_message(range_label: str, scanned: int, terms: list[str]) -> str:
    term_list = ", ".join(f"`{t}`" for t in terms)
    return (
        f"No standup meeting found in Granola for *{range_label}* "
        f"(scanned {scanned} note(s), matching {term_list}).\n"
        "_If your standup is titled differently, set `SUSAN_STANDUP_MEETING_TERMS` "
        "on the server to a comma-separated list of title words._"
    )


async def process_standup_digest(
    command_text: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
    *,
    auto_publish: bool = False,
) -> None:
    """Build the standup digest from Granola and post it, or preview it privately."""
    remainder = parse_daily_standup_command(command_text)
    remainder, auto_flag = strip_weekly_status_auto_post_flags(
        remainder if remainder is not None else command_text
    )
    auto_publish = auto_publish or auto_flag
    since_d, until_d, range_label = parse_standup_digest_window(remainder)

    if not await user_has_granola_tokens(user):
        await notify_user_ephemeral(
            channel,
            user,
            "Granola isn't connected. Run `/susan connect granola` (or set a shared "
            "`GRANOLA_API_KEY` on the server) so Susan can read standup notes.",
            None,
            response_url,
        )
        return

    terms = standup_meeting_terms()
    try:
        bearer = await get_granola_token(user)
        notes, scanned = await collect_granola_notes_matching_terms(
            bearer,
            since_d,
            until_d,
            terms,
            max_detail_fetch=_max_standup_notes(),
            include_transcript=True,
        )
    except httpx.HTTPStatusError as e:
        logger.warning("Standup digest Granola fetch failed: %s", e)
        await notify_user_ephemeral(
            channel,
            user,
            f"Granola API error ({e.response.status_code}) while loading standup notes.",
            None,
            response_url,
        )
        return
    except Exception as e:
        logger.exception("Standup digest Granola fetch failed")
        await notify_user_ephemeral(
            channel, user, f"Could not load Granola notes: {e}", None, response_url
        )
        return

    if not notes:
        await notify_user_ephemeral(
            channel, user, _no_notes_message(range_label, scanned, terms), None, response_url
        )
        return

    try:
        summary = await build_standup_digest(notes, range_label)
    except Exception as e:
        logger.exception("Standup digest summarization failed")
        await notify_user_ephemeral(
            channel,
            user,
            f"Loaded {len(notes)} standup note(s), but summarization failed: {e}",
            None,
            response_url,
        )
        return

    body = (str(summary) or "").strip()
    if not body:
        await notify_user_ephemeral(
            channel,
            user,
            f"Standup notes for *{range_label}* had nothing substantive to report.",
            None,
            response_url,
        )
        return

    model_route = getattr(summary, "model_route", None)
    model_name = getattr(summary, "model_name", None)
    header = f"*Standup — {range_label}*\n\n"

    if auto_publish:
        try:
            await post_message(
                channel,
                header + body,
                thread_ts=thread_ts,
                model_route=model_route,
                model_name=model_name,
            )
            await notify_user_ephemeral(
                channel,
                user,
                "✓ Posted the *standup digest* to the channel — everyone here can see it.",
                None,
                response_url,
            )
        except Exception as e:
            logger.exception("Standup digest post failed")
            await notify_user_ephemeral(
                channel, user, f"Could not post standup digest: {e}", None, response_url
            )
        return

    preview = (
        header
        + body
        + "\n\n_Only you can see this. Post it with "
        + "`/susan daily status --no-approval`, or schedule it with "
        + "`/susan schedule add daily status every weekday at 10:00 in this channel`._"
    )
    await notify_user_ephemeral(
        channel,
        user,
        preview,
        None,
        response_url,
        model_route=model_route,
        model_name=model_name,
    )
