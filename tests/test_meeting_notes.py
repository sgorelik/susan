"""Unit tests for the meeting-notes flow: parsing, calendar filtering, Granola matching,
Drive URL extraction / dedup, notes truncation, and message composition."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config import ACTIONS
from app.slack_api import detect_action
from app.meeting_notes import (
    aggregate_drive_docs,
    build_documents_section,
    build_meeting_notes_blocks,
    extract_drive_docs_from_attachments,
    extract_drive_docs_from_granola,
    extract_drive_file_id,
    extract_drive_urls_from_text,
    granola_note_event_id,
    is_qualifying_event,
    match_granola_by_event_id,
    match_granola_by_title_time,
    no_granola_notes_message,
    parse_meeting_notes_command,
    select_granola_record,
    select_recent_qualifying_event,
    truncate_notes_body,
)

NOW = datetime(2026, 6, 16, 12, 0, 0, tzinfo=timezone.utc)


def _event(
    *,
    eid="evt1",
    summary="Sprint Planning",
    start="2026-06-10T14:00:00+00:00",
    end="2026-06-10T15:00:00+00:00",
    attendees=None,
    description="",
    attachments=None,
):
    if attendees is None:
        attendees = [
            {"email": "me@corp.com", "self": True, "responseStatus": "accepted"},
            {"email": "other@corp.com", "responseStatus": "accepted"},
        ]
    return {
        "id": eid,
        "summary": summary,
        "start": {"dateTime": start},
        "end": {"dateTime": end},
        "attendees": attendees,
        "description": description,
        "attachments": attachments or [],
    }


# --- Intent parsing -----------------------------------------------------------

def test_parse_meeting_notes_command_triggers() -> None:
    assert parse_meeting_notes_command("meeting notes") == "meeting notes"
    assert parse_meeting_notes_command("share notes from my last call") is not None
    assert parse_meeting_notes_command("post notes please") is not None
    assert parse_meeting_notes_command("notes from my standup") is not None
    assert parse_meeting_notes_command("Meeting Notes") is not None  # case-insensitive


def test_parse_meeting_notes_command_non_triggers() -> None:
    assert parse_meeting_notes_command("create issue") is None
    assert parse_meeting_notes_command("weekly status") is None
    assert parse_meeting_notes_command("") is None
    # word-boundary: "compost notes" must not match "post notes"
    assert parse_meeting_notes_command("compost notes for the garden") is None


def test_meeting_notes_cmd_registered_without_keywords() -> None:
    assert ACTIONS["meeting_notes_cmd"][1] == []
    # detect_action must not steal the phrase (routing handles it before detect_action).
    assert detect_action("meeting notes") == "doc"  # 'notes' keyword still maps to doc here


# --- Calendar filtering -------------------------------------------------------

def test_is_qualifying_event_happy_path() -> None:
    assert is_qualifying_event(_event(), "me@corp.com", NOW) is True


def test_is_qualifying_event_self_attendee_without_email() -> None:
    # No email passed, but the self attendee is flagged.
    assert is_qualifying_event(_event(), None, NOW) is True


def test_is_qualifying_event_requires_two_attendees() -> None:
    solo = _event(attendees=[{"email": "me@corp.com", "self": True, "responseStatus": "accepted"}])
    assert is_qualifying_event(solo, "me@corp.com", NOW) is False


def test_is_qualifying_event_requires_past_end() -> None:
    future = _event(start="2999-01-01T10:00:00+00:00", end="2999-01-01T11:00:00+00:00")
    assert is_qualifying_event(future, "me@corp.com", NOW) is False


def test_is_qualifying_event_rsvp_must_be_accepted_or_tentative() -> None:
    declined = _event(
        attendees=[
            {"email": "me@corp.com", "self": True, "responseStatus": "declined"},
            {"email": "other@corp.com", "responseStatus": "accepted"},
        ]
    )
    assert is_qualifying_event(declined, "me@corp.com", NOW) is False
    tentative = _event(
        attendees=[
            {"email": "me@corp.com", "self": True, "responseStatus": "tentative"},
            {"email": "other@corp.com", "responseStatus": "accepted"},
        ]
    )
    assert is_qualifying_event(tentative, "me@corp.com", NOW) is True


def test_is_qualifying_event_needsAction_excluded() -> None:
    pending = _event(
        attendees=[
            {"email": "me@corp.com", "self": True, "responseStatus": "needsAction"},
            {"email": "other@corp.com", "responseStatus": "accepted"},
        ]
    )
    assert is_qualifying_event(pending, "me@corp.com", NOW) is False


def test_select_recent_qualifying_event_picks_latest() -> None:
    older = _event(eid="old", summary="Old", start="2026-06-01T10:00:00+00:00", end="2026-06-01T11:00:00+00:00")
    newer = _event(eid="new", summary="New", start="2026-06-12T10:00:00+00:00", end="2026-06-12T11:00:00+00:00")
    future = _event(eid="fut", summary="Future", start="2999-01-01T10:00:00+00:00", end="2999-01-01T11:00:00+00:00")
    picked = select_recent_qualifying_event([older, future, newer], "me@corp.com", NOW)
    assert picked is not None
    assert picked["id"] == "new"
    # Stored fields only.
    assert set(picked) == {"id", "summary", "start", "end", "attendees", "description", "attachments"}


def test_select_recent_qualifying_event_none_when_no_match() -> None:
    solo = _event(attendees=[{"email": "me@corp.com", "self": True, "responseStatus": "accepted"}])
    assert select_recent_qualifying_event([solo], "me@corp.com", NOW) is None


# --- Granola matching ---------------------------------------------------------

def test_granola_note_event_id_variants() -> None:
    assert granola_note_event_id({"calendar_event_id": "evt1"}) == "evt1"
    assert granola_note_event_id({"google_calendar_event_id": "evt2"}) == "evt2"
    assert granola_note_event_id({"event_id": "evt3"}) == "evt3"
    assert granola_note_event_id({"calendar": {"event_id": "evt4"}}) == "evt4"
    assert granola_note_event_id({"title": "x"}) is None


def test_match_granola_by_event_id() -> None:
    notes = [
        {"id": "not_1", "title": "Other", "calendar_event_id": "zzz"},
        {"id": "not_2", "title": "Sprint Planning", "calendar_event_id": "evt1"},
    ]
    matched = match_granola_by_event_id(notes, "evt1")
    assert matched is not None and matched["id"] == "not_2"
    assert match_granola_by_event_id(notes, "missing") is None
    assert match_granola_by_event_id(notes, None) is None


def test_match_granola_by_title_time_within_window() -> None:
    start = datetime(2026, 6, 10, 14, 0, 0, tzinfo=timezone.utc)
    notes = [
        {"id": "not_1", "title": "Sprint Planning", "start_time": "2026-06-10T14:10:00+00:00"},
    ]
    matched = match_granola_by_title_time(notes, "Sprint Planning", start, None)
    assert matched is not None and matched["id"] == "not_1"


def test_match_granola_by_title_time_outside_window() -> None:
    start = datetime(2026, 6, 10, 14, 0, 0, tzinfo=timezone.utc)
    notes = [
        {"id": "not_1", "title": "Sprint Planning", "start_time": "2026-06-10T15:30:00+00:00"},
    ]
    assert match_granola_by_title_time(notes, "Sprint Planning", start, None) is None


def test_match_granola_by_title_time_title_mismatch() -> None:
    start = datetime(2026, 6, 10, 14, 0, 0, tzinfo=timezone.utc)
    notes = [{"id": "not_1", "title": "Different Meeting", "start_time": "2026-06-10T14:05:00+00:00"}]
    assert match_granola_by_title_time(notes, "Sprint Planning", start, None) is None


def test_select_granola_record_prefers_event_id() -> None:
    event = _event()
    notes = [
        # Same title+time but WRONG event id; and the right one by id with a different title.
        {"id": "not_title", "title": "Sprint Planning", "start_time": "2026-06-10T14:05:00+00:00"},
        {"id": "not_id", "title": "Renamed", "calendar_event_id": "evt1", "start_time": "2026-06-10T14:00:00+00:00"},
    ]
    note, kind = select_granola_record(notes, event)
    assert kind == "event_id"
    assert note["id"] == "not_id"


def test_select_granola_record_falls_back_to_title_time() -> None:
    event = _event()
    notes = [{"id": "not_title", "title": "Sprint Planning", "start_time": "2026-06-10T14:05:00+00:00"}]
    note, kind = select_granola_record(notes, event)
    assert kind == "title_time"
    assert note["id"] == "not_title"


def test_select_granola_record_no_match() -> None:
    event = _event()
    note, kind = select_granola_record([{"id": "x", "title": "Nope"}], event)
    assert note is None and kind is None


# --- Drive URL extraction / dedup ---------------------------------------------

def test_extract_drive_urls_from_text() -> None:
    text = (
        "Agenda: https://docs.google.com/document/d/DOC1/edit and "
        "sheet https://drive.google.com/file/d/FILE2/view. Unrelated https://example.com/x"
    )
    urls = extract_drive_urls_from_text(text)
    assert "https://docs.google.com/document/d/DOC1/edit" in urls
    assert "https://drive.google.com/file/d/FILE2/view" in urls
    assert all("example.com" not in u for u in urls)


def test_extract_drive_file_id_variants() -> None:
    assert extract_drive_file_id("https://docs.google.com/document/d/DOC1/edit") == "DOC1"
    assert extract_drive_file_id("https://docs.google.com/spreadsheets/d/SHEET2/edit#gid=0") == "SHEET2"
    assert extract_drive_file_id("https://drive.google.com/file/d/FILE3/view") == "FILE3"
    assert extract_drive_file_id("https://drive.google.com/open?id=OPEN4") == "OPEN4"
    assert extract_drive_file_id("https://example.com/nope") is None


def test_extract_drive_docs_from_attachments() -> None:
    attachments = [
        {"fileId": "ATT1", "fileUrl": "https://docs.google.com/document/d/ATT1/edit", "title": "Spec"},
        {"fileUrl": "https://drive.google.com/file/d/ATT2/view"},  # no fileId → parsed from url
        {"title": "no file"},  # ignored
    ]
    docs = extract_drive_docs_from_attachments(attachments)
    ids = {d["file_id"] for d in docs}
    assert ids == {"ATT1", "ATT2"}


def test_extract_drive_docs_from_granola_structured_and_text() -> None:
    note = {
        "documents": [{"url": "https://docs.google.com/document/d/GDOC1/edit", "title": "Granola Doc"}],
        "summary_markdown": "Notes ref https://drive.google.com/file/d/GFILE2/view here.",
    }
    docs = extract_drive_docs_from_granola(note)
    ids = {d["file_id"] for d in docs}
    assert {"GDOC1", "GFILE2"} <= ids


def test_aggregate_drive_docs_dedupes_by_file_id() -> None:
    # Same doc appears in calendar description AND granola, with different URL forms.
    description = "Doc: https://docs.google.com/document/d/SHARED/edit"
    attachments = [
        {"fileId": "ATTACHED", "fileUrl": "https://docs.google.com/document/d/ATTACHED/edit"},
    ]
    granola = {
        "documents": [
            {"url": "https://docs.google.com/document/d/SHARED/edit?usp=sharing", "title": "Shared"},
        ]
    }
    docs = aggregate_drive_docs(description, attachments, granola)
    ids = [d["file_id"] for d in docs]
    assert ids.count("SHARED") == 1  # deduped by file id, not URL string
    assert set(ids) == {"SHARED", "ATTACHED"}


def test_aggregate_drive_docs_empty() -> None:
    assert aggregate_drive_docs("no links here", [], {"title": "x"}) == []


# --- Truncation ---------------------------------------------------------------

def test_truncate_notes_body_under_limit_unchanged() -> None:
    body = "short notes"
    assert truncate_notes_body(body, "https://granola.ai/n/1") == body


def test_truncate_notes_body_over_limit_appends_link() -> None:
    body = "x" * 5000
    out = truncate_notes_body(body, "https://granola.ai/n/1", limit=2800)
    assert "View full notes in Granola" in out
    assert "https://granola.ai/n/1" in out
    # The body portion (before the appended suffix) is capped at the limit.
    body_part = out.split("…", 1)[0]
    assert len(body_part) <= 2800


def test_truncate_notes_body_over_limit_without_url() -> None:
    out = truncate_notes_body("y" * 5000, None, limit=2800)
    assert "View full notes in Granola" in out
    assert "<" not in out  # no hyperlink when there's no URL


# --- Message composition ------------------------------------------------------

def test_build_documents_section_omitted_when_empty() -> None:
    assert build_documents_section([]) is None


def test_build_documents_section_hyperlinks_titles() -> None:
    section = build_documents_section(
        [{"file_id": "D1", "url": "https://docs.google.com/document/d/D1/edit", "title": "Plan"}]
    )
    assert section is not None
    txt = section["text"]["text"]
    assert "*Documents*" in txt
    assert "<https://docs.google.com/document/d/D1/edit|Plan>" in txt


def test_build_meeting_notes_blocks_includes_sections() -> None:
    meeting = select_recent_qualifying_event([_event(description="d")], "me@corp.com", NOW)
    blocks, fallback = build_meeting_notes_blocks(
        meeting,
        "Some notes body",
        "https://granola.ai/n/1",
        [{"file_id": "D1", "url": "https://docs.google.com/document/d/D1/edit", "title": "Plan"}],
    )
    rendered = " ".join(b["text"]["text"] for b in blocks)
    assert "Sprint Planning" in rendered
    assert "Some notes body" in rendered
    assert "Documents" in rendered
    assert fallback.startswith("Sprint Planning")


def test_build_meeting_notes_blocks_omits_documents_when_none() -> None:
    meeting = select_recent_qualifying_event([_event()], "me@corp.com", NOW)
    blocks, _ = build_meeting_notes_blocks(meeting, "notes", "", [])
    rendered = " ".join(b["text"]["text"] for b in blocks)
    assert "Documents" not in rendered


def test_no_granola_notes_message_names_meeting() -> None:
    meeting = select_recent_qualifying_event([_event()], "me@corp.com", NOW)
    msg = no_granola_notes_message(meeting)
    assert "Sprint Planning" in msg
    assert "couldn't find Granola notes" in msg
