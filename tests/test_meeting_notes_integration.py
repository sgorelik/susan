"""End-to-end integration tests for the Susan meeting-notes command.

Covers the full flow — calendar lookup → Granola fetch → Drive aggregation → Slack post —
against mocked external APIs (Calendar, Granola, Drive, Slack). Each test seeds its own
data so there is no order-dependency. Tagged ``integration`` so CI can run/skip the suite
separately from unit tests (``-m integration`` / ``-m "not integration"``).
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import time
import urllib.parse
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.meeting_notes import NO_MEETING_MESSAGE, process_meeting_notes

pytestmark = pytest.mark.integration


# --- Seed-data builders (isolated per test) -----------------------------------

def make_event(
    *,
    eid="evt-1",
    summary="Sprint Planning",
    start="2020-03-05T14:00:00+00:00",
    end="2020-03-05T15:00:00+00:00",
    attendees=None,
    description="",
    attachments=None,
):
    if attendees is None:
        attendees = [
            {"email": "me@corp.com", "self": True, "responseStatus": "accepted"},
            {"email": "teammate@corp.com", "responseStatus": "accepted"},
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


def make_granola_note(*, eid="evt-1", body="Discussed the roadmap.", url="https://granola.ai/notes/n1", **extra):
    note = {
        "id": "not_1",
        "title": "Sprint Planning",
        "calendar_event_id": eid,
        "start_time": "2020-03-05T14:00:00+00:00",
        "summary_markdown": body,
        "url": url,
    }
    note.update(extra)
    return note


def render_blocks(blocks) -> str:
    out = []
    for b in blocks or []:
        txt = (b.get("text") or {}).get("text")
        if txt:
            out.append(txt)
    return "\n".join(out)


@contextlib.contextmanager
def patched_flow(
    *,
    events,
    granola_notes=None,
    drive_titles=None,
    granola_connected=True,
    user_email="me@corp.com",
):
    """Patch every external boundary in app.meeting_notes; capture Slack side effects."""
    drive_titles = drive_titles or {}
    cap: dict = {"posts": [], "deletes": [], "ephemerals": [], "order": []}

    async def _post_message(channel, text, thread_ts=None, blocks=None):
        cap["order"].append("post")
        cap["posts"].append({"channel": channel, "text": text, "thread_ts": thread_ts, "blocks": blocks})
        return {"ok": True, "ts": "111.222"}

    async def _delete(url, payload):
        cap["order"].append("delete")
        cap["deletes"].append({"url": url, "payload": payload})

    async def _ephemeral(channel, user, text, blocks=None, response_url=None):
        cap["order"].append("ephemeral")
        cap["ephemerals"].append({"channel": channel, "user": user, "text": text})

    async def _fetch_events(token):
        return list(events)

    async def _fetch_candidates(bearer, event):
        return list(granola_notes or [])

    async def _fetch_title(token, file_id):
        val = drive_titles.get(file_id)
        if val is None:
            return None, None
        if isinstance(val, tuple):
            return val
        return val, f"https://drive.google.com/file/d/{file_id}/view"

    with mock.patch.multiple(
        "app.meeting_notes",
        get_valid_access_token=mock.AsyncMock(return_value="google-token"),
        slack_users_lookup_email=mock.AsyncMock(return_value=user_email),
        user_has_granola_tokens=mock.AsyncMock(return_value=granola_connected),
        get_granola_token=mock.AsyncMock(return_value="granola-token"),
        fetch_recent_calendar_events=_fetch_events,
        fetch_granola_candidates_for_event=_fetch_candidates,
        fetch_drive_file_title=_fetch_title,
        post_message=_post_message,
        post_slack_delayed_response=_delete,
        notify_user_ephemeral=_ephemeral,
    ):
        yield cap


# --- Scenario 1: happy path ---------------------------------------------------

async def test_happy_path_posts_full_summary() -> None:
    event = make_event(
        description="Pre-read: https://docs.google.com/document/d/DOC1/edit",
        attachments=[{"fileId": "DOC2", "fileUrl": "https://docs.google.com/document/d/DOC2/edit"}],
    )
    note = make_granola_note(body="We agreed to ship Friday.")
    with patched_flow(
        events=[event],
        granola_notes=[note],
        drive_titles={"DOC1": "Design Doc", "DOC2": "Spec Sheet"},
    ) as cap:
        await process_meeting_notes("meeting notes", "C123", "U1", None, "https://hooks.slack/x")

    assert len(cap["posts"]) == 1
    post = cap["posts"][0]
    assert post["channel"] == "C123"
    rendered = render_blocks(post["blocks"])
    assert "Sprint Planning" in rendered
    assert "Mar 5, 2020" in rendered
    assert "We agreed to ship Friday." in rendered
    assert "Design Doc" in rendered and "Spec Sheet" in rendered
    # Ack was deleted exactly once.
    assert len(cap["deletes"]) == 1


# --- Scenario 2: deduplication ------------------------------------------------

async def test_dedup_same_doc_in_calendar_and_granola_yields_one_link() -> None:
    event = make_event(description="Doc: https://docs.google.com/document/d/SHARED/edit")
    note = make_granola_note(
        documents=[{"url": "https://docs.google.com/document/d/SHARED/edit?usp=sharing", "title": "Shared"}]
    )
    with patched_flow(events=[event], granola_notes=[note], drive_titles={"SHARED": "Shared Roadmap"}) as cap:
        await process_meeting_notes("share notes", "C1", "U1", None, "https://hook")

    rendered = render_blocks(cap["posts"][0]["blocks"])
    # Exactly one bullet referencing the shared doc (deduped by file id, not URL string).
    assert rendered.count("Shared Roadmap") == 1
    assert rendered.count("• ") == 1
    assert rendered.count("SHARED") == 1


# --- Scenario 3: long-notes truncation ----------------------------------------

async def test_long_notes_truncated_with_granola_link() -> None:
    event = make_event()
    note = make_granola_note(body="A" * 5000, url="https://granola.ai/notes/long")
    with patched_flow(events=[event], granola_notes=[note]) as cap:
        await process_meeting_notes("meeting notes", "C1", "U1", None, "https://hook")

    rendered = render_blocks(cap["posts"][0]["blocks"])
    assert "View full notes in Granola" in rendered
    assert "https://granola.ai/notes/long" in rendered


# --- Scenario 4: no Granola notes ---------------------------------------------

async def test_no_granola_notes_posts_named_fallback() -> None:
    event = make_event(summary="Design Review")
    with patched_flow(events=[event], granola_notes=[]) as cap:
        await process_meeting_notes("meeting notes", "C1", "U1", None, "https://hook")

    assert len(cap["posts"]) == 1
    post = cap["posts"][0]
    assert post["blocks"] is None  # no partial summary, just the message
    assert "Design Review" in post["text"]
    assert "couldn't find Granola notes" in post["text"]
    # Ack is deleted BEFORE the fallback is posted.
    assert cap["order"].index("delete") < cap["order"].index("post")


# --- Scenario 5: no qualifying calendar event ---------------------------------

async def test_no_qualifying_event_posts_no_meeting_message() -> None:
    solo = make_event(attendees=[{"email": "me@corp.com", "self": True, "responseStatus": "accepted"}])
    future = make_event(eid="future", start="2999-01-01T10:00:00+00:00", end="2999-01-01T11:00:00+00:00")
    with patched_flow(events=[solo, future]) as cap:
        await process_meeting_notes("meeting notes", "C1", "U1", None, "https://hook")

    assert len(cap["posts"]) == 1
    assert cap["posts"][0]["text"] == NO_MEETING_MESSAGE
    assert cap["posts"][0]["blocks"] is None
    assert cap["order"].index("delete") < cap["order"].index("post")


# --- Scenario 6: no Drive docs ------------------------------------------------

async def test_no_drive_docs_omits_documents_section() -> None:
    event = make_event(description="No links in here at all.")
    note = make_granola_note(body="Plain notes, no docs.")
    with patched_flow(events=[event], granola_notes=[note]) as cap:
        await process_meeting_notes("meeting notes", "C1", "U1", None, "https://hook")

    rendered = render_blocks(cap["posts"][0]["blocks"])
    assert "Plain notes, no docs." in rendered
    assert "Documents" not in rendered


# --- Granola title+time fallback (no calendar-id link) ------------------------

async def test_title_time_fallback_when_no_event_id_link() -> None:
    event = make_event(eid="evt-x", summary="Weekly Sync", start="2020-03-05T09:00:00+00:00", end="2020-03-05T09:30:00+00:00")
    # Note has no calendar_event_id, but title + time match within ±15 min.
    note = {
        "id": "not_tt",
        "title": "Weekly Sync",
        "start_time": "2020-03-05T09:05:00+00:00",
        "summary_markdown": "Synced on priorities.",
        "url": "https://granola.ai/notes/tt",
    }
    with patched_flow(events=[event], granola_notes=[note]) as cap:
        await process_meeting_notes("meeting notes", "C1", "U1", None, "https://hook")

    rendered = render_blocks(cap["posts"][0]["blocks"])
    assert "Synced on priorities." in rendered


# --- Routing-level tests (slash command → ephemeral ack) ----------------------

@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "gid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "gsecret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "https://example.com/auth/google/callback")
    monkeypatch.setenv("GRANOLA_CLIENT_ID", "cid")
    monkeypatch.setenv("GRANOLA_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("GRANOLA_REDIRECT_URI", "https://example.com/auth/granola/callback")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://example.com")
    monkeypatch.delenv("GOOGLE_ACCESS_TOKEN", raising=False)

    from app.routes import app

    return TestClient(app)


def _slash_post(client: TestClient, text: str, *, user: str, channel: str = "C1") -> dict:
    body = urllib.parse.urlencode(
        {"text": text, "user_id": user, "channel_id": channel, "channel_name": "general"}
    ).encode()
    ts = str(int(time.time()))
    base = b"v0:" + ts.encode() + b":" + body
    sig = "v0=" + hmac.new(b"test-secret", base, hashlib.sha256).hexdigest()
    r = client.post(
        "/susan",
        content=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Slack-Request-Timestamp": ts,
            "X-Slack-Signature": sig,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_slash_meeting_notes_acks_when_connected(client: TestClient) -> None:
    import asyncio

    import db

    uid = "U-mn-connected"
    asyncio.run(db.init_db())
    asyncio.run(db.upsert_tokens(uid, "g-access", "g-refresh", 3600))
    asyncio.run(db.upsert_granola_token(uid, "granola-access"))

    with mock.patch("app.routes.process_meeting_notes", new=mock.AsyncMock()):
        j = _slash_post(client, "meeting notes", user=uid)
    assert j["response_type"] == "ephemeral"
    assert "Looking up your last meeting" in j["text"]


def test_slash_meeting_notes_without_google_offers_connect(client: TestClient) -> None:
    import asyncio

    import db

    asyncio.run(db.init_db())
    j = _slash_post(client, "meeting notes", user="U-mn-no-google")
    blocks_text = json.dumps(j.get("blocks") or [])
    assert "/auth/google?state=" in blocks_text
    assert "Connect Google Account" in blocks_text


def test_slash_meeting_notes_with_google_without_granola_offers_connect(client: TestClient) -> None:
    import asyncio

    import db

    uid = "U-mn-no-granola"
    asyncio.run(db.init_db())
    asyncio.run(db.upsert_tokens(uid, "g-access", "g-refresh", 3600))

    j = _slash_post(client, "meeting notes", user=uid)
    blocks_text = json.dumps(j.get("blocks") or [])
    assert "/auth/granola?state=" in blocks_text
    assert "Connect Granola Account" in blocks_text
