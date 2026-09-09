"""Tests for the daily standup digest built from Granola notes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import app.standup_digest as sd
from app.standup_digest import (
    parse_daily_standup_command,
    parse_standup_digest_window,
    standup_meeting_terms,
)


def test_parse_daily_standup_command() -> None:
    assert parse_daily_standup_command("daily status") == ""
    assert parse_daily_standup_command("daily status yesterday") == "yesterday"
    assert parse_daily_standup_command("daily standup") == ""
    assert parse_daily_standup_command("standup digest last 3 days") == "last 3 days"
    assert parse_daily_standup_command("weekly status") is None
    assert parse_daily_standup_command("standups") is None


def test_daily_command_wins_over_bare_standup_prefix() -> None:
    """channel_surface also matches a bare "standup"; the digest must be routed first."""
    from app.channel_surface import parse_standup_command

    assert parse_standup_command("standup digest") is not None
    assert parse_daily_standup_command("standup digest") is not None


def test_window_defaults_to_today() -> None:
    today = datetime.now(timezone.utc).date().isoformat()
    assert parse_standup_digest_window("") == (today, today, "today")
    assert parse_standup_digest_window("today") == (today, today, "today")


def test_window_yesterday() -> None:
    y = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    assert parse_standup_digest_window("yesterday") == (y, y, "yesterday")


def test_meeting_terms_are_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SUSAN_STANDUP_MEETING_TERMS", raising=False)
    assert "standup" in standup_meeting_terms()
    monkeypatch.setenv("SUSAN_STANDUP_MEETING_TERMS", "morning sync, huddle")
    assert standup_meeting_terms() == ["morning sync", "huddle"]


@pytest.mark.asyncio
async def test_no_matching_meeting_explains_how_to_fix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def has_tokens(user: str) -> bool:
        return True

    async def token(user: str) -> str:
        return "tok"

    async def no_matches(*args: object, **kwargs: object) -> tuple[list, int]:
        return [], 9

    sent: dict[str, str] = {}

    async def fake_notify(channel, user, text, blocks=None, response_url=None, **kw):
        sent["text"] = text

    monkeypatch.setattr(sd, "user_has_granola_tokens", has_tokens)
    monkeypatch.setattr(sd, "get_granola_token", token)
    monkeypatch.setattr(sd, "collect_granola_notes_matching_terms", no_matches)
    monkeypatch.setattr(sd, "notify_user_ephemeral", fake_notify)

    await sd.process_standup_digest("daily status", "C1", "U1", None, None)

    assert "No standup meeting found" in sent["text"]
    assert "SUSAN_STANDUP_MEETING_TERMS" in sent["text"]


@pytest.mark.asyncio
async def test_auto_publish_posts_to_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.claude_client import ModelCompletion

    async def has_tokens(user: str) -> bool:
        return True

    async def token(user: str) -> str:
        return "tok"

    async def one_note(*args: object, **kwargs: object) -> tuple[list, int]:
        return [{"id": "not_1", "title": "Daily standup", "summary_markdown": "Ana: shipped"}], 1

    async def fake_completion(*args: object, **kwargs: object) -> ModelCompletion:
        return ModelCompletion(
            "*Updates*\n• *Ana* — shipped the parser",
            model_route="sovereign",
            model_name="deepseek-v4",
        )

    posted: dict[str, object] = {}
    notes: list[str] = []

    async def fake_post(channel, text, **kwargs):
        posted.update(channel=channel, text=text, **kwargs)
        return {"ok": True, "ts": "1"}

    async def fake_notify(channel, user, text, blocks=None, response_url=None, **kw):
        notes.append(text)

    monkeypatch.setattr(sd, "user_has_granola_tokens", has_tokens)
    monkeypatch.setattr(sd, "get_granola_token", token)
    monkeypatch.setattr(sd, "collect_granola_notes_matching_terms", one_note)
    monkeypatch.setattr(sd, "call_claude", fake_completion)
    monkeypatch.setattr(sd, "post_message", fake_post)
    monkeypatch.setattr(sd, "notify_user_ephemeral", fake_notify)

    await sd.process_standup_digest(
        "daily status --no-approval", "C1", "U1", None, None
    )

    assert posted["channel"] == "C1"
    assert "*Standup — today*" in posted["text"]
    assert "*Ana* — shipped the parser" in posted["text"]
    # Attribution must follow the model that actually served the request.
    assert posted["model_route"] == "sovereign"
    assert posted["model_name"] == "deepseek-v4"
    assert any("everyone here can see it" in n for n in notes)


@pytest.mark.asyncio
async def test_no_approval_without_dashes_still_posts(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.claude_client import ModelCompletion

    async def has_tokens(user: str) -> bool:
        return True

    async def token(user: str) -> str:
        return "tok"

    async def one_note(*args: object, **kwargs: object) -> tuple[list, int]:
        return [{"id": "not_1", "title": "Daily standup", "summary_markdown": "Ana: shipped"}], 1

    async def fake_completion(*args: object, **kwargs: object) -> ModelCompletion:
        return ModelCompletion("*Updates*\n• *Ana* — shipped", model_route="sovereign")

    posted: list[object] = []

    async def fake_post(*args: object, **kwargs: object) -> dict:
        posted.append(args)
        return {"ok": True, "ts": "1"}

    async def fake_notify(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(sd, "user_has_granola_tokens", has_tokens)
    monkeypatch.setattr(sd, "get_granola_token", token)
    monkeypatch.setattr(sd, "collect_granola_notes_matching_terms", one_note)
    monkeypatch.setattr(sd, "call_claude", fake_completion)
    monkeypatch.setattr(sd, "post_message", fake_post)
    monkeypatch.setattr(sd, "notify_user_ephemeral", fake_notify)

    await sd.process_standup_digest("daily status no approval", "C1", "U1", None, None)

    assert posted, "plain 'no approval' must post to the channel, not stay ephemeral"


def test_strip_auto_post_flags_accepts_spoken_form() -> None:
    from app.weekly_context import strip_weekly_status_auto_post_flags

    cleaned, auto = strip_weekly_status_auto_post_flags("yesterday no approval")
    assert auto is True
    assert cleaned == "yesterday"
    cleaned, auto = strip_weekly_status_auto_post_flags("last week")
    assert auto is False
    assert cleaned == "last week"


@pytest.mark.asyncio
async def test_preview_is_private_and_not_posted(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.claude_client import ModelCompletion

    async def has_tokens(user: str) -> bool:
        return True

    async def token(user: str) -> str:
        return "tok"

    async def one_note(*args: object, **kwargs: object) -> tuple[list, int]:
        return [{"id": "not_1", "title": "Standup", "summary_markdown": "x"}], 1

    async def fake_completion(*args: object, **kwargs: object) -> ModelCompletion:
        return ModelCompletion("*Updates*\n• *Ana* — shipped", model_route="sovereign")

    posted: list[object] = []
    sent: dict[str, str] = {}

    async def fake_post(*args: object, **kwargs: object) -> dict:
        posted.append(args)
        return {"ok": True}

    async def fake_notify(channel, user, text, blocks=None, response_url=None, **kw):
        sent["text"] = text

    monkeypatch.setattr(sd, "user_has_granola_tokens", has_tokens)
    monkeypatch.setattr(sd, "get_granola_token", token)
    monkeypatch.setattr(sd, "collect_granola_notes_matching_terms", one_note)
    monkeypatch.setattr(sd, "call_claude", fake_completion)
    monkeypatch.setattr(sd, "post_message", fake_post)
    monkeypatch.setattr(sd, "notify_user_ephemeral", fake_notify)

    await sd.process_standup_digest("daily status", "C1", "U1", None, None)

    assert posted == []
    assert "Only you can see this" in sent["text"]


@pytest.mark.asyncio
async def test_missing_granola_tells_user_to_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def no_tokens(user: str) -> bool:
        return False

    sent: dict[str, str] = {}

    async def fake_notify(channel, user, text, blocks=None, response_url=None, **kw):
        sent["text"] = text

    monkeypatch.setattr(sd, "user_has_granola_tokens", no_tokens)
    monkeypatch.setattr(sd, "notify_user_ephemeral", fake_notify)

    await sd.process_standup_digest("daily status", "C1", "U1", None, None)

    assert "connect granola" in sent["text"].lower()


def test_schedule_add_parses_daily_status() -> None:
    from app.scheduler import parse_schedule_add

    spec = parse_schedule_add(
        "add daily status every weekday at 10:00 in C0ANY6ASRB5",
        slash_channel_id="C1",
        slash_channel_name="general",
    )
    assert spec.job_type == "standup_digest"
    assert spec.job_params["command_text"] == ""
    assert spec.days_of_week == [0, 1, 2, 3, 4]
    assert spec.hour == 10
    assert spec.channel_id == "C0ANY6ASRB5"
