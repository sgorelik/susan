"""Tests for `/susan schedule` parsing and next-run calculation."""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from app.scheduler import (
    compute_next_run_at,
    default_schedule_channel_id,
    parse_schedule_add,
    parse_schedule_command,
    resolve_schedule_channel,
)


def test_parse_schedule_command() -> None:
    assert parse_schedule_command("schedule") == ""
    assert parse_schedule_command("schedule list") == "list"
    assert parse_schedule_command("weekly status") is None


def test_parse_schedule_add_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUSAN_DEFAULT_SCHEDULE_CHANNEL", "C0ANY6ASRB5")
    spec = parse_schedule_add(
        'add message "Good morning" every weekday at 9:00 in #team-tech',
        slash_channel_id="COTHER",
        slash_channel_name="random",
    )
    assert spec.job_type == "slack_message"
    assert spec.job_params["text"] == "Good morning"
    assert spec.hour == 9 and spec.minute == 0
    assert spec.days_of_week == [0, 1, 2, 3, 4]
    assert spec.channel_id == "C0ANY6ASRB5"


def test_parse_schedule_add_weekly_status_this_channel() -> None:
    spec = parse_schedule_add(
        "add weekly status last calendar week every monday at 9:30am in this channel",
        slash_channel_id="C0ANY6ASRB5",
        slash_channel_name="team-tech",
    )
    assert spec.job_type == "weekly_status"
    assert spec.job_params["command_text"] == "last calendar week"
    assert spec.hour == 9 and spec.minute == 30
    assert spec.days_of_week == [0]
    assert spec.channel_id == "C0ANY6ASRB5"


def test_resolve_schedule_channel_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUSAN_DEFAULT_SCHEDULE_CHANNEL", "C0ANY6ASRB5")
    assert default_schedule_channel_id() == "C0ANY6ASRB5"
    assert (
        resolve_schedule_channel(
            None,
            slash_channel_id="",
            slash_channel_name=None,
        )
        == "C0ANY6ASRB5"
    )


def test_compute_next_run_at_weekday() -> None:
    tz = "America/Los_Angeles"
    # Monday 2026-06-22 17:00 UTC = Monday 10:00 PDT — next weekday 9am PDT is Tue Jun 23
    after = datetime(2026, 6, 22, 17, 0, tzinfo=timezone.utc)
    nxt = compute_next_run_at(
        hour=9,
        minute=0,
        days_of_week=[0, 1, 2, 3, 4],
        tz_name=tz,
        after=after,
    )
    local = nxt.astimezone(ZoneInfo(tz))
    assert local.weekday() == 1
    assert local.hour == 9 and local.minute == 0
