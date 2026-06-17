"""Tests for the set-timer skill including slot elicitation and expiry (Ticket 9)."""
from __future__ import annotations

import pytest

from app.skills import Session
from app.skills.engine import SkillContext, SkillEngine
from app.skills.matching import parse_duration
from app.skills.timers import TimerService


class RecordingScheduler:
    """Captures scheduled (delay, callback) pairs without firing them."""

    def __init__(self) -> None:
        self.calls: list[tuple[float, object]] = []

    def __call__(self, delay, callback):
        self.calls.append((delay, callback))
        return None


@pytest.fixture
def timer_engine(skills):
    scheduler = RecordingScheduler()
    context = SkillContext(timers=TimerService(scheduler=scheduler))
    engine = SkillEngine(skills, context=context)
    return engine, scheduler


@pytest.mark.parametrize("utterance", ["set a timer for 5 minutes", "timer for 5 minutes"])
async def test_timer_with_duration_in_trigger(timer_engine, utterance) -> None:
    engine, _ = timer_engine
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "set-timer"
    assert reply.text == "Timer set for 5 minutes. I'll let you know when it's done."


async def test_timer_extracts_duration_slot(timer_engine) -> None:
    engine, scheduler = timer_engine
    await engine.handle("set a timer for 1 hour 30 minutes", Session())
    assert scheduler.calls, "a timer should have been scheduled"
    delay, _ = scheduler.calls[-1]
    assert delay == 90 * 60


async def test_timer_elicits_missing_duration(timer_engine) -> None:
    engine, _ = timer_engine
    session = Session()
    reply = await engine.handle("set a timer for", session)
    assert reply.eliciting is True
    assert reply.text == "How long should I set the timer for?"
    assert session.pending_skill == "set-timer"
    assert session.pending_slot == "duration"


async def test_timer_resumes_after_elicitation(timer_engine) -> None:
    engine, _ = timer_engine
    session = Session()
    await engine.handle("set a timer for", session)
    reply = await engine.handle("10 minutes", session)
    assert reply.skill == "set-timer"
    assert reply.text == "Timer set for 10 minutes. I'll let you know when it's done."
    assert session.pending_slot is None


async def test_timer_fires_notification_on_expiry(timer_engine) -> None:
    engine, scheduler = timer_engine
    await engine.handle("set a timer for 5 minutes", Session())
    delay, callback = scheduler.calls[-1]
    assert delay == 300
    callback()  # simulate the timer expiring
    assert engine.context.notifications == ["⏰ Time's up! Your timer for 5 minutes is done."]


@pytest.mark.parametrize(
    "text,seconds",
    [
        ("5 minutes", 300),
        ("1 hour 30 minutes", 5400),
        ("30 seconds", 30),
        ("2 hours", 7200),
        ("an hour", 3600),
        ("not a duration", None),
    ],
)
def test_parse_duration(text, seconds) -> None:
    assert parse_duration(text) == seconds
