"""Tests for tell-time, tell-date, tell-joke, fun-fact skills (Tickets 4-7)."""
from __future__ import annotations

from datetime import datetime

import pytest

from app.skills import Session
from app.skills.handlers import format_date, format_time


# --- tell-time (Ticket 4) ----------------------------------------------------


@pytest.mark.parametrize("utterance", ["what time is it", "current time", "time", "What Time Is It"])
async def test_time_triggers(make_engine, utterance) -> None:
    engine = make_engine(clock=lambda: datetime(2025, 6, 17, 15, 45))
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "tell-time"
    assert reply.text == "It's 3:45 PM."


async def test_time_uses_dynamic_handler(engine) -> None:
    skill = engine.registry["tell-time"]
    assert skill.response.dynamic is True
    assert skill.response.handler == "time.current_local"
    assert skill.slots == () and skill.requires == ()


@pytest.mark.parametrize(
    "hour,minute,expected",
    [(0, 5, "12:05 AM"), (12, 0, "12:00 PM"), (13, 9, "1:09 PM"), (23, 59, "11:59 PM")],
)
def test_format_time_edge_cases(hour, minute, expected) -> None:
    assert format_time(datetime(2025, 1, 1, hour, minute)) == expected


# --- tell-date (Ticket 5) ----------------------------------------------------


@pytest.mark.parametrize("utterance", ["what's the date", "what day is it", "today's date"])
async def test_date_triggers(make_engine, utterance) -> None:
    when = datetime(2025, 6, 17, 9, 0)  # a Tuesday
    engine = make_engine(clock=lambda: when)
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "tell-date"
    expected = f"Today is {when.strftime('%A, %B')} {when.day}."
    assert reply.text == expected
    assert reply.text == "Today is Tuesday, June 17."


def test_format_date_has_no_year_and_no_leading_zero() -> None:
    assert format_date(datetime(2025, 1, 5)) == "Sunday, January 5"


async def test_date_uses_dynamic_handler(engine) -> None:
    skill = engine.registry["tell-date"]
    assert skill.response.dynamic is True
    assert skill.response.handler == "time.current_date"


# --- tell-joke (Ticket 6) ----------------------------------------------------


@pytest.mark.parametrize("utterance", ["tell me a joke", "joke", "make me laugh", "JOKE"])
async def test_joke_triggers(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "tell-joke"
    assert reply.text


async def test_jokes_rotate_across_invocations(engine) -> None:
    pool_size = len(engine.context.jokes)
    assert pool_size >= 5
    seen = [(await engine.handle("joke", Session())).text for _ in range(pool_size)]
    # Round-robin: every joke is used exactly once before any repeats.
    assert len(set(seen)) == pool_size
    # Consecutive invocations differ.
    assert seen[0] != seen[1]


# --- fun-fact (Ticket 7) -----------------------------------------------------


@pytest.mark.parametrize("utterance", ["tell me a fact", "fun fact", "surprise me", "Surprise Me"])
async def test_fact_triggers(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "fun-fact"
    assert reply.text


async def test_facts_rotate_across_invocations(engine) -> None:
    pool_size = len(engine.context.facts)
    assert pool_size >= 5
    seen = [(await engine.handle("fun fact", Session())).text for _ in range(pool_size)]
    assert len(set(seen)) == pool_size
    assert seen[0] != seen[1]
