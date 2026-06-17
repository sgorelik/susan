"""Tests for the repeat skill and session memory (Ticket 12)."""
from __future__ import annotations

import pytest

from app.skills import Session


@pytest.mark.parametrize("utterance", ["say that again", "repeat that", "repeat", "Repeat That"])
async def test_repeat_triggers(engine, utterance) -> None:
    # With a prior response stored, every trigger replays it.
    session = Session()
    await engine.handle("who are you", session)
    reply = await engine.handle(utterance, session)
    assert reply.skill == "repeat"
    assert reply.text == "I'm Susan, your personal assistant. Ask me anything!"


async def test_repeat_replays_last_response(engine) -> None:
    session = Session()
    await engine.handle("hello", session)
    reply = await engine.handle("repeat", session)
    assert reply.text == "Hello, World! I'm Susan, and I'm ready to help."


async def test_repeat_with_no_prior_response(engine) -> None:
    session = Session()
    reply = await engine.handle("repeat", session)
    assert reply.text == "I haven't said anything yet!"


async def test_repeat_does_not_overwrite_stored_response(engine) -> None:
    session = Session()
    await engine.handle("who are you", session)
    first = await engine.handle("repeat", session)
    second = await engine.handle("repeat that", session)
    assert first.text == second.text == "I'm Susan, your personal assistant. Ask me anything!"


async def test_repeat_no_prior_is_stable_across_calls(engine) -> None:
    session = Session()
    a = await engine.handle("repeat", session)
    b = await engine.handle("repeat", session)
    assert a.text == b.text == "I haven't said anything yet!"


async def test_session_persists_last_response_across_turns(engine) -> None:
    session = Session()
    await engine.handle("hello", session)
    assert session.last_response == "Hello, World! I'm Susan, and I'm ready to help."
    await engine.handle("who are you", session)
    assert session.last_response == "I'm Susan, your personal assistant. Ask me anything!"
