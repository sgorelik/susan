"""Tests for help, who-are-you, and goodbye skills (Tickets 3, 8, 11)."""
from __future__ import annotations

import pytest

from app.skills import Session


# --- help (Ticket 3) ---------------------------------------------------------


@pytest.mark.parametrize("utterance", ["help", "what can you do", "commands", "HELP", "Commands"])
async def test_help_triggers(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "help"


async def test_help_lists_every_registered_skill(engine) -> None:
    """The response must stay in sync with the registered skills."""
    reply = await engine.handle("help", Session())
    for skill in engine.skills:
        if skill.help_summary:
            assert skill.help_summary in reply.text


async def test_help_requires_no_slots_or_apis(engine) -> None:
    skill = engine.registry["help"]
    assert skill.slots == ()
    assert skill.requires == ()


# --- who-are-you (Ticket 8) --------------------------------------------------

WHO_RESPONSE = "I'm Susan, your personal assistant. Ask me anything!"


@pytest.mark.parametrize(
    "utterance",
    ["who are you", "what's your name", "introduce yourself", "Who Are You", "INTRODUCE YOURSELF"],
)
async def test_who_are_you(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "who-are-you"
    assert reply.text == WHO_RESPONSE


async def test_who_are_you_is_stateless(engine) -> None:
    a = await engine.handle("who are you", Session())
    b = await engine.handle("who are you", Session())
    assert a.text == b.text == WHO_RESPONSE
    skill = engine.registry["who-are-you"]
    assert skill.slots == () and skill.requires == ()


# --- goodbye (Ticket 11) -----------------------------------------------------

GOODBYE_RESPONSE = "Goodbye! Come back anytime."


@pytest.mark.parametrize(
    "utterance",
    ["goodbye", "bye susan", "see you later", "farewell", "GOODBYE", "Bye Susan"],
)
async def test_goodbye_triggers_and_response(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "goodbye"
    assert reply.text == GOODBYE_RESPONSE


async def test_goodbye_ends_session(engine) -> None:
    session = Session()
    reply = await engine.handle("goodbye", session)
    assert reply.end_session is True
    assert session.ended is True


async def test_goodbye_requires_no_slots_or_apis(engine) -> None:
    skill = engine.registry["goodbye"]
    assert skill.slots == ()
    assert skill.requires == ()
