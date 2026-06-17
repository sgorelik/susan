"""Tests for the Hello World skill (Tickets 1 & 2)."""
from __future__ import annotations

import pytest

from app.skills import Session

HELLO_RESPONSE = "Hello, World! I'm Susan, and I'm ready to help."


def test_registered_under_hello_world(engine) -> None:
    assert "hello-world" in engine.registry


@pytest.mark.parametrize("utterance", ["hello", "hi susan"])
async def test_trigger_phrases(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "hello-world"
    assert reply.text == HELLO_RESPONSE


@pytest.mark.parametrize("utterance", ["HELLO", "Hello", "Hi Susan", "HI SUSAN", "hello!"])
async def test_trigger_matching_is_case_insensitive(engine, utterance) -> None:
    reply = await engine.handle(utterance, Session())
    assert reply.skill == "hello-world"
    assert reply.text == HELLO_RESPONSE


async def test_requires_no_slots(engine) -> None:
    assert engine.registry["hello-world"].slots == ()


async def test_no_external_apis(engine) -> None:
    assert engine.registry["hello-world"].requires == ()


async def test_stateless_repeated_invocations(engine) -> None:
    # Same session and fresh sessions both return an identical response.
    shared = Session()
    first = await engine.handle("hello", shared)
    second = await engine.handle("hello", shared)
    third = await engine.handle("hi susan", Session())
    assert first.text == second.text == third.text == HELLO_RESPONSE


def test_static_definition_matches_spec(engine) -> None:
    skill = engine.registry["hello-world"]
    assert skill.response.dynamic is False
    assert skill.response.text == HELLO_RESPONSE
    assert set(skill.triggers) == {"hello", "hi susan"}
