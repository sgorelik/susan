"""Tests for trigger matching, normalization, and the loader/registry."""
from __future__ import annotations

import pytest

from app.skills import Session
from app.skills.loader import DEFINITIONS_DIR, load_definitions, load_skill
from app.skills.matching import match, normalize
from app.skills.models import SkillDefinitionError

EXPECTED_SKILLS = {
    "hello-world",
    "help",
    "tell-time",
    "tell-date",
    "tell-joke",
    "fun-fact",
    "who-are-you",
    "set-timer",
    "weather",
    "goodbye",
    "repeat",
}


def test_registry_contains_all_expected_skills(engine) -> None:
    assert set(engine.registry) == EXPECTED_SKILLS


def test_every_dynamic_skill_resolves_a_handler(engine) -> None:
    # SkillEngine validates handlers at construction; assert it explicitly too.
    for skill in engine.skills:
        if skill.response.dynamic:
            assert skill.response.handler in engine.handlers


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("  Hello  ", "hello"),
        ("HI SUSAN!", "hi susan"),
        ("What time is it?", "what time is it"),
        ("today's   date", "today's date"),
    ],
)
def test_normalize(raw, expected) -> None:
    assert normalize(raw) == expected


def test_match_is_case_insensitive(skills) -> None:
    for utterance in ("HELLO", "Hello", "hElLo"):
        found = match(skills, utterance)
        assert found is not None and found.skill.name == "hello-world"


def test_match_prefers_most_specific_trigger(skills) -> None:
    found = match(skills, "what time is it")
    assert found is not None
    assert found.skill.name == "tell-time"
    assert found.trigger == "what time is it"


def test_timer_word_does_not_collide_with_time(skills) -> None:
    found = match(skills, "timer for 5 minutes")
    assert found is not None
    assert found.skill.name == "set-timer"
    assert found.slots == {"duration": "5 minutes"}


def test_unknown_utterance_does_not_match(skills) -> None:
    assert match(skills, "please order me a pizza") is None


async def test_unknown_utterance_returns_fallback(engine) -> None:
    reply = await engine.handle("please order me a pizza", Session())
    assert reply.matched is False
    assert "didn't catch that" in reply.text


def test_all_definitions_load_from_disk() -> None:
    skills = load_definitions(DEFINITIONS_DIR)
    assert len(skills) == len(EXPECTED_SKILLS)


def test_loader_rejects_missing_name() -> None:
    with pytest.raises(SkillDefinitionError):
        load_skill({"triggers": ["hi"], "response": {"text": "hey"}})


def test_loader_rejects_empty_triggers() -> None:
    with pytest.raises(SkillDefinitionError):
        load_skill({"name": "x", "triggers": [], "response": {"text": "hey"}})


def test_loader_rejects_dynamic_without_handler() -> None:
    with pytest.raises(SkillDefinitionError):
        load_skill({"name": "x", "triggers": ["hi"], "response": {"dynamic": True}})


def test_loader_rejects_static_without_text() -> None:
    with pytest.raises(SkillDefinitionError):
        load_skill({"name": "x", "triggers": ["hi"], "response": {}})


def test_loader_parses_slots_and_session_end() -> None:
    skill = load_skill(
        {
            "name": "x",
            "triggers": ["bye"],
            "response": {"text": "later"},
            "session": {"end": True},
        }
    )
    assert skill.end_session is True
