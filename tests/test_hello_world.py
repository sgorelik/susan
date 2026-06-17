"""Unit tests for the Hello World skill (stateless, no external API calls)."""
from __future__ import annotations

from app.hello_world import (
    HELLO_WORLD_RESPONSE,
    HELLO_WORLD_SKILL_NAME,
    HELLO_WORLD_TRIGGERS,
    handle_hello_world,
    matches_hello_world,
)
from app.slack_api import detect_action

EXPECTED_RESPONSE = "Hello, World! I'm Susan, and I'm ready to help."


def test_skill_registered_under_hello_world_name() -> None:
    assert HELLO_WORLD_SKILL_NAME == "hello-world"


def test_response_matches_spec_exactly() -> None:
    assert HELLO_WORLD_RESPONSE == EXPECTED_RESPONSE


def test_triggers_are_hello_and_hi_susan() -> None:
    assert HELLO_WORLD_TRIGGERS == ("hello", "hi susan")


def test_hello_triggers_skill_and_returns_response() -> None:
    assert handle_hello_world("hello") == EXPECTED_RESPONSE


def test_hi_susan_triggers_skill_and_returns_response() -> None:
    assert handle_hello_world("hi susan") == EXPECTED_RESPONSE


def test_matching_is_case_insensitive() -> None:
    for phrase in ("HELLO", "Hello", "Hi Susan", "HI SUSAN", "hI sUsAn"):
        assert handle_hello_world(phrase) == EXPECTED_RESPONSE
        assert matches_hello_world(phrase) is True


def test_surrounding_whitespace_is_ignored() -> None:
    assert handle_hello_world("  hello  ") == EXPECTED_RESPONSE
    assert handle_hello_world("\thi susan\n") == EXPECTED_RESPONSE


def test_non_trigger_phrases_return_none() -> None:
    for phrase in ("hello there", "hi", "goodbye", "create a doc", "", "  "):
        assert handle_hello_world(phrase) is None
        assert matches_hello_world(phrase) is False


def test_triggers_do_not_collide_with_keyword_router() -> None:
    # The greeting is handled before (and independently of) detect_action, and
    # its phrases must not accidentally match another skill's keywords.
    for phrase in HELLO_WORLD_TRIGGERS:
        assert detect_action(phrase) is None


def test_skill_is_stateless_repeated_invocations_are_identical() -> None:
    # Calling the handler many times (and interleaving inputs) must not change
    # the output: the skill keeps no state between invocations.
    first = handle_hello_world("hello")
    for _ in range(5):
        assert handle_hello_world("hello") == first
        assert handle_hello_world("hi susan") == EXPECTED_RESPONSE
        assert handle_hello_world("not a greeting") is None
        assert handle_hello_world("hello") == first
