"""Tests for the YAML-defined skills catalog and the hello-world reference skill.

The hello-world skill is stateless, takes no parameters/slots, and makes no external
API calls — so these are pure input/output assertions against the skill handler with
no mocking or setup.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import urllib.parse

from fastapi.testclient import TestClient

from app.skills import CATALOG, match_skill, skill_response

EXPECTED_RESPONSE = "Hello, World! I'm Susan, and I'm ready to help."


def test_hello_world_skill_is_registered() -> None:
    skill = CATALOG.get("hello-world")
    assert skill is not None
    assert skill.name == "hello-world"
    assert skill.triggers == ("hello", "hi susan")
    assert skill.response_text == EXPECTED_RESPONSE


def test_hello_trigger_returns_expected_response() -> None:
    assert skill_response("hello") == EXPECTED_RESPONSE
    assert match_skill("hello").name == "hello-world"


def test_hi_susan_trigger_returns_expected_response() -> None:
    assert skill_response("hi susan") == EXPECTED_RESPONSE
    assert match_skill("hi susan").name == "hello-world"


def test_trigger_matching_is_case_insensitive() -> None:
    for utterance in ("HELLO", "Hello", "hElLo", "Hi Susan", "HI SUSAN", "hi SuSaN"):
        assert skill_response(utterance) == EXPECTED_RESPONSE, utterance


def test_trigger_matching_ignores_surrounding_whitespace_and_punctuation() -> None:
    assert skill_response("  hello  ") == EXPECTED_RESPONSE
    assert skill_response("hello!") == EXPECTED_RESPONSE
    assert skill_response("hi susan.") == EXPECTED_RESPONSE


def test_skill_is_stateless_repeated_invocations_are_identical() -> None:
    responses = [skill_response("hello") for _ in range(5)]
    responses += [skill_response("hi susan") for _ in range(5)]
    assert all(response == EXPECTED_RESPONSE for response in responses)


def test_non_trigger_text_does_not_match_hello_world() -> None:
    assert match_skill("create a doc") is None
    assert skill_response("weekly status") is None
    # Substrings of a trigger should not accidentally fire the greeting.
    assert skill_response("hello there team") is None


def test_hello_world_skill_requires_no_slots_and_makes_no_external_calls() -> None:
    skill = CATALOG.get("hello-world")
    # Static response: not dynamic and no handler to call out to.
    assert skill.dynamic is False
    assert skill.handler is None
    # respond() takes no arguments (no parameters/slots) and is pure.
    assert skill.respond() == EXPECTED_RESPONSE


def _sign_slack(body: bytes, ts: str, secret: str = "test-secret") -> str:
    base = b"v0:" + ts.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


def _slash_post(client: TestClient, text: str) -> dict:
    body = urllib.parse.urlencode(
        {"text": text, "user_id": "U1", "channel_id": "C1", "channel_name": "general"}
    ).encode()
    ts = str(int(time.time()))
    sig = _sign_slack(body, ts)
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


def test_slash_hello_returns_greeting() -> None:
    """`/susan hello` routes through the skills catalog to the greeting response."""
    from app.routes import app

    client = TestClient(app)
    for text in ("hello", "Hi Susan", "HELLO"):
        j = _slash_post(client, text)
        assert j["response_type"] == "ephemeral"
        assert j["text"] == EXPECTED_RESPONSE


def test_slash_help_lists_hello_world_skill() -> None:
    """The in-Slack help advertises the hello-world skill and its triggers."""
    import json

    from app.routes import app

    client = TestClient(app)
    j = _slash_post(client, "help")
    blocks_text = json.dumps(j["blocks"])
    assert "hello-world" in blocks_text
    assert "hi susan" in blocks_text
