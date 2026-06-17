"""Tests for the declarative skill registry and the `hello-world` skill."""
from __future__ import annotations

import hashlib
import hmac
import time
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from app.skills import SKILLS, match_skill

GREETING = "Hello, World! I'm Susan, and I'm ready to help."


def test_hello_world_registered() -> None:
    assert "hello-world" in SKILLS
    skill = SKILLS["hello-world"]
    assert skill.name == "hello-world"
    assert skill.description == "Greets the user with a Hello World message."
    assert skill.triggers == ("hello", "hi susan")
    assert skill.response_text == GREETING


def test_match_skill_case_insensitive() -> None:
    for text in ("hello", "Hello", "HELLO", "hi susan", "Hi Susan", "HI SUSAN"):
        skill = match_skill(text)
        assert skill is not None, text
        assert skill.name == "hello-world"
        assert skill.response_text == GREETING


def test_match_skill_tolerates_punctuation_and_whitespace() -> None:
    assert match_skill("  hello!  ").name == "hello-world"
    assert match_skill("hi   susan").name == "hello-world"


def test_match_skill_no_false_positives() -> None:
    assert match_skill("") is None
    assert match_skill("   ") is None
    assert match_skill("create a doc") is None
    assert match_skill("say hello to the team") is None
    assert match_skill("weekly status") is None


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


@pytest.fixture
def client() -> TestClient:
    from app.routes import app

    return TestClient(app)


def test_slash_hello_returns_greeting(client: TestClient) -> None:
    """`/susan hello` and `/susan hi susan` return the static greeting ephemerally."""
    for text in ("hello", "Hi Susan"):
        j = _slash_post(client, text)
        assert j["response_type"] == "ephemeral"
        assert j["text"] == GREETING
