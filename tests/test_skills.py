"""Tests for the YAML-defined skill registry and the ``hello-world`` greeting."""
from __future__ import annotations

import hashlib
import hmac
import time
import urllib.parse
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

EXPECTED_RESPONSE = "Hello, World! I'm Susan, and I'm ready to help."


@pytest.fixture
def client() -> TestClient:
    from app.routes import app

    return TestClient(app)


def _sign_slack(body: bytes, ts: str, secret: str = "test-secret") -> str:
    base = b"v0:" + ts.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


def _slash_post(client: TestClient, text: str, *, user: str = "U1", channel: str = "C1") -> dict:
    body = urllib.parse.urlencode(
        {"text": text, "user_id": user, "channel_id": channel, "channel_name": "general"}
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


def test_hello_world_registered_under_name() -> None:
    from app.skills import SKILLS

    assert "hello-world" in SKILLS
    skill = SKILLS["hello-world"]
    assert skill.response_text == EXPECTED_RESPONSE
    assert set(skill.triggers) == {"hello", "hi susan"}


@pytest.mark.parametrize("text", ["hello", "Hello", "HELLO", "hi susan", "Hi Susan", "hello!", "Hi   Susan"])
def test_match_skill_is_case_insensitive(text: str) -> None:
    from app.skills import match_skill

    skill = match_skill(text)
    assert skill is not None
    assert skill.name == "hello-world"


@pytest.mark.parametrize("text", ["", "help", "create issue", "hello there", "say hi susan"])
def test_match_skill_ignores_non_triggers(text: str) -> None:
    from app.skills import match_skill

    assert match_skill(text) is None


@pytest.mark.parametrize("text", ["hello", "Hi Susan"])
def test_slash_hello_returns_greeting(client: TestClient, text: str) -> None:
    j = _slash_post(client, text)
    assert j["response_type"] == "ephemeral"
    assert j["text"] == EXPECTED_RESPONSE
    # Stateless static reply: no preview blocks / interactive buttons.
    assert "blocks" not in j


def test_registry_matches_yaml_spec() -> None:
    """The loaded skill must match the canonical ``skills/hello-world.yaml`` spec."""
    from app.skills import SKILLS, _normalize

    spec_path = Path(__file__).resolve().parent.parent / "skills" / "hello-world.yaml"
    spec = (yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {})["skill"]

    skill = SKILLS[spec["name"]]
    assert skill.description == spec["description"]
    assert skill.response_text == spec["response"]["text"]
    assert set(skill.triggers) == {_normalize(t) for t in spec["triggers"]}
