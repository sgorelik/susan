"""Tests for the /auth/granola routes and the `/susan connect granola` slash command."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from unittest import mock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Configure Granola env then build the FastAPI app fresh."""
    monkeypatch.setenv("GRANOLA_CLIENT_ID", "cid")
    monkeypatch.setenv("GRANOLA_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("GRANOLA_REDIRECT_URI", "https://example.com/auth/granola/callback")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://example.com")
    monkeypatch.setenv("GRANOLA_TOKEN_URL", "https://granola.test/oauth/token")

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


def test_slash_connect_granola_returns_link(client: TestClient) -> None:
    """`/susan connect granola` returns an ephemeral with the OAuth link."""
    j = _slash_post(client, "connect granola")
    assert j["response_type"] == "ephemeral"
    blocks_text = json.dumps(j["blocks"])
    assert "/auth/granola?state=" in blocks_text
    assert "Connect Granola Account" in blocks_text


def test_slash_connect_combined_includes_granola(client: TestClient) -> None:
    """`/susan connect` (no provider) lists Granola alongside any other configured providers."""
    j = _slash_post(client, "connect")
    blocks_text = json.dumps(j["blocks"])
    assert "Connect Granola" in blocks_text
    assert "/auth/granola?state=" in blocks_text


def test_slash_connect_unknown_subcommand_lists_granola(client: TestClient) -> None:
    j = _slash_post(client, "connect foo")
    assert "connect granola" in j["text"]


def test_auth_granola_start_rejects_invalid_state(client: TestClient) -> None:
    r = client.get("/auth/granola", params={"state": "garbage"}, follow_redirects=False)
    assert r.status_code == 400


def test_auth_granola_start_redirects_with_valid_state(client: TestClient) -> None:
    from app.oauth import make_oauth_state

    state = make_oauth_state("U1", channel_id="C1")
    r = client.get("/auth/granola", params={"state": state}, follow_redirects=False)
    assert r.status_code in (302, 307)
    loc = r.headers["location"]
    assert loc.startswith("https://api.granola.ai/oauth/authorize?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    assert qs["client_id"] == ["cid"]
    assert qs["state"] == [state]


def test_auth_granola_callback_stores_token_and_consumes_resume(
    client: TestClient,
) -> None:
    """After OAuth, the token is upserted and any pending resume row is consumed."""
    import asyncio
    import db
    from app.oauth import make_oauth_state

    asyncio.get_event_loop().run_until_complete(db.init_db())

    uid = "U-callback"
    rid = asyncio.get_event_loop().run_until_complete(
        db.create_oauth_resume_pending(uid, "C1", None, "/susan x", "doc", "granola")
    )
    state = make_oauth_state(uid, channel_id="C1", resume_id=rid)

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"access_token": "granola-acc", "token_type": "Bearer"}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, *a, **k) -> _Resp:
            return _Resp()

    # Avoid a real Slack POST when the callback tries to confirm in-channel.
    async def _noop(*a, **k):
        return None

    with mock.patch("db.httpx.AsyncClient", _Client), mock.patch(
        "app.routes.post_ephemeral", side_effect=_noop
    ):
        r = client.get(
            "/auth/granola/callback",
            params={"code": "the-code", "state": state},
            follow_redirects=False,
        )

    assert r.status_code == 200, r.text
    assert "Granola connected" in r.text

    # Token persisted under the right Slack user id.
    has = asyncio.get_event_loop().run_until_complete(db.user_has_granola_tokens(uid))
    assert has is True
    tok = asyncio.get_event_loop().run_until_complete(db.get_granola_token(uid))
    assert tok == "granola-acc"
    # Resume row was consumed (returns None on second call).
    consumed = asyncio.get_event_loop().run_until_complete(
        db.consume_oauth_resume_pending(rid, uid, "granola")
    )
    assert consumed is None


def test_auth_granola_callback_invalid_state_returns_400(client: TestClient) -> None:
    r = client.get(
        "/auth/granola/callback",
        params={"code": "x", "state": "bogus"},
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert "Invalid or expired session" in r.text
