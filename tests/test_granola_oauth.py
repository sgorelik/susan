"""Tests for the Granola OAuth integration (oauth.py + db.py)."""
from __future__ import annotations

import asyncio
import os
import urllib.parse
from unittest import mock

import pytest


def _set_env(monkeypatch: pytest.MonkeyPatch, **kw: str | None) -> None:
    for k, v in kw.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


def test_granola_authorize_url_includes_signed_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """authorize URL must carry client_id, redirect_uri, response_type=code, and the signed state."""
    from app import oauth

    _set_env(
        monkeypatch,
        GRANOLA_CLIENT_ID="cid-123",
        GRANOLA_CLIENT_SECRET="secret",
        GRANOLA_REDIRECT_URI="https://example.com/auth/granola/callback",
        GRANOLA_AUTHORIZE_URL=None,
        GRANOLA_OAUTH_SCOPE=None,
    )

    state = oauth.make_oauth_state("U123", channel_id="C1")
    url = oauth.granola_authorize_url(state)

    assert url.startswith(oauth.GRANOLA_AUTHORIZE_URL_DEFAULT + "?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["client_id"] == ["cid-123"]
    assert qs["redirect_uri"] == ["https://example.com/auth/granola/callback"]
    assert qs["response_type"] == ["code"]
    assert qs["state"] == [state]
    # No scope unless GRANOLA_OAUTH_SCOPE is set
    assert "scope" not in qs


def test_granola_authorize_url_uses_overrides_and_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import oauth

    _set_env(
        monkeypatch,
        GRANOLA_CLIENT_ID="cid",
        GRANOLA_CLIENT_SECRET="s",
        GRANOLA_REDIRECT_URI="https://h/auth/granola/callback",
        GRANOLA_AUTHORIZE_URL="https://granola.test/oauth/authorize",
        GRANOLA_OAUTH_SCOPE="notes:read",
    )

    url = oauth.granola_authorize_url(oauth.make_oauth_state("U2"))
    assert url.startswith("https://granola.test/oauth/authorize?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["scope"] == ["notes:read"]


def test_granola_redirect_uri_falls_back_to_public_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import oauth

    _set_env(
        monkeypatch,
        GRANOLA_REDIRECT_URI=None,
        PUBLIC_BASE_URL="https://my.host",
    )
    assert oauth.granola_redirect_uri() == "https://my.host/auth/granola/callback"


def test_granola_oauth_configured_requires_id_secret_and_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import oauth

    _set_env(
        monkeypatch,
        GRANOLA_CLIENT_ID=None,
        GRANOLA_CLIENT_SECRET=None,
        GRANOLA_REDIRECT_URI=None,
        PUBLIC_BASE_URL=None,
    )
    assert oauth._granola_oauth_configured() is False

    _set_env(monkeypatch, GRANOLA_CLIENT_ID="x", GRANOLA_CLIENT_SECRET="y")
    assert oauth._granola_oauth_configured() is False  # still no redirect

    _set_env(monkeypatch, PUBLIC_BASE_URL="https://h")
    assert oauth._granola_oauth_configured() is True

    _set_env(monkeypatch, GRANOLA_CLIENT_ID="  ", GRANOLA_CLIENT_SECRET="y")
    assert oauth._granola_oauth_configured() is False


def test_public_origin_for_connect_links_from_granola_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import oauth

    _set_env(
        monkeypatch,
        PUBLIC_BASE_URL=None,
        GRANOLA_REDIRECT_URI="https://odd.host:8443/foo/oauth/callback",
    )
    assert oauth.public_base_url() == ""
    assert oauth.granola_redirect_uri() == "https://odd.host:8443/foo/oauth/callback"
    assert oauth.public_origin_for_connect_links() == "https://odd.host:8443"


def test_oauth_state_round_trip_with_resume_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Granola reuses the same signed-state mechanism as Google/GitHub for resume_id."""
    from app import oauth

    state = oauth.make_oauth_state("U9", channel_id="CABC", resume_id="resume-1")
    parsed = oauth.parse_oauth_state(state)
    assert parsed == ("U9", "CABC", "resume-1")


@pytest.mark.asyncio
async def test_granola_token_db_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    """upsert / user_has / get a Granola token; absence is treated as 'not connected'."""
    import db

    await db.init_db()

    uid = "U-granola-1"
    assert await db.user_has_granola_tokens(uid) is False

    await db.upsert_granola_token(uid, "access-1")
    assert await db.user_has_granola_tokens(uid) is True
    assert await db.get_granola_token(uid) == "access-1"

    # Re-upsert updates the access token in place (no duplicate row).
    await db.upsert_granola_token(uid, "access-2")
    assert await db.get_granola_token(uid) == "access-2"


@pytest.mark.asyncio
async def test_granola_no_shared_fallback_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even if some env var is set, get_granola_token must still raise without a per-user row."""
    import db

    await db.init_db()
    monkeypatch.setenv("GRANOLA_TOKEN", "shared-should-not-be-honored")
    monkeypatch.setenv("GRANOLA_CLIENT_ID", "cid")
    monkeypatch.setenv("GRANOLA_CLIENT_SECRET", "secret")

    uid_unconnected = "U-unconnected"
    assert await db.user_has_granola_tokens(uid_unconnected) is False
    with pytest.raises(ValueError) as exc:
        await db.get_granola_token(uid_unconnected)
    assert "/susan connect granola" in str(exc.value)


@pytest.mark.asyncio
async def test_exchange_granola_code_calls_token_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """The token exchange must POST client_id, client_secret, code, redirect_uri, grant_type."""
    import db

    monkeypatch.setenv("GRANOLA_CLIENT_ID", "cid")
    monkeypatch.setenv("GRANOLA_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("GRANOLA_TOKEN_URL", "https://granola.test/oauth/token")

    captured: dict = {}

    class _DummyResp:
        def __init__(self, payload: dict) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._payload

    class _DummyClient:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self) -> "_DummyClient":
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, url: str, headers=None, data=None) -> _DummyResp:
            captured["url"] = url
            captured["headers"] = headers
            captured["data"] = data
            return _DummyResp({"access_token": "acc-xyz", "token_type": "Bearer"})

    with mock.patch("db.httpx.AsyncClient", _DummyClient):
        out = await db.exchange_granola_code_for_token(
            "the-code", "https://h/auth/granola/callback"
        )

    assert out == {"access_token": "acc-xyz", "token_type": "Bearer"}
    assert captured["url"] == "https://granola.test/oauth/token"
    assert captured["data"]["client_id"] == "cid"
    assert captured["data"]["client_secret"] == "csecret"
    assert captured["data"]["code"] == "the-code"
    assert captured["data"]["redirect_uri"] == "https://h/auth/granola/callback"
    assert captured["data"]["grant_type"] == "authorization_code"


@pytest.mark.asyncio
async def test_exchange_granola_raises_on_oauth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An ``error`` field in the JSON response must be surfaced as ``ValueError``."""
    import db

    monkeypatch.setenv("GRANOLA_CLIENT_ID", "cid")
    monkeypatch.setenv("GRANOLA_CLIENT_SECRET", "s")

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"error": "invalid_grant", "error_description": "bad code"}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self) -> "_Client":
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, *a, **k) -> _Resp:
            return _Resp()

    with mock.patch("db.httpx.AsyncClient", _Client):
        with pytest.raises(ValueError) as exc:
            await db.exchange_granola_code_for_token("c", "u")
    assert "bad code" in str(exc.value)


@pytest.mark.asyncio
async def test_oauth_resume_pending_supports_granola_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """The resume mechanism is provider-keyed; a Granola row must round-trip."""
    import db

    await db.init_db()
    rid = await db.create_oauth_resume_pending(
        "U7", "C1", None, "/susan something granola-dependent", "doc", "granola"
    )
    # Wrong provider -> None (won't accidentally consume across providers).
    assert await db.consume_oauth_resume_pending(rid, "U7", "github") is None
    row = await db.consume_oauth_resume_pending(rid, "U7", "granola")
    assert row is not None
    assert row["action"] == "doc"
    assert row["command_text"] == "/susan something granola-dependent"
    # Already consumed.
    assert await db.consume_oauth_resume_pending(rid, "U7", "granola") is None
