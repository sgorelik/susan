"""OAuth state signing and authorize URLs for Google, GitHub, and Granola."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse

from app.config import SLACK_SIGNING_SECRET

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
]

GRANOLA_AUTHORIZE_URL_DEFAULT = "https://api.granola.ai/oauth/authorize"


def oauth_state_secret() -> str:
    return os.environ.get("OAUTH_STATE_SECRET", SLACK_SIGNING_SECRET).strip()


def oauth_state_ttl_seconds() -> int:
    """How long the OAuth link stays valid (default 24h). Override with OAUTH_STATE_TTL_SECONDS."""
    try:
        return max(300, int(os.environ.get("OAUTH_STATE_TTL_SECONDS", "86400")))
    except ValueError:
        return 86400


def make_oauth_state(
    slack_user_id: str,
    channel_id: str | None = None,
    resume_id: str | None = None,
) -> str:
    """Signed state for OAuth (Google/GitHub/Granola). Optional resume_id continues a /susan command after connect."""
    exp = int(time.time()) + oauth_state_ttl_seconds()
    payload: dict = {"u": slack_user_id, "exp": exp}
    if channel_id:
        payload["ch"] = channel_id
    if resume_id:
        payload["rid"] = resume_id
    body = json.dumps(payload, separators=(",", ":")).encode()
    sig = hmac.new(oauth_state_secret().encode(), body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + sig).decode()


def parse_oauth_state(state: str) -> tuple[str, str | None, str | None] | None:
    """Returns (slack_user_id, channel_id_or_none, resume_id_or_none)."""
    try:
        raw = base64.urlsafe_b64decode(state.encode())
        body, sig = raw[:-32], raw[-32:]
        expected = hmac.new(oauth_state_secret().encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(body.decode())
        if payload["exp"] < time.time():
            return None
        uid = payload["u"]
        ch = payload.get("ch")
        if not isinstance(ch, str) or not ch.strip():
            ch = None
        rid = payload.get("rid")
        if not isinstance(rid, str) or not rid.strip():
            rid = None
        return uid, ch, rid
    except Exception:
        return None


def _ensure_url_with_scheme(base: str) -> str:
    """Slack link buttons and mrkdwn links need an absolute URL with a scheme."""
    u = base.strip().rstrip("/")
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u.lstrip("/")
    return u


def public_base_url() -> str:
    explicit = _ensure_url_with_scheme(os.environ.get("PUBLIC_BASE_URL", ""))
    if explicit:
        return explicit
    redir = os.environ.get("GOOGLE_REDIRECT_URI", "")
    if redir.endswith("/auth/google/callback"):
        return _ensure_url_with_scheme(redir[: -len("/auth/google/callback")])
    redir = os.environ.get("GITHUB_REDIRECT_URI", "")
    if redir.endswith("/auth/github/callback"):
        return _ensure_url_with_scheme(redir[: -len("/auth/github/callback")])
    redir = os.environ.get("GRANOLA_REDIRECT_URI", "")
    if redir.endswith("/auth/granola/callback"):
        return _ensure_url_with_scheme(redir[: -len("/auth/granola/callback")])
    return ""


def google_authorize_url(state: str) -> str:
    redirect_uri = os.environ["GOOGLE_REDIRECT_URI"]
    params = {
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


def _google_oauth_configured() -> bool:
    try:
        _ = os.environ["GOOGLE_CLIENT_ID"]
        _ = os.environ["GOOGLE_CLIENT_SECRET"]
        _ = os.environ["GOOGLE_REDIRECT_URI"]
        return True
    except KeyError:
        return False


def _github_oauth_configured() -> bool:
    try:
        _ = os.environ["GITHUB_CLIENT_ID"]
        _ = os.environ["GITHUB_CLIENT_SECRET"]
        _ = os.environ["GITHUB_REDIRECT_URI"]
        return True
    except KeyError:
        return False


def github_authorize_url(state: str) -> str:
    redirect_uri = os.environ["GITHUB_REDIRECT_URI"]
    scope = (os.environ.get("GITHUB_OAUTH_SCOPE") or "repo").strip() or "repo"
    params = {
        "client_id": os.environ["GITHUB_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "state": state,
        "scope": scope,
    }
    return "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)


def _granola_oauth_configured() -> bool:
    """True only if all required Granola OAuth env vars are set.

    ``GRANOLA_REDIRECT_URI`` may be derived from ``PUBLIC_BASE_URL``; both fallbacks
    are accepted so we don't force admins to set redundant variables.
    """
    try:
        _ = os.environ["GRANOLA_CLIENT_ID"]
        _ = os.environ["GRANOLA_CLIENT_SECRET"]
    except KeyError:
        return False
    return bool(granola_redirect_uri())


def granola_redirect_uri() -> str:
    """Return the Granola OAuth redirect URI.

    Prefers ``GRANOLA_REDIRECT_URI``; falls back to ``<PUBLIC_BASE_URL>/auth/granola/callback``
    so admins can configure the host once.
    """
    explicit = (os.environ.get("GRANOLA_REDIRECT_URI") or "").strip()
    if explicit:
        return explicit
    base = public_base_url()
    if base:
        return f"{base}/auth/granola/callback"
    return ""


def granola_authorize_url(state: str) -> str:
    """Build the Granola OAuth authorize URL for this signed state.

    Mirrors the GitHub authorize-URL helper: query string contains ``client_id``,
    ``redirect_uri``, ``response_type``, ``state``, and (optionally) ``scope``.
    The base URL is configurable via ``GRANOLA_AUTHORIZE_URL`` so we can adjust if
    Granola moves its OAuth endpoint.
    """
    redirect_uri = granola_redirect_uri()
    base = (os.environ.get("GRANOLA_AUTHORIZE_URL") or GRANOLA_AUTHORIZE_URL_DEFAULT).strip() or GRANOLA_AUTHORIZE_URL_DEFAULT
    params = {
        "client_id": os.environ["GRANOLA_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": state,
    }
    scope = (os.environ.get("GRANOLA_OAUTH_SCOPE") or "").strip()
    if scope:
        params["scope"] = scope
    return base + "?" + urllib.parse.urlencode(params)
