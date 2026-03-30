"""Persistent store for per-Slack-user OAuth tokens (Google, GitHub).

Uses PostgreSQL when DATABASE_URL is set (e.g. Railway Postgres). Otherwise uses a
local SQLite file (async via aiosqlite) so refresh tokens survive process restarts.

Pure in-memory storage is not used: it would drop every token on redeploy/cold start
and force users to re-run /susan connect constantly.

On Railway without Postgres: mount a volume (e.g. /data) and set SQLITE_PATH=/data/susan.db
so the database survives redeploys. Ephemeral disk alone loses the file on each deploy.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from sqlalchemy import String, Text, DateTime
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _async_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return "postgresql+asyncpg://" + url[len("postgres://") :]
    if url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        return "postgresql+asyncpg://" + url[len("postgresql://") :]
    return url


def _postgres_connect_args(url: str) -> dict:
    u = url.lower()
    if "localhost" in u or "127.0.0.1" in u:
        return {}
    return {"ssl": True}


def _sqlite_path() -> str:
    explicit = os.environ.get("SQLITE_PATH", "").strip()
    if explicit:
        return os.path.expanduser(explicit)
    return str(Path(__file__).resolve().parent / "data" / "susan.db")


def _build_engine():
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url:
        return create_async_engine(
            _async_database_url(database_url),
            echo=False,
            connect_args=_postgres_connect_args(database_url),
        )
    path = Path(_sqlite_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    abs_path = path.resolve().as_posix()
    return create_async_engine(
        f"sqlite+aiosqlite:///{abs_path}",
        echo=False,
    )


def normalize_google_access_token(raw: str) -> str:
    """Return a bare OAuth access token. Accepts JSON blobs from OAuth Playground pasted into env."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if '"access_token"' in raw or "'access_token'" in raw:
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and data.get("access_token"):
                return str(data["access_token"]).strip()
        except json.JSONDecodeError:
            pass
    t = raw
    if t.lower().startswith("bearer "):
        t = t[7:].strip()
    # Drop anything after a newline (illegal in HTTP headers)
    t = t.split("\n")[0].strip().strip('"').strip("'")
    return t


def _as_utc_aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes for timezone=True columns; comparisons need UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


DATABASE_URL = os.environ.get("DATABASE_URL", "")
engine = _build_engine()
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


class GoogleToken(Base):
    __tablename__ = "google_tokens"

    slack_user_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GithubToken(Base):
    """Per-Slack-user GitHub OAuth user access token (no refresh in standard GitHub OAuth app flow)."""

    __tablename__ = "github_tokens"

    slack_user_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RepoPickPending(Base):
    """Short-lived state for GitHub repo picker (Slack button value size limits)."""

    __tablename__ = "repo_pick_pending"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    slack_user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    channel_id: Mapped[str] = mapped_column(String(32), nullable=False)
    thread_ts: Mapped[str | None] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    command_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def create_repo_pick_pending(
    slack_user_id: str,
    channel_id: str,
    thread_ts: str | None,
    kind: str,
    command_text: str,
) -> str:
    pick_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        session.add(
            RepoPickPending(
                id=pick_id,
                slack_user_id=slack_user_id,
                channel_id=channel_id,
                thread_ts=thread_ts,
                kind=kind,
                command_text=command_text,
                created_at=now,
            )
        )
        await session.commit()
    return pick_id


async def consume_repo_pick_pending(pick_id: str, slack_user_id: str) -> dict | None:
    """Load and delete pending row if it matches the user and is not expired (~2h)."""
    async with SessionLocal() as session:
        row = await session.get(RepoPickPending, pick_id)
        if not row or row.slack_user_id != slack_user_id:
            return None
        created = _as_utc_aware(row.created_at)
        if datetime.now(timezone.utc) - created > timedelta(hours=2):
            await session.delete(row)
            await session.commit()
            return None
        out = {
            "channel_id": row.channel_id,
            "thread_ts": row.thread_ts,
            "kind": row.kind,
            "command_text": row.command_text,
        }
        await session.delete(row)
        await session.commit()
        return out


class OauthResumePending(Base):
    """Remembers a /susan command so we can continue it after Google/GitHub OAuth."""

    __tablename__ = "oauth_resume_pending"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    slack_user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    command_text: Mapped[str] = mapped_column(Text, nullable=False)
    channel_id: Mapped[str] = mapped_column(String(32), nullable=False)
    thread_ts: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


async def create_oauth_resume_pending(
    slack_user_id: str,
    channel_id: str,
    thread_ts: str | None,
    command_text: str,
    action: str,
    provider: str,
) -> str:
    rid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        session.add(
            OauthResumePending(
                id=rid,
                slack_user_id=slack_user_id,
                provider=provider,
                action=action,
                command_text=command_text,
                channel_id=channel_id,
                thread_ts=thread_ts,
                created_at=now,
            )
        )
        await session.commit()
    return rid


async def consume_oauth_resume_pending(
    resume_id: str, slack_user_id: str, provider: str
) -> dict | None:
    async with SessionLocal() as session:
        row = await session.get(OauthResumePending, resume_id)
        if not row or row.slack_user_id != slack_user_id or row.provider != provider:
            return None
        created = _as_utc_aware(row.created_at)
        if datetime.now(timezone.utc) - created > timedelta(hours=24):
            await session.delete(row)
            await session.commit()
            return None
        out = {
            "slack_user_id": row.slack_user_id,
            "action": row.action,
            "command_text": row.command_text,
            "channel_id": row.channel_id,
            "thread_ts": row.thread_ts,
        }
        await session.delete(row)
        await session.commit()
        return out


GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"


async def exchange_github_code_for_token(code: str, redirect_uri: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": os.environ["GITHUB_CLIENT_ID"],
                "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
    r.raise_for_status()
    data = r.json()
    if data.get("error"):
        raise ValueError(data.get("error_description", data.get("error", "oauth_error")))
    return data


async def upsert_github_token(slack_user_id: str, access_token: str) -> None:
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        row = await session.get(GithubToken, slack_user_id)
        if row:
            row.access_token = access_token
            row.updated_at = now
        else:
            session.add(
                GithubToken(
                    slack_user_id=slack_user_id,
                    access_token=access_token,
                    updated_at=now,
                )
            )
        await session.commit()


async def user_has_github_tokens(slack_user_id: str) -> bool:
    if (os.environ.get("GITHUB_TOKEN") or "").strip():
        return True
    async with SessionLocal() as session:
        row = await session.get(GithubToken, slack_user_id)
        return row is not None


async def get_github_token(slack_user_id: str) -> str:
    """Env GITHUB_TOKEN wins; else stored OAuth token for this Slack user."""
    env = (os.environ.get("GITHUB_TOKEN") or "").strip()
    if env:
        return env
    async with SessionLocal() as session:
        row = await session.get(GithubToken, slack_user_id)
        if row:
            return row.access_token.strip()
    raise ValueError(
        "GitHub is not connected. Type `/susan connect github` in Slack to link your account."
    )


async def _refresh_access_token(refresh_token: str) -> tuple[str, int]:
    client_id = os.environ["GOOGLE_CLIENT_ID"]
    client_secret = os.environ["GOOGLE_CLIENT_SECRET"]
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
        )
    r.raise_for_status()
    data = r.json()
    return data["access_token"], int(data.get("expires_in", 3600))


async def exchange_code_for_tokens(code: str, redirect_uri: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": os.environ["GOOGLE_CLIENT_ID"],
                "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    r.raise_for_status()
    return r.json()


async def upsert_tokens(slack_user_id: str, access_token: str, refresh_token: str, expires_in: int) -> None:
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        row = await session.get(GoogleToken, slack_user_id)
        if row:
            row.access_token = access_token
            row.refresh_token = refresh_token
            row.expires_at = expires_at
            row.updated_at = now
        else:
            session.add(
                GoogleToken(
                    slack_user_id=slack_user_id,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    expires_at=expires_at,
                    updated_at=now,
                )
            )
        await session.commit()


async def user_has_google_tokens(slack_user_id: str) -> bool:
    """True if env fallback or a DB row exists for this Slack user."""
    if normalize_google_access_token(os.environ.get("GOOGLE_ACCESS_TOKEN", "")):
        return True
    async with SessionLocal() as session:
        row = await session.get(GoogleToken, slack_user_id)
        return row is not None


async def get_valid_access_token(slack_user_id: str) -> str:
    """Return a valid Google access token for this Slack user, refreshing if needed."""
    env_fallback = normalize_google_access_token(os.environ.get("GOOGLE_ACCESS_TOKEN", ""))
    async with SessionLocal() as session:
        row = await session.get(GoogleToken, slack_user_id)
        if not row:
            if env_fallback:
                return env_fallback
            raise ValueError("Google is not connected. Type `/susan connect` in Slack to link your account.")

        buffer = timedelta(minutes=2)
        expires_at = _as_utc_aware(row.expires_at)
        if expires_at > datetime.now(timezone.utc) + buffer:
            return normalize_google_access_token(row.access_token)

        new_access, expires_in = await _refresh_access_token(row.refresh_token)
        row.access_token = new_access
        row.expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        row.updated_at = datetime.now(timezone.utc)
        await session.commit()
        return new_access
