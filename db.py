"""Persistent store for per-Slack-user OAuth tokens (Google, GitHub, Granola).

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
from sqlalchemy import String, Text, DateTime, Integer
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


class GranolaToken(Base):
    """Per-Slack-user Granola OAuth access token.

    Mirrors ``GithubToken`` exactly: no refresh token handling for now (Granola refresh
    token support is an open question — see ``app/oauth.py``). Each user must
    authenticate their own Granola account; there is no shared/fallback token.
    """

    __tablename__ = "granola_tokens"

    slack_user_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
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
    """Remembers a /susan command so we can continue it after Google/GitHub/Granola OAuth."""

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


class UserDraftPending(Base):
    """Full draft for email/invite/pr_summary — button payloads only store id (Slack 2000-char limit)."""

    __tablename__ = "user_draft_pending"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    slack_user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ActionItemDigest(Base):
    """Posted action-item roundup in a channel; thread replies update tracked items."""

    __tablename__ = "action_item_digests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    channel_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    message_ts: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    thread_root_ts: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_by_slack_user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    range_label: Mapped[str] = mapped_column(String(240), nullable=False)
    since_d: Mapped[str] = mapped_column(String(10), nullable=False)
    until_d: Mapped[str] = mapped_column(String(10), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ActionItemRecord(Base):
    """Tracked action item for a channel; status survives across digests."""

    __tablename__ = "action_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    channel_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    assignee_slack_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    status_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    updated_by_slack_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_digest_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ActionItemsRegistry(Base):
    """Single workspace spreadsheet for all action-item channel tabs."""

    __tablename__ = "action_items_registry"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    spreadsheet_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by_slack_user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ActionItemChannelTab(Base):
    """Maps a Slack channel to a tab in the action-items spreadsheet."""

    __tablename__ = "action_item_channel_tabs"

    channel_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    spreadsheet_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tab_title: Mapped[str] = mapped_column(String(100), nullable=False)
    sheet_gid: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


ACTION_ITEMS_REGISTRY_KEY = "default"
ACTION_ITEM_ACTIVE_STATUSES = frozenset({"open", "in_progress"})
ACTION_ITEM_TERMINAL_STATUSES = frozenset({"done", "wont_do"})


def _action_item_row_dict(row: ActionItemRecord) -> dict:
    return {
        "id": row.id,
        "channel_id": row.channel_id,
        "assignee_slack_id": row.assignee_slack_id,
        "text": row.text,
        "status": row.status,
        "status_note": row.status_note,
        "source": row.source,
        "updated_by_slack_user_id": row.updated_by_slack_user_id,
        "last_digest_id": row.last_digest_id,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


async def list_active_action_items(channel_id: str) -> list[dict]:
    """Open and in-progress items for a channel, oldest first."""
    async with SessionLocal() as session:
        from sqlalchemy import select

        q = (
            select(ActionItemRecord)
            .where(
                ActionItemRecord.channel_id == channel_id,
                ActionItemRecord.status.in_(tuple(ACTION_ITEM_ACTIVE_STATUSES)),
            )
            .order_by(ActionItemRecord.created_at.asc())
        )
        rows = (await session.execute(q)).scalars().all()
        return [_action_item_row_dict(r) for r in rows]


async def get_action_item(item_id: str) -> dict | None:
    async with SessionLocal() as session:
        row = await session.get(ActionItemRecord, item_id)
        return _action_item_row_dict(row) if row else None


async def get_digest_for_thread(channel_id: str, thread_ts: str) -> dict | None:
    """Find latest digest whose thread root matches (replies use thread_ts = root)."""
    async with SessionLocal() as session:
        from sqlalchemy import select

        q = (
            select(ActionItemDigest)
            .where(
                ActionItemDigest.channel_id == channel_id,
                ActionItemDigest.thread_root_ts == thread_ts,
            )
            .order_by(ActionItemDigest.created_at.desc())
            .limit(1)
        )
        row = (await session.execute(q)).scalar_one_or_none()
        if not row:
            return None
        return {
            "id": row.id,
            "channel_id": row.channel_id,
            "message_ts": row.message_ts,
            "thread_root_ts": row.thread_root_ts,
            "created_by_slack_user_id": row.created_by_slack_user_id,
            "range_label": row.range_label,
            "since_d": row.since_d,
            "until_d": row.until_d,
            "created_at": row.created_at.isoformat(),
        }


async def list_action_items_for_sheet(channel_id: str) -> list[dict]:
    """All action items for a channel (full audit trail for Sheets export)."""
    async with SessionLocal() as session:
        from sqlalchemy import select

        q = (
            select(ActionItemRecord)
            .where(ActionItemRecord.channel_id == channel_id)
            .order_by(ActionItemRecord.created_at.asc())
        )
        rows = (await session.execute(q)).scalars().all()
        return [_action_item_row_dict(r) for r in rows]


async def get_action_items_registry() -> dict | None:
    async with SessionLocal() as session:
        row = await session.get(ActionItemsRegistry, ACTION_ITEMS_REGISTRY_KEY)
        if not row:
            return None
        return {
            "spreadsheet_id": row.spreadsheet_id,
            "created_by_slack_user_id": row.created_by_slack_user_id,
            "created_at": row.created_at.isoformat(),
        }


async def set_action_items_registry(spreadsheet_id: str, created_by_slack_user_id: str) -> None:
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        row = await session.get(ActionItemsRegistry, ACTION_ITEMS_REGISTRY_KEY)
        if row:
            row.spreadsheet_id = spreadsheet_id
            row.created_by_slack_user_id = created_by_slack_user_id
        else:
            session.add(
                ActionItemsRegistry(
                    id=ACTION_ITEMS_REGISTRY_KEY,
                    spreadsheet_id=spreadsheet_id,
                    created_by_slack_user_id=created_by_slack_user_id,
                    created_at=now,
                )
            )
        await session.commit()


async def get_channel_sheet_tab(channel_id: str) -> dict | None:
    async with SessionLocal() as session:
        row = await session.get(ActionItemChannelTab, channel_id)
        if not row:
            return None
        return {
            "channel_id": row.channel_id,
            "spreadsheet_id": row.spreadsheet_id,
            "tab_title": row.tab_title,
            "sheet_gid": row.sheet_gid,
        }


async def upsert_channel_sheet_tab(
    channel_id: str,
    tab_title: str,
    sheet_gid: int,
    spreadsheet_id: str,
) -> None:
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        row = await session.get(ActionItemChannelTab, channel_id)
        if row:
            row.tab_title = tab_title
            row.sheet_gid = sheet_gid
            row.spreadsheet_id = spreadsheet_id
            row.updated_at = now
        else:
            session.add(
                ActionItemChannelTab(
                    channel_id=channel_id,
                    spreadsheet_id=spreadsheet_id,
                    tab_title=tab_title,
                    sheet_gid=sheet_gid,
                    updated_at=now,
                )
            )
        await session.commit()


async def create_action_item_digest(
    channel_id: str,
    message_ts: str,
    thread_root_ts: str,
    created_by: str,
    range_label: str,
    since_d: str,
    until_d: str,
) -> str:
    did = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        session.add(
            ActionItemDigest(
                id=did,
                channel_id=channel_id,
                message_ts=message_ts,
                thread_root_ts=thread_root_ts,
                created_by_slack_user_id=created_by,
                range_label=range_label,
                since_d=since_d,
                until_d=until_d,
                created_at=now,
            )
        )
        await session.commit()
    return did


async def upsert_action_items(
    channel_id: str,
    items: list[dict],
    *,
    digest_id: str | None = None,
) -> list[dict]:
    """Insert new items or update existing by id. Returns saved rows (active only)."""
    now = datetime.now(timezone.utc)
    saved: list[dict] = []
    async with SessionLocal() as session:
        for it in items:
            iid = (it.get("id") or "").strip()
            text = (it.get("text") or "").strip()
            if not text:
                continue
            status = (it.get("status") or "open").strip().lower()
            if status not in ACTION_ITEM_ACTIVE_STATUSES | ACTION_ITEM_TERMINAL_STATUSES:
                status = "open"
            assignee = (it.get("assignee_slack_id") or "").strip() or None
            source = (it.get("source") or "slack").strip()[:16] or "slack"
            note = (it.get("status_note") or "").strip() or None

            row: ActionItemRecord | None = None
            if iid:
                row = await session.get(ActionItemRecord, iid)
                if row and row.channel_id != channel_id:
                    row = None
            if row:
                row.text = text
                row.assignee_slack_id = assignee
                if it.get("sync_from_sheet"):
                    row.status = status
                elif status in ACTION_ITEM_TERMINAL_STATUSES:
                    row.status = status
                elif row.status in ACTION_ITEM_TERMINAL_STATUSES:
                    pass
                else:
                    row.status = status
                if note:
                    row.status_note = note
                row.source = source
                row.last_digest_id = digest_id
                row.updated_at = now
            else:
                row = ActionItemRecord(
                    id=str(uuid.uuid4()),
                    channel_id=channel_id,
                    assignee_slack_id=assignee,
                    text=text,
                    status=status,
                    status_note=note,
                    source=source,
                    updated_by_slack_user_id=None,
                    last_digest_id=digest_id,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            saved.append(_action_item_row_dict(row))
        await session.commit()
    return saved


async def update_action_item_status(
    item_id: str,
    channel_id: str,
    status: str,
    *,
    note: str | None = None,
    updated_by: str | None = None,
) -> dict | None:
    status = status.strip().lower()
    if status not in ACTION_ITEM_ACTIVE_STATUSES | ACTION_ITEM_TERMINAL_STATUSES:
        return None
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        row = await session.get(ActionItemRecord, item_id)
        if not row or row.channel_id != channel_id:
            return None
        row.status = status
        if note:
            row.status_note = note.strip()[:2000]
        row.updated_by_slack_user_id = updated_by
        row.updated_at = now
        await session.commit()
        return _action_item_row_dict(row)


async def list_action_items_for_digest_display(channel_id: str) -> list[dict]:
    """Active items plus recently closed (last 7 days) for context in replies."""
    async with SessionLocal() as session:
        from sqlalchemy import select

        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        q = (
            select(ActionItemRecord)
            .where(ActionItemRecord.channel_id == channel_id)
            .order_by(ActionItemRecord.created_at.asc())
        )
        rows = (await session.execute(q)).scalars().all()
        out: list[dict] = []
        for r in rows:
            if r.status in ACTION_ITEM_ACTIVE_STATUSES:
                out.append(_action_item_row_dict(r))
            elif r.status in ACTION_ITEM_TERMINAL_STATUSES and _as_utc_aware(r.updated_at) >= cutoff:
                out.append(_action_item_row_dict(r))
        return out


async def create_user_draft(slack_user_id: str, kind: str, content: str) -> str:
    did = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        session.add(
            UserDraftPending(
                id=did,
                slack_user_id=slack_user_id,
                kind=kind,
                content=content,
                created_at=now,
            )
        )
        await session.commit()
    return did


async def get_user_draft(draft_id: str, slack_user_id: str) -> dict | None:
    async with SessionLocal() as session:
        row = await session.get(UserDraftPending, draft_id)
        if not row or row.slack_user_id != slack_user_id:
            return None
        created = _as_utc_aware(row.created_at)
        if datetime.now(timezone.utc) - created > timedelta(hours=2):
            return None
        return {"kind": row.kind, "content": row.content}


async def consume_user_draft(draft_id: str, slack_user_id: str) -> dict | None:
    async with SessionLocal() as session:
        row = await session.get(UserDraftPending, draft_id)
        if not row or row.slack_user_id != slack_user_id:
            return None
        created = _as_utc_aware(row.created_at)
        if datetime.now(timezone.utc) - created > timedelta(hours=2):
            await session.delete(row)
            await session.commit()
            return None
        out = {"kind": row.kind, "content": row.content}
        await session.delete(row)
        await session.commit()
        return out


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
GRANOLA_TOKEN_URL_DEFAULT = "https://api.granola.ai/oauth/token"


def granola_token_url() -> str:
    """Granola token endpoint. Override with ``GRANOLA_TOKEN_URL`` if Granola moves it."""
    return (os.environ.get("GRANOLA_TOKEN_URL") or GRANOLA_TOKEN_URL_DEFAULT).strip() or GRANOLA_TOKEN_URL_DEFAULT


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
    """Return a GitHub token for API calls.

    If ``GITHUB_TOKEN`` is set in the environment, it is used for **every** user
    (single shared identity). Otherwise the token from this Slack user's OAuth
    connect is used. See SECURITY.md before using a shared PAT in multi-user workspaces.
    """
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


async def exchange_granola_code_for_token(code: str, redirect_uri: str) -> dict:
    """Exchange a Granola OAuth ``code`` for an access token.

    Mirrors the GitHub OAuth code exchange; no refresh token is requested or stored
    (Granola refresh token support is an open question for now).
    """
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            granola_token_url(),
            headers={"Accept": "application/json"},
            data={
                "client_id": os.environ["GRANOLA_CLIENT_ID"],
                "client_secret": os.environ["GRANOLA_CLIENT_SECRET"],
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    r.raise_for_status()
    data = r.json()
    if data.get("error"):
        raise ValueError(data.get("error_description", data.get("error", "oauth_error")))
    return data


async def upsert_granola_token(slack_user_id: str, access_token: str) -> None:
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        row = await session.get(GranolaToken, slack_user_id)
        if row:
            row.access_token = access_token
            row.updated_at = now
        else:
            session.add(
                GranolaToken(
                    slack_user_id=slack_user_id,
                    access_token=access_token,
                    created_at=now,
                    updated_at=now,
                )
            )
        await session.commit()


async def user_has_granola_tokens(slack_user_id: str) -> bool:
    """True only if this Slack user has connected their own Granola account.

    There is *no* shared/fallback token: every user must run ``/susan connect granola``.
    """
    async with SessionLocal() as session:
        row = await session.get(GranolaToken, slack_user_id)
        return row is not None


async def get_granola_token(slack_user_id: str) -> str:
    """Return this Slack user's Granola access token, or raise if not connected.

    No shared fallback — each user must authenticate individually. The error message
    instructs the user to run ``/susan connect granola``; callers that want graceful
    degradation should call :func:`user_has_granola_tokens` first and silently skip.
    """
    async with SessionLocal() as session:
        row = await session.get(GranolaToken, slack_user_id)
        if row:
            return row.access_token.strip()
    raise ValueError(
        "Granola is not connected. Run `/susan connect granola` to connect your Granola account."
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
    """Return a valid Google access token for this Slack user, refreshing if needed.

    If ``GOOGLE_ACCESS_TOKEN`` is set, it is used as a global fallback when the user
    has no DB row — same caveats as ``GITHUB_TOKEN``; see SECURITY.md.
    """
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
