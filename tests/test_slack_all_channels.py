"""Cross-channel Slack history collection for personal actions."""
from __future__ import annotations

import pytest

import app.slack_api as slack


class Response:
    def json(self) -> dict:
        return {
            "ok": True,
            "channels": [
                {"id": "C1", "name": "team-tech", "is_member": True},
                {"id": "C2", "name": "private-sales", "is_member": True},
                {"id": "C3", "name": "not-joined", "is_member": False},
            ],
            "response_metadata": {"next_cursor": ""},
        }


class Client:
    async def __aenter__(self) -> Client:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def get(self, *args: object, **kwargs: object) -> Response:
        return Response()


class MissingScopeResponse:
    def json(self) -> dict:
        return {
            "ok": False,
            "error": "missing_scope",
            "needed": "channels:read",
        }


class MissingScopeClient(Client):
    async def get(self, *args: object, **kwargs: object) -> MissingScopeResponse:
        return MissingScopeResponse()


@pytest.mark.asyncio
async def test_all_channel_scan_only_reads_joined_channels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(slack.httpx, "AsyncClient", lambda **kwargs: Client())

    read: list[str] = []

    async def fake_history(
        channel: str,
        oldest: str,
        user: str,
        *,
        include_thread_replies: bool,
    ) -> str:
        read.append(channel)
        return f"{user}: action in {channel}"

    async def no_sleep(seconds: float) -> None:
        return None

    monkeypatch.setattr(slack, "fetch_slack_channel_history_since", fake_history)
    monkeypatch.setattr(slack.asyncio, "sleep", no_sleep)

    transcript, skipped = await slack.fetch_slack_all_channel_history_since(
        "123.0", "U-ME"
    )

    assert read == ["C1", "C2"]
    assert "#team-tech" in transcript
    assert "#private-sales" in transcript
    assert "not-joined" not in transcript
    assert skipped == []


@pytest.mark.asyncio
async def test_all_channel_scan_explains_missing_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(slack.httpx, "AsyncClient", lambda **kwargs: MissingScopeClient())

    with pytest.raises(RuntimeError, match=r"`channels:read`.*reinstall Susan"):
        await slack.fetch_slack_all_channel_history_since("123.0", "U-ME")
