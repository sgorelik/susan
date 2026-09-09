"""Read-only Google sources for the personal action inbox."""
from __future__ import annotations

import pytest

import app.personal_actions_google as google_actions
from app.oauth import GOOGLE_SCOPES


class Response:
    def __init__(self, status: int, data: dict) -> None:
        self.status_code = status
        self._data = data

    def json(self) -> dict:
        return self._data


@pytest.mark.asyncio
async def test_drive_collector_keeps_only_unresolved_mentions() -> None:
    class Client:
        async def get(self, url: str, **kwargs: object) -> Response:
            if url.endswith("/drive/v3/files"):
                return Response(
                    200,
                    {
                        "files": [
                            {
                                "id": "doc1",
                                "name": "Launch plan",
                                "webViewLink": "https://docs.example/doc1",
                            }
                        ]
                    },
                )
            return Response(
                200,
                {
                    "comments": [
                        {
                            "content": "Stacy, please approve the launch plan",
                            "createdTime": "2026-09-05T12:00:00Z",
                            "resolved": False,
                            "mentionedEmailAddresses": ["stacy@example.com"],
                            "author": {"displayName": "Alex"},
                        },
                        {
                            "content": "Task for someone else",
                            "createdTime": "2026-09-05T12:00:00Z",
                            "resolved": False,
                            "mentionedEmailAddresses": ["other@example.com"],
                            "author": {"displayName": "Alex"},
                        },
                        {
                            "content": "Old resolved task",
                            "createdTime": "2026-09-05T12:00:00Z",
                            "resolved": True,
                            "mentionedEmailAddresses": ["stacy@example.com"],
                            "author": {"displayName": "Alex"},
                        },
                    ]
                },
            )

    text, warning = await google_actions._drive_comment_actions_context(
        Client(),  # type: ignore[arg-type]
        "token",
        "stacy@example.com",
        "2026-09-01",
        "2026-09-08",
    )

    assert warning is None
    assert "approve the launch plan" in text
    assert "someone else" not in text
    assert "resolved task" not in text


@pytest.mark.asyncio
async def test_gmail_missing_read_scope_is_actionable() -> None:
    class Client:
        async def get(self, url: str, **kwargs: object) -> Response:
            return Response(403, {"error": {"message": "insufficient scope"}})

    text, warning = await google_actions._gmail_actions_context(
        Client(),  # type: ignore[arg-type]
        "token",
        "2026-09-01",
        "2026-09-08",
    )

    assert text == ""
    assert "gmail.readonly" in (warning or "")
    assert "Reconnect Google" in (warning or "")


def test_google_oauth_requests_personal_inbox_read_scopes() -> None:
    assert "https://www.googleapis.com/auth/gmail.readonly" in GOOGLE_SCOPES
    assert "https://www.googleapis.com/auth/drive.readonly" in GOOGLE_SCOPES
