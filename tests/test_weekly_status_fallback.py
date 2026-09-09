"""Weekly status should survive optional GitHub enrichment failures."""
from __future__ import annotations

import pytest

import app.weekly_status as weekly
from app.claude_client import ModelCompletion


@pytest.mark.asyncio
async def test_github_failure_still_generates_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        weekly,
        "parse_weekly_status_time_range",
        lambda text: ("2026-09-01", "2026-09-08", "last week"),
    )
    monkeypatch.setattr(weekly, "utc_date_start_slack_ts", lambda date: "123.0")

    async def fake_slack(*args: object, **kwargs: object) -> str:
        return "Monday: shipped the launch.\nFriday: closed follow-ups."

    async def fake_bookmarks(*args: object, **kwargs: object) -> tuple[list, str]:
        return [], ""

    async def fake_drive(*args: object, **kwargs: object) -> str:
        return ""

    async def fake_token(user: str) -> str:
        return "token"

    async def rate_limited(*args: object, **kwargs: object) -> list:
        raise RuntimeError("still rate limited after 4 attempts")

    captured: dict[str, str] = {}

    async def fake_completion(
        system: str,
        prompt: str,
        max_tokens: int | None = None,
        **kwargs: object,
    ) -> ModelCompletion:
        captured["prompt"] = prompt
        return ModelCompletion(
            "Complete weekly digest",
            model_route="sovereign",
            model_name="deepseek-ai-deepseek-v4-a05f5b",
        )

    async def fake_draft(*args: object, **kwargs: object) -> str:
        return "draft-1"

    notices: list[str] = []

    async def fake_notify(
        channel: str,
        user: str,
        text: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        notices.append(text)

    monkeypatch.setattr(weekly, "fetch_slack_channel_history_since", fake_slack)
    monkeypatch.setattr(weekly, "slack_channel_bookmarks_for_weekly", fake_bookmarks)
    monkeypatch.setattr(weekly, "weekly_status_drive_activity_block", fake_drive)
    monkeypatch.setattr(weekly, "get_github_token", fake_token)
    monkeypatch.setattr(weekly, "fetch_merged_prs_for_repo_range", rate_limited)
    monkeypatch.setattr(weekly, "fetch_opened_prs_for_repo_range", rate_limited)
    monkeypatch.setattr(weekly, "fetch_dependabot_alert_stats", rate_limited)
    monkeypatch.setattr(weekly, "call_claude", fake_completion)
    monkeypatch.setattr(weekly, "create_user_draft", fake_draft)
    monkeypatch.setattr(weekly, "notify_user_ephemeral", fake_notify)

    await weekly.process_weekly_status(
        ["Frontier-One/cloud-infra"],
        "last week",
        "C123",
        "C123",
        "U123",
        None,
        None,
        include_github=True,
    )

    assert "GitHub enrichment unavailable" in captured["prompt"]
    assert "Monday: shipped the launch" in captured["prompt"]
    assert notices == [
        "Susan weekly status preview ready (`Frontier-One/cloud-infra`)"
    ]
