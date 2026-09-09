"""Keyword-to-action detection for /susan free-text commands."""
from __future__ import annotations

import pytest

from app.slack_api import detect_action


@pytest.mark.parametrize(
    "text",
    [
        "create pr",
        "open pr for this thread",
        "draft a pull request",
        "raise a PR",
    ],
)
def test_real_pr_requests_still_detected(text: str) -> None:
    assert detect_action(text) == "pr"


@pytest.mark.parametrize(
    "text",
    [
        "prepare me for a sales call with Saga",
        "approve the design doc later",  # 'doc' is genuine here, just not a PR
        "summarize the sprint retro",
        "improve the onboarding flow",
        "what is our product priority",
    ],
)
def test_pr_not_matched_inside_longer_words(text: str) -> None:
    """`pr` used to match as a substring of prepare/sprint/improve/product."""
    assert detect_action(text) != "pr"


def test_plurals_still_match() -> None:
    assert detect_action("open some issues") == "issue"
    assert detect_action("send emails to the team") == "email"


def test_unknown_text_returns_none() -> None:
    assert detect_action("what is the weather") is None
    assert detect_action("") is None
