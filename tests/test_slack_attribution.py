"""Attribution footer on Slack messages."""
from __future__ import annotations

from unittest.mock import patch

from app.config import F1_ATTRIBUTION
from app.slack_api import _append_attribution


def test_skip_sovereign_attribution_when_f1_active() -> None:
    with patch("app.slack_api.f1_model_active", return_value=True):
        text, blocks = _append_attribution(
            "Hello", None, skip_sovereign_attribution=True
        )
    assert text == "Hello"
    assert blocks is None
    assert F1_ATTRIBUTION not in (text or "")


def test_commercial_footer_overrides_sovereign() -> None:
    with patch("app.slack_api.f1_model_active", return_value=True):
        text, _ = _append_attribution(
            "Brief ready",
            None,
            commercial_footer="Prepared with Claude Opus via Susan",
        )
    assert "Prepared with Claude Opus via Susan" in (text or "")
    assert F1_ATTRIBUTION not in (text or "")
