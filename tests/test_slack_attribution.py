"""Attribution footer on Slack messages."""
from __future__ import annotations

from app.config import F1_ATTRIBUTION
from app.slack_api import _append_attribution


def test_sovereign_route_gets_attribution() -> None:
    text, blocks = _append_attribution("Hello", None, model_route="sovereign")
    assert F1_ATTRIBUTION in (text or "")
    assert blocks is None


def test_commercial_route_does_not_get_sovereign_attribution() -> None:
    text, blocks = _append_attribution("Hello", None, model_route="commercial")
    assert text == "Hello"
    assert blocks is None
    assert F1_ATTRIBUTION not in (text or "")


def test_no_route_does_not_claim_sovereign_attribution() -> None:
    text, _ = _append_attribution("Hello", None)
    assert text == "Hello"
    assert F1_ATTRIBUTION not in (text or "")


def test_commercial_footer_overrides_sovereign() -> None:
    text, _ = _append_attribution(
        "Brief ready",
        None,
        model_route="sovereign",
        commercial_footer="Prepared with Claude Opus via Susan",
    )
    assert "Prepared with Claude Opus via Susan" in (text or "")
    assert F1_ATTRIBUTION not in (text or "")
