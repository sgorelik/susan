"""Tests for splitting long bodies into Slack section blocks."""
from __future__ import annotations

from app.slack_api import split_for_slack_sections


def test_short_body_stays_one_section() -> None:
    assert split_for_slack_sections("*Platform*\n- shipped", 2800) == ["*Platform*\n- shipped"]


def test_split_never_cuts_mid_word() -> None:
    body = "*Inference platform (<@U123>)*\n- Shipped a change that improves latency.\n" * 60
    parts = split_for_slack_sections(body.strip(), 2800)
    assert len(parts) > 1
    for part in parts:
        assert len(part) <= 2800
        assert part == part.strip()
        for line in part.splitlines():
            assert line in ("*Inference platform (<@U123>)*", "- Shipped a change that improves latency.")


def test_split_keeps_slack_markup_intact() -> None:
    line = "- see <https://github.com/o/r/pull/1|PR #1> and *bold text* here\n"
    parts = split_for_slack_sections((line * 80).strip(), 2800)
    assert len(parts) > 1
    for part in parts:
        assert part.count("<") == part.count(">")
        assert part.count("*") % 2 == 0


def test_overlong_single_line_splits_on_whitespace() -> None:
    parts = split_for_slack_sections("word " * 1000, 200)
    assert all(len(p) <= 200 for p in parts)
    assert all(set(p.split()) == {"word"} for p in parts)


def test_blank_input_yields_no_sections() -> None:
    assert split_for_slack_sections("   \n\n  ", 2800) == []
