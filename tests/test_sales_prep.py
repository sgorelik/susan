"""Unit tests for sales prep command parsing (no external API calls)."""
from __future__ import annotations

from app.config import ACTIONS
from app.sales_prep import extract_search_terms, parse_sales_prep_command


def test_parse_sales_prep_command_primary() -> None:
    assert parse_sales_prep_command("prep me for a sales call with Acme Corp") == "Acme Corp"
    assert parse_sales_prep_command("prep for a sales call with HSBC") == "HSBC"
    assert parse_sales_prep_command("Prep Me For A Sales Call With Jane Doe at BigBank") == (
        "Jane Doe at BigBank"
    )


def test_parse_sales_prep_command_alternates() -> None:
    assert parse_sales_prep_command("sales prep Acme Corp") == "Acme Corp"
    assert parse_sales_prep_command("sales prep for a call with NATO") == "NATO"
    assert parse_sales_prep_command("prep sales call with CoreWeave") == "CoreWeave"
    assert parse_sales_prep_command("prep sales with FinTech sector") == "FinTech sector"


def test_parse_sales_prep_command_rejects_unrelated() -> None:
    assert parse_sales_prep_command("weekly status") is None
    assert parse_sales_prep_command("prep the deck") is None
    assert parse_sales_prep_command("") is None


def test_sales_prep_not_matched_by_detect_action() -> None:
    assert ACTIONS["sales_prep"][1] == []
    # "prep" contains substring "pr" — explicit parser in routes.py runs before detect_action.
    assert parse_sales_prep_command("prep me for a sales call with Acme") == "Acme"


def test_extract_search_terms() -> None:
    terms = extract_search_terms("Jane Smith at Acme Corp")
    assert "Jane Smith at Acme Corp" in terms
    assert "Jane Smith" in terms
    assert "Acme Corp" in terms
    assert "Acme" in terms


def test_doc_name_relevance_scoring() -> None:
    from app.sales_prep import doc_name_relevance_score, is_sales_relevant_filename

    assert is_sales_relevant_filename("F1 GTM Deck", [])
    assert doc_name_relevance_score("F1 GTM Deck", []) >= 4
    assert doc_name_relevance_score("Acme Corp — qualification", ["Acme Corp"]) >= 12
    assert not is_sales_relevant_filename("Team lunch notes", ["Acme"])
    assert is_sales_relevant_filename("Acme discovery call notes", ["Acme"])


def test_cap_sales_prep_context() -> None:
    from app.sales_prep import _cap_sales_prep_context

    docs = "D" * 50_000
    granola = "G" * 1000
    d, g = _cap_sales_prep_context(docs, granola, 10_000)
    assert len(d) + len(g) <= 10_500
    assert "truncated" in d or "omitted" in d


def test_parse_prep_response_new_shape() -> None:
    from app.sales_prep import _parse_prep_response

    raw = """
    {
      "tldr_slack": "• *Who:* Acme Corp\\n• *Angle:* sovereign inference",
      "talking_points": ["Lead with data residency", "Ask about GPU workload"],
      "action_items": ["Pull F1 deck", "Confirm decision maker"],
      "sections": [
        {"title": "Company context", "body": "Acme is a fintech."},
        {"title": "F1 fit", "body": "Strong fit for regulated workloads."}
      ]
    }
    """
    parsed = _parse_prep_response(raw)
    assert "Acme Corp" in parsed["tldr_slack"]
    assert len(parsed["talking_points"]) == 2
    assert len(parsed["action_items"]) == 2
    assert len(parsed["sections"]) == 2


def test_parse_prep_response_legacy_topics_fallback() -> None:
    from app.sales_prep import _parse_prep_response

    raw = """
    {
      "tldr": "Quick summary",
      "talking_points": ["Point A"],
      "action_items": ["Task 1"],
      "topics": [{"title": "Section", "body": "Details here."}]
    }
    """
    parsed = _parse_prep_response(raw)
    assert parsed["tldr_slack"] == "Quick summary"
    assert parsed["sections"][0]["title"] == "Section"


def test_format_sales_prep_doc_content() -> None:
    from app.sales_prep import format_sales_prep_doc_content

    parsed = {
        "tldr_slack": "• Key insight",
        "talking_points": ["Lead with F1", "Ask about compliance"],
        "action_items": ["Send deck", "Book follow-up"],
        "sections": [{"title": "Company", "body": "Large enterprise."}],
    }
    doc = format_sales_prep_doc_content("Acme Corp", parsed)
    assert "Sales Call Prep — Acme Corp" in doc
    assert "▸ TALKING POINTS" in doc
    assert "▸ ACTION ITEMS" in doc
    assert "☐ Send deck" in doc
    assert "1. Lead with F1" in doc
    assert "DETAILED BRIEF" in doc
    assert "COMPANY" in doc


def test_format_sales_prep_slack_message() -> None:
    from app.sales_prep import format_sales_prep_slack_message, format_sales_prep_slack_payload

    parsed = {
        "tldr_slack": "• *Who:* Acme",
        "talking_points": [],
        "action_items": [],
        "sections": [],
    }
    doc_url = "https://docs.google.com/document/d/abc/edit"
    msg = format_sales_prep_slack_message("Acme Corp", parsed, doc_url)
    assert "Acme Corp" in msg
    assert doc_url in msg

    fallback, blocks = format_sales_prep_slack_payload("Acme Corp", parsed, doc_url)
    assert doc_url in fallback
    assert len(blocks) >= 2
    first_text = blocks[0]["text"]["text"]
    assert "<https://docs.google.com/document/d/abc/edit|Open full brief in Google Docs>" in first_text
    assert doc_url in first_text
