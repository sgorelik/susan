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
