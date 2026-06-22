"""Tests for action-item context gathering helpers."""
from __future__ import annotations

from app.weekly_drive import extract_plain_text_from_google_doc


def test_extract_plain_text_from_google_doc_paragraphs_and_table() -> None:
    doc = {
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [{"textRun": {"content": "Action items\n"}}],
                    }
                },
                {
                    "table": {
                        "tableRows": [
                            {
                                "tableCells": [
                                    {
                                        "content": [
                                            {
                                                "paragraph": {
                                                    "elements": [
                                                        {"textRun": {"content": "Ship feature"}}
                                                    ],
                                                }
                                            }
                                        ]
                                    },
                                    {
                                        "content": [
                                            {
                                                "paragraph": {
                                                    "elements": [
                                                        {"textRun": {"content": " @alice"}}
                                                    ],
                                                }
                                            }
                                        ]
                                    },
                                ]
                            }
                        ]
                    }
                },
            ]
        }
    }
    text = extract_plain_text_from_google_doc(doc)
    assert "Action items" in text
    assert "Ship feature" in text
    assert "@alice" in text
