"""Unit tests for the GitHub GraphQL layer (Projects v2 board reads)."""
from __future__ import annotations

import json

import pytest

import app.github_graphql as gq
from app.github_graphql import (
    GithubGraphQLError,
    GithubProjectScopeError,
    _board_item_from_node,
    _field_value,
    board_write_enabled,
    github_graphql,
)


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | str) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = payload if isinstance(payload, str) else json.dumps(payload)

    def json(self) -> dict:
        if isinstance(self._payload, str):
            raise ValueError("not JSON")
        return self._payload


class _FakeClient:
    """Stands in for httpx.AsyncClient as an async context manager."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def post(self, *args: object, **kwargs: object) -> _FakeResponse:
        return self._response


def _patch_response(monkeypatch, response: _FakeResponse) -> None:
    monkeypatch.setattr(gq.httpx, "AsyncClient", lambda *a, **k: _FakeClient(response))


async def test_graphql_returns_data(monkeypatch) -> None:
    _patch_response(monkeypatch, _FakeResponse(200, {"data": {"organization": {"id": "O_1"}}}))
    data = await github_graphql("query{ x }", {}, "tok")
    assert data == {"organization": {"id": "O_1"}}


async def test_missing_read_project_scope_tells_the_user_how_to_fix_it(monkeypatch) -> None:
    _patch_response(
        monkeypatch,
        _FakeResponse(
            200,
            {"errors": [{"type": "INSUFFICIENT_SCOPES", "message": "requires read:project"}]},
        ),
    )
    with pytest.raises(GithubProjectScopeError) as excinfo:
        await github_graphql("query{ x }", {}, "tok")
    message = str(excinfo.value)
    assert "read:project" in message
    assert "/susan connect github" in message


async def test_http_403_is_treated_as_a_scope_problem(monkeypatch) -> None:
    _patch_response(monkeypatch, _FakeResponse(403, {"message": "Forbidden"}))
    with pytest.raises(GithubProjectScopeError):
        await github_graphql("query{ x }", {}, "tok")


async def test_other_graphql_errors_surface_the_message(monkeypatch) -> None:
    _patch_response(
        monkeypatch,
        _FakeResponse(200, {"errors": [{"type": "NOT_FOUND", "message": "Could not resolve"}]}),
    )
    with pytest.raises(GithubGraphQLError) as excinfo:
        await github_graphql("query{ x }", {}, "tok")
    assert "Could not resolve" in str(excinfo.value)
    assert not isinstance(excinfo.value, GithubProjectScopeError)


def test_field_value_reads_each_project_field_shape() -> None:
    assert _field_value(
        {"__typename": "ProjectV2ItemFieldSingleSelectValue", "name": "Partial", "field": {"name": "Status"}}
    ) == ("Status", "Partial")
    assert _field_value(
        {"__typename": "ProjectV2ItemFieldTextValue", "text": "Augur", "field": {"name": "Customer"}}
    ) == ("Customer", "Augur")
    assert _field_value(
        {"__typename": "ProjectV2ItemFieldNumberValue", "number": 3.0, "field": {"name": "Size"}}
    ) == ("Size", "3")
    assert _field_value({"text": "orphan", "field": {}}) is None


def test_board_item_from_issue_node() -> None:
    node = {
        "id": "PVTI_1",
        "updatedAt": "2026-08-06T09:00:00Z",
        "fieldValues": {
            "nodes": [
                {"name": "Done (dev)", "field": {"name": "Status"}},
                {"name": "W1 prod env", "field": {"name": "Phase"}},
                {"name": "P0", "field": {"name": "Priority"}},
            ]
        },
        "content": {
            "__typename": "Issue",
            "number": 231,
            "title": "Pilot roadmap epic",
            "url": "https://github.com/frontier-one/cloud-infra/issues/231",
            "state": "OPEN",
            "updatedAt": "2026-08-06T09:00:00Z",
            "body": "checklists",
            "repository": {"nameWithOwner": "frontier-one/cloud-infra"},
            "assignees": {"nodes": [{"login": "stacy"}]},
            "labels": {"nodes": [{"name": "roadmap"}]},
        },
    }
    item = _board_item_from_node(node)
    assert item is not None
    assert item.kind == "issue"
    assert item.ref == "cloud-infra#231"
    assert item.project_field("Status") == "Done (dev)"
    assert item.project_field("Priority") == "P0"
    assert item.assignees == ["stacy"]
    assert item.labels == ["roadmap"]


def test_board_item_from_pull_request_and_draft_nodes() -> None:
    pr = _board_item_from_node(
        {
            "fieldValues": {"nodes": []},
            "content": {
                "__typename": "PullRequest",
                "number": 42,
                "title": "Add guardrails",
                "state": "MERGED",
                "merged": True,
                "repository": {"nameWithOwner": "frontier-one/f1-asgardOS"},
            },
        }
    )
    assert pr is not None and pr.kind == "pull_request" and pr.merged

    draft = _board_item_from_node(
        {"fieldValues": {"nodes": []}, "content": {"__typename": "DraftIssue", "title": "Idea"}}
    )
    assert draft is not None and draft.kind == "draft" and draft.number is None


def test_board_item_skips_content_the_token_cannot_see() -> None:
    assert _board_item_from_node({"fieldValues": {"nodes": []}, "content": {}}) is None
    assert _board_item_from_node({}) is None


def test_board_writes_are_opt_in(monkeypatch) -> None:
    monkeypatch.delenv("SUSAN_ROADMAP_BOARD_WRITE", raising=False)
    assert board_write_enabled() is False
    monkeypatch.setenv("SUSAN_ROADMAP_BOARD_WRITE", "true")
    assert board_write_enabled() is True
    monkeypatch.setenv("SUSAN_ROADMAP_BOARD_WRITE", "no")
    assert board_write_enabled() is False
