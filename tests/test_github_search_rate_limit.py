"""Serialization and backoff for GitHub /search/issues."""
from __future__ import annotations

import asyncio

import pytest

import app.github_http as gh


class FakeResponse:
    def __init__(self, status_code: int, payload: dict, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> dict:
        return self._payload


class FakeClient:
    """Records call ordering so overlap between concurrent searches is visible."""

    def __init__(self, responses: list[FakeResponse], log: list[str]) -> None:
        self._responses = responses
        self._log = log

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get(self, url: str, headers: dict, params: dict) -> FakeResponse:
        self._log.append(f"start:{params['q']}")
        await asyncio.sleep(0)
        self._log.append(f"end:{params['q']}")
        return self._responses.pop(0)


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests fast; pacing itself is not what these assert."""
    monkeypatch.setenv("GITHUB_SEARCH_MIN_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(gh, "_SEARCH_LAST_TS", 0.0)


@pytest.mark.asyncio
async def test_searches_do_not_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    log: list[str] = []

    def client_factory(**kwargs: object) -> FakeClient:
        return FakeClient([FakeResponse(200, {"items": []})], log)

    monkeypatch.setattr(gh.httpx, "AsyncClient", client_factory)

    await asyncio.gather(
        gh.search_issues("repo:a", "t"),
        gh.search_issues("repo:b", "t"),
        gh.search_issues("repo:c", "t"),
    )

    # Each request must complete before the next begins.
    assert log == [
        "start:repo:a", "end:repo:a",
        "start:repo:b", "end:repo:b",
        "start:repo:c", "end:repo:c",
    ]


@pytest.mark.asyncio
async def test_secondary_rate_limit_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    log: list[str] = []
    responses = [
        FakeResponse(403, {"message": "You have exceeded a secondary rate limit."},
                     {"retry-after": "1"}),
        FakeResponse(200, {"items": [{"number": 1}]}),
    ]
    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda **kw: FakeClient(responses, log))

    slept: list[float] = []

    async def fake_sleep(s: float) -> None:
        slept.append(s)

    monkeypatch.setattr(gh.asyncio, "sleep", fake_sleep)

    items = await gh.search_issues("repo:a", "t")

    assert items == [{"number": 1}]
    # Ignore the zero-length yields the fake transport performs.
    assert [s for s in slept if s] == [1.0], "should honour Retry-After, not guess"


@pytest.mark.asyncio
async def test_rate_limit_gives_up_with_actionable_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_SEARCH_MAX_RETRIES", "2")
    responses = [
        FakeResponse(403, {"message": "You have exceeded a secondary rate limit."}),
        FakeResponse(403, {"message": "You have exceeded a secondary rate limit."}),
    ]
    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda **kw: FakeClient(responses, []))

    async def fake_sleep(s: float) -> None:
        return None

    monkeypatch.setattr(gh.asyncio, "sleep", fake_sleep)

    with pytest.raises(RuntimeError, match="Wait a few minutes"):
        await gh.search_issues("repo:a", "t")


@pytest.mark.asyncio
async def test_non_rate_limit_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [FakeResponse(422, {"message": "Validation failed"})]
    monkeypatch.setattr(gh.httpx, "AsyncClient", lambda **kw: FakeClient(responses, []))

    with pytest.raises(RuntimeError, match="422"):
        await gh.search_issues("repo:a", "t")
