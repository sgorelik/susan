"""Tests for the weather skill: success, API error, permissions (Ticket 10)."""
from __future__ import annotations

import pytest

from app.skills import Session
from app.skills.engine import SkillContext, SkillEngine
from app.skills.weather import WeatherError, WeatherReport


class FakeWeatherProvider:
    def __init__(self, report: WeatherReport | None = None, error: Exception | None = None):
        self._report = report
        self._error = error
        self.calls: list[str | None] = []

    async def current(self, location: str | None = None) -> WeatherReport:
        self.calls.append(location)
        if self._error is not None:
            raise self._error
        assert self._report is not None
        return self._report


def _engine(skills, provider) -> SkillEngine:
    return SkillEngine(skills, context=SkillContext(weather=provider))


@pytest.mark.parametrize("utterance", ["what's the weather", "weather today", "is it raining"])
async def test_weather_success(skills, utterance) -> None:
    provider = FakeWeatherProvider(WeatherReport("London", "Cloudy", "18°C"))
    engine = _engine(skills, provider)
    session = Session()
    session.permissions["location"] = "granted"
    reply = await engine.handle(utterance, session)
    assert reply.skill == "weather"
    assert reply.text == "Currently in London: Cloudy, 18°C."


async def test_weather_requests_permission_when_not_granted(skills) -> None:
    provider = FakeWeatherProvider(WeatherReport("London", "Cloudy", "18°C"))
    engine = _engine(skills, provider)
    session = Session()
    reply = await engine.handle("what's the weather", session)
    assert reply.permission_request == "location"
    assert "location" in reply.text.lower()
    assert provider.calls == []  # no API call without permission


async def test_weather_permission_denied(skills) -> None:
    provider = FakeWeatherProvider(WeatherReport("London", "Cloudy", "18°C"))
    engine = _engine(skills, provider)
    session = Session()
    session.permissions["location"] = "denied"
    reply = await engine.handle("what's the weather", session)
    assert provider.calls == []
    assert "location" in reply.text.lower()
    assert "can't" in reply.text.lower()


async def test_weather_api_unavailable(skills) -> None:
    provider = FakeWeatherProvider(error=WeatherError("service down"))
    engine = _engine(skills, provider)
    session = Session()
    session.permissions["location"] = "granted"
    reply = await engine.handle("weather today", session)
    assert "trouble" in reply.text.lower()


async def test_weather_unexpected_error_is_graceful(skills) -> None:
    provider = FakeWeatherProvider(error=RuntimeError("boom"))
    engine = _engine(skills, provider)
    session = Session()
    session.permissions["location"] = "granted"
    reply = await engine.handle("is it raining", session)
    assert "trouble" in reply.text.lower()


def test_weather_declares_requirements(skills) -> None:
    skill = {s.name: s for s in skills}["weather"]
    assert "location" in skill.required_permissions
    assert "weather_service" in skill.required_apis
