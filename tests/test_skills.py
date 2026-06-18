"""Tests for Susan's declarative skill system (set-timer, weather, goodbye)."""
from __future__ import annotations

import asyncio

import pytest

from app.skills import Session, dispatch, get_registry
from app.skills.matcher import match
from app.skills.services import Services
from app.skills.timer import TimerService, parse_duration
from app.skills.weather import Weather, WeatherUnavailable


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #
class FakeWeatherClient:
    def __init__(self, weather: Weather | None = None, fail: bool = False) -> None:
        self._weather = weather or Weather("London", "Cloudy", "18°C")
        self._fail = fail

    async def current(self, location: str | None = None) -> Weather:
        if self._fail:
            raise WeatherUnavailable("boom")
        return self._weather


def make_services(weather: FakeWeatherClient | None = None) -> tuple[Services, list[str]]:
    """Services with an instant timer (no real sleep) recording fired alerts."""
    fired: list[str] = []
    timer = TimerService(notifier=fired.append, sleep=lambda _s: asyncio.sleep(0))
    return Services(timer=timer, weather=weather or FakeWeatherClient()), fired


# --------------------------------------------------------------------------- #
# Registry / loader
# --------------------------------------------------------------------------- #
def test_skills_registered_under_expected_names() -> None:
    registry = get_registry()
    assert set(registry) == {"set-timer", "weather", "goodbye"}


def test_goodbye_is_static_stateless_and_ends_session() -> None:
    skill = get_registry()["goodbye"]
    assert skill.session_end is True
    assert skill.response.dynamic is False
    assert skill.response.text == "Goodbye! Come back anytime."
    assert skill.slots == []
    assert skill.api is None and skill.permission is None


def test_weather_declares_api_and_permission() -> None:
    skill = get_registry()["weather"]
    assert skill.api == "weather_service"
    assert skill.permission == "location"
    assert skill.response.handler == "weather.current"


def test_set_timer_declares_duration_slot_with_prompt() -> None:
    skill = get_registry()["set-timer"]
    assert skill.response.handler == "timer.set"
    assert len(skill.slots) == 1
    slot = skill.slots[0]
    assert slot.name == "duration"
    assert slot.required is True
    assert slot.prompt == "How long should I set the timer for?"


# --------------------------------------------------------------------------- #
# Duration parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text,expected",
    [
        ("5 minutes", 300),
        ("1 hour 30 minutes", 5400),
        ("30 seconds", 30),
        ("2 hours", 7200),
        ("an hour", 3600),
        ("90 secs", 90),
        ("1h", 3600),
        ("30s", 30),
        ("2m", 120),
        ("", None),
        ("banana", None),
    ],
)
def test_parse_duration(text: str, expected: int | None) -> None:
    assert parse_duration(text) == expected


# --------------------------------------------------------------------------- #
# Matcher: triggers, case-insensitivity, slot extraction, elicitation stems
# --------------------------------------------------------------------------- #
def test_match_set_timer_extracts_duration() -> None:
    reg = get_registry()
    result = match("set a timer for 5 minutes", reg.values())
    assert result is not None
    assert result.skill.name == "set-timer"
    assert result.slots["duration"] == "5 minutes"

    result = match("timer for 1 hour 30 minutes", reg.values())
    assert result.skill.name == "set-timer"
    assert result.slots["duration"] == "1 hour 30 minutes"


def test_match_set_timer_without_duration_yields_no_slots() -> None:
    result = match("set a timer", get_registry().values())
    assert result is not None
    assert result.skill.name == "set-timer"
    assert result.slots == {}


@pytest.mark.parametrize(
    "utterance",
    ["what's the weather", "WHAT'S THE WEATHER?", "Weather today", "Is it raining?"],
)
def test_match_weather_is_case_insensitive(utterance: str) -> None:
    result = match(utterance, get_registry().values())
    assert result is not None and result.skill.name == "weather"


@pytest.mark.parametrize(
    "utterance",
    ["goodbye", "Bye Susan", "SEE YOU LATER", "Farewell"],
)
def test_match_goodbye_is_case_insensitive(utterance: str) -> None:
    result = match(utterance, get_registry().values())
    assert result is not None and result.skill.name == "goodbye"


def test_match_returns_none_for_unknown() -> None:
    assert match("make me a sandwich", get_registry().values()) is None


# --------------------------------------------------------------------------- #
# Goodbye skill
# --------------------------------------------------------------------------- #
async def test_goodbye_responds_and_ends_session() -> None:
    session = Session()
    result = await dispatch("Goodbye", session)
    assert result.text == "Goodbye! Come back anytime."
    assert result.session_end is True
    assert session.ended is True


# --------------------------------------------------------------------------- #
# Weather skill
# --------------------------------------------------------------------------- #
async def test_weather_requests_permission_when_not_granted() -> None:
    services, _ = make_services()
    session = Session()
    result = await dispatch("what's the weather", session, services=services)
    assert result.needs_permission == "location"
    assert "permission" in result.text.lower()


async def test_weather_error_when_permission_denied() -> None:
    services, _ = make_services()
    session = Session(permissions={"location": "denied"})
    result = await dispatch("weather today", session, services=services)
    assert result.error is True
    assert "location" in result.text.lower()


async def test_weather_success_includes_location_conditions_temperature() -> None:
    services, _ = make_services(FakeWeatherClient(Weather("London", "Cloudy", "18°C")))
    session = Session(permissions={"location": "granted"})
    result = await dispatch("is it raining", session, services=services)
    assert result.text == "Currently in London: Cloudy, 18°C."
    assert result.error is False


async def test_weather_graceful_error_when_api_unavailable() -> None:
    services, _ = make_services(FakeWeatherClient(fail=True))
    session = Session(permissions={"location": "granted"})
    result = await dispatch("what's the weather", session, services=services)
    assert result.error is True
    assert "weather service" in result.text.lower()


# --------------------------------------------------------------------------- #
# Set-timer skill
# --------------------------------------------------------------------------- #
async def test_set_timer_with_duration_confirms_and_schedules_alert() -> None:
    services, fired = make_services()
    session = Session()
    result = await dispatch("set a timer for 5 minutes", session, services=services)

    assert result.text == "Timer set for 5 minutes. I'll let you know when it's done."
    assert result.data["seconds"] == 300
    assert result.session_end is False

    # The scheduled timer fires its alert when the (instant) delay elapses.
    for task in list(services.timer.active):
        await task
    assert fired == ["Time's up! Your 5 minutes timer is done."]


async def test_set_timer_elicits_missing_duration_then_confirms() -> None:
    services, fired = make_services()
    session = Session()

    elicit = await dispatch("set a timer", session, services=services)
    assert elicit.elicit is True
    assert elicit.text == "How long should I set the timer for?"
    assert session.pending_slot == "duration"

    confirm = await dispatch("10 minutes", session, services=services)
    assert confirm.text == "Timer set for 10 minutes. I'll let you know when it's done."
    assert confirm.data["seconds"] == 600
    assert session.pending_skill is None

    for task in list(services.timer.active):
        await task
    assert fired == ["Time's up! Your 10 minutes timer is done."]


async def test_set_timer_rejects_unparseable_duration() -> None:
    services, _ = make_services()
    session = Session()
    result = await dispatch("set a timer for bananas", session, services=services)
    assert result.error is True
    assert not services.timer.active


# --------------------------------------------------------------------------- #
# Unmatched input
# --------------------------------------------------------------------------- #
async def test_unknown_utterance_is_not_matched() -> None:
    result = await dispatch("tell me a joke", Session())
    assert result.matched is False
