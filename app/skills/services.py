"""Dependency container for skill handlers.

Handlers receive a ``Services`` instance so external dependencies (the timer
scheduler, the weather client) can be swapped out in tests.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.skills.timer import TimerService
from app.skills.weather import WeatherClient


@dataclass
class Services:
    timer: TimerService
    weather: WeatherClient


_DEFAULT: Services | None = None


def build_default_services() -> Services:
    """Create the process-wide services using environment-backed clients."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Services(timer=TimerService(), weather=WeatherClient())
    return _DEFAULT
