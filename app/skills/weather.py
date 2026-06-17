"""Weather lookup for the ``weather`` skill.

The default provider targets an OpenWeatherMap-style API configured via
environment variables. The provider is injectable so tests can supply a fake
without network access.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx


class WeatherError(Exception):
    """Raised when the weather service is unconfigured or unavailable."""


@dataclass(frozen=True)
class WeatherReport:
    location: str
    conditions: str
    temperature: str  # human-readable, e.g. "18\u00b0C"


class WeatherProvider:
    """Fetches current conditions from a configured weather API.

    Configuration (env):
      * ``WEATHER_API_URL`` — endpoint (default OpenWeatherMap current weather).
      * ``WEATHER_API_KEY`` — API key; required, else :class:`WeatherError`.
      * ``WEATHER_DEFAULT_LOCATION`` — fallback when no location is resolved.
      * ``WEATHER_UNITS`` — ``metric`` (default) or ``imperial``.
    """

    async def current(self, location: str | None = None) -> WeatherReport:
        api_key = (os.environ.get("WEATHER_API_KEY") or "").strip()
        if not api_key:
            raise WeatherError("weather service is not configured (missing WEATHER_API_KEY)")

        url = (os.environ.get("WEATHER_API_URL") or "https://api.openweathermap.org/data/2.5/weather").strip()
        query = (location or os.environ.get("WEATHER_DEFAULT_LOCATION") or "").strip()
        if not query:
            raise WeatherError("no location available for weather lookup")
        units = (os.environ.get("WEATHER_UNITS") or "metric").strip().lower()

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    url,
                    params={"q": query, "appid": api_key, "units": units},
                )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # network error, timeout, bad status, bad JSON
            raise WeatherError(str(exc)) from exc

        return _parse_openweathermap(data, units, fallback_location=query)


def _parse_openweathermap(data: dict, units: str, *, fallback_location: str) -> WeatherReport:
    name = data.get("name") or fallback_location
    weather = data.get("weather") or []
    conditions = "Unknown"
    if weather and isinstance(weather[0], dict):
        conditions = (weather[0].get("description") or weather[0].get("main") or "Unknown").strip().capitalize()
    main = data.get("main") or {}
    temp = main.get("temp")
    unit_symbol = "\u00b0F" if units == "imperial" else "\u00b0C"
    temperature = f"{round(float(temp))}{unit_symbol}" if temp is not None else "unknown"
    return WeatherReport(location=name, conditions=conditions, temperature=temperature)
