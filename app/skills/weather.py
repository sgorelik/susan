"""Weather lookup for the ``weather.current`` handler.

Talks to a configured JSON weather API (defaults to a WeatherAPI.com-style
endpoint). Any transport, status or shape problem is surfaced as
``WeatherUnavailable`` so the skill can return a graceful message.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from app.config import logger


class WeatherUnavailable(Exception):
    """Raised when the weather service cannot be reached or returned bad data."""


@dataclass
class Weather:
    location: str
    conditions: str
    temperature: str


def _api_url() -> str:
    return (os.environ.get("WEATHER_API_URL") or "https://api.weatherapi.com/v1/current.json").strip()


def _api_key() -> str:
    return (os.environ.get("WEATHER_API_KEY") or "").strip()


def _default_query() -> str:
    # "auto:ip" lets the provider geolocate; overridable once a precise location
    # is available from the device/location service.
    return (os.environ.get("WEATHER_DEFAULT_LOCATION") or "auto:ip").strip()


def _parse_current(payload: dict) -> Weather:
    """Map a WeatherAPI.com-style payload to our normalised ``Weather``."""
    try:
        location = str(payload["location"]["name"])
        current = payload["current"]
        conditions = str(current["condition"]["text"])
        temp_c = current["temp_c"]
        temperature = f"{round(float(temp_c))}°C"
    except (KeyError, TypeError, ValueError) as exc:
        raise WeatherUnavailable("unexpected weather API response") from exc
    return Weather(location=location, conditions=conditions, temperature=temperature)


class WeatherClient:
    """Fetches current conditions from the configured weather API."""

    def __init__(self, api_url: str | None = None, api_key: str | None = None) -> None:
        self._api_url = api_url
        self._api_key = api_key

    async def current(self, location: str | None = None) -> Weather:
        """Return current weather for ``location`` (default: provider geolocation)."""
        url = self._api_url or _api_url()
        key = self._api_key if self._api_key is not None else _api_key()
        if not key:
            raise WeatherUnavailable("weather API key is not configured")
        params = {"key": key, "q": location or _default_query()}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                payload = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("Weather API request failed: %s", exc)
            raise WeatherUnavailable(str(exc)) from exc
        return _parse_current(payload)
