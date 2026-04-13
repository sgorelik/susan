"""Anthropic Claude API with backoff retries."""
from __future__ import annotations

import asyncio
import json
import os

import httpx

from app.config import ANTHROPIC_API_KEY, logger

def _anthropic_error_payload(data: dict) -> str:
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or err.get("type") or err)
    if err is not None:
        return str(err)
    return str(data)


def _anthropic_is_overloaded(status: int, data: dict) -> bool:
    if status in (503, 529):
        return True
    msg = _anthropic_error_payload(data).lower()
    if "overload" in msg:
        return True
    err = data.get("error")
    if isinstance(err, dict) and "overload" in (err.get("type") or "").lower():
        return True
    return False


def _anthropic_should_retry(status: int, data: dict) -> bool:
    """Transient capacity / rate limits — safe to backoff and retry."""
    if status == 429:
        return True
    if status in (503, 529):
        return True
    if status >= 500:
        return True
    if data.get("type") == "error":
        err = data.get("error")
        if isinstance(err, dict):
            et = (err.get("type") or "").lower()
            em = (err.get("message") or "").lower()
            if "overloaded" in em or "overloaded" in et or "rate_limit" in et:
                return True
    return False


async def call_claude(system: str, user: str, max_tokens: int | None = None) -> str:
    max_attempts = max(1, min(8, int(os.environ.get("ANTHROPIC_MAX_RETRIES", "5"))))
    base_delay = max(1.0, float(os.environ.get("ANTHROPIC_RETRY_DELAY_SECONDS", "2")))
    last_data: dict = {}
    last_status = 0
    last_text = ""

    for attempt in range(max_attempts):
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": max_tokens if max_tokens is not None else 1500,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
            )
        last_status = r.status_code
        last_text = r.text
        try:
            data = r.json()
        except json.JSONDecodeError:
            data = {}
        last_data = data

        if r.status_code < 400 and data.get("type") != "error":
            content = data.get("content") or []
            if content and content[0].get("type") == "text":
                return content[0]["text"]
            logger.error("Unexpected Anthropic response: %s", data)
            raise RuntimeError("Unexpected response from Claude API")

        logger.error("Anthropic HTTP %s: %s", r.status_code, data or last_text)
        if not _anthropic_should_retry(r.status_code, data) or attempt >= max_attempts - 1:
            break
        delay = min(base_delay * (2**attempt), 60.0)
        logger.warning(
            "Anthropic retry %s/%s in %.1fs (transient error)",
            attempt + 2,
            max_attempts,
            delay,
        )
        await asyncio.sleep(delay)

    if _anthropic_is_overloaded(last_status, last_data):
        raise RuntimeError(
            "Claude is temporarily overloaded. Please try again in a minute or two."
        )
    if last_status == 429:
        raise RuntimeError(
            "Claude API rate limit — please wait a bit and try again."
        )
    raise RuntimeError(_anthropic_error_payload(last_data) if last_data else last_text or "Claude API error")
