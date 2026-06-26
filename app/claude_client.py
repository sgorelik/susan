"""LLM client: Anthropic (commercial) or self-hosted FrontierOne sovereign model."""
from __future__ import annotations

import asyncio
import json
import os

import httpx

from app.config import (
    ANTHROPIC_API_KEY,
    F1_MODEL_API_KEY,
    F1_MODEL_BASE_URL,
    F1_MODEL_MAX_COMPLETION_TOKENS,
    F1_MODEL_MAX_PROMPT_CHARS,
    F1_MODEL_NAME,
    f1_model_active,
    logger,
)
from app.model_routing import resolve_model, route_for_action


async def _call_f1_sovereign(system: str, user: str, max_tokens: int | None = None) -> str:
    """Call the self-hosted FrontierOne model via its OpenAI-compatible endpoint.

    Used for light commands when F1_MODEL_BASE_URL is set. Same (system, user) -> text
    contract as call_claude.
    """
    url = f"{F1_MODEL_BASE_URL}/chat/completions"
    headers = {"content-type": "application/json"}
    if F1_MODEL_API_KEY:
        headers["Authorization"] = f"Bearer {F1_MODEL_API_KEY}"
    if len(user) > F1_MODEL_MAX_PROMPT_CHARS:
        user = "[earlier context truncated]\n" + user[-F1_MODEL_MAX_PROMPT_CHARS:]
    req_max = max_tokens if max_tokens is not None else 1500
    body = {
        "model": F1_MODEL_NAME,
        "max_tokens": min(req_max, F1_MODEL_MAX_COMPLETION_TOKENS),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    max_attempts = max(1, min(8, int(os.environ.get("F1_MODEL_MAX_RETRIES", "4"))))
    base_delay = max(1.0, float(os.environ.get("F1_MODEL_RETRY_DELAY_SECONDS", "2")))
    last = ""
    for attempt in range(max_attempts):
        async with httpx.AsyncClient(timeout=180) as client:
            r = await client.post(url, headers=headers, json=body)
        if r.status_code < 400:
            try:
                data = r.json()
                return data["choices"][0]["message"]["content"]
            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                logger.error("Unexpected F1 model response: %s", r.text[:500])
                raise RuntimeError("Unexpected response from FrontierOne model")
        last = f"HTTP {r.status_code}: {r.text[:300]}"
        logger.error("F1 sovereign model %s", last)
        if r.status_code < 500 and r.status_code != 429:
            break
        if attempt >= max_attempts - 1:
            break
        await asyncio.sleep(min(base_delay * (2**attempt), 30.0))
    raise RuntimeError(f"FrontierOne model error ({last or 'unreachable'})")


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


async def _call_anthropic(
    system: str,
    user: str,
    max_tokens: int | None,
    *,
    action: str | None = None,
    model_route: str | None = None,
) -> str:
    if not ANTHROPIC_API_KEY:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Context-heavy commands (sales prep, weekly status, "
            "Granola, action items) require Anthropic; light commands need F1_MODEL_BASE_URL "
            "or an Anthropic key."
        )
    max_attempts = max(1, min(8, int(os.environ.get("ANTHROPIC_MAX_RETRIES", "5"))))
    base_delay = max(1.0, float(os.environ.get("ANTHROPIC_RETRY_DELAY_SECONDS", "2")))
    last_data: dict = {}
    last_status = 0
    last_text = ""

    model = resolve_model(action=action, model_route=model_route)
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
                    "model": model,
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


async def call_claude(
    system: str,
    user: str,
    max_tokens: int | None = None,
    *,
    action: str | None = None,
    model_route: str | None = None,
) -> str:
    """Route to commercial Anthropic or the self-hosted sovereign model."""
    route = (model_route or route_for_action(action)).strip().lower()
    if route == "commercial":
        return await _call_anthropic(
            system, user, max_tokens, action=action, model_route="commercial"
        )
    if f1_model_active():
        return await _call_f1_sovereign(system, user, max_tokens)
    return await _call_anthropic(system, user, max_tokens, action=action, model_route=model_route)
