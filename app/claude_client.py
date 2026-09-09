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
from app.model_routing import is_commercial_action, resolve_model, route_for_action


class ModelCompletion(str):
    """Completion text annotated with the route and model that actually served it."""

    model_route: str
    model_name: str | None

    def __new__(
        cls, text: str, *, model_route: str, model_name: str | None = None
    ) -> ModelCompletion:
        value = super().__new__(cls, text)
        value.model_route = model_route
        value.model_name = model_name
        return value


async def _call_f1_sovereign(
    system: str, user: str, max_tokens: int | None = None
) -> tuple[str, str]:
    """Call the self-hosted FrontierOne model via its OpenAI-compatible endpoint.

    Returns (text, served_model). The served model is read back from the response
    so attribution reflects what answered, not what we asked for.
    """
    url = f"{F1_MODEL_BASE_URL}/chat/completions"
    headers = {"content-type": "application/json"}
    if F1_MODEL_API_KEY:
        headers["Authorization"] = f"Bearer {F1_MODEL_API_KEY}"
    if len(user) > F1_MODEL_MAX_PROMPT_CHARS:
        user = "[earlier context truncated]\n" + user[-F1_MODEL_MAX_PROMPT_CHARS:]
    req_max = max_tokens if max_tokens is not None else F1_MODEL_MAX_COMPLETION_TOKENS
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
                text = data["choices"][0]["message"]["content"]
                served_model = str(data.get("model") or "").strip() or F1_MODEL_NAME
                return text, served_model
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
            "ANTHROPIC_API_KEY is not set. Commercial-routed commands require Anthropic; "
            "sovereign-routed commands need F1_MODEL_BASE_URL."
        )
    max_attempts = max(1, min(8, int(os.environ.get("ANTHROPIC_MAX_RETRIES", "5"))))
    base_delay = max(1.0, float(os.environ.get("ANTHROPIC_RETRY_DELAY_SECONDS", "2")))
    last_data: dict = {}
    last_status = 0
    last_text = ""

    model = resolve_model(action=action, model_route=model_route)
    logger.info("Anthropic request model=%s action=%s route=%s", model, action, model_route)
    if action == "sales_prep":
        read_timeout = float(os.environ.get("SALES_PREP_ANTHROPIC_TIMEOUT_SECONDS", "300"))
    elif is_commercial_action(action, model_route):
        read_timeout = float(os.environ.get("ANTHROPIC_COMMERCIAL_TIMEOUT_SECONDS", "180"))
    else:
        read_timeout = float(os.environ.get("ANTHROPIC_TIMEOUT_SECONDS", "120"))
    http_timeout = httpx.Timeout(30.0, read=read_timeout)
    for attempt in range(max_attempts):
        try:
            async with httpx.AsyncClient(timeout=http_timeout) as client:
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
        except httpx.TimeoutException as e:
            last_status = 0
            last_text = f"timed out: {e}"
            last_data = {}
            logger.error(
                "Anthropic timeout action=%s attempt=%s/%s",
                action,
                attempt + 1,
                max_attempts,
            )
            if attempt >= max_attempts - 1:
                break
            delay = min(base_delay * (2**attempt), 60.0)
            await asyncio.sleep(delay)
            continue
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

    if last_status == 0 and "timed out" in (last_text or "").lower():
        raise RuntimeError(
            "Claude request timed out. Try again — or ask an admin to raise "
            "SALES_PREP_ANTHROPIC_TIMEOUT_SECONDS for large briefs."
        )
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
) -> ModelCompletion:
    """Route the request and return text annotated with the route actually used."""
    requested_route = (model_route or route_for_action(action)).strip().lower()
    if is_commercial_action(action, requested_route):
        model = resolve_model(action=action, model_route="commercial")
        logger.info(
            "LLM route: commercial Anthropic (action=%s model=%s)", action, model
        )
        text = await _call_anthropic(
            system, user, max_tokens, action=action, model_route="commercial"
        )
        return ModelCompletion(text, model_route="commercial", model_name=model)
    if requested_route in ("sovereign", "local") and f1_model_active():
        text, served_model = await _call_f1_sovereign(system, user, max_tokens)
        logger.info(
            "LLM route: F1 sovereign (action=%s model=%s)", action, served_model
        )
        return ModelCompletion(text, model_route="sovereign", model_name=served_model)
    default_model = resolve_model(action=action, model_route=model_route)
    logger.info(
        "LLM route: default Anthropic (action=%s model=%s)", action, default_model
    )
    text = await _call_anthropic(
        system, user, max_tokens, action=action, model_route=model_route
    )
    return ModelCompletion(text, model_route="commercial", model_name=default_model)
