"""Route Susan commands to commercial (Anthropic) vs sovereign (F1 self-hosted) models."""
from __future__ import annotations

import os

from app.config import ANTHROPIC_MODEL

# Context-heavy flows that need a large commercial model (not the F1 sovereign instance).
COMMERCIAL_ACTIONS = frozenset(
    {
        "sales_prep",
        "weekly_status",
        "granola_cmd",
        "action_items_cmd",
    }
)

# Default Anthropic model per commercial action (override via env, e.g. SALES_PREP_ANTHROPIC_MODEL).
COMMERCIAL_ACTION_MODELS: dict[str, str] = {
    "sales_prep": "claude-opus-4-6",
    "weekly_status": "claude-opus-4-6",
}


def is_commercial_action(action: str | None, model_route: str | None = None) -> bool:
    if (model_route or "").strip().lower() == "commercial":
        return True
    return action in COMMERCIAL_ACTIONS


def route_for_action(action: str | None) -> str:
    """Return ``commercial`` or ``default`` for the given slash-command action key."""
    if action in COMMERCIAL_ACTIONS:
        return "commercial"
    mode = (os.environ.get("SUSAN_DEFAULT_MODEL_ROUTE") or "default").strip().lower()
    if mode in ("sovereign", "local"):
        return "sovereign"
    return "default"


def resolve_model(*, action: str | None = None, model_route: str | None = None) -> str:
    """Pick the model id for an Anthropic Messages API call."""
    route = (model_route or route_for_action(action)).strip().lower()
    default_model = (os.environ.get("ANTHROPIC_MODEL") or ANTHROPIC_MODEL).strip()
    if route == "commercial":
        if action and action in COMMERCIAL_ACTION_MODELS:
            env_key = f"{action.upper()}_ANTHROPIC_MODEL"
            override = (os.environ.get(env_key) or "").strip()
            if override:
                return override
            return COMMERCIAL_ACTION_MODELS[action]
        return (os.environ.get("ANTHROPIC_COMMERCIAL_MODEL") or default_model).strip()
    if route in ("sovereign", "local"):
        sovereign = (os.environ.get("SOVEREIGN_MODEL") or "").strip()
        if sovereign:
            return sovereign
        return default_model
    return default_model
