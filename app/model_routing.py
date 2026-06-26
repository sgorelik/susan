"""Route Susan commands to commercial (Anthropic) vs sovereign (F1 self-hosted) models."""
from __future__ import annotations

import os

from app.config import ANTHROPIC_MODEL

# Context-heavy flows that need a large commercial model (not a local/sovereign one).
COMMERCIAL_ACTIONS = frozenset(
    {
        "sales_prep",
        "weekly_status",
        "granola_cmd",
        "action_items_cmd",
    }
)


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
        return (os.environ.get("ANTHROPIC_COMMERCIAL_MODEL") or default_model).strip()
    if route in ("sovereign", "local"):
        sovereign = (os.environ.get("SOVEREIGN_MODEL") or "").strip()
        if sovereign:
            return sovereign
        return default_model
    return default_model
