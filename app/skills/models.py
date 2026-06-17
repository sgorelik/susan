"""Core data types for Susan's skill engine.

A *skill* is declared in YAML (see ``app/skills/definitions``) and parsed into a
:class:`Skill`. Skills produce either a *static* response (a fixed string) or a
*dynamic* response delegated to a named handler (see ``handlers.py``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class SkillDefinitionError(ValueError):
    """Raised when a YAML skill definition is missing or malformed."""


@dataclass(frozen=True)
class Slot:
    """A value the skill needs from the user (e.g. the timer ``duration``)."""

    name: str
    type: str = "string"
    required: bool = False
    prompt: str | None = None


@dataclass(frozen=True)
class Response:
    """How a skill replies: a static ``text`` or a ``dynamic`` ``handler``."""

    text: str | None = None
    dynamic: bool = False
    handler: str | None = None


@dataclass(frozen=True)
class Requirement:
    """An external dependency a skill needs: an ``api`` and/or a ``permission``."""

    api: str | None = None
    permission: str | None = None


@dataclass(frozen=True)
class Skill:
    """A parsed skill definition."""

    name: str
    triggers: tuple[str, ...]
    response: Response
    slots: tuple[Slot, ...] = ()
    requires: tuple[Requirement, ...] = ()
    end_session: bool = False
    help_summary: str | None = None
    order: int = 1000

    def slot(self, name: str) -> Slot | None:
        for s in self.slots:
            if s.name == name:
                return s
        return None

    @property
    def required_permissions(self) -> tuple[str, ...]:
        return tuple(r.permission for r in self.requires if r.permission)

    @property
    def required_apis(self) -> tuple[str, ...]:
        return tuple(r.api for r in self.requires if r.api)


@dataclass
class Session:
    """Per-conversation state.

    Most skills are stateless, but the engine threads a ``Session`` through every
    turn so the ``repeat`` skill can replay :attr:`last_response`, ``set-timer``
    can elicit a missing slot across turns, and ``weather`` can read location
    permission.
    """

    last_response: str | None = None
    ended: bool = False

    # Slot elicitation carried between turns.
    pending_skill: str | None = None
    pending_slot: str | None = None
    pending_slots: dict[str, str] = field(default_factory=dict)

    # Permission grants (e.g. ``{"location": "granted"}``) and resolved location.
    permissions: dict[str, str] = field(default_factory=dict)
    location: str | None = None

    def set_pending(self, skill: str, slot: str, slots: dict[str, str]) -> None:
        self.pending_skill = skill
        self.pending_slot = slot
        self.pending_slots = dict(slots)

    def clear_pending(self) -> None:
        self.pending_skill = None
        self.pending_slot = None
        self.pending_slots = {}


@dataclass
class HandlerRequest:
    """Everything a dynamic handler needs to produce a response."""

    skill: Skill
    slots: dict[str, str]
    session: Session
    context: Any  # SkillContext (avoids an import cycle)
    engine: Any  # SkillEngine


@dataclass
class HandlerResult:
    """What a dynamic handler returns."""

    text: str
    end_session: bool = False
    permission_request: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillResponse:
    """The engine's reply for a single turn."""

    text: str
    skill: str | None = None
    matched: bool = True
    end_session: bool = False
    eliciting: bool = False
    permission_request: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
