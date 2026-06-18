"""Core data structures for Susan's declarative skill system.

A *skill* is a small, self-contained capability described by a YAML file
(see ``app/skills/definitions``). Each skill declares the phrases that trigger
it, optional slots to collect from the user, and how to respond — either with
static text or by delegating to a dynamic ``handler``.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Slot:
    """A value the skill needs from the user (e.g. the timer ``duration``)."""

    name: str
    type: str = "string"
    required: bool = True
    prompt: str | None = None


@dataclass
class ResponseSpec:
    """How a skill replies once all required slots are filled.

    ``text`` is a template (``str.format``) used for static responses or as the
    confirmation template for dynamic handlers. ``dynamic`` + ``handler`` route
    the response through a registered handler (e.g. ``timer.set``).
    """

    text: str | None = None
    dynamic: bool = False
    handler: str | None = None


@dataclass
class Skill:
    """A fully parsed skill definition."""

    name: str
    description: str
    triggers: list[str]
    response: ResponseSpec
    slots: list[Slot] = field(default_factory=list)
    session_end: bool = False
    api: str | None = None
    permission: str | None = None


@dataclass
class Session:
    """Conversational state carried across turns.

    ``permissions`` maps a permission name to ``"granted"`` / ``"denied"``.
    The ``pending_*`` fields and ``slots`` track an in-progress slot elicitation
    so a follow-up utterance is treated as the awaited value.
    """

    permissions: dict[str, str] = field(default_factory=dict)
    pending_skill: str | None = None
    pending_slot: str | None = None
    slots: dict[str, str] = field(default_factory=dict)
    ended: bool = False


@dataclass
class SkillResult:
    """The outcome of dispatching an utterance.

    ``text`` is what Susan should say back. The remaining flags let the caller
    (a Slack handler, a voice front-end, tests, …) react to control signals:
    elicitation prompts, permission requests, session termination and errors.
    """

    text: str = ""
    skill: str | None = None
    matched: bool = True
    elicit: bool = False
    session_end: bool = False
    needs_permission: str | None = None
    error: bool = False
    data: dict = field(default_factory=dict)
