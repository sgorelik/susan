"""Susan's skill engine.

Skills are declared as YAML in :mod:`app.skills.definitions` and executed by the
:class:`~app.skills.engine.SkillEngine`. Typical use::

    from app.skills import default_engine, Session

    engine = default_engine()
    session = Session()
    reply = await engine.handle("hello", session)
    print(reply.text)  # "Hello, World! I'm Susan, and I'm ready to help."
"""
from __future__ import annotations

from app.skills.engine import SkillContext, SkillEngine, default_engine
from app.skills.loader import load_definitions, load_skill
from app.skills.models import (
    HandlerRequest,
    HandlerResult,
    Session,
    Skill,
    SkillResponse,
    Slot,
)

__all__ = [
    "SkillContext",
    "SkillEngine",
    "default_engine",
    "load_definitions",
    "load_skill",
    "HandlerRequest",
    "HandlerResult",
    "Session",
    "Skill",
    "SkillResponse",
    "Slot",
]
