"""Pytest fixtures: minimal env to import Susan, isolated SQLite DB per session."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure Susan modules are importable regardless of where pytest is invoked.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Required env vars must exist *before* `app.config` is imported (it raises on KeyError).
os.environ.setdefault("SLACK_SIGNING_SECRET", "test-secret")
os.environ.setdefault("SLACK_BOT_TOKEN", "xoxb-test")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic")

# Use a fresh on-disk SQLite file per test session so async SQLAlchemy can create the
# schema and the GranolaToken row writes survive across event loops.
_TMP = tempfile.NamedTemporaryFile(prefix="susan-test-", suffix=".db", delete=False)
_TMP.close()
os.environ["SQLITE_PATH"] = _TMP.name
os.environ.pop("DATABASE_URL", None)


# --- Skill engine fixtures ---------------------------------------------------


@pytest.fixture
def skills():
    """Freshly loaded YAML skill definitions."""
    from app.skills.loader import load_definitions

    return load_definitions()


@pytest.fixture
def make_engine(skills):
    """Factory building a SkillEngine with an overridable context (services)."""
    from app.skills.engine import SkillContext, SkillEngine

    def _make(**context_kwargs):
        context = SkillContext(**context_kwargs) if context_kwargs else SkillContext()
        return SkillEngine(skills, context=context)

    return _make


@pytest.fixture
def engine(make_engine):
    """A default SkillEngine with the bundled services."""
    return make_engine()
