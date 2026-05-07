"""Pytest fixtures: minimal env to import Susan, isolated SQLite DB per session."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

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
