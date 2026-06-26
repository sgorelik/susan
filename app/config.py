"""Environment-backed settings, action registry, and shared logging."""
from __future__ import annotations

import logging
import os
import re
from inspect import cleandoc

logger = logging.getLogger("susan")

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].strip()
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"].strip()
# Optional now: when F1_MODEL_BASE_URL is set, LLM calls route to our sovereign
# model and an Anthropic key is not required to boot.
ANTHROPIC_API_KEY = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
# claude-sonnet-4-20250514 was retired 2026-06-15; override via ANTHROPIC_MODEL if needed.
ANTHROPIC_MODEL = (os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-4-6").strip()

# --- FrontierOne sovereign model (OpenAI-compatible, self-hosted on OVH) ---
# When F1_MODEL_BASE_URL is set, ALL LLM calls route here instead of Anthropic,
# and every Slack message is attributed to the sovereign model.
F1_MODEL_BASE_URL = (os.environ.get("F1_MODEL_BASE_URL") or "").strip().rstrip("/")
F1_MODEL_API_KEY = (os.environ.get("F1_MODEL_API_KEY") or "").strip()
F1_MODEL_NAME = (os.environ.get("F1_MODEL_NAME") or "model-a").strip()
F1_ATTRIBUTION = "running on Secure Sovereign FrontierOne AI model"
# Keep susan within a small, model-friendly context (a 7B model doesn't benefit
# from huge contexts, and this removes any dependence on the served context size).
# Prompt is truncated (keeping the most recent text) to this many chars (~4 chars/token).
F1_MODEL_MAX_PROMPT_CHARS = int(os.environ.get("F1_MODEL_MAX_PROMPT_CHARS", "20000"))
F1_MODEL_MAX_COMPLETION_TOKENS = int(os.environ.get("F1_MODEL_MAX_COMPLETION_TOKENS", "1500"))


def f1_model_active() -> bool:
    return bool(F1_MODEL_BASE_URL)

ACTIONS = {
    "doc": ("create a doc", ["doc", "document", "notes"]),
    "email": ("send email", ["email", "mail"]),
    "invite": ("create invite", ["invite", "calendar", "meeting", "event"]),
    "issue": (
        "open a GitHub issue",
        ["github issue", "open issue", "file issue", "create issue", "issue"],
    ),
    "pr_summary": (
        "summarize merged GitHub PRs",
        [
            "summarize pull requests",
            "summarize prs",
            "summarize merged pr",
            "pr summary",
            "pull request summary",
            "github pr summary",
            "prs summary",
            "pr summaries",
        ],
    ),
    "weekly_status": (
        "weekly team & repo status",
        [
            "weekly status",
            "week status",
            "weekly report",
            "status report",
            "team status",
            "engineering status",
        ],
    ),
    "granola_cmd": (
        "Granola notes summary",
        [],  # Routed only via `/susan granola` / `/susan gn`; empty keywords avoid accidental matches.
    ),
    "action_items_cmd": (
        "action items digest",
        [],  # Routed via `/susan actions` / `/susan action items` / `/susan todos`.
    ),
    "sales_prep": (
        "sales call prep",
        [],  # Routed via `/susan prep me for a sales call with …` (explicit parser).
    ),
    "pr": ("create a GitHub PR", ["pull request", "create pr", "open pr", "pr"]),
}

GOOGLE_ACTIONS = frozenset({"doc", "email", "invite"})
GITHUB_ACTIONS = frozenset({"pr", "issue", "pr_summary"})
APPROVE_ACTION_TYPES = frozenset(
    {"doc", "email", "invite", "pr", "issue", "pr_summary", "weekly_status", "action_items"}
)

EMAIL_IN_TEXT_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Prompts are multiline for editing; cleandoc() removes shared leading whitespace only.
SYSTEM_PROMPTS = {
    "doc": cleandoc(
        """
        You are Susan. Given a Slack conversation, write a structured document with
        sections: ## Summary, ## Key Decisions, ## Action Items, ## Open Questions.
        Be concise and professional.
        """
    ),
    "email": cleandoc(
        """
        You are Susan. Given a Slack conversation, draft a professional email.
        Output ONLY this structure:

        To: …
        Subject: <subject>

        <body>

        Recipients in To: must be comma-separated. Use real email@domain when known.
        When the thread shows Slack user ids before each message (e.g. U01ABC2XYZ3: hello),
        you may put those people in To: as Slack mentions: <@U01ABC2XYZ3> (one per person
        Susan should email). Susan will resolve mentions to workspace emails.
        If the user types @mentions in Slack, the thread text may already contain <@U…>
        — keep those in To:. If no recipients, leave To: empty.
        """
    ),
    "invite": cleandoc(
        """
        You are Susan. Given a Slack conversation, draft a calendar invite.
        Output ONLY:

        Title: <short title>
        Attendees: … (comma-separated emails and/or <@SLACK_USER_ID> mentions as in the thread)
        Start: <ISO8601 e.g. 2026-04-15T14:00:00>
        End: <ISO8601>
        TimeZone: <IANA e.g. America/New_York or UTC>
        Description:
        <agenda / notes>

        Infer date/time from the thread. For people only identified by Slack user id in
        the thread (U01…), use <@U01…> in Attendees: so Susan can resolve emails.
        """
    ),
    "issue": cleandoc(
        """
        You are Susan. Given a Slack conversation, draft a GitHub issue.
        Output ONLY:

        Title: <short title>

        Description:
        <markdown body with context, steps to reproduce, expected vs actual, or acceptance criteria as appropriate>
        """
    ),
    "pr": cleandoc(
        """
        You are Susan. Given a Slack conversation about code, draft a GitHub PR.
        Output ONLY:

        Title: ...

        Description:
        ...

        Files changed:
        For each file: one repo-relative path on its own line, then a fenced code block
        with the full file contents. Example:

        src/foo.py
        ```python
        ...
        ```

        Repeat for more files.
        """
    ),
}

REPO_PREFIX = "__REPO__:"
