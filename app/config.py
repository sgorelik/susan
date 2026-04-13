"""Environment-backed settings, action registry, and shared logging."""
from __future__ import annotations

import logging
import os
import re
from inspect import cleandoc

logger = logging.getLogger("susan")

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"].strip()
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"].strip()
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]

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
    "pr": ("create a GitHub PR", ["pull request", "create pr", "open pr", "pr"]),
}

GOOGLE_ACTIONS = frozenset({"doc", "email", "invite"})
GITHUB_ACTIONS = frozenset({"pr", "issue", "pr_summary"})
APPROVE_ACTION_TYPES = frozenset(
    {"doc", "email", "invite", "pr", "issue", "pr_summary", "weekly_status"}
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
