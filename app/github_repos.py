"""GitHub repo allowlists, slug parsing, and PR summary date ranges."""
from __future__ import annotations

import os
import re

def _comma_repo_list(raw: str) -> list[str]:
    if not (raw or "").strip():
        return []
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def _pr_allowlist() -> list[str]:
    return _comma_repo_list(os.environ.get("GITHUB_REPOS", ""))


def _issue_allowlist() -> list[str]:
    """GITHUB_ISSUES_REPOS if set, else same allowlist as PR (GITHUB_REPOS)."""
    raw = (os.environ.get("GITHUB_ISSUES_REPOS") or "").strip()
    if raw:
        return _comma_repo_list(raw)
    return _pr_allowlist()


def is_plausible_github_repo_slug(slug: str) -> bool:
    """Reject Slack URLs and other false positives (e.g. frontier-one.slack.com/archives)."""
    if not slug or "/" not in slug:
        return False
    parts = slug.split("/", 1)
    if len(parts) != 2:
        return False
    owner, name = parts[0].strip(), parts[1].strip()
    if not owner or not name:
        return False
    low = slug.lower()
    if "slack.com" in low or "archives" in name.lower():
        return False
    if "http://" in low or "https://" in low:
        return False
    if "." in owner:
        return False
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,38}[a-zA-Z0-9])?/[a-zA-Z0-9._-]+$", slug):
        return False
    return True


def parse_repo_slug_from_text(text: str) -> str | None:
    """Extract owner/repo from slash text; validated so Slack links are never treated as repos."""
    all_slugs = parse_all_repo_slugs_from_text(text)
    return all_slugs[0] if all_slugs else None


def parse_all_repo_slugs_from_text(text: str) -> list[str]:
    """All distinct owner/repo slugs from slash text (order preserved)."""
    if not (text or "").strip():
        return []
    seen: set[str] = set()
    out: list[str] = []

    def add_slug(cand: str) -> None:
        if not is_plausible_github_repo_slug(cand):
            return
        c = cand.strip().lower()
        if c not in seen:
            seen.add(c)
            out.append(c)

    m_list = re.search(r"(?i)\b(?:repos?|in)\s*:\s*([^\n]+)", text)
    if m_list:
        for part in m_list.group(1).split(","):
            p = part.strip()
            if p:
                add_slug(p)

    for m in re.finditer(r"github\.com/([^/\s]+)/([^/\s?#]+)", text, re.I):
        add_slug(f"{m.group(1)}/{m.group(2)}")

    for m in re.finditer(
        r"\b([a-zA-Z0-9][a-zA-Z0-9-]{0,38}/[a-zA-Z0-9._-]+)\b", text
    ):
        add_slug(m.group(1))

    return out


def resolve_github_repos_for_pr_summary(
    text: str,
) -> tuple[list[str] | None, str | None, bool]:
    """Returns (repos, error_ephemeral, needs_multi_picker)."""
    allow = _pr_allowlist()
    parsed = parse_all_repo_slugs_from_text(text)
    if parsed:
        if allow:
            bad = [r for r in parsed if r not in allow]
            if bad:
                return None, (
                    f"Repo(s) not allowed: {', '.join(f'`{b}`' for b in bad)}. "
                    f"Allowed: {', '.join(allow)}."
                ), False
        return parsed, None, False
    default = (os.environ.get("GITHUB_REPO") or "").strip().lower()
    if default:
        if allow and default not in allow:
            return None, (
                f"Default `GITHUB_REPO` (`{default}`) is not in `GITHUB_REPOS`: {', '.join(allow)}."
            ), False
        return [default], None, False
    if len(allow) == 1:
        return [allow[0]], None, False
    if len(allow) > 1:
        return None, None, True
    return None, (
        "No GitHub repo configured. Set `GITHUB_REPO` or `GITHUB_REPOS`, "
        "or name repos in your command (e.g. `org/a org/b` or `repos: org/a, org/b`)."
    ), False


def resolve_github_repo_for_pr(text: str) -> tuple[str | None, str | None, bool]:
    """Returns (repo, error_ephemeral, needs_interactive_picker)."""
    allow = _pr_allowlist()
    parsed = parse_repo_slug_from_text(text)
    default = (os.environ.get("GITHUB_REPO") or "").strip().lower()
    if parsed:
        if allow and parsed not in allow:
            return None, f"Repo `{parsed}` is not allowed. Allowed: {', '.join(allow)}.", False
        return parsed, None, False
    if default:
        if allow and default not in allow:
            return None, f"Default `GITHUB_REPO` (`{default}`) is not in `GITHUB_REPOS`: {', '.join(allow)}.", False
        return default, None, False
    if len(allow) == 1:
        return allow[0], None, False
    if len(allow) > 1:
        return None, None, True
    return None, (
        "No GitHub repo configured. Set `GITHUB_REPO` (default) or `GITHUB_REPOS` (comma-separated allowlist) "
        "on the server, or include `owner/repo` in your command."
    ), False


def parse_pr_summary_time_range(text: str) -> tuple[str, str]:
    """Return inclusive merged-date range as YYYY-MM-DD (UTC) for GitHub search."""
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    today = now.date()
    lower = text.lower()

    m = re.search(r"last\s+(\d+)\s+days?", lower)
    if m:
        n = max(1, min(365, int(m.group(1))))
        start = today - timedelta(days=n)
        return start.isoformat(), today.isoformat()

    if re.search(r"\b(last|past)\s+week\b", lower):
        start = today - timedelta(days=7)
        return start.isoformat(), today.isoformat()

    if re.search(r"\b(last|past)\s+month\b", lower):
        start = today - timedelta(days=30)
        return start.isoformat(), today.isoformat()

    m = re.search(r"\bsince\s+(\d{4}-\d{2}-\d{2})\b", lower)
    if m:
        return m.group(1), today.isoformat()

    m = re.search(
        r"\b(?:between|from)\s+(\d{4}-\d{2}-\d{2})\s+(?:and|to)\s+(\d{4}-\d{2}-\d{2})\b",
        lower,
    )
    if m:
        return m.group(1), m.group(2)

    m = re.search(r"\bin\s+(?:the\s+)?last\s+(\d+)\s+weeks?\b", lower)
    if m:
        w = max(1, min(52, int(m.group(1))))
        start = today - timedelta(weeks=w)
        return start.isoformat(), today.isoformat()

    start = today - timedelta(days=7)
    return start.isoformat(), today.isoformat()
