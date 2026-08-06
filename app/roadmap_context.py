"""Assemble roadmap evidence: the board, the plan-of-record epic, and window activity.

Everything here is read-only. Counts that anyone might quote outside the company
(how many items are Blocked, which P0s are not done) are computed in Python and
handed to the model as arithmetic it is told not to redo — the failure mode we
care about is a confident summary that rounds *Partial* up to *done*.
"""
from __future__ import annotations

import asyncio
import os
from collections import Counter

from app.config import logger
from app.github_graphql import (
    BoardItem,
    ProjectField,
    ProjectRef,
    fetch_project_fields,
    fetch_project_items,
    resolve_project,
)
from app.github_http import (
    fetch_issue,
    fetch_issue_comments,
    fetch_merged_prs_for_repo_range,
    search_issues,
)
from app.github_repos import _pr_allowlist

# Status vocabulary from the house rules. Order = pipeline order, worst news last.
STATUS_ORDER = (
    "Todo",
    "In Progress",
    "Partial",
    "Done (dev)",
    "Blocked",
    "Done",
)

# Only "Done" is done. Partial and Done (dev) are the two that get overstated.
DONE_STATUSES = frozenset({"done"})
OVERSTATED_STATUSES = frozenset({"partial", "done (dev)"})

HIGH_PRIORITIES = frozenset({"p0", "p1"})


# --- Configuration ----------------------------------------------------------


def roadmap_repos() -> list[str]:
    """Repos that hold roadmap issues: SUSAN_ROADMAP_REPOS, else the GitHub allowlist."""
    raw = (os.environ.get("SUSAN_ROADMAP_REPOS") or "").strip()
    if raw:
        return [p.strip().lower() for p in raw.split(",") if p.strip()]
    allow = _pr_allowlist()
    if allow:
        return list(allow)
    default = (os.environ.get("GITHUB_REPO") or "").strip().lower()
    return [default] if default else []


def roadmap_owner() -> str:
    """Org (or user) that owns the board — defaults to the owner of the first repo."""
    org = (os.environ.get("SUSAN_ROADMAP_ORG") or "").strip()
    if org:
        return org
    repos = roadmap_repos()
    if repos and "/" in repos[0]:
        return repos[0].split("/", 1)[0]
    return ""


def roadmap_project_spec() -> str:
    return (os.environ.get("SUSAN_ROADMAP_PROJECT") or "").strip()


def roadmap_status_field() -> str:
    return (os.environ.get("SUSAN_ROADMAP_STATUS_FIELD") or "Status").strip()


def roadmap_phase_field() -> str:
    return (os.environ.get("SUSAN_ROADMAP_PHASE_FIELD") or "Phase").strip()


def roadmap_priority_field() -> str:
    return (os.environ.get("SUSAN_ROADMAP_PRIORITY_FIELD") or "Priority").strip()


def roadmap_epic_ref() -> tuple[str, int] | None:
    """(repo, number) for the plan-of-record epic from SUSAN_ROADMAP_EPIC (e.g. cloud-infra#231)."""
    raw = (os.environ.get("SUSAN_ROADMAP_EPIC") or "").strip().lstrip("#")
    if not raw:
        return None
    repo_part, _, num_part = raw.rpartition("#")
    if not num_part.isdigit():
        return None
    repo = repo_part.strip().lower()
    if not repo:
        return None
    if "/" not in repo:
        # Short name like `cloud-infra` — resolve against the configured repos.
        match = next((r for r in roadmap_repos() if r.split("/")[-1] == repo), "")
        if not match:
            owner = roadmap_owner()
            match = f"{owner}/{repo}" if owner else ""
        repo = match
    return (repo, int(num_part)) if repo else None


def roadmap_issue_repo() -> str:
    """Where `/susan roadmap add` files new roadmap issues."""
    for key in ("SUSAN_ROADMAP_ISSUE_REPO", "GITHUB_ISSUES_REPO"):
        val = (os.environ.get(key) or "").strip().lower()
        if val:
            return val
    epic = roadmap_epic_ref()
    if epic:
        return epic[0]
    repos = roadmap_repos()
    return repos[0] if repos else ""


def _int_env(name: str, default: int, *, lo: int, hi: int) -> int:
    try:
        val = int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        val = default
    return max(lo, min(hi, val))


def roadmap_max_items() -> int:
    return _int_env("SUSAN_ROADMAP_MAX_ITEMS", 400, lo=25, hi=2000)


def roadmap_max_context_chars() -> int:
    return _int_env("SUSAN_ROADMAP_MAX_CONTEXT_CHARS", 60000, lo=5000, hi=300000)


def roadmap_lookback_days() -> int:
    return _int_env("SUSAN_ROADMAP_LOOKBACK_DAYS", 7, lo=1, hi=180)


def roadmap_configured() -> tuple[bool, str | None]:
    """(ready, error message for Slack)."""
    if not roadmap_owner():
        return False, (
            "No roadmap board configured. Set `SUSAN_ROADMAP_ORG` (GitHub org that owns the "
            "board) and `SUSAN_ROADMAP_PROJECT` (project number or title) on the server."
        )
    if not roadmap_project_spec():
        return False, (
            "No roadmap board configured. Set `SUSAN_ROADMAP_PROJECT` to the project number "
            "or title (for example `Pilot Roadmap`)."
        )
    return True, None


# --- Board loading and rendering -------------------------------------------


class Board:
    """The board as Susan reads it, plus the field metadata needed to write to it."""

    def __init__(
        self,
        project: ProjectRef,
        items: list[BoardItem],
        fields: dict[str, ProjectField],
    ) -> None:
        self.project = project
        self.items = items
        self.fields = fields

    def status_of(self, item: BoardItem) -> str:
        return item.project_field(roadmap_status_field())

    def phase_of(self, item: BoardItem) -> str:
        return item.project_field(roadmap_phase_field())

    def priority_of(self, item: BoardItem) -> str:
        return item.project_field(roadmap_priority_field())

    def field_options(self, field_name: str) -> list[str]:
        want = (field_name or "").casefold()
        for name, fld in self.fields.items():
            if name.casefold() == want:
                return list(fld.options)
        return []


async def load_board(token: str) -> Board:
    """Resolve the configured project and read every row plus its field options."""
    project = await resolve_project(roadmap_owner(), roadmap_project_spec(), token)
    items, fields = await asyncio.gather(
        fetch_project_items(project, token, max_items=roadmap_max_items()),
        fetch_project_fields(project, token),
    )
    logger.info(
        "Roadmap board loaded: %s (#%s) items=%d fields=%d",
        project.title,
        project.number,
        len(items),
        len(fields),
    )
    return Board(project, items, fields)


def _status_sort_key(status: str) -> int:
    want = (status or "").casefold()
    for i, s in enumerate(STATUS_ORDER):
        if s.casefold() == want:
            return i
    return len(STATUS_ORDER)


def _item_line(board: Board, item: BoardItem) -> str:
    status = board.status_of(item) or "(no Status)"
    priority = board.priority_of(item) or "(no Priority)"
    bits = [f"- {item.ref} [Status: {status}] [{priority}] {item.title}"]
    if item.assignees:
        bits.append("assignee " + ", ".join(f"@{a}" for a in item.assignees))
    if item.updated_at:
        bits.append(f"updated {item.updated_at[:10]}")
    if item.kind == "pull_request":
        bits.append("PR" + (" merged" if item.merged else f" {item.state or ''}".rstrip()))
    elif item.state:
        bits.append(f"issue {item.state.lower()}")
    if item.url:
        bits.append(item.url)
    return " · ".join(bits)


def render_board_digest(board: Board) -> str:
    """The board grouped by Phase, then by Status in pipeline order."""
    by_phase: dict[str, list[BoardItem]] = {}
    for item in board.items:
        by_phase.setdefault(board.phase_of(item) or "(no Phase)", []).append(item)

    lines = [
        f"### Board: {board.project.title} (project #{board.project.number}) — "
        f"{len(board.items)} items · {board.project.url}"
    ]
    for phase in sorted(by_phase, key=lambda p: (p.startswith("("), p.casefold())):
        rows = sorted(
            by_phase[phase],
            key=lambda it: (
                _status_sort_key(board.status_of(it)),
                (board.priority_of(it) or "zz").casefold(),
                it.title.casefold(),
            ),
        )
        lines.append(f"\n#### Phase: {phase} ({len(rows)} item{'s' if len(rows) != 1 else ''})")
        lines.extend(_item_line(board, it) for it in rows)
    return "\n".join(lines)


def render_board_arithmetic(board: Board) -> str:
    """Counts computed by Susan so the model never has to (or gets to) invent them."""
    status_counts: Counter[str] = Counter()
    priority_counts: Counter[str] = Counter()
    blocked: list[BoardItem] = []
    overstated: list[BoardItem] = []
    high_not_done: list[BoardItem] = []

    for item in board.items:
        status = board.status_of(item) or "(no Status)"
        priority = board.priority_of(item) or "(no Priority)"
        status_counts[status] += 1
        priority_counts[priority] += 1
        folded = status.casefold()
        if folded == "blocked":
            blocked.append(item)
        if folded in OVERSTATED_STATUSES:
            overstated.append(item)
        if priority.casefold() in HIGH_PRIORITIES and folded not in DONE_STATUSES:
            high_not_done.append(item)

    def _refs(items: list[BoardItem]) -> str:
        return ", ".join(f"{it.ref} ({board.status_of(it) or 'no Status'})" for it in items) or "none"

    done = sum(v for k, v in status_counts.items() if k.casefold() in DONE_STATUSES)
    lines = [
        "### Board arithmetic (computed by Susan from the board — use these numbers verbatim)",
        f"Total items: {len(board.items)}",
        "By Status: "
        + ", ".join(
            f"{k}={v}"
            for k, v in sorted(status_counts.items(), key=lambda kv: _status_sort_key(kv[0]))
        ),
        "By Priority: " + ", ".join(f"{k}={v}" for k, v in sorted(priority_counts.items())),
        f"Complete and verified (Status exactly 'Done'): {done} of {len(board.items)}",
        f"Not done but easily overstated (Partial / Done (dev)): {len(overstated)} — {_refs(overstated)}",
        f"Blocked: {len(blocked)} — {_refs(blocked)}",
        f"P0/P1 not done: {len(high_not_done)} — {_refs(high_not_done)}",
    ]
    return "\n".join(lines)


def _clip(text: str, limit: int, label: str) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… _({label} truncated at {limit} chars)_"


# --- Plan of record (epic) --------------------------------------------------


async def load_epic_block(token: str, *, max_comments: int = 12) -> str:
    """The tracking epic's checklists plus its most recent discussion."""
    ref = roadmap_epic_ref()
    if not ref:
        return "### Plan of record\n_(No epic configured — set `SUSAN_ROADMAP_EPIC`, e.g. `cloud-infra#231`.)_"
    repo, number = ref
    try:
        issue, comments = await asyncio.gather(
            fetch_issue(repo, number, token),
            fetch_issue_comments(repo, number, token, max_comments=max_comments),
        )
    except Exception as e:
        logger.warning("Epic fetch failed %s#%s: %s", repo, number, e)
        return f"### Plan of record\n_(Could not read {repo}#{number}: {e})_"
    if not issue:
        return f"### Plan of record\n_(Could not read {repo}#{number} — check access.)_"

    short = repo.split("/")[-1]
    head = (
        f"### Plan of record: {short}#{number} — {issue.get('title') or ''}\n"
        f"State: {issue.get('state')} · updated {(issue.get('updated_at') or '')[:10]} · "
        f"{issue.get('html_url') or ''}\n\n"
        f"{issue.get('body') or ''}"
    )
    parts = [_clip(head, 12000, "epic body")]
    if comments:
        parts.append("\n#### Recent epic comments")
        for c in comments:
            who = (c.get("user") or {}).get("login") or "?"
            when = (c.get("created_at") or "")[:10]
            body = (c.get("body") or "").strip()
            parts.append(f"- {when} @{who}: {_clip(body, 1200, 'comment')}")
    return "\n".join(parts)


# --- Activity in a window ---------------------------------------------------


def _repo_qualifiers(repos: list[str]) -> str:
    return " ".join(f"repo:{r}" for r in repos)


async def load_window_activity(token: str, since_d: str, until_d: str) -> str:
    """What shipped (merged PRs, closed issues) vs what merely moved (updated issues)."""
    repos = roadmap_repos()[:8]
    if not repos:
        return "### Activity\n_(No repos configured — set `SUSAN_ROADMAP_REPOS` or `GITHUB_REPOS`.)_"

    async def merged(repo: str) -> tuple[str, list[dict]]:
        try:
            return repo, await fetch_merged_prs_for_repo_range(repo, since_d, until_d, token)
        except Exception as e:
            logger.warning("Merged PR fetch failed %s: %s", repo, e)
            return repo, []

    async def closed_issues() -> list[dict]:
        q = f"{_repo_qualifiers(repos)} is:issue closed:>={since_d} closed:<={until_d}"
        try:
            return await search_issues(q, token, max_pages=3)
        except Exception as e:
            logger.warning("Closed issue search failed: %s", e)
            return []

    async def updated_issues() -> list[dict]:
        q = f"{_repo_qualifiers(repos)} is:issue updated:>={since_d} updated:<={until_d}"
        try:
            return await search_issues(q, token, max_pages=3)
        except Exception as e:
            logger.warning("Updated issue search failed: %s", e)
            return []

    merged_batches, closed, updated = await asyncio.gather(
        asyncio.gather(*[merged(r) for r in repos]),
        closed_issues(),
        updated_issues(),
    )

    lines = [f"### Activity {since_d} → {until_d} (UTC)"]
    lines.append("\n#### Merged pull requests (evidence that something shipped)")
    any_pr = False
    for repo, items in merged_batches:
        short = repo.split("/")[-1]
        for it in items[:40]:
            any_pr = True
            author = (it.get("user") or {}).get("login") or "?"
            when = ((it.get("pull_request") or {}).get("merged_at") or "")[:10]
            lines.append(
                f"- {short}#{it.get('number')} {it.get('title')} · merged {when} · @{author} · "
                f"{it.get('html_url') or ''}"
            )
    if not any_pr:
        lines.append("- (none)")

    closed_urls: set[str] = set()
    lines.append("\n#### Issues closed in window")
    if closed:
        for it in closed[:60]:
            url = it.get("html_url") or ""
            short = url.split("/issues/")[0].split("/")[-1] if "/issues/" in url else ""
            closed_urls.add(url)
            lines.append(
                f"- {short}#{it.get('number')} {it.get('title')} · closed "
                f"{(it.get('closed_at') or '')[:10]} · {url}"
            )
    else:
        lines.append("- (none)")

    lines.append("\n#### Issues touched but still open (movement, not delivery)")
    open_touched = [
        it
        for it in updated
        if (it.get("state") or "") == "open" and (it.get("html_url") or "") not in closed_urls
    ]
    if open_touched:
        for it in open_touched[:60]:
            url = it.get("html_url") or ""
            short = url.split("/issues/")[0].split("/")[-1] if "/issues/" in url else ""
            lines.append(
                f"- {short}#{it.get('number')} {it.get('title')} · updated "
                f"{(it.get('updated_at') or '')[:10]} · {url}"
            )
    else:
        lines.append("- (none)")
    return "\n".join(lines)


# --- Customer / topic search ------------------------------------------------


async def load_topic_block(token: str, topic: str, *, max_hydrate: int | None = None) -> str:
    """Issues mentioning a customer or topic, with full discussion for the top hits."""
    repos = roadmap_repos()[:8]
    if not repos:
        return "### Search\n_(No repos configured — set `SUSAN_ROADMAP_REPOS` or `GITHUB_REPOS`.)_"
    term = (topic or "").strip()
    if not term:
        return "### Search\n_(No search term.)_"
    quoted = f'"{term}"' if " " in term else term
    if max_hydrate is None:
        max_hydrate = _int_env("SUSAN_ROADMAP_TOPIC_MAX_ISSUES", 8, lo=1, hi=25)

    q = f"{_repo_qualifiers(repos)} {quoted} in:title,body,comments"
    try:
        hits = await search_issues(q, token, max_pages=3)
    except Exception as e:
        logger.warning("Topic search failed for %r: %s", term, e)
        return f"### Search: {term}\n_(GitHub search failed: {e})_"
    if not hits:
        return f"### Search: {term}\n_(No issues or PRs mention '{term}' in {', '.join(repos)}.)_"

    lines = [f"### Search: '{term}' — {len(hits)} matching issues/PRs in {', '.join(repos)}"]
    for it in hits[:60]:
        kind = "PR" if it.get("pull_request") else "issue"
        url = it.get("html_url") or ""
        short = url.split(f"/{'pull' if kind == 'PR' else 'issues'}/")[0].split("/")[-1]
        lines.append(
            f"- {short}#{it.get('number')} [{kind} {it.get('state')}] {it.get('title')} · "
            f"updated {(it.get('updated_at') or '')[:10]} · {url}"
        )

    def _repo_of(item: dict) -> str:
        url = item.get("repository_url") or ""
        return "/".join(url.split("/repos/")[-1].split("/")[:2]) if "/repos/" in url else ""

    top = [it for it in hits if _repo_of(it)][:max_hydrate]

    async def detail(item: dict) -> str:
        repo = _repo_of(item)
        number = int(item.get("number") or 0)
        try:
            comments = await fetch_issue_comments(repo, number, token, max_comments=15)
        except Exception as e:
            logger.warning("Comment fetch failed %s#%s: %s", repo, number, e)
            comments = []
        short = repo.split("/")[-1]
        out = [
            f"\n#### {short}#{number} — {item.get('title')} ({item.get('state')})",
            _clip((item.get("body") or "").strip() or "_(no description)_", 3000, "body"),
        ]
        for c in comments:
            who = (c.get("user") or {}).get("login") or "?"
            when = (c.get("created_at") or "")[:10]
            out.append(f"- {when} @{who}: {_clip((c.get('body') or '').strip(), 900, 'comment')}")
        return "\n".join(out)

    if top:
        lines.append("\n### Detail on the most recently updated matches")
        details = await asyncio.gather(*[detail(it) for it in top], return_exceptions=True)
        for res in details:
            if isinstance(res, Exception):
                logger.warning("Topic detail failed: %s", res)
                continue
            lines.append(res)
    return "\n".join(lines)


def assemble_context(blocks: list[str]) -> str:
    """Join context blocks and hold the whole prompt under the configured cap."""
    body = "\n\n".join(b for b in blocks if b and b.strip())
    return _clip(body, roadmap_max_context_chars(), "roadmap context")
