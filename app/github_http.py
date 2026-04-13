"""GitHub REST: PR search, Dependabot, participants, file commits."""
from __future__ import annotations

import asyncio
import base64
import os
import urllib.parse

import httpx

from app.config import logger

def _pr_turnaround_hours(item: dict) -> float | None:
    from datetime import datetime

    created = item.get("created_at")
    pr = item.get("pull_request") or {}
    merged = pr.get("merged_at")
    if not created or not merged:
        return None
    try:
        c = datetime.fromisoformat(created.replace("Z", "+00:00"))
        m = datetime.fromisoformat(merged.replace("Z", "+00:00"))
        return (m - c).total_seconds() / 3600.0
    except (ValueError, TypeError):
        return None


async def fetch_opened_prs_for_repo_range(
    repo: str, since_d: str, until_d: str, token: str
) -> list[dict]:
    q = f"repo:{repo} is:pr created:>={since_d} created:<={until_d}"
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    items: list[dict] = []
    async with httpx.AsyncClient(timeout=60) as client:
        for page in range(1, 11):
            r = await client.get(
                "https://api.github.com/search/issues",
                headers=hdrs,
                params={"q": q, "per_page": 100, "page": page},
            )
            data = r.json()
            if r.status_code != 200:
                raise RuntimeError(
                    f"GitHub search failed ({r.status_code}): {data.get('message', data)}"
                )
            batch = data.get("items") or []
            items.extend(batch)
            if len(batch) < 100:
                break
    return items


async def fetch_dependabot_alert_stats(
    repo: str, since_d: str, until_d: str, token: str
) -> dict:
    """Counts open alerts + fixed/dismissed in date window. On 403, returns error hint."""
    from datetime import datetime, timezone

    hdrs = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    since_dt = datetime.strptime(since_d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    until_dt = datetime.strptime(until_d, "%Y-%m-%d").replace(
        hour=23, minute=59, second=59, tzinfo=timezone.utc
    )

    open_count = 0
    fixed_in_window = 0
    dismissed_in_window = 0
    new_open_in_window = 0
    url = f"https://api.github.com/repos/{repo}/dependabot/alerts"
    async with httpx.AsyncClient(timeout=60) as client:
        page = 1
        while page <= 20:
            r = await client.get(
                url, headers=hdrs, params={"state": "all", "per_page": 100, "page": page}
            )
            if r.status_code == 403:
                return {
                    "ok": False,
                    "hint": (
                        "Dependabot alerts unavailable (403). Add scope **`security_events`** to "
                        "`GITHUB_OAUTH_SCOPE` (e.g. `repo security_events`) and reconnect GitHub."
                    ),
                }
            if r.status_code != 200:
                return {
                    "ok": False,
                    "hint": f"Dependabot API error {r.status_code}: {r.text[:200]}",
                }
            batch = r.json()
            if not isinstance(batch, list):
                return {"ok": False, "hint": f"Unexpected Dependabot response: {batch!s}"[:300]}
            if not batch:
                break
            for a in batch:
                st = (a.get("state") or "").lower()
                created_s = a.get("created_at") or ""
                fixed_s = a.get("fixed_at") or ""
                dismissed_s = a.get("dismissed_at") or ""
                try:
                    created = (
                        datetime.fromisoformat(created_s.replace("Z", "+00:00"))
                        if created_s
                        else None
                    )
                except ValueError:
                    created = None
                in_created_window = (
                    created is not None and since_dt <= created <= until_dt
                )
                if st == "open":
                    open_count += 1
                    if in_created_window:
                        new_open_in_window += 1
                if st == "fixed" and fixed_s:
                    try:
                        fx = datetime.fromisoformat(fixed_s.replace("Z", "+00:00"))
                        if since_dt <= fx <= until_dt:
                            fixed_in_window += 1
                    except ValueError:
                        pass
                if st == "dismissed" and dismissed_s:
                    try:
                        ds = datetime.fromisoformat(dismissed_s.replace("Z", "+00:00"))
                        if since_dt <= ds <= until_dt:
                            dismissed_in_window += 1
                    except ValueError:
                        pass
            if len(batch) < 100:
                break
            page += 1

    return {
        "ok": True,
        "open_total": open_count,
        "fixed_in_window": fixed_in_window,
        "dismissed_in_window": dismissed_in_window,
        "new_open_in_window": new_open_in_window,
    }


async def _github_put_file_on_branch(
    client: httpx.AsyncClient,
    repo: str,
    path: str,
    file_body: str,
    branch: str,
    message: str,
    hdrs: dict,
) -> str | None:
    """Create or update a file on ``branch``. Returns None on success, else an error message."""
    enc = urllib.parse.quote(path, safe="/")
    url = f"https://api.github.com/repos/{repo}/contents/{enc}"
    gr = await client.get(url, headers=hdrs, params={"ref": branch})
    existing_sha = None
    if gr.status_code == 200:
        existing_sha = gr.json().get("sha")
    b64 = base64.b64encode(file_body.encode("utf-8")).decode("ascii")
    payload: dict = {"message": message, "content": b64, "branch": branch}
    if existing_sha:
        payload["sha"] = existing_sha
    put_r = await client.put(url, headers=hdrs, json=payload)
    if put_r.status_code not in (200, 201):
        return f"Could not commit `{path}`: {put_r.status_code} {put_r.text}"
    return None


async def fetch_merged_prs_for_repo_range(
    repo: str, since_d: str, until_d: str, token: str
) -> list[dict]:
    """GitHub search API: merged PRs in repo between since_d and until_d (YYYY-MM-DD)."""
    q = f"repo:{repo} is:pr is:merged merged:>={since_d} merged:<={until_d}"
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    items: list[dict] = []
    async with httpx.AsyncClient(timeout=60) as client:
        for page in range(1, 11):
            r = await client.get(
                "https://api.github.com/search/issues",
                headers=hdrs,
                params={"q": q, "per_page": 100, "page": page},
            )
            data = r.json()
            if r.status_code != 200:
                raise RuntimeError(
                    f"GitHub search failed ({r.status_code}): {data.get('message', data)}"
                )
            batch = data.get("items") or []
            items.extend(batch)
            if len(batch) < 100:
                break
    return items


_PR_SUMMARY_PARTICIPANT_SEM = asyncio.Semaphore(10)


async def _github_list_all_pages(
    client: httpx.AsyncClient, url: str, headers: dict, max_pages: int = 15
) -> list[dict]:
    out: list[dict] = []
    for page in range(1, max_pages + 1):
        r = await client.get(url, headers=headers, params={"per_page": 100, "page": page})
        if r.status_code != 200:
            break
        batch = r.json()
        if not isinstance(batch, list):
            break
        out.extend(batch)
        if len(batch) < 100:
            break
    return out


async def fetch_merged_pr_participant_logins(repo: str, pr_number: int, token: str) -> set[str]:
    """Logins from issue comments, pull review comments, and submitted reviews (non-bot)."""
    hdrs = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    base = f"https://api.github.com/repos/{repo}"
    urls = [
        f"{base}/issues/{pr_number}/comments",
        f"{base}/pulls/{pr_number}/comments",
        f"{base}/pulls/{pr_number}/reviews",
    ]
    logins: set[str] = set()
    async with _PR_SUMMARY_PARTICIPANT_SEM:
        async with httpx.AsyncClient(timeout=45) as client:
            batches = await asyncio.gather(
                _github_list_all_pages(client, urls[0], hdrs),
                _github_list_all_pages(client, urls[1], hdrs),
                _github_list_all_pages(client, urls[2], hdrs),
            )
            for batch in batches:
                for item in batch:
                    u = item.get("user")
                    if isinstance(u, dict):
                        lg = u.get("login")
                        if lg and not str(lg).endswith("[bot]"):
                            logins.add(lg)
    return logins


def _pr_merged_sort_key(pair: tuple[str, dict]) -> float:
    from datetime import datetime

    it = pair[1]
    pr_meta = it.get("pull_request") or {}
    m = pr_meta.get("merged_at") or it.get("closed_at") or ""
    if not m:
        return 0.0
    try:
        return datetime.fromisoformat(m.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


async def build_pr_summary_engagement_appendix(
    repos: list[str], batches: list[list[dict]], token: str
) -> str:
    """Authors + comment/review participation for the Claude prompt (caps GitHub fan-out)."""
    from collections import Counter

    author_counts: Counter[str] = Counter()
    for _repo, items in zip(repos, batches):
        for it in items:
            login = (it.get("user") or {}).get("login") or "?"
            author_counts[login] += 1

    flat: list[tuple[str, dict]] = []
    for repo, items in zip(repos, batches):
        for it in items:
            flat.append((repo, it))
    flat.sort(key=_pr_merged_sort_key, reverse=True)

    max_fetch = max(0, min(500, int(os.environ.get("PR_SUMMARY_MAX_PARTICIPANT_FETCH", "80"))))
    slice_pairs = flat[:max_fetch] if max_fetch else []

    commenter_pr_touch: Counter[str] = Counter()
    if slice_pairs:
        try:

            async def _participants(repo: str, it: dict) -> set[str]:
                n = it.get("number")
                if n is None:
                    return set()
                return await fetch_merged_pr_participant_logins(repo, int(n), token)

            results = await asyncio.gather(
                *[_participants(repo, it) for repo, it in slice_pairs],
                return_exceptions=True,
            )
            for pair, res in zip(slice_pairs, results):
                if isinstance(res, Exception):
                    logger.warning(
                        "PR participant fetch failed for %s #%s: %s",
                        pair[0],
                        pair[1].get("number"),
                        res,
                    )
                    continue
                for lg in res:
                    commenter_pr_touch[lg] += 1
        except Exception as e:
            logger.exception("PR participant gather failed: %s", e)

    lines = [
        "### Aggregated participation (from GitHub: issue comments, review comments, reviews)",
    ]
    if author_counts:
        lines.append(
            "Merged-PR authors (@login → count of merged PRs they opened in this window): "
            + ", ".join(f"@{k} ({v})" for k, v in author_counts.most_common())
        )
    else:
        lines.append("(No merged PRs in window.)")

    if commenter_pr_touch:
        lines.append(
            "Commenters & reviewers (@login → number of merged PRs in this window they commented on "
            "or reviewed; bots excluded): "
            + ", ".join(f"@{k} ({v})" for k, v in commenter_pr_touch.most_common(40))
        )
    elif flat and max_fetch == 0:
        lines.append(
            "(Comment/review participation not fetched: PR_SUMMARY_MAX_PARTICIPANT_FETCH is 0.)"
        )
    elif slice_pairs:
        lines.append(
            "(No non-bot issue/review activity found on the sampled PRs, or GitHub returned errors.)"
        )

    if len(flat) > max_fetch and max_fetch > 0:
        lines.append(
            f"_Note: comment/review data was fetched for the {max_fetch} most recently merged PRs only "
            f"({len(flat)} total in window); authors above include all merged PRs._"
        )

    return "\n".join(lines)
