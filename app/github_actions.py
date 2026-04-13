"""Create GitHub issues and PRs from approved Slack drafts."""
from __future__ import annotations

import os
import re
import time
import uuid

import httpx

from db import get_github_token

from app.github_http import _github_put_file_on_branch
from app.slack_commands import (
    _parse_pr_files_changed,
    _sanitize_repo_rel_path,
    split_repo_prefix_from_approve_value,
)

async def create_github_issue(content: str, slack_user_id: str) -> str:
    try:
        token = await get_github_token(slack_user_id)
    except ValueError as e:
        return str(e)
    repo_meta, body = split_repo_prefix_from_approve_value(content)
    repo = repo_meta or (os.environ.get("GITHUB_ISSUES_REPO") or os.environ.get("GITHUB_REPO") or "").strip()
    if not repo:
        return "Issue not created — no repo (approve payload missing `__REPO__` line)."
    content = body
    title_m = re.search(r"^Title:\s*(.+)", content, re.M)
    title = title_m.group(1).strip() if title_m else "Susan: issue from Slack"
    desc_m = re.search(r"^Description:\s*", content, re.M)
    body = content[desc_m.end() :].strip() if desc_m else content
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers=hdrs,
            json={"title": title, "body": body},
        )
    data = r.json()
    if r.status_code >= 400:
        return f"GitHub issue error ({r.status_code}): {data}"
    return f"Issue created: {data.get('html_url', data)}"


async def create_github_pr(content: str, slack_user_id: str) -> str:
    try:
        token = await get_github_token(slack_user_id)
    except ValueError as e:
        return str(e)
    repo_meta, body = split_repo_prefix_from_approve_value(content)
    repo = repo_meta or (os.environ.get("GITHUB_REPO") or "").strip()
    if not repo:
        return "PR not created — no repo (approve payload missing `__REPO__` line)."
    content = body
    base = os.environ.get("GITHUB_BASE_BRANCH", "main")
    title_m = re.search(r"^Title:\s*(.+)", content, re.M)
    desc_m = re.search(r"Description:\s*([\s\S]+?)(?=Files changed:|$)", content)
    title = title_m.group(1).strip() if title_m else "Susan: changes from Slack"
    desc = desc_m.group(1).strip() if desc_m else content

    parsed: list[tuple[str, str]] = []
    for raw_path, file_body in _parse_pr_files_changed(content):
        sp = _sanitize_repo_rel_path(raw_path)
        if sp:
            parsed.append((sp, file_body))
    by_path: dict[str, str] = {}
    for p, b in parsed:
        by_path[p] = b
    file_list = list(by_path.items())
    ts = int(time.time())
    if not file_list:
        file_list = [
            (
                f"docs/susan/slack-pr-{ts}.md",
                f"# {title}\n\n{desc}\n\n"
                "_*(No `Files changed:` block was parsed; add real file edits in this branch or adjust the preview format.)*_\n",
            )
        ]

    branch = f"susan/slack-{ts}-{uuid.uuid4().hex[:8]}"
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=120) as client:
        sha_r = await client.get(
            f"https://api.github.com/repos/{repo}/git/refs/heads/{base}",
            headers=hdrs,
        )
        if sha_r.status_code >= 400:
            return f"Could not read base branch `{base}` in `{repo}`: {sha_r.status_code} {sha_r.text}"
        sha = sha_r.json().get("object", {}).get("sha")
        if not sha:
            return f"Could not find base branch '{base}' in {repo}."
        ref_r = await client.post(
            f"https://api.github.com/repos/{repo}/git/refs",
            headers=hdrs,
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )
        if ref_r.status_code not in (201,):
            return f"Could not create branch `{branch}`: {ref_r.status_code} {ref_r.text}"

        nfiles = len(file_list)
        for i, (path, file_body) in enumerate(file_list):
            msg = f"susan: {title[:60]}"
            if nfiles > 1:
                msg = f"{msg} ({path})"
            err = await _github_put_file_on_branch(
                client, repo, path, file_body, branch, msg, hdrs
            )
            if err:
                return err

        pr_r = await client.post(
            f"https://api.github.com/repos/{repo}/pulls",
            headers=hdrs,
            json={"title": title, "body": desc, "head": branch, "base": base},
        )
        pr_status = pr_r.status_code
        pr_data = pr_r.json()

    if pr_status >= 400:
        return f"PR not created ({pr_status}): {pr_data}"
    return f"PR created: {pr_data.get('html_url', pr_data)}"
