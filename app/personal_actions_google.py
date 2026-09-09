"""Read-only Gmail and Drive-comment context for a user's personal action inbox."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.config import logger
from app.slack_api import slack_users_lookup_email
from db import get_valid_access_token


def _cap(name: str, default: int, maximum: int) -> int:
    return max(1, min(maximum, int(os.environ.get(name, str(default)))))


def _header(message: dict[str, Any], name: str) -> str:
    for h in (message.get("payload") or {}).get("headers") or []:
        if str(h.get("name") or "").lower() == name.lower():
            return str(h.get("value") or "")
    return ""


async def _gmail_actions_context(
    client: httpx.AsyncClient,
    token: str,
    since_d: str,
    until_d: str,
) -> tuple[str, str | None]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    profile = await client.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/profile", headers=headers
    )
    if profile.status_code >= 400:
        return "", (
            "Gmail read unavailable. Reconnect Google so Susan receives the "
            "`gmail.readonly` scope."
        )
    email = str(profile.json().get("emailAddress") or "")
    until_exclusive = (
        datetime.strptime(until_d, "%Y-%m-%d").date() + timedelta(days=1)
    ).strftime("%Y/%m/%d")
    query = (
        f"after:{since_d.replace('-', '/')} before:{until_exclusive} "
        "{to:me cc:me} -from:me"
    )
    listed = await client.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={
            "q": query,
            "maxResults": str(_cap("ACTION_ITEMS_GMAIL_MAX_MESSAGES", 60, 200)),
        },
    )
    if listed.status_code >= 400:
        return "", f"Gmail search unavailable (HTTP {listed.status_code})."

    sem = asyncio.Semaphore(5)

    async def one(mid: str) -> str:
        async with sem:
            r = await client.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}",
                headers=headers,
                params={
                    "format": "metadata",
                    "metadataHeaders": ["Subject", "From", "Date", "To", "Cc"],
                },
            )
        if r.status_code >= 400:
            return ""
        msg = r.json()
        return (
            f"- From: {_header(msg, 'From')} | Date: {_header(msg, 'Date')} | "
            f"Subject: {_header(msg, 'Subject')} | Snippet: {msg.get('snippet', '')} | "
            f"https://mail.google.com/mail/u/0/#all/{msg.get('threadId') or mid}"
        )

    rows = await asyncio.gather(
        *[
            one(str(m.get("id") or ""))
            for m in listed.json().get("messages") or []
            if m.get("id")
        ]
    )
    body = "\n".join(row for row in rows if row)
    if not body:
        body = "(No messages addressed to this user in the window.)"
    return (
        "### Gmail addressed to the requesting user\n"
        f"Google account: {email or '(unknown)'}\n"
        "Extract only concrete asks, promised replies, approvals needed, and deadlines.\n"
        f"{body}",
        None,
    )


async def _drive_comment_actions_context(
    client: httpx.AsyncClient,
    token: str,
    user_email: str | None,
    since_d: str,
    until_d: str,
) -> tuple[str, str | None]:
    if not user_email:
        return "", (
            "Drive mention matching unavailable because Susan could not resolve the "
            "requesting user's email."
        )
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    mime_q = (
        "(mimeType='application/vnd.google-apps.document' or "
        "mimeType='application/vnd.google-apps.spreadsheet' or "
        "mimeType='application/vnd.google-apps.presentation') and trashed=false"
    )
    r = await client.get(
        "https://www.googleapis.com/drive/v3/files",
        headers=headers,
        params={
            "q": mime_q,
            "orderBy": "modifiedTime desc",
            "pageSize": str(_cap("ACTION_ITEMS_DRIVE_COMMENT_MAX_FILES", 50, 200)),
            "fields": "files(id,name,modifiedTime,webViewLink)",
            "supportsAllDrives": "true",
            "includeItemsFromAllDrives": "true",
        },
    )
    if r.status_code >= 400:
        return "", (
            "Drive comments unavailable. Reconnect Google so Susan receives the "
            "`drive.readonly` scope."
        )

    start = datetime.strptime(since_d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    end = datetime.strptime(until_d, "%Y-%m-%d").replace(
        hour=23, minute=59, second=59, tzinfo=timezone.utc
    )
    sem = asyncio.Semaphore(4)

    async def comments_for_file(file: dict[str, Any]) -> list[str]:
        fid = str(file.get("id") or "")
        if not fid:
            return []
        async with sem:
            cr = await client.get(
                f"https://www.googleapis.com/drive/v3/files/{fid}/comments",
                headers=headers,
                params={
                    "pageSize": "100",
                    "includeDeleted": "false",
                    "fields": (
                        "comments(id,content,htmlContent,createdTime,modifiedTime,resolved,"
                        "mentionedEmailAddresses,author(displayName,emailAddress),"
                        "replies(content,createdTime,author(displayName,emailAddress),deleted))"
                    ),
                },
            )
        if cr.status_code in (401, 403):
            return []
        if cr.status_code >= 400:
            logger.warning("Drive comments %s: HTTP %s", fid, cr.status_code)
            return []
        rows: list[str] = []
        for comment in cr.json().get("comments") or []:
            if comment.get("resolved"):
                continue
            stamp = comment.get("modifiedTime") or comment.get("createdTime") or ""
            try:
                when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
            except ValueError:
                continue
            if not (start <= when <= end):
                continue
            mentions = [
                str(x).lower() for x in comment.get("mentionedEmailAddresses") or []
            ]
            content = str(comment.get("content") or "")
            if (
                user_email.lower() not in mentions
                and user_email.lower() not in content.lower()
            ):
                continue
            author = comment.get("author") or {}
            rows.append(
                f"- {file.get('name') or fid} — unresolved comment by "
                f"{author.get('displayName') or author.get('emailAddress') or 'unknown'}: "
                f"{content[:1000]} — {file.get('webViewLink') or ''}"
            )
        return rows

    nested = await asyncio.gather(
        *[comments_for_file(f) for f in r.json().get("files") or []]
    )
    rows = [row for group in nested for row in group]
    return (
        "### Google Drive comments mentioning the requesting user\n"
        + ("\n".join(rows) if rows else "(No unresolved mentions found in the window.)"),
        None,
    )


async def collect_personal_google_actions(
    slack_user_id: str,
    since_d: str,
    until_d: str,
) -> tuple[str, list[str]]:
    """Return Gmail and Drive-comment evidence plus non-fatal scope warnings."""
    token = await get_valid_access_token(slack_user_id)
    warnings: list[str] = []
    user_email = await slack_users_lookup_email(slack_user_id)
    async with httpx.AsyncClient(timeout=60) as client:
        gmail, gmail_warning = await _gmail_actions_context(
            client, token, since_d, until_d
        )
        if gmail:
            for line in gmail.splitlines():
                if line.startswith("Google account: "):
                    account_email = line.removeprefix("Google account: ").strip()
                    if account_email and account_email != "(unknown)":
                        user_email = account_email
                    break
        drive, drive_warning = await _drive_comment_actions_context(
            client, token, user_email, since_d, until_d
        )
    if gmail_warning:
        warnings.append(gmail_warning)
    if drive_warning:
        warnings.append(drive_warning)
    sections = [s for s in (gmail, drive) if s]
    return "\n\n".join(sections), warnings
