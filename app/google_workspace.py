"""Google Docs, Gmail, Calendar via user OAuth tokens."""
from __future__ import annotations

import base64
import os
from email.mime.text import MIMEText

import httpx

from db import get_valid_access_token

from app.config import EMAIL_IN_TEXT_RE
from app.slack_api import _slack_unresolved_recipients_help, resolve_slack_recipients_to_emails
from app.slack_commands import parse_email_draft, parse_invite_draft

async def create_google_doc(content: str, slack_user_id: str) -> str:
    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://docs.googleapis.com/v1/documents",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"title": "Susan — Meeting Notes"},
        )
        doc = r.json()
        if r.status_code >= 400:
            hint = (
                " Enable **Google Docs API** for the same GCP project as your OAuth client "
                "(APIs & Services → Library → Google Docs API). "
                "Then revoke Susan at https://myaccount.google.com/permissions and run `/susan connect` again."
            )
            if r.status_code in (401, 403):
                return f"Google Docs rejected this token ({r.status_code}).{hint} Raw: {doc}"
            return f"Failed to create doc: {doc}"
        doc_id = doc.get("documentId")
        if not doc_id:
            return f"Failed to create doc: {doc}"
        await client.post(
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"requests": [{"insertText": {"location": {"index": 1}, "text": content}}]},
        )
    return f"Google Doc created: https://docs.google.com/document/d/{doc_id}"


async def send_gmail(content: str, slack_user_id: str) -> str:
    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    parsed = parse_email_draft(content)
    to_raw = (parsed.get("to") or "").strip()
    if not to_raw:
        to_raw = (os.environ.get("DEFAULT_EMAIL_TO") or "").strip()
    to_raw, slack_unres = await resolve_slack_recipients_to_emails(to_raw)
    if slack_unres and not EMAIL_IN_TEXT_RE.findall(to_raw):
        return "Email not sent — " + _slack_unresolved_recipients_help(", ".join(slack_unres))
    if not to_raw:
        return (
            "Email not sent — add *To:* recipients in the draft (or set DEFAULT_EMAIL_TO on the server)."
        )
    recipients = list(dict.fromkeys(EMAIL_IN_TEXT_RE.findall(to_raw)))
    if not recipients:
        return (
            "Email not sent — no valid email addresses in *To:* after resolving Slack mentions. "
            "Use emails or <@USER_ID> with **users:read.email** scope."
        )
    subject = (parsed.get("subject") or "Email from Susan").strip()
    body = parsed.get("body") or ""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["To"] = ", ".join(recipients)
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {token}"},
            json={"raw": raw},
        )
    if r.status_code == 200:
        return "Email sent via Gmail."
    try:
        err = r.json()
    except json.JSONDecodeError:
        err = r.text
    return f"Gmail error ({r.status_code}): {err}"


async def create_calendar_invite(content: str, slack_user_id: str) -> str:
    try:
        token = await get_valid_access_token(slack_user_id)
    except ValueError as e:
        return str(e)
    p = parse_invite_draft(content)
    title = p["title"]
    tz = p["timezone"] or "UTC"
    start = p["start"]
    end = p["end"]
    desc = p["description"]
    att_raw, att_unres = await resolve_slack_recipients_to_emails(p["attendees"])
    emails = list(dict.fromkeys(EMAIL_IN_TEXT_RE.findall(att_raw)))
    if not emails and att_unres:
        return "Calendar invite not created — " + _slack_unresolved_recipients_help(
            ", ".join(att_unres)
        )
    if not emails:
        fallback = (os.environ.get("DEFAULT_EMAIL_TO") or "").strip()
        if fallback:
            emails = EMAIL_IN_TEXT_RE.findall(fallback) or ([fallback] if "@" in fallback else [])
    event: dict = {
        "summary": title,
        "description": desc or content,
        "start": {"dateTime": start, "timeZone": tz},
        "end": {"dateTime": end, "timeZone": tz},
    }
    if emails:
        event["attendees"] = [{"email": e} for e in emails]
    url = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    if emails:
        url = f"{url}?sendUpdates=all"
    async with httpx.AsyncClient() as client:
        r = await client.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=event,
        )
    data = r.json()
    if r.status_code >= 400:
        return f"Calendar error ({r.status_code}): {data}"
    link = data.get("htmlLink", "")
    return f"Calendar invite created: {link}" if link else f"Calendar error: {data}"
