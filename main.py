import os, hmac, hashlib, time, httpx
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
SLACK_BOT_TOKEN      = os.environ["SLACK_BOT_TOKEN"]
ANTHROPIC_API_KEY    = os.environ["ANTHROPIC_API_KEY"]
GITHUB_TOKEN         = os.environ.get("GITHUB_TOKEN", "")

ACTIONS = {
    "doc":    ("create a doc",   ["doc", "document", "notes"]),
    "email":  ("send email",     ["email", "mail"]),
    "invite": ("create invite",  ["invite", "calendar", "meeting", "event"]),
    "pr":     ("create pr",      ["pr", "pull request", "github"]),
}

def verify_slack(req_body: bytes, timestamp: str, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False
    sig_base = f"v0:{timestamp}:{req_body.decode()}"
    expected = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_base.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

def detect_action(text: str) -> str | None:
    lower = text.lower()
    for key, (_, keywords) in ACTIONS.items():
        if any(k in lower for k in keywords):
            return key
    return None

async def fetch_slack_history(channel: str, thread_ts: str | None) -> str:
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}"}
    params = {"channel": channel, "limit": 50}
    endpoint = "https://slack.com/api/conversations.replies" if thread_ts else "https://slack.com/api/conversations.history"
    if thread_ts:
        params["ts"] = thread_ts
    async with httpx.AsyncClient() as client:
        r = await client.get(endpoint, headers=headers, params=params)
    data = r.json()
    msgs = data.get("messages", [])
    lines = []
    for m in reversed(msgs):
        user = m.get("user", "unknown")
        text = m.get("text", "")
        lines.append(f"{user}: {text}")
    return "\n".join(lines)

async def call_claude(system: str, user: str) -> str:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
    data = r.json()
    return data["content"][0]["text"]

async def post_ephemeral(channel: str, user: str, text: str, blocks: list | None = None):
    payload = {"channel": channel, "user": user, "text": text}
    if blocks:
        payload["blocks"] = blocks
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://slack.com/api/chat.postEphemeral",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json=payload,
        )

async def post_message(channel: str, text: str, thread_ts: str | None = None):
    payload = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json=payload,
        )

SYSTEM_PROMPTS = {
    "doc": "You are Susan. Given a Slack conversation, write a structured document with sections: ## Summary, ## Key Decisions, ## Action Items, ## Open Questions. Be concise and professional.",
    "email": "You are Susan. Given a Slack conversation, draft a professional email. Output ONLY:\nSubject: <subject>\n\n<body>",
    "invite": "You are Susan. Given a Slack conversation, draft a calendar invite. Output ONLY:\nTitle: ...\nDate/Time: ...\nDuration: ...\nAttendees: ...\nAgenda: ...\nInfer details from context.",
    "pr": "You are Susan. Given a Slack conversation about code, draft a GitHub PR. Output ONLY:\nTitle: ...\n\nDescription:\n...\n\nFiles changed:\n<filename>\n```\n<code>\n```",
}

async def process_command(action: str, convo: str, instructions: str, channel: str, user: str, thread_ts: str | None):
    try:
        preview = await call_claude(SYSTEM_PROMPTS[action], f"Slack conversation:\n{convo}\n\nExtra instructions: {instructions}")
        truncated = preview[:2800] + ("..." if len(preview) > 2800 else "")
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Susan preview — {ACTIONS[action][0]}*\n_(Only visible to you)_"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"```{truncated}```"}},
            {"type": "actions", "block_id": f"susan_{action}_{channel}_{thread_ts or 'none'}",
             "elements": [
                 {"type": "button", "text": {"type": "plain_text", "text": "✓ Approve & execute"}, "style": "primary", "action_id": f"approve_{action}", "value": preview[:2000]},
                 {"type": "button", "text": {"type": "plain_text", "text": "✗ Cancel"}, "action_id": "cancel_susan"},
             ]},
        ]
        await post_ephemeral(channel, user, f"Susan preview ready for: {ACTIONS[action][0]}", blocks)
    except Exception as e:
        await post_ephemeral(channel, user, f"Susan error: {str(e)}")

@app.post("/susan")
async def slash_susan(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    ts  = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    if not verify_slack(body, ts, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    form = await request.form()
    text      = form.get("text", "").strip()
    channel   = form.get("channel_id", "")
    user      = form.get("user_id", "")
    thread_ts = form.get("thread_ts")
    action = detect_action(text)
    if not action:
        return JSONResponse({"response_type": "ephemeral", "text": "Susan doesn't understand that command. Try: `create a doc`, `send email`, `create invite`, or `create pr`."})
    async def run():
        convo = await fetch_slack_history(channel, thread_ts)
        await process_command(action, convo, text, channel, user, thread_ts)
    background_tasks.add_task(run)
    return JSONResponse({"response_type": "ephemeral", "text": f"Got it — Susan is reading the channel and preparing a *{ACTIONS[action][0]}* preview..."})

@app.post("/susan/actions")
async def handle_action(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    ts  = request.headers.get("X-Slack-Request-Timestamp", "")
    sig = request.headers.get("X-Slack-Signature", "")
    if not verify_slack(body, ts, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")
    import json, urllib.parse
    form = await request.form()
    payload     = json.loads(urllib.parse.unquote(form.get("payload", "{}")))
    action_id   = payload["actions"][0]["action_id"]
    value       = payload["actions"][0].get("value", "")
    channel     = payload["container"]["channel_id"]
    user        = payload["user"]["id"]
    if action_id == "cancel_susan":
        return JSONResponse({"response_type": "ephemeral", "text": "Susan cancelled. No action taken."})
    action_type = action_id.replace("approve_", "")
    async def execute():
        try:
            if action_type == "doc":
                result = await create_google_doc(value)
            elif action_type == "email":
                result = await send_gmail(value)
            elif action_type == "invite":
                result = await create_calendar_invite(value)
            elif action_type == "pr":
                result = await create_github_pr(value)
            else:
                result = "Unknown action."
            await post_ephemeral(channel, user, f"✓ Susan done: {result}")
        except Exception as e:
            await post_ephemeral(channel, user, f"Susan error during execution: {str(e)}")
    background_tasks.add_task(execute)
    return JSONResponse({"response_type": "ephemeral", "text": "Susan is executing..."})

async def create_google_doc(content: str) -> str:
    token = os.environ.get("GOOGLE_ACCESS_TOKEN")
    if not token:
        return "Google Doc not created — GOOGLE_ACCESS_TOKEN not set."
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://docs.googleapis.com/v1/documents",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"title": "Susan — Meeting Notes"},
        )
        doc = r.json()
        doc_id = doc.get("documentId")
        if not doc_id:
            return f"Failed to create doc: {doc}"
        await client.post(
            f"https://docs.googleapis.com/v1/documents/{doc_id}:batchUpdate",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"requests": [{"insertText": {"location": {"index": 1}, "text": content}}]},
        )
    return f"Google Doc created: https://docs.google.com/document/d/{doc_id}"

async def send_gmail(content: str) -> str:
    import base64
    from email.mime.text import MIMEText
    token = os.environ.get("GOOGLE_ACCESS_TOKEN")
    if not token:
        return "Email not sent — GOOGLE_ACCESS_TOKEN not set."
    lines = content.split("\n")
    subj_line = next((l for l in lines if l.lower().startswith("subject:")), "Subject: Update from Susan")
    subject = subj_line.split(":", 1)[1].strip()
    body = "\n".join(lines[lines.index(subj_line)+2:]) if subj_line in lines else content
    to_addr = os.environ.get("DEFAULT_EMAIL_TO", "")
    if not to_addr:
        return "Email not sent — DEFAULT_EMAIL_TO not set."
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["To"] = to_addr
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {token}"},
            json={"raw": raw},
        )
    return "Email sent via Gmail." if r.status_code == 200 else f"Gmail error: {r.text}"

async def create_calendar_invite(content: str) -> str:
    import re
    token = os.environ.get("GOOGLE_ACCESS_TOKEN")
    if not token:
        return "Invite not created — GOOGLE_ACCESS_TOKEN not set."
    title = re.search(r"Title:\s*(.+)", content)
    title = title.group(1).strip() if title else "Meeting"
    event = {
        "summary": title,
        "description": content,
        "start": {"dateTime": "2026-04-01T10:00:00Z", "timeZone": "UTC"},
        "end":   {"dateTime": "2026-04-01T11:00:00Z", "timeZone": "UTC"},
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events",
            headers={"Authorization": f"Bearer {token}"},
            json=event,
        )
    data = r.json()
    link = data.get("htmlLink", "")
    return f"Calendar invite created: {link}" if link else f"Calendar error: {data}"

async def create_github_pr(content: str) -> str:
    import re
    token = GITHUB_TOKEN
    repo  = os.environ.get("GITHUB_REPO", "")
    base  = os.environ.get("GITHUB_BASE_BRANCH", "main")
    if not token or not repo:
        return "PR not created — GITHUB_TOKEN or GITHUB_REPO not set."
    title_m = re.search(r"^Title:\s*(.+)", content, re.M)
    desc_m  = re.search(r"Description:\s*([\s\S]+?)(?=Files changed:|$)", content)
    title = title_m.group(1).strip() if title_m else "Susan: changes from Slack"
    desc  = desc_m.group(1).strip() if desc_m else content
    branch = f"susan/slack-{int(time.time())}"
    hdrs = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        sha_r = await client.get(f"https://api.github.com/repos/{repo}/git/refs/heads/{base}", headers=hdrs)
        sha = sha_r.json().get("object", {}).get("sha")
        if not sha:
            return f"Could not find base branch '{base}' in {repo}."
        await client.post(f"https://api.github.com/repos/{repo}/git/refs", headers=hdrs,
                          json={"ref": f"refs/heads/{branch}", "sha": sha})
        pr_r = await client.post(f"https://api.github.com/repos/{repo}/pulls", headers=hdrs,
                                 json={"title": title, "body": desc, "head": branch, "base": base})
    pr = pr_r.json()
    return f"PR created: {pr.get('html_url', pr)}"

@app.get("/health")
async def health():
    return {"status": "ok", "service": "susan"}
