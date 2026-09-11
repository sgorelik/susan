"""`/susan babysit` — trigger the PR farm.

The PR farm (dev-tools/pr-farm) babysits every open PR across the configured
repos to green on an always-on machine. Susan is just a trigger: it POSTs to
the farm's HTTP endpoint (`POST /babysit`) and reports back that a pass has
started. The farm runs asynchronously on its own host; Susan does not wait for
babysitting to finish (a pass can take many minutes).

Env:
  FARM_BASE_URL    e.g. http://farm-host:8787  (required for this command)
  FARM_SERVE_TOKEN bearer token the farm requires on POST /babysit (optional)
"""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger("susan")


def farm_configured() -> bool:
    return bool(os.environ.get("FARM_BASE_URL"))


def _farm_url() -> str:
    return os.environ["FARM_BASE_URL"].rstrip("/")


async def process_babysit(
    text: str,
    channel: str,
    user: str,
    thread_ts: str | None,
    response_url: str | None,
) -> None:
    """POST a babysit trigger to the farm and tell the user it started."""
    from app.slack_api import notify_user_ephemeral

    if not farm_configured():
        await notify_user_ephemeral(
            channel,
            user,
            "The PR farm isn’t configured on this server (`FARM_BASE_URL` unset). "
            "Ask an admin to set it, or run the farm locally with `./run-farm.sh`.",
            None,
            response_url,
        )
        return

    payload: dict = {}
    # Optional: `babysit pr 579 in f1-asgardOS` targets a single PR.
    try:
        body = text.lower()
        if "pr" in body:
            import re

            m = re.search(r"pr\s+#?(\d+)", body)
            if m:
                payload["pr"] = int(m.group(1))
                repo_m = re.search(r"in\s+([\w-]+)", body)
                if repo_m:
                    payload["repo"] = repo_m.group(1)
    except Exception:  # noqa: BLE001
        payload = {}

    headers = {"Content-Type": "application/json"}
    token = os.environ.get("FARM_SERVE_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{_farm_url()}/babysit", json=payload, headers=headers
            )
        if r.status_code in (200, 202):
            target = f"PR #{payload['pr']} in {payload['repo']}" if payload.get("pr") else "all open PRs"
            await notify_user_ephemeral(
                channel,
                user,
                f"PR farm pass started for *{target}*. "
                "Babysitting runs on the farm host and can take several minutes per PR; "
                "the babysitter never merges.",
                None,
                response_url,
            )
        elif r.status_code == 401:
            await notify_user_ephemeral(
                channel,
                user,
                "The PR farm rejected the trigger (401) — `FARM_SERVE_TOKEN` mismatch. "
                "Ask an admin to align the token.",
                None,
                response_url,
            )
        else:
            await notify_user_ephemeral(
                channel,
                user,
                f"PR farm returned HTTP {r.status_code}: {r.text[:300]}",
                None,
                response_url,
            )
    except Exception as e:  # noqa: BLE001
        logger.exception("babysit trigger failed")
        await notify_user_ephemeral(
            channel,
            user,
            f"Could not reach the PR farm at {_farm_url()}: {e}",
            None,
            response_url,
        )
