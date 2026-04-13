# Security

This document is for anyone **deploying** or **hardening** Susan. Slack slash commands are only as trustworthy as your workspace membership and your server configuration.

## What Susan trusts

| Input | How it is validated |
|--------|----------------------|
| `POST /susan`, `POST /susan/actions` | Slack [request signing](https://api.slack.com/authentication/verifying-requests-from-slack): each request must include a valid `X-Slack-Signature` and a timestamp within **~5 minutes** of server time. That limit applies only to **that HTTP request** (anti-replay). It is **not** a user session timeout: Slack users do **not** need to reconnect to Susan every five minutes. |
| OAuth `state` (Google/GitHub browser flow) | HMAC-SHA256 over JSON payload + expiry. Default link lifetime **24 hours** (`OAUTH_STATE_TTL_SECONDS`, minimum 300s). This is only how long the **“Connect” URL** remains valid; after a successful connect, **Google refresh tokens** and **GitHub access tokens** stay in the database until the user reconnects or revokes access. |
| GitHub repo targets | `GITHUB_REPOS` / `GITHUB_ISSUES_REPOS` allowlists (when set) constrain which `owner/repo` values are honored. |

Unauthenticated endpoints include OAuth browser redirects, `GET /`, and `GET /health`. They do not accept Slack commands.

## High-impact configuration (read before multi-user or public-ish deploys)

### Shared tokens (`GITHUB_TOKEN`, `GOOGLE_ACCESS_TOKEN`)

If these environment variables are set, **every** Slack user’s GitHub or Google actions use the **same** credentials. That is appropriate only for a **single-operator** or **fully trusted** workspace.

For normal team use, leave them **unset** and rely on per-user OAuth via `/susan connect google` and `/susan connect github`.

### Repo allowlists (`GITHUB_REPOS`, `GITHUB_ISSUES_REPOS`)

Without an allowlist, a user who can run `/susan` and who types `owner/repo` in the command may target any repo their linked GitHub token can access. For broader adoption, set **`GITHUB_REPOS`** (comma-separated) so PR summary pickers and defaults cannot wander onto arbitrary org repos.

### OAuth state secret (`OAUTH_STATE_SECRET`)

By default, OAuth state is signed with `SLACK_SIGNING_SECRET`. For defense in depth, set a **dedicated** `OAUTH_STATE_SECRET` (long random string) so a compromised Slack signing secret does not automatically forge OAuth state.

### Weekly auto-post (`--no-approval`)

`/susan weekly status --no-approval` posts directly to a channel. Restrict who may use it with **`SUSAN_WEEKLY_AUTO_POST_USER_IDS`** (comma-separated Slack user IDs). If unset, any workspace member who can invoke `/susan` can use the flag.

### Cost and abuse (Anthropic API)

There is **no application-level rate limit** on Claude calls. A busy workspace or a noisy channel can drive API usage. Mitigations: limit who can install/use the app, monitor Anthropic usage, and optionally put a reverse proxy or WAF with rate limits in front of your deployment.

## Data you are responsible for protecting

- **Database** (`DATABASE_URL` or SQLite file): stores Google **refresh tokens** and GitHub **access tokens** keyed by Slack user ID. Use managed Postgres with encryption at rest where available; restrict network access to the DB.
- **Environment / secrets**: treat `.env` and platform secret stores like production credentials; never commit real values (see `.env.example` for names only).

## Reporting issues

If you believe you found a vulnerability, please report it privately to the repository maintainers (or your org’s security contact) rather than opening a public issue with exploit details.
