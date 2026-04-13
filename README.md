# Susan — AI Chief of Staff

FastAPI service that powers the **`/susan`** slash command in Slack: summarize threads, draft email and calendar invites, open GitHub issues and PRs, merged-PR summaries, and weekly status (Slack + optional GitHub + Google Drive metadata).

**Security model and hardening:** see [SECURITY.md](SECURITY.md).

## Repository layout

| Path | Purpose |
|------|--------|
| `main.py` | Loads `.env`, exposes `app` for Uvicorn |
| `app/` | Application code (routes, Slack, OAuth, GitHub, Google, weekly flows) |
| `db.py` | Async SQLAlchemy store for OAuth tokens and short-lived picker / resume rows |
| `requirements.txt` | Python dependencies |
| `.env.example` | Environment variable names (copy to `.env`; never commit secrets) |
| `slack-manifest.json` | Slack [app manifest](https://api.slack.com/reference/manifests) — scopes, slash command, interactivity |

## Slack app setup

Susan expects these HTTPS endpoints (replace `https://YOUR_PUBLIC_HOST` with the same base URL you set as `PUBLIC_BASE_URL` in `.env`, with no trailing slash):

| Slack setting | URL |
|---------------|-----|
| Slash command `/susan` | `https://YOUR_PUBLIC_HOST/susan` |
| Interactivity & shortcuts | `https://YOUR_PUBLIC_HOST/susan/actions` |

Both must be **HTTPS** and reachable from Slack’s servers (use a tunnel such as [ngrok](https://ngrok.com/) for local development).

### Option A — Create the app from the manifest (recommended)

1. Open [Your Apps](https://api.slack.com/apps) → **Create New App** → **From an app manifest**.
2. Choose a development workspace and pick **JSON** (or YAML if you convert the file).
3. Edit **`slack-manifest.json`**: replace every `your-host.example` with your real public hostname (e.g. `susan.example.com` or `my-app.up.railway.app`), then paste the file contents into the manifest editor.
4. **Create** the app and review the summary.
5. **Install to Workspace** (left sidebar under *OAuth & Permissions* or the install banner).
6. Copy credentials into `.env`:
   - **Basic Information** → *Signing Secret* → `SLACK_SIGNING_SECRET`
   - **OAuth & Permissions** → *Bot User OAuth Token* → `SLACK_BOT_TOKEN`

### Option B — Configure the app manually

If you prefer not to use the manifest file:

1. **Create New App** → **From scratch**.
2. **Slash Commands** → create `/susan` → Request URL `https://YOUR_PUBLIC_HOST/susan` (POST).
3. **Interactivity & Shortcuts** → On → Request URL `https://YOUR_PUBLIC_HOST/susan/actions`.
4. **OAuth & Permissions** → *Scopes* → *Bot Token Scopes* — add the same scopes as in `slack-manifest.json` (e.g. `commands`, `chat:write`, `chat:write.public`, `channels:history`, `channels:join`, `groups:history`, `im:history`, `im:write`, `mpim:history`, `mpim:write`, `users:read`, `users:read.email`).
5. **Install to Workspace** and copy Signing Secret + Bot Token as above.

### Updating Slack when `slack-manifest.json` changes

When you pull changes that modify scopes, slash command text, or URLs:

1. Edit **`slack-manifest.json`** locally (URLs and any new scopes).
2. In [api.slack.com/apps](https://api.slack.com/apps) → your Susan app → **App Manifest** (left sidebar, under *Settings*).
3. Open the **JSON** (or YAML) editor, **replace** the manifest with your updated file contents, and **Save changes**. Slack shows a diff of what will change.
4. If **bot scopes** changed, go to **OAuth & Permissions** and use **Reinstall to Workspace** (or follow the banner). Otherwise new scopes are not granted and features will fail with `missing_scope`.
5. If only **URLs** changed (e.g. new deployment host), saving the manifest is usually enough; confirm **Slash Commands** and **Interactivity** show the new URLs.

For official reference, see Slack’s [app manifest documentation](https://api.slack.com/reference/manifests) and [manifest fields](https://api.slack.com/reference/manifests#fields).

## Deploy (e.g. Railway)

1. Connect this directory as the service root (the folder that contains `main.py`).
2. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Set environment variables (start from `.env.example`). You need **PostgreSQL** (`DATABASE_URL`) or a **persistent disk** for SQLite (`SQLITE_PATH`), or users will lose OAuth tokens on every redeploy — see the top comment in `db.py`.
4. **Google Cloud / GitHub OAuth apps:** redirect URIs must match `GOOGLE_REDIRECT_URI` and `GITHUB_REDIRECT_URI` exactly (including `https`).
5. After you have a stable public URL, set `PUBLIC_BASE_URL` and **update Slack** (`slack-manifest.json` URLs → **App Manifest** in the Slack app settings, or edit Slash Command / Interactivity URLs manually) so they match this deployment.

## Local development

Requirements: **Python 3.11+** recommended.

```bash
cd susan   # this folder (contains main.py)
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — use ngrok (or similar) for an HTTPS URL; set PUBLIC_BASE_URL and OAuth redirect URIs to that host.
# Edit slack-manifest.json: replace the hostname `your-host.example` with your tunnel/deploy host (keep `https://` and the `/susan` paths).
# Create/update the Slack app from the manifest (see "Slack app setup" above).
uvicorn main:app --reload --port 8000
```

Run tests / checks (if you add them): `python -m py_compile app/*.py` is a minimal syntax smoke test.

**Contributing:** open a PR with a short description of behavior changes; if you touch OAuth, tokens, or Slack verification, note any security impact and update [SECURITY.md](SECURITY.md) if the threat model changes.

## Commands (high level)

- `/susan connect` — Google and/or GitHub (whatever is configured)
- `/susan connect google` / `/susan connect github`
- `/susan create a doc …`, `send email …`, `create invite …`
- `/susan create issue …`, `create pr …` (GitHub OAuth + allowlists)
- `/susan summarize merged prs …` / keywords like `pr summary` — merged PRs over a date range, preview then approve to post to channel
- `/susan weekly status …` — Slack digest; in configured “tech” channel names, includes GitHub metrics and linked Drive activity; optional `--no-approval` (restrict with `SUSAN_WEEKLY_AUTO_POST_USER_IDS`)
- `/susan help` — full in-Slack help

## Environment variables

| Variable | Required? | Description |
|----------|-----------|-------------|
| `SLACK_SIGNING_SECRET` | Yes | Slack app → Basic Information |
| `SLACK_BOT_TOKEN` | Yes | Bot token (`xoxb-…`); needs **`users:read.email`** if you resolve `<@U…>` for Gmail/Calendar |
| `ANTHROPIC_API_KEY` | Yes | [Anthropic Console](https://console.anthropic.com) |
| `GOOGLE_CLIENT_ID` | For Google features | OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | For Google features | OAuth client secret |
| `GOOGLE_REDIRECT_URI` | For Google features | e.g. `https://<host>/auth/google/callback` |
| `GITHUB_CLIENT_ID` | For GitHub features | GitHub OAuth App |
| `GITHUB_CLIENT_SECRET` | For GitHub features | |
| `GITHUB_REDIRECT_URI` | For GitHub features | e.g. `https://<host>/auth/github/callback` |
| `PUBLIC_BASE_URL` | Strongly recommended | e.g. `https://<host>` — used for “Connect” links in Slack |
| `DATABASE_URL` | Recommended in prod | Postgres URL on Railway, etc. |
| `SQLITE_PATH` | Optional | SQLite file path if not using Postgres (use a **persistent** path on PaaS) |
| `OAUTH_STATE_SECRET` | Optional | Separate HMAC key for OAuth `state` (default: `SLACK_SIGNING_SECRET`) |
| `GITHUB_REPO` | Optional | Default `owner/repo` when not specified in text |
| `GITHUB_REPOS` | **Recommended** for teams | Comma-separated allowlist; enables safe repo pickers |
| `GITHUB_ISSUES_REPO` | Optional | Default repo for issues |
| `GITHUB_ISSUES_REPOS` | Optional | Issue allowlist (defaults to `GITHUB_REPOS` if unset) |
| `GITHUB_OAUTH_SCOPE` | Optional | Default `repo`; add `security_events` for Dependabot in weekly status (e.g. `repo security_events`) |
| `GITHUB_BASE_BRANCH` | Optional | Default `main` |
| `GITHUB_TOKEN` | Optional | **Shared PAT for all users** — see SECURITY.md |
| `GOOGLE_ACCESS_TOKEN` | Optional | **Shared Google token for all users** — see SECURITY.md |
| `DEFAULT_EMAIL_TO` | Optional | Fallback when draft has no To: line |
| `SLACK_USER_EMAIL_MAP` | Optional | `U123:a@b.com,…` or JSON map when Slack hides emails |
| `SUSAN_WEEKLY_AUTO_POST_USER_IDS` | Optional | Comma Slack user IDs allowed to use `--no-approval` on weekly status |
| `SUSAN_TECH_WEEKLY_CHANNEL_NAMES` | Optional | Channel name slugs (comma) that get GitHub metrics in weekly status; default `team-tech,software,security` |

Tuning knobs (messages, Drive scan depth, Claude retries, etc.) are documented inline in `.env.example`.

## License / ownership

Add a `LICENSE` file if you distribute the repo; this README does not impose one by default.
