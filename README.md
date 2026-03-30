# Susan — AI Chief of Staff

A FastAPI backend powering `/susan` in Slack.

## Commands
- `/susan connect` — link Google and/or GitHub (OAuth)
- `/susan connect google` / `/susan connect github`
- `/susan create a doc [instructions]`
- `/susan send email [instructions]`
- `/susan create invite [instructions]`
- `/susan create issue [instructions]` — open a GitHub issue (repo: `GITHUB_ISSUES_REPO` or `GITHUB_REPO`)
- `/susan create pr [instructions]` — open a PR (repo: `GITHUB_REPO`)

## Deploy on Railway
1. Connect this repo in Railway
2. Set start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Add environment variables (see below)

## Environment variables
| Variable | Description |
|---|---|
| `SLACK_SIGNING_SECRET` | Slack App → Basic Information |
| `SLACK_BOT_TOKEN` | Bot User OAuth Token (`xoxb-...`) |
| `ANTHROPIC_API_KEY` | console.anthropic.com |
| `GOOGLE_ACCESS_TOKEN` | Optional: single shared Google token (else per-user OAuth via `/susan connect google`) |
| `DEFAULT_EMAIL_TO` | Default email recipient |
| `GITHUB_TOKEN` | Optional: shared PAT for PRs (else per-user OAuth via `/susan connect github`) |
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID (per-user connect) |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |
| `GITHUB_REDIRECT_URI` | Must match the app exactly, e.g. `https://<host>/auth/github/callback` |
| `GITHUB_OAUTH_SCOPE` | Optional; default `repo` (use `public_repo` for public repos only) |
| `GITHUB_REPO` | Default repo for PRs (e.g. `myorg/myrepo`) when you don’t type `owner/repo` in the command |
| `GITHUB_REPOS` | Optional comma-separated **allowlist** (e.g. `org/a,org/b`). If several repos are listed and `GITHUB_REPO` is not set, Susan sends a **repo picker** (buttons or dropdown) in Slack instead of mis-parsing URLs. |
| `GITHUB_ISSUES_REPO` | Optional; default repo for issues if not set in the command |
| `GITHUB_ISSUES_REPOS` | Optional; comma allowlist for issues (defaults to `GITHUB_REPOS` if unset) |
| `GITHUB_BASE_BRANCH` | e.g. `main` |

See the full README in the artifacts for detailed setup instructions.
