# Susan — AI Chief of Staff

A FastAPI backend powering `/susan` in Slack.

## Commands
- `/susan create a doc [instructions]`
- `/susan send email [instructions]`
- `/susan create invite [instructions]`
- `/susan create pr [instructions]`

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
| `GOOGLE_ACCESS_TOKEN` | OAuth2 token for Docs/Gmail/Calendar |
| `DEFAULT_EMAIL_TO` | Default email recipient |
| `GITHUB_TOKEN` | GitHub personal access token |
| `GITHUB_REPO` | e.g. `myorg/myrepo` |
| `GITHUB_BASE_BRANCH` | e.g. `main` |

See the full README in the artifacts for detailed setup instructions.
