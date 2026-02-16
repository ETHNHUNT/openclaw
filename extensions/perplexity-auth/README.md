# Perplexity Auth (OpenClaw plugin)

Auth provider plugin for **Perplexity AI** — supports Google OAuth sign-in
(cookie-based, no API key) and standard API key authentication.

## Enable

Bundled plugins are disabled by default. Enable this one:

```bash
openclaw plugins enable perplexity-auth
```

Restart the Gateway after enabling.

## Authenticate

### Method 1: Google Sign-In (Cookie) — no API key needed

```bash
openclaw models auth login --provider perplexity
# Select "Google Sign-In (via Perplexity)"
```

This opens a localhost page that walks you through:

1. Click **"Sign in with Google on Perplexity"** — opens perplexity.ai
2. Click **"Continue with Google"** and authenticate with the Google account
   linked to your Perplexity account
3. After login, run a small JS snippet in the browser console (provided
   on the page) to send your session cookies back to the local server
4. The plugin validates the session and stores the cookies

Sessions typically last 30 days. Re-run the login flow if they expire.

### Method 2: API Key

```bash
openclaw models auth login --provider perplexity
# Select "API Key"
```

Get your API key from [perplexity.ai/settings/api](https://www.perplexity.ai/settings/api).

## Models

- `perplexity/sonar` — fast Q&A with web search
- `perplexity/sonar-pro` (default) — multi-step reasoning + web search
- `perplexity/sonar-reasoning` — chain of thought reasoning
- `perplexity/sonar-reasoning-pro` — advanced reasoning
- `perplexity/sonar-deep-research` — deep research mode

## Notes

- Cookie auth is useful when you don't have or want to pay for a Perplexity API key.
- API key auth is more reliable for production use.
- If cookie-based sessions expire, re-authenticate with the browser login flow.
