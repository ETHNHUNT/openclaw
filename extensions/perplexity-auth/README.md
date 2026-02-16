# Perplexity Auth (OpenClaw plugin)

Auth provider plugin for **Perplexity AI** — supports both cookie-based session
authentication (no API key required) and standard API key authentication.

## Enable

Bundled plugins are disabled by default. Enable this one:

```bash
openclaw plugins enable perplexity-auth
```

Restart the Gateway after enabling.

## Authenticate

### Method 1: Browser Login (Cookie) — no API key needed

```bash
openclaw models auth login --provider perplexity
# Select "Browser Login (Cookie)"
```

This opens Perplexity in your browser. After logging in, your session cookies
are captured and stored. Sessions typically last 30 days.

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
