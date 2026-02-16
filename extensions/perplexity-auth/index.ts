import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import {
  buildOauthProviderAuthResult,
  emptyPluginConfigSchema,
  isWSL2Sync,
  type OpenClawPluginApi,
  type ProviderAuthContext,
  type ProviderAuthResult,
} from "openclaw/plugin-sdk";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PROVIDER_ID = "perplexity";
const PROVIDER_LABEL = "Perplexity";
const DEFAULT_MODEL = "perplexity/sonar-pro";

const PERPLEXITY_BASE = "https://www.perplexity.ai";
const PERPLEXITY_API_BASE = "https://api.perplexity.ai";
const LOGIN_URL = `${PERPLEXITY_BASE}/api/auth/signin/email`;
const SESSION_URL = `${PERPLEXITY_BASE}/api/auth/session`;
const CALLBACK_PORT = 51122;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/perplexity-callback`;

const SESSION_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

const PERPLEXITY_MODELS = [
  "perplexity/sonar",
  "perplexity/sonar-pro",
  "perplexity/sonar-reasoning",
  "perplexity/sonar-reasoning-pro",
  "perplexity/sonar-deep-research",
];

const RESPONSE_PAGE = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>OpenClaw Perplexity Auth</title>
    <style>
      body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
             align-items: center; min-height: 100vh; margin: 0; background: #0a0a0a; color: #e0e0e0; }
      main { text-align: center; padding: 2rem; }
      h1 { color: #20b2aa; }
    </style>
  </head>
  <body>
    <main>
      <h1>Authentication complete</h1>
      <p>You can return to the terminal.</p>
    </main>
  </body>
</html>`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function shouldUseManualFlow(isRemote: boolean): boolean {
  return isRemote || isWSL2Sync();
}

function generateState(): string {
  return randomBytes(16).toString("hex");
}

// ---------------------------------------------------------------------------
// Cookie-based session auth flow
// ---------------------------------------------------------------------------
// Perplexity uses email-based magic link / OTP login. The flow:
// 1. We start a localhost callback server
// 2. We open Perplexity's login page in the user's browser
// 3. user logs in → Perplexity sets session cookies
// 4. We extract cookies via a helper page -OR- user pastes them manually
//
// Since Perplexity doesn't expose standard OAuth2, we use a session-cookie
// approach similar to how Antigravity captures Google OAuth tokens.
// ---------------------------------------------------------------------------

/**
 * Starts a local HTTP server that serves a cookie-extraction helper page.
 * The page has a small JS snippet that reads document.cookie after
 * Perplexity login and POSTs it back to the server.
 */
async function startCookieCallbackServer(params: { timeoutMs: number }) {
  const port = CALLBACK_PORT;
  let settled = false;
  let resolveCallback: (data: { cookies: string; sessionToken?: string }) => void;
  let rejectCallback: (err: Error) => void;

  const callbackPromise = new Promise<{ cookies: string; sessionToken?: string }>(
    (resolve, reject) => {
      resolveCallback = (data) => {
        if (settled) return;
        settled = true;
        resolve(data);
      };
      rejectCallback = (err) => {
        if (settled) return;
        settled = true;
        reject(err);
      };
    },
  );

  const timeout = setTimeout(() => {
    rejectCallback(new Error("Timed out waiting for Perplexity login callback"));
  }, params.timeoutMs);
  timeout.unref?.();

  const server = createServer((req, res) => {
    if (!req.url) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Missing URL");
      return;
    }

    const url = new URL(req.url, `http://localhost:${port}`);

    // POST /perplexity-callback — receives cookies from the helper page or manual paste
    if (url.pathname === "/perplexity-callback" && req.method === "POST") {
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(RESPONSE_PAGE);

        try {
          const data = JSON.parse(body) as { cookies?: string; sessionToken?: string };
          resolveCallback({
            cookies: data.cookies ?? "",
            sessionToken: data.sessionToken,
          });
        } catch {
          resolveCallback({ cookies: body });
        }

        setImmediate(() => server.close());
      });
      return;
    }

    // OPTIONS preflight for CORS
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    // GET /perplexity-callback — info page
    if (url.pathname === "/perplexity-callback") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(RESPONSE_PAGE);
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      server.off("error", onError);
      reject(err);
    };
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });

  return {
    waitForCallback: () => callbackPromise,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

/**
 * Validates Perplexity session cookies by hitting the session endpoint.
 */
async function validatePerplexitySession(
  cookies: string,
): Promise<{ valid: boolean; email?: string; isPro?: boolean }> {
  try {
    const res = await fetch(SESSION_URL, {
      headers: {
        Cookie: cookies,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) OpenClaw/1.0",
      },
    });

    if (!res.ok) {
      return { valid: false };
    }

    const data = (await res.json()) as {
      user?: { email?: string; name?: string; image?: string };
      expires?: string;
    };

    if (data.user?.email) {
      return { valid: true, email: data.user.email };
    }

    return { valid: false };
  } catch {
    return { valid: false };
  }
}

/**
 * Main login flow — opens Perplexity in browser for the user to log in,
 * then captures session cookies (via local callback or manual paste).
 */
async function loginPerplexity(params: {
  isRemote: boolean;
  openUrl: (url: string) => Promise<void>;
  prompt: (message: string) => Promise<string>;
  note: (message: string, title?: string) => Promise<void>;
  log: (message: string) => void;
  progress: { update: (msg: string) => void; stop: (msg?: string) => void };
}): Promise<{
  cookies: string;
  email?: string;
  expires: number;
}> {
  const needsManual = shouldUseManualFlow(params.isRemote);
  const loginUrl = `${PERPLEXITY_BASE}/`;

  let callbackServer: Awaited<ReturnType<typeof startCookieCallbackServer>> | null = null;

  if (!needsManual) {
    try {
      callbackServer = await startCookieCallbackServer({ timeoutMs: CALLBACK_TIMEOUT_MS });
    } catch {
      callbackServer = null;
    }
  }

  // Manual flow: user must copy cookies after logging in
  if (!callbackServer) {
    await params.note(
      [
        "1. Open Perplexity in your browser and log in",
        "2. Open DevTools (F12) → Application → Cookies → perplexity.ai",
        "3. Copy all cookies as a semicolon-separated string",
        "   Format: name1=value1; name2=value2; ...",
        "",
        `Login URL: ${loginUrl}`,
      ].join("\n"),
      "Perplexity Cookie Auth",
    );
    params.log("");
    params.log("Login to Perplexity here:");
    params.log(loginUrl);
    params.log("");

    params.progress.update("Waiting for cookies…");
    const cookieInput = await params.prompt(
      "Paste your Perplexity cookies (from browser DevTools): ",
    );

    if (!cookieInput?.trim()) {
      throw new Error("No cookies provided");
    }

    const validation = await validatePerplexitySession(cookieInput.trim());
    if (!validation.valid) {
      throw new Error(
        "Cookie validation failed. Make sure to copy all cookies from perplexity.ai.",
      );
    }

    return {
      cookies: cookieInput.trim(),
      email: validation.email,
      expires: Date.now() + SESSION_EXPIRY_MS,
    };
  }

  // Automatic flow: open browser and wait for callback
  params.progress.update("Opening Perplexity login…");
  try {
    await params.openUrl(loginUrl);
  } catch {
    // ignore — user can still open manually
  }

  await params.note(
    [
      "Log in to Perplexity in your browser.",
      "After logging in, run this in the browser console (F12):",
      "",
      `fetch("${REDIRECT_URI}", {`,
      `  method: "POST",`,
      `  headers: { "Content-Type": "application/json" },`,
      `  body: JSON.stringify({ cookies: document.cookie })`,
      `});`,
      "",
      "Or paste your cookies below.",
    ].join("\n"),
    "Perplexity Login",
  );

  params.progress.update("Waiting for Perplexity session…");

  // Race: wait for callback OR manual paste
  const callbackResult = await Promise.race([
    callbackServer.waitForCallback(),
    (async () => {
      // Give the callback server a few seconds head start
      await new Promise((r) => setTimeout(r, 3000));
      const input = await params.prompt(
        "Or paste cookies here (leave empty to wait for browser callback): ",
      );
      if (input?.trim()) {
        return { cookies: input.trim(), sessionToken: undefined };
      }
      // If empty, keep waiting for the callback server
      return callbackServer!.waitForCallback();
    })(),
  ]);

  await callbackServer.close().catch(() => {});

  const cookies = callbackResult.cookies;
  if (!cookies) {
    throw new Error("No session cookies received");
  }

  params.progress.update("Validating session…");
  const validation = await validatePerplexitySession(cookies);

  return {
    cookies,
    email: validation.email,
    expires: Date.now() + SESSION_EXPIRY_MS,
  };
}

// ---------------------------------------------------------------------------
// Plugin definition
// ---------------------------------------------------------------------------
const perplexityPlugin = {
  id: "perplexity-auth",
  name: "Perplexity Auth",
  description: "Cookie-based session auth and API key auth for Perplexity AI",
  configSchema: emptyPluginConfigSchema(),
  register(api: OpenClawPluginApi) {
    api.registerProvider({
      id: PROVIDER_ID,
      label: PROVIDER_LABEL,
      docsPath: "/perplexity",
      aliases: ["pplx"],
      envVars: ["PERPLEXITY_API_KEY"],
      auth: [
        // ----------------------------------------------------------------
        // Method 1: Cookie / session auth (no API key needed)
        // ----------------------------------------------------------------
        {
          id: "cookie",
          label: "Browser Login (Cookie)",
          hint: "Log in via browser — no API key required",
          kind: "oauth" as const,
          run: async (ctx: ProviderAuthContext) => {
            const spin = ctx.prompter.progress("Starting Perplexity cookie auth…");
            try {
              const result = await loginPerplexity({
                isRemote: ctx.isRemote,
                openUrl: ctx.openUrl,
                prompt: async (message) => String(await ctx.prompter.text({ message })),
                note: ctx.prompter.note,
                log: (message) => ctx.runtime.log(message),
                progress: spin,
              });

              const email = result.email ?? "default";
              const profileId = `${PROVIDER_ID}:${email}`;
              const modelEntries: Record<string, Record<string, never>> = {};
              for (const m of PERPLEXITY_MODELS) {
                modelEntries[m] = {};
              }

              spin.stop("Perplexity cookie auth complete");

              return {
                profiles: [
                  {
                    profileId,
                    credential: {
                      type: "oauth" as const,
                      provider: PROVIDER_ID,
                      access: result.cookies,
                      refresh: "",
                      expires: result.expires,
                      email: result.email,
                    },
                  },
                ],
                configPatch: {
                  agents: {
                    defaults: {
                      models: modelEntries,
                    },
                  },
                } as ProviderAuthResult["configPatch"],
                defaultModel: DEFAULT_MODEL,
                notes: [
                  "Cookie-based auth — sessions typically last 30 days.",
                  "If requests fail, re-run: openclaw models auth login --provider perplexity",
                  "For stable API access, use an API key instead (perplexity.ai/settings/api).",
                ],
              } satisfies ProviderAuthResult;
            } catch (err) {
              spin.stop("Perplexity cookie auth failed");
              throw err;
            }
          },
        },
        // ----------------------------------------------------------------
        // Method 2: API key auth
        // ----------------------------------------------------------------
        {
          id: "api-key",
          label: "API Key",
          hint: "Enter your Perplexity API key from perplexity.ai/settings/api",
          kind: "api_key" as const,
          run: async (ctx: ProviderAuthContext) => {
            const spin = ctx.prompter.progress("Perplexity API key setup…");
            try {
              const key = await ctx.prompter.text({
                message: "Perplexity API key (pplx-...):",
              });

              const apiKey = String(key ?? "").trim();
              if (!apiKey) {
                throw new Error("No API key provided");
              }

              // Quick validation: try a lightweight request
              spin.update("Validating API key…");
              const valid = await validateApiKey(apiKey);
              if (!valid) {
                throw new Error(
                  "API key validation failed. Check your key at perplexity.ai/settings/api.",
                );
              }

              const modelEntries: Record<string, Record<string, never>> = {};
              for (const m of PERPLEXITY_MODELS) {
                modelEntries[m] = {};
              }

              spin.stop("Perplexity API key configured");

              return {
                profiles: [
                  {
                    profileId: `${PROVIDER_ID}:api-key`,
                    credential: {
                      type: "api_key" as const,
                      provider: PROVIDER_ID,
                      key: apiKey,
                    },
                  },
                ],
                configPatch: {
                  agents: {
                    defaults: {
                      models: modelEntries,
                    },
                  },
                } as ProviderAuthResult["configPatch"],
                defaultModel: DEFAULT_MODEL,
                notes: [
                  "API key auth — usage is billed through your Perplexity account.",
                  `API endpoint: ${PERPLEXITY_API_BASE}/chat/completions`,
                  "Available models: sonar, sonar-pro, sonar-reasoning, sonar-reasoning-pro, sonar-deep-research",
                ],
              } satisfies ProviderAuthResult;
            } catch (err) {
              spin.stop("Perplexity API key setup failed");
              throw err;
            }
          },
        },
      ],
    });
  },
};

// ---------------------------------------------------------------------------
// API key validation
// ---------------------------------------------------------------------------
async function validateApiKey(apiKey: string): Promise<boolean> {
  try {
    const res = await fetch(`${PERPLEXITY_API_BASE}/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "sonar",
        messages: [{ role: "user", content: "ping" }],
        max_tokens: 1,
      }),
    });

    // 200 = valid; 401/403 = invalid; 429 = rate limited but key works
    return res.status === 200 || res.status === 429;
  } catch {
    return false;
  }
}

export default perplexityPlugin;
