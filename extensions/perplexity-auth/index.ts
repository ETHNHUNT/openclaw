import { randomBytes } from "node:crypto";
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
const SESSION_URL = `${PERPLEXITY_BASE}/api/auth/session`;

// Perplexity uses NextAuth.js — the Google sign-in trigger.
// Opening this URL (POST via form) initiates the Google OAuth flow on
// Perplexity's side. After Google auth, Perplexity sets session cookies
// and redirects to callbackUrl.
const GOOGLE_SIGNIN_URL = `${PERPLEXITY_BASE}/api/auth/signin/google`;
const CSRF_URL = `${PERPLEXITY_BASE}/api/auth/csrf`;

const CALLBACK_PORT = 51122;
const CALLBACK_PATH = "/perplexity-callback";
const CALLBACK_URI = `http://localhost:${CALLBACK_PORT}${CALLBACK_PATH}`;

const SESSION_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

const PERPLEXITY_MODELS = [
  "perplexity/sonar",
  "perplexity/sonar-pro",
  "perplexity/sonar-reasoning",
  "perplexity/sonar-reasoning-pro",
  "perplexity/sonar-deep-research",
];

// ---------------------------------------------------------------------------
// HTML pages served by the localhost callback server
// ---------------------------------------------------------------------------

/** Page shown after cookies are captured — tells user to return to terminal. */
const DONE_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>OpenClaw Perplexity Auth</title>
  <style>
    body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
           align-items: center; min-height: 100vh; margin: 0; background: #0a0a0a; color: #e0e0e0; }
    main { text-align: center; padding: 2rem; }
    h1 { color: #20b2aa; }
    .check { font-size: 3rem; }
  </style>
</head>
<body>
  <main>
    <div class="check">&#10003;</div>
    <h1>Authentication complete</h1>
    <p>You can close this tab and return to the terminal.</p>
  </main>
</body>
</html>`;

/**
 * Landing page served at the root of the localhost server.
 * It opens Perplexity's Google sign-in in the same window. After the
 * user authenticates with Google, Perplexity redirects back to perplexity.ai
 * with session cookies set. The page then guides the user to extract and
 * send those cookies to the localhost callback.
 *
 * Flow:
 *   localhost:51122  →  (button click) → perplexity.ai/api/auth/signin/google
 *                                       → accounts.google.com (Google OAuth)
 *                                       → perplexity.ai (session set)
 *                    ←  user runs bookmarklet or pastes cookies
 */
function buildLandingPage(state: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>OpenClaw — Perplexity Google Sign-In</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0a;
           color: #e0e0e0; min-height: 100vh; display: flex; justify-content: center;
           align-items: center; }
    main { max-width: 540px; padding: 2.5rem; text-align: center; }
    h1 { color: #20b2aa; margin-bottom: 0.5rem; font-size: 1.5rem; }
    .subtitle { color: #888; margin-bottom: 2rem; }
    .step { background: #151515; border: 1px solid #2a2a2a; border-radius: 12px;
            padding: 1.2rem 1.5rem; margin-bottom: 1rem; text-align: left; }
    .step-num { display: inline-block; width: 1.5rem; height: 1.5rem; background: #20b2aa;
                color: #000; border-radius: 50%; text-align: center; line-height: 1.5rem;
                font-size: 0.85rem; font-weight: 700; margin-right: 0.5rem; }
    .btn { display: inline-block; background: #4285f4; color: #fff; border: none;
           padding: 0.8rem 2rem; border-radius: 8px; font-size: 1rem;
           cursor: pointer; text-decoration: none; margin: 0.5rem 0; }
    .btn:hover { background: #3367d6; }
    .btn-green { background: #20b2aa; }
    .btn-green:hover { background: #1a9e97; }
    .code-box { background: #111; border: 1px solid #333; border-radius: 6px;
                padding: 0.6rem 0.8rem; font-family: monospace; font-size: 0.8rem;
                word-break: break-all; margin: 0.5rem 0; color: #ccc;
                max-height: 80px; overflow-y: auto; }
    #status { margin-top: 1.5rem; padding: 0.8rem; border-radius: 8px; display: none; }
    #status.ok { display: block; background: #0d3d2e; border: 1px solid #20b2aa; color: #20b2aa; }
    #status.err { display: block; background: #3d0d0d; border: 1px solid #aa2020; color: #ff6b6b; }
    textarea { width: 100%; background: #111; border: 1px solid #333; border-radius: 6px;
               color: #ccc; font-family: monospace; font-size: 0.8rem; padding: 0.5rem;
               resize: vertical; min-height: 60px; margin: 0.5rem 0; }
  </style>
</head>
<body>
  <main>
    <h1>Perplexity &times; OpenClaw</h1>
    <p class="subtitle">Sign in with your Google account linked to Perplexity</p>

    <div class="step">
      <span class="step-num">1</span>
      <strong>Sign in with Google</strong>
      <p style="margin:0.5rem 0 0.3rem;color:#999;">Click below to open Perplexity's Google sign-in.
         Authenticate with the Google account linked to your Perplexity.</p>
      <a class="btn" href="${PERPLEXITY_BASE}/" target="_blank" rel="noopener"
         id="loginBtn">Sign in with Google on Perplexity</a>
    </div>

    <div class="step">
      <span class="step-num">2</span>
      <strong>Send cookies back</strong>
      <p style="margin:0.5rem 0 0.3rem;color:#999;">After you are logged in on perplexity.ai,
         open the browser console (<kbd>F12</kbd> → Console) and paste this snippet:</p>
      <div class="code-box" id="snippet">fetch("${CALLBACK_URI}",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cookies:document.cookie,state:"${state}"})})</div>
      <button class="btn btn-green" onclick="copySnippet()" style="font-size:0.85rem;">Copy snippet</button>
    </div>

    <div class="step">
      <span class="step-num" style="background:#888;">&#8230;</span>
      <strong>Or paste cookies manually</strong>
      <p style="margin:0.5rem 0 0.3rem;color:#999;">DevTools → Application → Cookies → perplexity.ai.
         Copy all as <code>name=val; name=val; ...</code></p>
      <textarea id="manualCookies" placeholder="Paste cookies here..."></textarea>
      <button class="btn btn-green" onclick="submitManual()" style="font-size:0.85rem;">Submit cookies</button>
    </div>

    <div id="status"></div>
  </main>
  <script>
    function copySnippet() {
      navigator.clipboard.writeText(document.getElementById("snippet").textContent)
        .then(() => { setStatus("Snippet copied! Paste it in the browser console on perplexity.ai.", "ok"); })
        .catch(() => { setStatus("Copy failed — select the text manually.", "err"); });
    }
    async function submitManual() {
      const cookies = document.getElementById("manualCookies").value.trim();
      if (!cookies) { setStatus("No cookies entered.", "err"); return; }
      try {
        const res = await fetch("${CALLBACK_URI}", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cookies, state: "${state}" }),
        });
        if (res.ok) { setStatus("Cookies sent! Return to the terminal.", "ok"); }
        else { setStatus("Server error — try again.", "err"); }
      } catch (e) { setStatus("Failed to reach local server: " + e.message, "err"); }
    }
    function setStatus(msg, kind) {
      const el = document.getElementById("status");
      el.textContent = msg;
      el.className = kind;
    }
  </script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function shouldUseManualFlow(isRemote: boolean): boolean {
  return isRemote || isWSL2Sync();
}

// ---------------------------------------------------------------------------
// Cookie-based session auth flow (Google OAuth via Perplexity)
// ---------------------------------------------------------------------------
//
// Perplexity uses NextAuth.js with Google as an identity provider.
// The complete flow:
//
//   1. We start a localhost HTTP server that serves a landing page.
//   2. The landing page has a "Sign in with Google on Perplexity" button
//      that opens perplexity.ai (the user clicks "Continue with Google").
//   3. Google OAuth happens (PKCE is handled by Perplexity's server).
//   4. After Google auth, Perplexity sets session cookies in the browser.
//   5. The user runs a small JS snippet (or bookmarklet) on perplexity.ai
//      that POST's document.cookie back to our localhost callback.
//   6. We validate the cookies against Perplexity's session endpoint.
//   7. Cookies are stored as an OAuth credential in OpenClaw.
//
// This mirrors the Antigravity plugin pattern: open Google sign-in →
// authenticate → capture tokens via localhost callback.
// ---------------------------------------------------------------------------

/**
 * Starts a local callback server with a landing page that guides the user
 * through Google sign-in on Perplexity.
 */
async function startCookieCallbackServer(params: { timeoutMs: number; state: string }) {
  const port = CALLBACK_PORT;
  let settled = false;
  let resolveCallback: (data: { cookies: string; state?: string }) => void;
  let rejectCallback: (err: Error) => void;

  const callbackPromise = new Promise<{ cookies: string; state?: string }>((resolve, reject) => {
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
  });

  const timeout = setTimeout(() => {
    rejectCallback(new Error("Timed out waiting for Perplexity login"));
  }, params.timeoutMs);
  timeout.unref?.();

  const landingHtml = buildLandingPage(params.state);

  const server = createServer((req, res) => {
    if (!req.url) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Missing URL");
      return;
    }

    const url = new URL(req.url, `http://localhost:${port}`);

    // GET / — serve the landing/guide page
    if (url.pathname === "/" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(landingHtml);
      return;
    }

    // POST /perplexity-callback — receives cookies
    if (url.pathname === CALLBACK_PATH && req.method === "POST") {
      let body = "";
      req.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(DONE_PAGE);

        try {
          const data = JSON.parse(body) as { cookies?: string; state?: string };
          resolveCallback({
            cookies: data.cookies ?? "",
            state: data.state,
          });
        } catch {
          resolveCallback({ cookies: body });
        }

        setImmediate(() => server.close());
      });
      return;
    }

    // OPTIONS preflight
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      });
      res.end();
      return;
    }

    // GET /perplexity-callback — direct hit shows done page
    if (url.pathname === CALLBACK_PATH && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(DONE_PAGE);
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
 * Validates Perplexity session cookies by hitting the NextAuth session endpoint.
 */
async function validatePerplexitySession(
  cookies: string,
): Promise<{ valid: boolean; email?: string }> {
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
 * Full login flow — opens a localhost landing page that guides the user
 * through Perplexity's Google OAuth sign-in, then captures session cookies.
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
  const state = randomBytes(16).toString("hex");

  // ---- manual flow (remote / WSL2) ----
  if (needsManual) {
    await params.note(
      [
        "1. Open Perplexity in your browser and sign in with Google:",
        `   ${PERPLEXITY_BASE}/`,
        "",
        "2. After login, open DevTools (F12) → Console and run:",
        `   fetch("${CALLBACK_URI}",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cookies:document.cookie})})`,
        "",
        "   OR copy cookies from DevTools → Application → Cookies → perplexity.ai",
        "   and paste them below.",
      ].join("\n"),
      "Perplexity Google Sign-In",
    );
    params.log("");
    params.log("Open Perplexity and sign in with Google:");
    params.log(`${PERPLEXITY_BASE}/`);
    params.log("");

    params.progress.update("Waiting for cookies…");
    const cookieInput = await params.prompt("Paste your Perplexity session cookies: ");

    if (!cookieInput?.trim()) {
      throw new Error("No cookies provided");
    }

    params.progress.update("Validating session…");
    const validation = await validatePerplexitySession(cookieInput.trim());
    if (!validation.valid) {
      throw new Error(
        "Cookie validation failed — make sure you are logged in and copied all cookies from perplexity.ai.",
      );
    }

    return {
      cookies: cookieInput.trim(),
      email: validation.email,
      expires: Date.now() + SESSION_EXPIRY_MS,
    };
  }

  // ---- automatic flow: localhost server + browser ----
  let callbackServer: Awaited<ReturnType<typeof startCookieCallbackServer>> | null = null;
  try {
    callbackServer = await startCookieCallbackServer({
      timeoutMs: CALLBACK_TIMEOUT_MS,
      state,
    });
  } catch {
    // Port busy — fall back to manual paste
    params.progress.update("Waiting for cookies…");
    await params.note(
      `Could not start local server on port ${CALLBACK_PORT}. Paste cookies manually.`,
      "Fallback",
    );
    const cookieInput = await params.prompt("Paste your Perplexity session cookies: ");
    if (!cookieInput?.trim()) throw new Error("No cookies provided");

    const validation = await validatePerplexitySession(cookieInput.trim());
    if (!validation.valid) {
      throw new Error("Cookie validation failed.");
    }
    return {
      cookies: cookieInput.trim(),
      email: validation.email,
      expires: Date.now() + SESSION_EXPIRY_MS,
    };
  }

  // Open the localhost landing page (which has the Google sign-in button)
  const landingUrl = `http://localhost:${CALLBACK_PORT}/`;
  params.progress.update("Opening Google sign-in for Perplexity…");
  try {
    await params.openUrl(landingUrl);
  } catch {
    // ignore — user can open manually
  }

  params.log("");
  params.log("A browser page has opened to guide you through Google sign-in.");
  params.log(`If it didn't open, go to: ${landingUrl}`);
  params.log("");

  params.progress.update("Waiting for Google sign-in via Perplexity…");

  // Wait for cookies to arrive via the callback
  const callbackResult = await callbackServer.waitForCallback();
  await callbackServer.close().catch(() => {});

  const cookies = callbackResult.cookies;
  if (!cookies) {
    throw new Error("No session cookies received");
  }

  // Validate state if it was included
  if (callbackResult.state && callbackResult.state !== state) {
    throw new Error("State mismatch — possible CSRF. Please try again.");
  }

  params.progress.update("Validating Perplexity session…");
  const validation = await validatePerplexitySession(cookies);

  if (!validation.valid) {
    throw new Error(
      "Session validation failed — the cookies may be incomplete. " +
        "Make sure you ran the snippet on perplexity.ai after signing in.",
    );
  }

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
  description: "Google OAuth + cookie auth and API key auth for Perplexity AI",
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
        // Method 1: Google OAuth via Perplexity (cookie-based, no API key)
        // ----------------------------------------------------------------
        {
          id: "google-oauth",
          label: "Google Sign-In (via Perplexity)",
          hint: "Sign in with Google → captures Perplexity session cookies",
          kind: "oauth" as const,
          run: async (ctx: ProviderAuthContext) => {
            const spin = ctx.prompter.progress("Starting Perplexity Google sign-in…");
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

              spin.stop("Perplexity Google sign-in complete");

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
                  "Authenticated via Google → Perplexity session cookies.",
                  "Sessions typically last 30 days.",
                  "If requests fail, re-run: openclaw models auth login --provider perplexity",
                  "For stable API access, use an API key instead (perplexity.ai/settings/api).",
                ],
              } satisfies ProviderAuthResult;
            } catch (err) {
              spin.stop("Perplexity Google sign-in failed");
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
