import "dotenv/config";
import express from "express";
import rateLimit from "express-rate-limit";
import { randomUUID, createHash } from "crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createNotionClient } from "easy-notion-mcp/dist/notion-client.js";
import { createServer } from "easy-notion-mcp/dist/server.js";

const PORT = parseInt(process.env.PORT ?? "3333", 10);
const ALLOWED_REDIRECT_URI =
  process.env.OAUTH_REDIRECT_URI ?? "https://claude.ai/api/mcp/auth_callback";
const ROOT_PAGE_ID = process.env.NOTION_ROOT_PAGE_ID;
const TRUST_CONTENT = process.env.NOTION_TRUST_CONTENT === "true";
// Optional uniform connector check for org-shared connectors. When set, the
// client_secret sent at /token must match this value — same for every member,
// carries no per-person meaning. When unset, client_secret is ignored entirely.
const SHARED_CLIENT_SECRET = process.env.SHARED_CLIENT_SECRET || null;

function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/$/, "");
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// In-memory only — cleared on restart/redeploy, by design (see "Operational notes").
const codes = new Map();          // code          -> { notionToken, clientId, redirectUri, codeChallenge, codeChallengeMethod, expires }
const accessTokens = new Map();   // access token  -> { notionToken, expires }
const refreshTokens = new Map();  // refresh token -> { notionToken, expires }

const CODE_TTL_MS = 10 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 180 * 24 * 60 * 60 * 1000;

function sweepExpired() {
  const now = Date.now();
  for (const [k, v] of codes) if (v.expires < now) codes.delete(k);
  for (const [k, v] of accessTokens) if (v.expires < now) accessTokens.delete(k);
  for (const [k, v] of refreshTokens) if (v.expires < now) refreshTokens.delete(k);
}
setInterval(sweepExpired, 5 * 60 * 1000).unref();

const app = express();
app.disable("x-powered-by");
// Sevalla terminates TLS at Cloudflare's edge and forwards requests with
// X-Forwarded-For / X-Forwarded-Proto. Express must trust one proxy hop so
// express-rate-limit can key off the real client IP and getBaseUrl() reads
// the correct scheme — otherwise the limiter throws ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
// and every /authorize and /token call 500s.
app.set("trust proxy", 1);
app.use(express.json());
// OAuth 2.0 token endpoints MUST accept application/x-www-form-urlencoded per
// RFC 6749 §3.2 — Claude.ai (python-httpx) sends the /token request form-encoded,
// not JSON. Without this parser, req.body is undefined and every token exchange
// returns 400 unsupported_grant_type, failing the whole OAuth dance.
app.use(express.urlencoded({ extended: true }));

const authLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false });

app.get("/", (_req, res) => {
  res.json({ status: "ok", server: "notion-mcp-gateway", endpoint: "/mcp" });
});

// --- OAuth discovery (no registration_endpoint on purpose — this forces
// Claude.ai to use the manual Client ID / Client Secret fields instead of
// auto-registering; the "secret" is now just an optional uniform connector
// check, and each person's Notion token is collected at /authorize instead) ---
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    resource: baseUrl,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
  });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const baseUrl = getBaseUrl(req);
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["mcp"],
  });
});

// --- HTML helpers for the personal /authorize interaction ---
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderAuthorizeForm({ client_id, redirect_uri, code_challenge, code_challenge_method, state, error }) {
  const errorHtml = error ? `<div class="error">${escapeHtml(error)}</div>` : "";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect your Notion to Claude</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f6f6f4;color:#191919;margin:0;padding:24px;min-height:100vh;display:flex;justify-content:center}
  form.card{max-width:480px;width:100%;background:#fff;border-radius:14px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);margin-top:48px}
  h1{font-size:20px;margin:0 0 6px}
  .sub{font-size:14px;line-height:1.5;color:#666;margin:0 0 20px}
  label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
  input[name=notion_token]{width:100%;padding:11px 12px;font-size:14px;border:1px solid #d6d6d6;border-radius:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
  input[name=notion_token]:focus{outline:none;border-color:#191919;box-shadow:0 0 0 3px rgba(25,25,25,.08)}
  button{margin-top:16px;width:100%;padding:12px;font-size:14px;font-weight:600;background:#191919;color:#fff;border:none;border-radius:8px;cursor:pointer}
  button:hover{background:#000}
  .error{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;padding:10px 12px;border-radius:8px;font-size:13px;margin-bottom:16px}
  .hint{font-size:12.5px;line-height:1.5;color:#888;margin:14px 0 0}
  a{color:#191919}
  code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
</style>
</head>
<body>
<form class="card" method="POST" action="/authorize" autocomplete="off">
  <h1>Connect your Notion</h1>
  <p class="sub">Paste your own Notion integration token. It is validated against Notion now and bound to your personal session — not shared with anyone else using this connector.</p>
  ${errorHtml}
  <label for="notion_token">Notion integration token</label>
  <input id="notion_token" name="notion_token" type="password" placeholder="ntn_..." autocomplete="off" autofocus required>
  <button type="submit">Connect</button>
  <p class="hint">Create a token at <a href="https://www.notion.so/profile/integrations" target="_blank" rel="noopener">notion.so/profile/integrations</a>, then share each page/database you want Claude to reach via its <code>···</code> → Connections menu.</p>
  <input type="hidden" name="response_type" value="code">
  <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
  <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
  <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}">
  <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method)}">
  <input type="hidden" name="state" value="${escapeHtml(state)}">
</form>
</body>
</html>`;
}

function renderAuthorizeError(message) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authorization error</title><style>body{font-family:-apple-system,sans-serif;background:#f6f6f4;color:#191919;padding:48px;text-align:center}.card{max-width:420px;margin:0 auto;background:#fff;border-radius:14px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,.08)}h1{font-size:18px}p{color:#666;font-size:14px}</style></head><body><div class="card"><h1>Authorization error</h1><p>${escapeHtml(message)}</p></div></body></html>`;
}

// --- Authorize (personal, per-person): the only point in the flow where an
// individual hands over their own Notion token, even under a shared org
// connector. Claude.ai opens this URL in each member's own browser. ---
app.get("/authorize", authLimiter, (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query;
  if (response_type !== "code") {
    return res.status(400).type("html").send(renderAuthorizeError("Unsupported response_type."));
  }
  if (redirect_uri !== ALLOWED_REDIRECT_URI) {
    return res.status(400).type("html").send(renderAuthorizeError("Unrecognized redirect_uri."));
  }
  res.type("html").send(renderAuthorizeForm({ client_id, redirect_uri, code_challenge, code_challenge_method, state, error: null }));
});

app.post("/authorize", authLimiter, async (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, notion_token } = req.body ?? {};

  if (response_type !== "code") {
    return res.status(400).type("html").send(renderAuthorizeError("Unsupported response_type."));
  }
  if (redirect_uri !== ALLOWED_REDIRECT_URI) {
    return res.status(400).type("html").send(renderAuthorizeError("Unrecognized redirect_uri."));
  }

  if (typeof notion_token !== "string" || notion_token.trim().length === 0) {
    return res.type("html").send(renderAuthorizeForm({ client_id, redirect_uri, code_challenge, code_challenge_method, state, error: "Please paste your Notion integration token." }));
  }
  const notionToken = notion_token.trim();

  try {
    await createNotionClient(notionToken).users.me({});
  } catch {
    return res.type("html").send(renderAuthorizeForm({ client_id, redirect_uri, code_challenge, code_challenge_method, state, error: "Notion rejected this token — check it was copied fully and that the integration has been shared with at least one page." }));
  }

  const code = randomUUID();
  codes.set(code, {
    notionToken,
    clientId: typeof client_id === "string" ? client_id : null,
    redirectUri: redirect_uri,
    codeChallenge: typeof code_challenge === "string" ? code_challenge : null,
    codeChallengeMethod: typeof code_challenge_method === "string" ? code_challenge_method : null,
    expires: Date.now() + CODE_TTL_MS,
  });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (typeof state === "string") url.searchParams.set("state", state);
  res.redirect(url.toString());
});

// --- Token: the back-channel exchange. The Notion token is NOT read here
// anymore — it was already validated and bound to the auth code at the
// personal /authorize step. Here we just pull it off the code binding and
// optionally check client_secret against the uniform SHARED_CLIENT_SECRET. ---
app.post("/token", authLimiter, async (req, res) => {
  const { grant_type } = req.body ?? {};

  if (grant_type === "refresh_token") {
    const { refresh_token, client_secret } = req.body;
    if (SHARED_CLIENT_SECRET && client_secret !== SHARED_CLIENT_SECRET) {
      return res.status(400).json({ error: "invalid_client", error_description: "client_secret mismatch" });
    }
    const stored = refresh_token && refreshTokens.get(refresh_token);
    if (!stored || stored.expires < Date.now()) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    const accessToken = randomUUID();
    const newRefreshToken = randomUUID();
    accessTokens.set(accessToken, { notionToken: stored.notionToken, expires: Date.now() + ACCESS_TOKEN_TTL_MS });
    refreshTokens.set(newRefreshToken, { notionToken: stored.notionToken, expires: Date.now() + REFRESH_TOKEN_TTL_MS });
    refreshTokens.delete(refresh_token);
    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      refresh_token: newRefreshToken,
      scope: "mcp",
    });
  }

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  const { code, redirect_uri, code_verifier, client_id, client_secret } = req.body;

  const stored = code && codes.get(code);
  if (!stored || stored.expires < Date.now()) {
    return res.status(400).json({ error: "invalid_grant", error_description: "Unknown or expired code" });
  }
  codes.delete(code); // single-use

  if (stored.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
  }
  if (stored.clientId && stored.clientId !== client_id) {
    return res.status(400).json({ error: "invalid_grant", error_description: "client_id mismatch" });
  }
  if (stored.codeChallenge) {
    if (typeof code_verifier !== "string" || !code_verifier) {
      return res.status(400).json({ error: "invalid_grant", error_description: "Missing code_verifier" });
    }
    const expected = createHash("sha256").update(code_verifier).digest("base64url");
    if (expected !== stored.codeChallenge) {
      return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }
  }

  // The Notion token rides on this person's auth code (validated at
  // /authorize), not on the shared client_secret.
  const notionToken = stored.notionToken;

  // Optional uniform connector check — same value for every org member.
  if (SHARED_CLIENT_SECRET && client_secret !== SHARED_CLIENT_SECRET) {
    return res.status(400).json({ error: "invalid_client", error_description: "client_secret mismatch" });
  }

  const accessToken = randomUUID();
  const newRefreshToken = randomUUID();
  accessTokens.set(accessToken, { notionToken, expires: Date.now() + ACCESS_TOKEN_TTL_MS });
  refreshTokens.set(newRefreshToken, { notionToken, expires: Date.now() + REFRESH_TOKEN_TTL_MS });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_MS / 1000,
    refresh_token: newRefreshToken,
    scope: "mcp",
  });
});

function checkAuth(req, res, next) {
  const baseUrl = getBaseUrl(req);
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.set("WWW-Authenticate", `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);
    return res.status(401).json({ error: "invalid_token" });
  }
  const token = authHeader.slice(7);
  const stored = accessTokens.get(token);
  if (!stored || stored.expires < Date.now()) {
    res.set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);
    return res.status(401).json({ error: "invalid_token" });
  }
  req.notionToken = stored.notionToken;
  next();
}

const transports = new Map(); // sessionId -> StreamableHTTPServerTransport

// Per-session registry of in-flight JSON-RPC request ids. The MCP SDK's
// stateful StreamableHTTPServerTransport (v1.30.0) routes each response to its
// originating POST through a map keyed by JSON-RPC request id with NO
// duplicate-in-flight guard: two concurrent POSTs on one session that reuse
// the same id cross-wire — the second POST overwrites the first's routing
// slot, so the first's response is delivered to the second's HTTP stream and
// the first hangs. Clients that pool a single session across conversations and
// number every request from 1 (e.g. claude.ai's custom MCP connector) hit this
// under concurrent tool calls, and one conversation receives another's
// response. We serialize only the colliding requests: a POST whose request id
// is already in flight on the session waits for that id's HTTP response to be
// fully delivered (the SDK clears _requestToStreamMapping[id] before the HTTP
// response finishes) before being allowed to register its own slot.
// Notifications and unique-id requests stay fully concurrent, so cancellation
// and progress notifications are never blocked. See
// modelcontextprotocol/typescript-sdk#2433.
const inFlightBySession = new Map(); // sessionId -> Map<requestId, Promise>

function extractRequestIds(body) {
  if (!body) return [];
  const messages = Array.isArray(body) ? body : [body];
  const ids = [];
  for (const m of messages) {
    if (m && typeof m === "object" &&
        typeof m.method === "string" &&
        Object.prototype.hasOwnProperty.call(m, "id")) {
      ids.push(m.id);
    }
  }
  return ids;
}

function getInFlightMap(sessionId) {
  let map = inFlightBySession.get(sessionId);
  if (!map) { map = new Map(); inFlightBySession.set(sessionId, map); }
  return map;
}

app.post("/mcp", checkAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  let transport = sessionId ? transports.get(sessionId) : undefined;

  if (!transport) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => transports.set(id, transport),
      onsessionclosed: (id) => { transports.delete(id); inFlightBySession.delete(id); },
    });
    transport.onclose = () => {
      if (transport.sessionId) {
        transports.delete(transport.sessionId);
        inFlightBySession.delete(transport.sessionId);
      }
    };

    const notion = createNotionClient(req.notionToken);
    const mcpServer = createServer(() => notion, {
      rootPageId: ROOT_PAGE_ID,
      trustContent: TRUST_CONTENT,
      allowWorkspaceParent: false,
      transport: "http",
    });
    await mcpServer.connect(transport);
  }

  // Serialize colliding in-flight request ids within this session (see
  // inFlightBySession above). Initialize requests carry no session id and are
  // exempt — the client waits for the initialize response before sending more.
  if (sessionId) {
    const ids = extractRequestIds(req.body);
    if (ids.length > 0) {
      const inFlight = getInFlightMap(sessionId);
      // Synchronously capture prior in-flight promises for these ids and
      // register ourselves as the new holder. No awaits between capture and
      // registration, so concurrent POSTs observe a consistent chain.
      const waiters = ids.map((id) => inFlight.get(id)).filter(Boolean);
      let markDone;
      const done = new Promise((resolve) => { markDone = resolve; });
      for (const id of ids) inFlight.set(id, done);
      // Wait for any prior colliding request to finish delivering its
      // response, then register a clean routing slot of our own.
      if (waiters.length > 0) await Promise.all(waiters);

      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        for (const id of ids) if (inFlight.get(id) === done) inFlight.delete(id);
        markDone();
      };
      res.on("finish", release);
      res.on("close", release);
      try {
        await transport.handleRequest(req, res, req.body);
      } catch (err) {
        release();
        throw err;
      }
      return;
    }
  }

  await transport.handleRequest(req, res, req.body);
});

app.get("/mcp", checkAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  const transport = sessionId ? transports.get(sessionId) : undefined;
  if (!transport) return res.status(400).json({ error: "No active session" });
  await transport.handleRequest(req, res);
});

app.delete("/mcp", checkAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  const transport = sessionId ? transports.get(sessionId) : undefined;
  if (!transport) return res.status(400).json({ error: "No active session" });
  await transport.handleRequest(req, res);
  transports.delete(sessionId);
  inFlightBySession.delete(sessionId);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`notion-mcp-gateway listening on 0.0.0.0:${PORT}`);
});
