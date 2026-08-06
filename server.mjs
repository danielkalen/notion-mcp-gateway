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

function getBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/$/, "");
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers["x-forwarded-host"] || req.get("host");
  return `${proto}://${host}`;
}

// In-memory only — cleared on restart/redeploy, by design (see "Operational notes").
const codes = new Map();          // code          -> { clientId, redirectUri, codeChallenge, codeChallengeMethod, expires }
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
app.use(express.json());

const authLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false });

app.get("/", (_req, res) => {
  res.json({ status: "ok", server: "notion-mcp-gateway", endpoint: "/mcp" });
});

// --- OAuth discovery (no registration_endpoint on purpose — this forces
// Claude.ai to use the manual Client ID / Client Secret fields instead of
// auto-registering, which is what lets the "secret" be your Notion token) ---
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

// --- Authorize: no secret is visible here (correct OAuth semantics — the
// secret only ever travels server-to-server at /token) ---
app.get("/authorize", authLimiter, (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state } = req.query;

  if (response_type !== "code") {
    return res.status(400).json({ error: "unsupported_response_type" });
  }
  if (redirect_uri !== ALLOWED_REDIRECT_URI) {
    return res.status(400).json({ error: "invalid_request", error_description: "Unrecognized redirect_uri" });
  }

  const code = randomUUID();
  codes.set(code, {
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

// --- Token: this is where client_secret arrives, and here it IS the
// Notion token. We verify it against the real Notion API before minting
// anything, so a bad paste fails here with a clear message instead of
// failing silently on every later tool call. ---
app.post("/token", authLimiter, async (req, res) => {
  const { grant_type } = req.body ?? {};

  if (grant_type === "refresh_token") {
    const { refresh_token } = req.body;
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

  if (typeof client_secret !== "string" || client_secret.trim().length === 0) {
    return res.status(400).json({ error: "invalid_client", error_description: "client_secret (your Notion token) is required" });
  }
  const notionToken = client_secret.trim();

  try {
    await createNotionClient(notionToken).users.me({});
  } catch {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Notion rejected this token — check it was copied correctly and the integration has been shared with your pages.",
    });
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

app.post("/mcp", checkAuth, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  let transport = sessionId ? transports.get(sessionId) : undefined;

  if (!transport) {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => transports.set(id, transport),
      onsessionclosed: (id) => transports.delete(id),
    });
    transport.onclose = () => {
      if (transport.sessionId) transports.delete(transport.sessionId);
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
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`notion-mcp-gateway listening on 0.0.0.0:${PORT}`);
});
