/**
 * X OAuth Worker for Browser Extension with Server-Side Storage
 *
 * This worker handles X OAuth 2.0 with PKCE, JWT-based authentication,
 * and stores tracking data in SQLite Durable Objects.
 */

interface Env {
  X_CLIENT_ID: string;
  X_CLIENT_SECRET: string;
  JWT_SECRET: string;
  USER_STATS: DurableObjectNamespace;
}

// The extension will listen for redirects to this URL pattern
const EXTENSION_CALLBACK_PATH = "/extension-callback";

// ===== JWT Utilities =====

interface JWTPayload {
  sub: string;
  username: string;
  name: string;
  pfp: string;
  iat: number;
}

async function createJWT(payload: JWTPayload, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };

  const encodedHeader = btoa(JSON.stringify(header))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const encodedPayload = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const data = `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return `${data}.${encodedSignature}`;
}

async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const data = `${encodedHeader}.${encodedPayload}`;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    // Decode signature from base64url
    const signatureStr = atob(
      encodedSignature.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - (encodedSignature.length % 4)) % 4)
    );
    const signature = new Uint8Array(signatureStr.length);
    for (let i = 0; i < signatureStr.length; i++) {
      signature[i] = signatureStr.charCodeAt(i);
    }

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(data)
    );

    if (!valid) return null;

    // Decode payload
    const payloadStr = atob(
      encodedPayload.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - (encodedPayload.length % 4)) % 4)
    );

    return JSON.parse(payloadStr) as JWTPayload;
  } catch {
    return null;
  }
}

// ===== UserStats Durable Object =====

interface VisitRow {
  domain: string;
  total_time: number;
  visit_count: number;
  last_visit: string;
}

interface IndividualVisit {
  id: number;
  domain: string;
  duration_seconds: number;
  visited_at: string;
}

export class UserStats implements DurableObject {
  private sql: SqlStorage;

  constructor(state: DurableObjectState) {
    this.sql = state.storage.sql;
    this.initializeSchema();
  }

  private initializeSchema() {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        duration_seconds INTEGER NOT NULL,
        visited_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_domain ON visits(domain);
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/track" && request.method === "POST") {
      return this.handleTrack(request);
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      return this.handleStats();
    }

    if (url.pathname === "/visits" && request.method === "GET") {
      return this.handleVisits();
    }

    return new Response("Not found", { status: 404 });
  }

  private async handleTrack(request: Request): Promise<Response> {
    try {
      const body = (await request.json()) as {
        domain: string;
        duration: number;
      };

      const { domain, duration } = body;

      if (!domain || typeof duration !== "number" || duration <= 0) {
        return new Response(
          JSON.stringify({ error: "Invalid domain or duration" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const visitedAt = new Date().toISOString();

      this.sql.exec(
        `INSERT INTO visits (domain, duration_seconds, visited_at) VALUES (?, ?, ?)`,
        domain,
        duration,
        visitedAt
      );

      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to track visit",
          details: error instanceof Error ? error.message : "Unknown error",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  private async handleStats(): Promise<Response> {
    try {
      // Get aggregated stats by domain
      const rows = this.sql.exec(`
        SELECT
          domain,
          SUM(duration_seconds) as total_time,
          COUNT(*) as visit_count,
          MAX(visited_at) as last_visit
        FROM visits
        GROUP BY domain
        ORDER BY total_time DESC
      `).toArray() as unknown as VisitRow[];

      const stats = rows.map((row: VisitRow) => ({
        domain: row.domain,
        totalTime: row.total_time,
        visitCount: row.visit_count,
        lastVisit: row.last_visit,
      }));

      return new Response(JSON.stringify({ stats }), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to get stats",
          details: error instanceof Error ? error.message : "Unknown error",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  private async handleVisits(): Promise<Response> {
    try {
      // Get individual visits ordered reverse chronologically
      const rows = this.sql.exec(`
        SELECT
          id,
          domain,
          duration_seconds,
          visited_at
        FROM visits
        ORDER BY visited_at DESC
        LIMIT 1000
      `).toArray() as unknown as IndividualVisit[];

      const visits = rows.map((row: IndividualVisit) => ({
        id: row.id,
        url: row.domain,
        duration: row.duration_seconds,
        visitedAt: row.visited_at,
      }));

      return new Response(JSON.stringify({ visits }), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "Failed to get visits",
          details: error instanceof Error ? error.message : "Unknown error",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }
}

// ===== Helper Functions =====

async function generateRandomString(length: number): Promise<string> {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function generateCodeChallenge(codeVerifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function getCookie(
  cookieHeader: string | null,
  name: string
): string | undefined {
  if (!cookieHeader) return undefined;
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  const cookie = cookies.find((c) => c.startsWith(`${name}=`));
  return cookie?.split("=")[1];
}

function formatTime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  } else {
    return `${secs}s`;
  }
}

function formatDate(isoString: string): string {
  const date = new Date(isoString);
  return date.toLocaleString();
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ===== Main Worker =====

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const isLocalhost = url.hostname === "localhost";
    const securePart = isLocalhost ? "" : "Secure; ";
    const redirectUri = `https://redirect.simplerauth.com/callback?redirect_to=${encodeURIComponent(url.origin + `/callback`)}`;

    // Validate environment
    if (!env.X_CLIENT_ID || !env.X_CLIENT_SECRET) {
      return new Response(
        JSON.stringify({
          error: "Server misconfigured: missing X credentials",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    // CORS headers for extension
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // GET /login - Start OAuth flow
    if (url.pathname === "/login") {
      const scope =
        url.searchParams.get("scope") || "users.read tweet.read offline.access";

      const state = await generateRandomString(16);
      const codeVerifier = await generateRandomString(43);
      const codeChallenge = await generateCodeChallenge(codeVerifier);

      const authUrl = new URL("https://x.com/i/oauth2/authorize");
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("client_id", env.X_CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("scope", scope);
      authUrl.searchParams.set("state", state);
      authUrl.searchParams.set("code_challenge", codeChallenge);
      authUrl.searchParams.set("code_challenge_method", "S256");

      const headers = new Headers({
        Location: authUrl.toString(),
      });

      // Store state and verifier in cookies for callback validation
      headers.append(
        "Set-Cookie",
        `x_oauth_state=${state}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `x_code_verifier=${codeVerifier}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
      );
      headers.append(
        "Set-Cookie",
        `x_redirect_uri=${encodeURIComponent(redirectUri)}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=600`
      );

      return new Response("Redirecting to X...", { status: 307, headers });
    }

    // GET /callback - X OAuth callback
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const urlState = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        return redirectToExtension(url.origin, {
          error,
          error_description:
            url.searchParams.get("error_description") || "Authorization denied",
        });
      }

      const cookieHeader = request.headers.get("Cookie");
      const stateCookie = getCookie(cookieHeader, "x_oauth_state");
      const codeVerifier = getCookie(cookieHeader, "x_code_verifier");
      const finalRedirectUri = decodeURIComponent(
        getCookie(cookieHeader, "x_redirect_uri") || redirectUri
      );

      // Validate state
      if (
        !urlState ||
        !stateCookie ||
        urlState !== stateCookie ||
        !codeVerifier
      ) {
        return redirectToExtension(url.origin, {
          error: "invalid_state",
          error_description: "Invalid or expired state. Please try again.",
        });
      }

      try {
        // Exchange code for tokens
        const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`,
          },
          body: new URLSearchParams({
            code: code || "",
            client_id: env.X_CLIENT_ID,
            grant_type: "authorization_code",
            redirect_uri: finalRedirectUri,
            code_verifier: codeVerifier,
          }),
        });

        const tokenText = await tokenResponse.text();

        if (!tokenResponse.ok) {
          console.error(
            "Token exchange failed:",
            tokenResponse.status,
            tokenText
          );
          return redirectToExtension(url.origin, {
            error: "token_exchange_failed",
            error_description: `Failed to exchange token: ${tokenResponse.status}`,
          });
        }

        const tokenData = JSON.parse(tokenText);
        const { access_token, refresh_token } = tokenData;

        // Fetch user info
        interface XUser {
          id: string;
          username: string;
          name: string;
          profile_image_url?: string;
        }
        let user: XUser | null = null;
        try {
          const userResponse = await fetch(
            "https://api.x.com/2/users/me?user.fields=profile_image_url,username,name",
            { headers: { Authorization: `Bearer ${access_token}` } }
          );
          if (userResponse.ok) {
            const userData = (await userResponse.json()) as { data: XUser };
            user = userData.data;
          }
        } catch (e) {
          console.error("Failed to fetch user info:", e);
        }

        if (!user) {
          return redirectToExtension(url.origin, {
            error: "user_fetch_failed",
            error_description: "Failed to fetch user information",
          });
        }

        // Create JWT token
        const jwtPayload: JWTPayload = {
          sub: user.id,
          username: user.username,
          name: user.name,
          pfp: user.profile_image_url || "",
          iat: Math.floor(Date.now() / 1000),
        };

        const jwt = await createJWT(jwtPayload, env.JWT_SECRET);

        // Redirect to extension callback with JWT
        return redirectToExtension(url.origin, {
          jwt,
          refresh_token,
          user: JSON.stringify(user),
        });
      } catch (error) {
        console.error("OAuth callback error:", error);
        return redirectToExtension(url.origin, {
          error: "server_error",
          error_description:
            error instanceof Error ? error.message : "Unknown error",
        });
      }
    }

    // GET /extension-callback - Landing page the extension intercepts
    if (url.pathname === EXTENSION_CALLBACK_PATH) {
      const jwt = url.searchParams.get("jwt");
      const error = url.searchParams.get("error");

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>${error ? "Login Failed" : "Login Successful"}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .icon { font-size: 48px; margin-bottom: 16px; }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">${error ? "X" : "OK"}</div>
    <h1>${error ? "Login Failed" : "Login Successful"}</h1>
    <p>${error ? url.searchParams.get("error_description") || error : "You can close this tab now."}</p>
  </div>
</body>
</html>`;

      return new Response(html, {
        headers: {
          "Content-Type": "text/html;charset=utf8",
          ...corsHeaders,
        },
      });
    }

    // POST /api/track - Record a visit (requires JWT)
    if (url.pathname === "/api/track" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response(
          JSON.stringify({ error: "Missing or invalid authorization header" }),
          { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      }

      const token = authHeader.slice(7);
      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      }

      // Get user's Durable Object
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);

      // Forward request to Durable Object
      const doRequest = new Request("https://do/track", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: request.body,
      });

      const response = await stub.fetch(doRequest);
      const responseBody = await response.text();

      return new Response(responseBody, {
        status: response.status,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    // GET /api/stats - Get stats as JSON (requires JWT)
    if (url.pathname === "/api/stats" && request.method === "GET") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response(
          JSON.stringify({ error: "Missing or invalid authorization header" }),
          { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      }

      const token = authHeader.slice(7);
      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          JSON.stringify({ error: "Invalid or expired token" }),
          { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      }

      // Get user's Durable Object
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);

      const response = await stub.fetch(new Request("https://do/stats"));
      const responseBody = await response.text();

      return new Response(responseBody, {
        status: response.status,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    // GET /stats - HTML stats page (JWT from query param or cookie)
    if (url.pathname === "/stats") {
      const tokenFromQuery = url.searchParams.get("token");
      const tokenFromCookie = getCookie(request.headers.get("Cookie"), "jwt");
      const token = tokenFromQuery || tokenFromCookie;

      if (!token) {
        return new Response(
          `<!DOCTYPE html>
<html>
<head>
  <title>Not Authorized</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Not Authorized</h1>
    <p>Please login from the browser extension to view your stats.</p>
  </div>
</body>
</html>`,
          { status: 401, headers: { "Content-Type": "text/html;charset=utf8" } }
        );
      }

      const payload = await verifyJWT(token, env.JWT_SECRET);

      if (!payload) {
        return new Response(
          `<!DOCTYPE html>
<html>
<head>
  <title>Invalid Token</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #f5f5f5;
    }
    .container {
      text-align: center;
      padding: 40px;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 { margin: 0 0 8px 0; color: #333; }
    p { color: #666; margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Invalid Token</h1>
    <p>Your session may have expired. Please login again from the browser extension.</p>
  </div>
</body>
</html>`,
          { status: 401, headers: { "Content-Type": "text/html;charset=utf8" } }
        );
      }

      // If token came from query param, set cookie and redirect to clean URL
      if (tokenFromQuery) {
        const headers = new Headers({
          Location: `${url.origin}/stats`,
        });
        headers.append(
          "Set-Cookie",
          `jwt=${token}; HttpOnly; Path=/; ${securePart}SameSite=Lax; Max-Age=31536000`
        );
        return new Response("Redirecting...", { status: 302, headers });
      }

      // Get user's visits
      const id = env.USER_STATS.idFromName(payload.sub);
      const stub = env.USER_STATS.get(id);
      const response = await stub.fetch(new Request("https://do/visits"));
      const visitsData = (await response.json()) as { visits: Array<{ id: number; url: string; duration: number; visitedAt: string }> };

      // Build stats HTML - grouped by date
      let statsHtml = "";
      if (!visitsData.visits || visitsData.visits.length === 0) {
        statsHtml = '<div class="no-data">No websites tracked yet</div>';
      } else {
        // Group visits by date
        const visitsByDate: Record<string, typeof visitsData.visits> = {};
        for (const visit of visitsData.visits) {
          const date = new Date(visit.visitedAt).toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          });
          if (!visitsByDate[date]) {
            visitsByDate[date] = [];
          }
          visitsByDate[date].push(visit);
        }

        // Build HTML for each date group
        for (const [date, visits] of Object.entries(visitsByDate)) {
          statsHtml += `<div class="date-group">
            <div class="date-header">${date}</div>`;

          for (const visit of visits) {
            const llmTextUrl = `https://llmtext.com/${visit.url}`;
            const visitTime = new Date(visit.visitedAt).toLocaleTimeString('en-US', {
              hour: '2-digit',
              minute: '2-digit'
            });

            statsHtml += `
            <div class="site-entry">
              <div class="site-info">
                <div class="site-name">${escapeHtml(visit.url)}</div>
                <div class="site-details">
                  ${visitTime} | Duration: ${formatTime(visit.duration)}
                </div>
              </div>
              <a href="${llmTextUrl}" target="_blank" rel="noopener noreferrer" class="context-btn">Look up context</a>
            </div>`;
          }

          statsHtml += `</div>`;
        }
      }

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>Website Time Tracker - Stats</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
      background: #f5f5f5;
      min-height: 100vh;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      overflow: hidden;
    }
    .header {
      padding: 20px;
      background: #f8f9fa;
      border-bottom: 1px solid #eee;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .user-avatar {
      width: 48px;
      height: 48px;
      border-radius: 50%;
      object-fit: cover;
    }
    .user-info h1 {
      margin: 0;
      font-size: 18px;
      color: #333;
    }
    .user-info p {
      margin: 4px 0 0 0;
      font-size: 14px;
      color: #666;
    }
    .stats {
      padding: 0;
    }
    .site-entry {
      padding: 15px 20px;
      border-bottom: 1px solid #eee;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .site-entry:last-child {
      border-bottom: none;
    }
    .site-entry:hover {
      background: #f9f9f9;
    }
    .site-info {
      flex: 1;
    }
    .site-name {
      font-weight: 500;
      color: #333;
      margin-bottom: 4px;
      word-break: break-all;
      font-size: 13px;
      line-height: 1.4;
    }
    .site-details {
      font-size: 12px;
      color: #666;
    }
    .time-badge {
      background: #2196F3;
      color: white;
      padding: 6px 12px;
      border-radius: 16px;
      font-size: 13px;
      font-weight: bold;
    }
    .date-group {
      margin-bottom: 0;
    }
    .date-header {
      background: #f0f4f8;
      padding: 12px 20px;
      font-weight: 600;
      color: #555;
      font-size: 14px;
      border-bottom: 1px solid #e0e0e0;
      position: sticky;
      top: 0;
    }
    .context-btn {
      background: #10b981;
      color: white;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 500;
      text-decoration: none;
      white-space: nowrap;
      transition: background-color 0.2s;
    }
    .context-btn:hover {
      background: #059669;
    }
    .no-data {
      text-align: center;
      color: #999;
      padding: 40px 20px;
    }
    .refresh-note {
      text-align: center;
      padding: 15px;
      font-size: 12px;
      color: #999;
      border-top: 1px solid #eee;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      ${payload.pfp ? `<img class="user-avatar" src="${payload.pfp}" alt="${payload.name}">` : ""}
      <div class="user-info">
        <h1>${payload.name}</h1>
        <p>@${payload.username}</p>
      </div>
    </div>
    <div class="stats">
      ${statsHtml}
    </div>
    <div class="refresh-note">
      Refresh this page to see updated stats
    </div>
  </div>
</body>
</html>`;

      return new Response(html, {
        headers: { "Content-Type": "text/html;charset=utf8" },
      });
    }

    // POST /refresh - Refresh access token (returns new JWT)
    if (url.pathname === "/refresh" && request.method === "POST") {
      try {
        const body = (await request.json()) as { refresh_token: string };
        const { refresh_token } = body;

        if (!refresh_token) {
          return new Response(
            JSON.stringify({ error: "refresh_token required" }),
            {
              status: 400,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        const tokenResponse = await fetch("https://api.x.com/2/oauth2/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: `Basic ${btoa(`${env.X_CLIENT_ID}:${env.X_CLIENT_SECRET}`)}`,
          },
          body: new URLSearchParams({
            refresh_token,
            grant_type: "refresh_token",
            client_id: env.X_CLIENT_ID,
          }),
        });

        const tokenData = await tokenResponse.json() as {
          access_token: string;
          refresh_token?: string;
          error?: string;
        };

        if (!tokenResponse.ok) {
          return new Response(
            JSON.stringify({ error: "refresh_failed", details: tokenData }),
            {
              status: tokenResponse.status,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // Fetch updated user info
        interface XUserRefresh {
          id: string;
          username: string;
          name: string;
          profile_image_url?: string;
        }
        let userRefresh: XUserRefresh | null = null;
        try {
          const userResponse = await fetch(
            "https://api.x.com/2/users/me?user.fields=profile_image_url,username,name",
            { headers: { Authorization: `Bearer ${tokenData.access_token}` } }
          );
          if (userResponse.ok) {
            const userData = (await userResponse.json()) as { data: XUserRefresh };
            userRefresh = userData.data;
          }
        } catch (e) {
          console.error("Failed to fetch user info:", e);
        }

        if (!userRefresh) {
          return new Response(
            JSON.stringify({ error: "user_fetch_failed" }),
            {
              status: 500,
              headers: { "Content-Type": "application/json", ...corsHeaders },
            }
          );
        }

        // Create new JWT
        const jwtPayload: JWTPayload = {
          sub: userRefresh.id,
          username: userRefresh.username,
          name: userRefresh.name,
          pfp: userRefresh.profile_image_url || "",
          iat: Math.floor(Date.now() / 1000),
        };

        const jwt = await createJWT(jwtPayload, env.JWT_SECRET);

        return new Response(
          JSON.stringify({
            jwt,
            refresh_token: tokenData.refresh_token || refresh_token,
            user: userRefresh,
          }),
          {
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: "server_error",
            message: error instanceof Error ? error.message : "Unknown error",
          }),
          {
            status: 500,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }
    }

    // Default: show info
    return new Response(
      JSON.stringify({
        name: "Website Time Tracker X Auth",
        endpoints: {
          "/login": "Start X OAuth flow (GET)",
          "/callback": "X OAuth callback (handled automatically)",
          "/extension-callback": "Extension intercepts this URL",
          "/api/track": "Record a visit (POST with JWT)",
          "/api/stats": "Get stats as JSON (GET with JWT)",
          "/stats": "Stats HTML page (GET with JWT token param)",
          "/refresh": "Refresh access token (POST with refresh_token)",
        },
      }),
      { headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  },
};

function redirectToExtension(
  origin: string,
  params: Record<string, string | undefined>
): Response {
  const callbackUrl = new URL(`${origin}${EXTENSION_CALLBACK_PATH}`);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      callbackUrl.searchParams.set(key, value);
    }
  }

  const headers = new Headers({
    Location: callbackUrl.toString(),
  });

  // Clear OAuth cookies
  headers.append("Set-Cookie", "x_oauth_state=; Max-Age=0; Path=/");
  headers.append("Set-Cookie", "x_code_verifier=; Max-Age=0; Path=/");
  headers.append("Set-Cookie", "x_redirect_uri=; Max-Age=0; Path=/");

  return new Response("Redirecting...", { status: 307, headers });
}
