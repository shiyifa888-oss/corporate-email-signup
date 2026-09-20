import { createServer } from "node:http";
import { parse } from "node:querystring";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { emailDomain, isAllowedEmail, normalizeEmail, parseAllowedDomains } from "./domain.js";
import { hashPassword, randomToken, signValue, verifyPassword, verifySignedValue } from "./security.js";
import { JsonStore } from "./store.js";

const here = dirname(fileURLToPath(import.meta.url));
const store = new JsonStore(join(here, "..", "data", "users.json"));
const port = Number(process.env.PORT || 3000);
const origin = process.env.APP_ORIGIN || `http://localhost:${port}`;
const allowedDomains = parseAllowedDomains(process.env.ALLOWED_EMAIL_DOMAINS || "example.com");
const sessionSecret = process.env.SESSION_SECRET || "development-only-change-this-secret-now";
const verificationTtlMs = 30 * 60 * 1000;
const rateBuckets = new Map();

function html(title, body) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title><style>body{font:16px system-ui;max-width:34rem;margin:4rem auto;padding:0 1rem}form{display:grid;gap:1rem}input,button{font:inherit;padding:.75rem}small{color:#555}.error{color:#b00020}</style><main><h1>${title}</h1>${body}</main></html>`;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'", ...headers });
  res.end(body);
}

async function formBody(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 16_384) throw new Error("Request too large");
  }
  return parse(body);
}

function rateLimited(ip) {
  const now = Date.now();
  const bucket = rateBuckets.get(ip) || [];
  const recent = bucket.filter((time) => now - time < 60_000);
  recent.push(now);
  rateBuckets.set(ip, recent);
  return recent.length > 10;
}

function signupPage(message = "") {
  const domains = [...allowedDomains].map((d) => `@${d}`).join(", ");
  return html("Corporate email signup", `${message}<form method="post" action="/signup"><label>Work email<input name="email" type="email" required autocomplete="email"></label><label>Password<input name="password" type="password" minlength="12" required autocomplete="new-password"></label><button>Create account</button><small>Allowed domain: ${domains}. Use 12 or more characters.</small></form>`);
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, origin);
    if (req.method === "GET" && url.pathname === "/") return send(res, 200, signupPage());

    if (req.method === "POST" && url.pathname === "/signup") {
      if (rateLimited(req.socket.remoteAddress || "unknown")) return send(res, 429, signupPage('<p class="error">Too many attempts. Try again later.</p>'));
      const { email: rawEmail = "", password = "" } = await formBody(req);
      const email = normalizeEmail(String(rawEmail));
      if (!isAllowedEmail(email, allowedDomains)) return send(res, 400, signupPage('<p class="error">Use an approved corporate email address.</p>'));
      if (String(password).length < 12 || String(password).length > 256) return send(res, 400, signupPage('<p class="error">Password must be 12–256 characters.</p>'));
      const verificationToken = randomToken();
      const outcome = await store.update(async (data) => {
        if (data.users.some((user) => user.email === email)) return "exists";
        data.users.push({ email, domain: emailDomain(email), passwordHash: await hashPassword(String(password)), verified: false, verificationToken, verificationExpiresAt: Date.now() + verificationTtlMs, createdAt: new Date().toISOString() });
        return "created";
      });
      if (outcome === "exists") return send(res, 409, signupPage('<p class="error">An account already exists for this email.</p>'));
      const link = `${origin}/verify?token=${encodeURIComponent(verificationToken)}`;
      if (process.env.DEV_SHOW_VERIFICATION_LINK === "true") console.log(`Verification link for ${email}: ${link}`);
      return send(res, 201, html("Check your email", "<p>Your account was created. Open the verification link sent by your configured mail provider.</p>"));
    }

    if (req.method === "GET" && url.pathname === "/verify") {
      const token = url.searchParams.get("token") || "";
      const verified = await store.update((data) => {
        const user = data.users.find((item) => item.verificationToken === token && item.verificationExpiresAt > Date.now());
        if (!user) return false;
        user.verified = true;
        delete user.verificationToken;
        delete user.verificationExpiresAt;
        return true;
      });
      return send(res, verified ? 200 : 400, html(verified ? "Email verified" : "Invalid link", verified ? '<p>Your corporate email is verified. <a href="/login">Sign in</a>.</p>' : "<p>The link is invalid or expired.</p>"));
    }

    if (req.method === "GET" && url.pathname === "/login") return send(res, 200, html("Sign in", '<form method="post" action="/login"><label>Email<input name="email" type="email" required></label><label>Password<input name="password" type="password" required></label><button>Sign in</button></form>'));

    if (req.method === "POST" && url.pathname === "/login") {
      if (rateLimited(req.socket.remoteAddress || "unknown")) return send(res, 429, html("Try later", "<p>Too many attempts.</p>"));
      const { email: rawEmail = "", password = "" } = await formBody(req);
      const email = normalizeEmail(String(rawEmail));
      const data = await store.read();
      const user = data.users.find((item) => item.email === email);
      const valid = user && user.verified && (await verifyPassword(String(password), user.passwordHash));
      if (!valid) return send(res, 401, html("Sign in failed", '<p class="error">Invalid credentials or unverified email.</p>'));
      const session = signValue(`${email}|${Date.now() + 3_600_000}`, sessionSecret);
      return send(res, 302, "", { location: "/account", "set-cookie": `session=${encodeURIComponent(session)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600${origin.startsWith("https:") ? "; Secure" : ""}` });
    }

    if (req.method === "GET" && url.pathname === "/account") {
      const cookie = req.headers.cookie?.split(";").map((part) => part.trim()).find((part) => part.startsWith("session="));
      const value = cookie ? verifySignedValue(decodeURIComponent(cookie.slice(8)), sessionSecret) : null;
      const [email, expires = 0] = value?.split("|") || [];
      if (!email || Number(expires) < Date.now()) return send(res, 302, "", { location: "/login" });
      return send(res, 200, html("Account", `<p>Signed in as ${email.replaceAll("&", "&amp;").replaceAll("<", "&lt;")}.</p>`));
    }

    send(res, 404, html("Not found", "<p>The requested page does not exist.</p>"));
  } catch (error) {
    console.error(error);
    send(res, 500, html("Server error", "<p>Something went wrong.</p>"));
  }
});

server.listen(port, () => console.log(`Listening on ${origin}`));
