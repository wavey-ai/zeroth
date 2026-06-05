const DEFAULT_ISSUER = "https://id.wavey.ai";
const DEFAULT_VALIDATE_TIMEOUT_MS = 2500;

const DEFAULT_SECURITY_HEADERS = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

export default {
  async fetch(request, env, ctx) {
    return handleGateRequest(request, env, ctx);
  },
};

export async function handleGateRequest(request, env = {}, _ctx = {}) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return withSecurityHeaders(new Response(null, { status: 204 }), url, env, true);
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return withSecurityHeaders(new Response("Method not allowed\n", { status: 405 }), url, env, true);
  }

  const route = routeConfig(env);
  const canonical = canonicalPathRedirect(url, route);
  if (canonical) return redirectNoStore(canonical.toString(), url, env);

  if (!pathAllowedByRoute(url.pathname, route)) {
    return withSecurityHeaders(new Response("Not found\n", { status: 404 }), url, env, request.method === "HEAD");
  }

  if (route.protected && !(await isAuthenticated(request, env))) {
    return redirectNoStore(loginUrl(request, env).toString(), url, env);
  }

  return serveAssets(request, env, url, route);
}

export async function isAuthenticated(request, env = {}) {
  if (authBypassEnabled(request, env)) return true;

  const validateUrl = new URL(env.ZEROTH_VALIDATE_URL || "/validate", issuerFromEnv(env));
  const headers = new Headers({ Accept: "application/json" });
  const cookie = request.headers.get("Cookie");
  if (cookie) headers.set("Cookie", cookie);
  const authorization = request.headers.get("Authorization");
  if (authorization) headers.set("Authorization", authorization);

  const controller = new AbortController();
  const timeoutMs = positiveInteger(env.ZEROTH_VALIDATE_TIMEOUT_MS, DEFAULT_VALIDATE_TIMEOUT_MS);
  const timeout = setTimeout(() => controller.abort("zeroth validation timed out"), timeoutMs);
  try {
    const response = await fetch(validateUrl.toString(), {
      method: "GET",
      headers,
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const result = await response.json().catch(() => null);
    return Boolean(result && (result.valid || result.authenticated));
  } catch (error) {
    console.warn("[zeroth-gate] validation failed", error && (error.message || error));
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export function loginUrl(request, env = {}) {
  const target = new URL(env.ZEROTH_LOGIN_URL || "/login", issuerFromEnv(env));
  const returnParam = String(env.ZEROTH_RETURN_TO_PARAM || "return_to").trim() || "return_to";
  target.searchParams.set(returnParam, request.url);
  const clientId = String(env.ZEROTH_CLIENT_ID || "").trim();
  if (clientId) target.searchParams.set("client_id", clientId);
  return target;
}

export function routeConfig(env = {}) {
  const publicPaths = pathList(env.ZEROTH_PUBLIC_PATHS);
  const protectedPrefixes = pathList(env.ZEROTH_PROTECTED_PREFIXES);
  const assetPrefix = normalizePrefix(env.ZEROTH_ASSET_PREFIX || firstPrefix(protectedPrefixes) || "/");
  return {
    assetPrefix,
    publicPaths,
    protectedPrefixes: protectedPrefixes.length ? protectedPrefixes : [assetPrefix],
    protected: true,
  };
}

export function pathAllowedByRoute(pathname, route) {
  return route.publicPaths.some((path) => pathMatchesPrefix(pathname, path))
    || route.protectedPrefixes.some((prefix) => pathMatchesPrefix(pathname, prefix));
}

export function assetPathFor(pathname, route) {
  const prefix = route.assetPrefix || "/";
  if (prefix === "/") return pathname === "/" ? "/index.html" : pathname;
  if (pathname === prefix) return "/index.html";
  const slashPrefix = `${prefix}/`;
  if (!pathname.startsWith(slashPrefix)) return pathname;
  const assetPath = pathname.slice(prefix.length);
  return assetPath || "/index.html";
}

export function authBypassEnabled(request, env = {}) {
  const mode = String(env.ZEROTH_AUTH_BYPASS || env.AUTH_BYPASS || "").trim().toLowerCase();
  if (["1", "true", "yes", "on", "always"].includes(mode)) return true;
  if (["local", "localhost", "auto", "local-only"].includes(mode)) {
    const hostname = new URL(request.url).hostname.toLowerCase();
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  }
  return false;
}

export function cacheControlForPath(pathname) {
  const lower = pathname.toLowerCase();
  if (lower.endsWith(".html") || lower === "/" || lower.endsWith("/")) return "private, no-store";
  if (lower.endsWith(".pdf")) return "private, no-store";
  return "private, max-age=300";
}

async function serveAssets(request, env, url, route) {
  if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") {
    return withSecurityHeaders(new Response("ASSETS binding is not configured\n", { status: 500 }), url, env, true);
  }

  const assetUrl = new URL(request.url);
  assetUrl.pathname = assetPathFor(url.pathname, route);
  const assetRequest = new Request(assetUrl, {
    method: "GET",
    headers: request.headers,
  });
  let response = await env.ASSETS.fetch(assetRequest);

  if (response.status === 404 && isNavigation(request)) {
    const fallbackUrl = new URL(request.url);
    fallbackUrl.pathname = "/index.html";
    response = await env.ASSETS.fetch(new Request(fallbackUrl, {
      method: "GET",
      headers: request.headers,
    }));
  }

  return withSecurityHeaders(response, url, env, request.method === "HEAD");
}

function canonicalPathRedirect(url, route) {
  if (route.assetPrefix === "/" || url.pathname !== route.assetPrefix) return null;
  const target = new URL(url);
  target.pathname = `${route.assetPrefix}/`;
  return target;
}

function redirectNoStore(location, url, env) {
  return withSecurityHeaders(new Response(null, {
    status: 307,
    headers: {
      Location: location,
      "Cache-Control": "no-store",
    },
  }), url, env, true);
}

function withSecurityHeaders(response, url, env, headOnly = false) {
  const headers = new Headers(response.headers);
  const configured = securityHeadersFromEnv(env);
  for (const [name, value] of Object.entries({ ...DEFAULT_SECURITY_HEADERS, ...configured })) {
    if (value) headers.set(name, value);
  }
  if (!headers.has("Cache-Control")) headers.set("Cache-Control", cacheControlForPath(url.pathname));

  return new Response(headOnly ? null : response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function securityHeadersFromEnv(env) {
  const raw = String(env.ZEROTH_SECURITY_HEADERS_JSON || "").trim();
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function issuerFromEnv(env) {
  return String(env.ZEROTH_ISSUER || DEFAULT_ISSUER).replace(/\/+$/, "");
}

function pathList(value) {
  return String(value || "")
    .split(/[\n,]+/)
    .map((item) => normalizePrefix(item))
    .filter(Boolean);
}

function firstPrefix(values) {
  return Array.isArray(values) && values.length ? values[0] : "";
}

function normalizePrefix(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  const prefixed = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return prefixed.length > 1 ? prefixed.replace(/\/+$/, "") : "/";
}

function pathMatchesPrefix(pathname, prefix) {
  if (prefix === "/") return true;
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function isNavigation(request) {
  return (
    (request.method === "GET" || request.method === "HEAD") &&
    (request.headers.get("Sec-Fetch-Mode") === "navigate" ||
      request.headers.get("Accept")?.includes("text/html"))
  );
}
