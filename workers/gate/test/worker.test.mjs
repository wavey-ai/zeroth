import assert from "node:assert/strict";
import test from "node:test";

import {
  assetPathFor,
  authBypassEnabled,
  cacheControlForPath,
  handleGateRequest,
  loginUrl,
  pathAllowedByRoute,
  routeConfig,
} from "../src/worker.js";

test("route config is deployment-driven", () => {
  const route = routeConfig({
    ZEROTH_PROTECTED_PREFIXES: "/dataroom,/account",
    ZEROTH_PUBLIC_PATHS: "/dataroom/public",
    ZEROTH_ASSET_PREFIX: "/dataroom",
  });

  assert.equal(route.assetPrefix, "/dataroom");
  assert.deepEqual(route.protectedPrefixes, ["/dataroom", "/account"]);
  assert.deepEqual(route.publicPaths, ["/dataroom/public"]);
  assert.equal(pathAllowedByRoute("/dataroom/docs/file.pdf", route), true);
  assert.equal(pathAllowedByRoute("/dataroom-public", route), false);
  assert.equal(assetPathFor("/dataroom/docs/file.pdf", route), "/docs/file.pdf");
});

test("login URL preserves return target and client id", () => {
  const request = new Request("https://app.example.com/dataroom/");
  const url = loginUrl(request, {
    ZEROTH_ISSUER: "https://id.example.com/",
    ZEROTH_CLIENT_ID: "app-web",
  });

  assert.equal(url.origin, "https://id.example.com");
  assert.equal(url.pathname, "/login");
  assert.equal(url.searchParams.get("client_id"), "app-web");
  assert.equal(url.searchParams.get("return_to"), request.url);
});

test("local auth bypass only applies to local hosts", () => {
  assert.equal(
    authBypassEnabled(new Request("https://localhost/protected"), { ZEROTH_AUTH_BYPASS: "local" }),
    true,
  );
  assert.equal(
    authBypassEnabled(new Request("https://example.com/protected"), { ZEROTH_AUTH_BYPASS: "local" }),
    false,
  );
});

test("unauthenticated protected route redirects to Zeroth login", async () => {
  const request = new Request("https://app.example.com/dataroom/");
  const response = await handleGateRequest(request, {
    ZEROTH_ISSUER: "https://id.example.com",
    ZEROTH_PROTECTED_PREFIXES: "/dataroom",
    ZEROTH_ASSET_PREFIX: "/dataroom",
  });

  assert.equal(response.status, 307);
  assert.equal(new URL(response.headers.get("Location")).origin, "https://id.example.com");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
});

test("authenticated route serves configured assets", async () => {
  const seen = [];
  const request = new Request("https://app.example.com/dataroom/docs/file.html", {
    headers: { Cookie: "zeroth_session=sess_123" },
  });
  const response = await handleGateRequest(request, {
    ZEROTH_AUTH_BYPASS: "always",
    ZEROTH_PROTECTED_PREFIXES: "/dataroom",
    ZEROTH_ASSET_PREFIX: "/dataroom",
    ASSETS: {
      async fetch(assetRequest) {
        seen.push(new URL(assetRequest.url).pathname);
        return new Response("asset", { status: 200 });
      },
    },
  });

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "asset");
  assert.deepEqual(seen, ["/docs/file.html"]);
  assert.equal(response.headers.get("Cache-Control"), "private, no-store");
});

test("cache policy keeps gated binary assets private", () => {
  assert.equal(cacheControlForPath("/index.html"), "private, no-store");
  assert.equal(cacheControlForPath("/pitch.pdf"), "private, no-store");
  assert.equal(cacheControlForPath("/app.js"), "private, max-age=300");
});
