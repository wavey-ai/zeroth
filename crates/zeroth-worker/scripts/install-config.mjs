#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const knownProviders = new Set(["apple", "google", "spotify"]);
const defaultCompatibilityDate = "2026-06-05";
const defaultOutput = "wrangler.generated.jsonc";

function parseArgs(argv) {
  const options = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      options.set("help", "true");
      continue;
    }
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected argument: ${arg}`);
    }
    const [rawName, inlineValue] = arg.slice(2).split(/=(.*)/s, 2);
    const name = rawName.trim();
    if (!name) {
      throw new Error(`invalid option: ${arg}`);
    }
    if (inlineValue !== undefined) {
      options.set(name, inlineValue);
      continue;
    }
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--")) {
      options.set(name, "true");
      continue;
    }
    options.set(name, next);
    index += 1;
  }
  return options;
}

function usage() {
  return `usage:
  node scripts/install-config.mjs --auth-origin https://auth.example.com --d1-id D1_UUID [options]

required:
  --auth-origin OR PUBLIC_BASE_URL
  --d1-id OR ZEROTH_D1_DATABASE_ID OR D1_DATABASE_ID

options:
  --name NAME
  --d1-name NAME
  --route HOST_OR_PATTERN
  --workers-dev true|false
  --out PATH
  --product-name NAME
  --session-cookie-domain DOMAIN
  --default-login-client-id CLIENT_ID
  --disabled-providers apple,google,spotify
  --apple-client-id CLIENT_ID
  --google-client-id CLIENT_ID
  --spotify-client-id CLIENT_ID
  --apple-native-client-ids CLIENT_ID[,CLIENT_ID]
  --google-native-client-ids CLIENT_ID[,CLIENT_ID]
  --spotify-native-client-ids CLIENT_ID[,CLIENT_ID]
  --magic-link-from EMAIL
  --magic-link-delivery cloudflare_email|webhook|resend|mailchannels
  --magic-link-webhook-url URL
  --email-binding NAME`;
}

function option(options, name, envNames = []) {
  const value = options.get(name);
  if (value !== undefined && value !== "true") {
    return value;
  }
  for (const envName of envNames) {
    const envValue = process.env[envName];
    if (envValue !== undefined && envValue.trim() !== "") {
      return envValue;
    }
  }
  return undefined;
}

function requiredOption(options, name, envNames = []) {
  const value = option(options, name, envNames);
  if (value === undefined || value.trim() === "") {
    throw new Error(`missing --${name}`);
  }
  return value.trim();
}

function boolOption(options, name, fallback) {
  const value = option(options, name);
  if (value === undefined) {
    return fallback;
  }
  if (["1", "true", "yes"].includes(value.toLowerCase())) {
    return true;
  }
  if (["0", "false", "no"].includes(value.toLowerCase())) {
    return false;
  }
  throw new Error(`--${name} must be true or false`);
}

function listOption(options, name, envNames = []) {
  const value = option(options, name, envNames);
  if (value === undefined) {
    return [];
  }
  return value
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeProviderList(values) {
  const providers = [];
  for (const rawValue of values) {
    const provider = rawValue.toLowerCase();
    if (!knownProviders.has(provider)) {
      throw new Error(`unknown provider in --disabled-providers: ${rawValue}`);
    }
    if (!providers.includes(provider)) {
      providers.push(provider);
    }
  }
  return providers;
}

function publicBaseUrl(rawOrigin) {
  let url;
  try {
    url = new URL(rawOrigin);
  } catch (error) {
    throw new Error(`--auth-origin is invalid: ${error.message}`);
  }
  const localhost = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(localhost && url.protocol === "http:")) {
    throw new Error("--auth-origin must be https, except local http localhost origins");
  }
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.origin;
}

function slugFromHost(hostname) {
  const slug = hostname
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug ? `zeroth-${slug}` : "zeroth";
}

function requireUuidLike(value, name) {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      value,
    )
  ) {
    throw new Error(`--${name} must be a D1 UUID`);
  }
}

function setVar(vars, name, value) {
  if (value !== undefined && value.trim() !== "") {
    vars[name] = value.trim();
  }
}

function magicLinkDeliveryIsCloudflareEmail(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return !normalized || normalized === "cloudflare" || normalized === "cloudflare_email";
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.has("help")) {
    console.log(usage());
    return;
  }

  const issuer = publicBaseUrl(
    requiredOption(options, "auth-origin", ["PUBLIC_BASE_URL"]),
  );
  const issuerUrl = new URL(issuer);
  const d1Id = requiredOption(options, "d1-id", [
    "ZEROTH_D1_DATABASE_ID",
    "D1_DATABASE_ID",
  ]);
  requireUuidLike(d1Id, "d1-id");

  const disabledProviders = normalizeProviderList(
    listOption(options, "disabled-providers", ["DISABLED_PROVIDERS"]),
  );
  const route = option(options, "route", ["ZEROTH_ROUTE"]);
  const workersDev = boolOption(options, "workers-dev", route ? false : true);
  const vars = {
    PUBLIC_BASE_URL: issuer,
    PRODUCT_NAME: option(options, "product-name", ["PRODUCT_NAME"]) ?? "Zeroth",
    SESSION_COOKIE_NAME:
      option(options, "session-cookie-name", ["SESSION_COOKIE_NAME"]) ??
      "zeroth_session",
    TX_COOKIE_NAME:
      option(options, "tx-cookie-name", ["TX_COOKIE_NAME"]) ?? "zeroth_tx",
  };

  setVar(
    vars,
    "SESSION_COOKIE_DOMAIN",
    option(options, "session-cookie-domain", ["SESSION_COOKIE_DOMAIN"]),
  );
  setVar(
    vars,
    "DEFAULT_LOGIN_CLIENT_ID",
    option(options, "default-login-client-id", ["DEFAULT_LOGIN_CLIENT_ID"]),
  );
  if (disabledProviders.length > 0) {
    vars.DISABLED_PROVIDERS = disabledProviders.join(",");
  }
  setVar(vars, "APPLE_CLIENT_ID", option(options, "apple-client-id", ["APPLE_CLIENT_ID"]));
  setVar(vars, "GOOGLE_CLIENT_ID", option(options, "google-client-id", ["GOOGLE_CLIENT_ID"]));
  setVar(
    vars,
    "SPOTIFY_CLIENT_ID",
    option(options, "spotify-client-id", ["SPOTIFY_CLIENT_ID"]),
  );
  setVar(
    vars,
    "APPLE_NATIVE_CLIENT_IDS",
    listOption(options, "apple-native-client-ids", [
      "APPLE_NATIVE_CLIENT_IDS",
    ]).join(","),
  );
  setVar(
    vars,
    "GOOGLE_NATIVE_CLIENT_IDS",
    listOption(options, "google-native-client-ids", [
      "GOOGLE_NATIVE_CLIENT_IDS",
    ]).join(","),
  );
  setVar(
    vars,
    "SPOTIFY_NATIVE_CLIENT_IDS",
    listOption(options, "spotify-native-client-ids", [
      "SPOTIFY_NATIVE_CLIENT_IDS",
    ]).join(","),
  );
  const magicLinkFrom = option(options, "magic-link-from", ["MAGIC_LINK_FROM"]);
  const magicLinkDelivery = option(options, "magic-link-delivery", ["MAGIC_LINK_DELIVERY"]);
  const effectiveMagicLinkDelivery =
    magicLinkDelivery ?? (magicLinkFrom ? "cloudflare_email" : undefined);
  setVar(vars, "MAGIC_LINK_FROM", magicLinkFrom);
  setVar(
    vars,
    "MAGIC_LINK_DELIVERY",
    effectiveMagicLinkDelivery,
  );
  setVar(
    vars,
    "MAGIC_LINK_WEBHOOK_URL",
    option(options, "magic-link-webhook-url", ["MAGIC_LINK_WEBHOOK_URL"]),
  );

  const config = {
    $schema: "./node_modules/wrangler/config-schema.json",
    name: option(options, "name", ["ZEROTH_WORKER_NAME"]) ?? slugFromHost(issuerUrl.hostname),
    main: "build/worker/shim.mjs",
    compatibility_date:
      option(options, "compatibility-date", ["ZEROTH_COMPATIBILITY_DATE"]) ??
      defaultCompatibilityDate,
    workers_dev: workersDev,
    observability: {
      enabled: true,
    },
    vars,
    d1_databases: [
      {
        binding: "ZEROTH_DB",
        database_name: option(options, "d1-name", ["ZEROTH_D1_DATABASE_NAME"]) ?? "zeroth",
        database_id: d1Id,
      },
    ],
    build: {
      command: "cargo install -q worker-build && worker-build --release",
    },
  };

  if (magicLinkFrom && magicLinkDeliveryIsCloudflareEmail(effectiveMagicLinkDelivery)) {
    config.send_email = [
      {
        name: option(options, "email-binding", ["ZEROTH_EMAIL_BINDING"]) ?? "EMAIL",
        allowed_sender_addresses: [magicLinkFrom.trim()],
      },
    ];
  }

  if (route !== undefined && route.trim() !== "") {
    config.routes = [
      {
        pattern: route.trim(),
        custom_domain: !route.includes("*") && !route.includes("/"),
      },
    ];
  }

  const output = resolve(option(options, "out") ?? defaultOutput);
  writeFileSync(output, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });
  console.log(output);
}

try {
  main();
} catch (error) {
  console.error(`error: ${error.message}`);
  console.error(usage());
  process.exit(1);
}
