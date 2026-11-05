const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const bindings = {
  entra: ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET"],
  google_workspace: ["GOOGLE_WORKSPACE_CLIENT_ID", "GOOGLE_WORKSPACE_DOMAINS", "GOOGLE_WORKSPACE_CLIENT_SECRET"],
};

function value(env, name) {
  return String(env[name] || "").trim();
}

function present(input) {
  return Boolean(input) && !/^(replace[-_ ]|your[-_ ]|<)/i.test(input);
}

export function workspaceDomains(raw) {
  const domains = [...new Set(String(raw || "").toLowerCase().split(/[,\s]+/).filter(Boolean))];
  if (!domains.length || domains.some((domain) => {
    const labels = domain.split(".");
    return domain.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1))
      || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
  })) {
    throw new Error("GOOGLE_WORKSPACE_DOMAINS must contain exact DNS domains, without wildcards or URLs");
  }
  return domains;
}

export function enterprisePublicVars(env = {}) {
  const vars = {};
  if (value(env, "ENTRA_TENANT_ID") || value(env, "ENTRA_CLIENT_ID")) {
    for (const name of ["ENTRA_TENANT_ID", "ENTRA_CLIENT_ID"]) {
      const input = value(env, name);
      if (!uuid.test(input) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(input)) {
        throw new Error(`${name} must be a nonzero GUID from the Entra app registration`);
      }
      vars[name] = input.toLowerCase();
    }
  }
  if (value(env, "GOOGLE_WORKSPACE_CLIENT_ID") || value(env, "GOOGLE_WORKSPACE_DOMAINS")) {
    const input = value(env, "GOOGLE_WORKSPACE_CLIENT_ID");
    if (!/^[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com$/.test(input)) {
      throw new Error("GOOGLE_WORKSPACE_CLIENT_ID must be a Google OAuth web client ID");
    }
    vars.GOOGLE_WORKSPACE_CLIENT_ID = input;
    vars.GOOGLE_WORKSPACE_DOMAINS = workspaceDomains(value(env, "GOOGLE_WORKSPACE_DOMAINS")).join(",");
  }
  return vars;
}

export function enterprisePreflight(env, provider = "all") {
  if (provider !== "all" && !Object.hasOwn(bindings, provider)) {
    throw new Error("provider must be entra, google_workspace, or all");
  }
  const selected = provider === "all" ? Object.keys(bindings) : [provider];
  const errors = [];
  let issuer;
  try {
    const url = new URL(value(env, "PUBLIC_BASE_URL"));
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(local && url.protocol === "http:"))
      || url.username || url.password || url.search || url.hash || url.pathname !== "/") throw new Error();
    issuer = url.origin;
  } catch {
    errors.push("PUBLIC_BASE_URL must be an HTTPS origin, or HTTP localhost for development");
  }
  const providers = {};
  const disabled = value(env, "DISABLED_PROVIDERS").toLowerCase().split(/[,\s]+/);
  for (const id of selected) {
    if (disabled.includes(id)) errors.push(`${id} is disabled by DISABLED_PROVIDERS`);
    const checks = Object.fromEntries(bindings[id].map((name) => [name, present(value(env, name)) ? "present" : "missing"]));
    for (const [name, status] of Object.entries(checks)) {
      if (status === "missing") errors.push(`${name} is missing`);
    }
    const publicEnv = Object.fromEntries(bindings[id].filter((name) => !name.endsWith("SECRET")).map((name) => [name, env[name]]));
    try { enterprisePublicVars(publicEnv); } catch (error) { errors.push(error.message); }
    providers[id] = { bindings: checks };
  }
  return {
    localConfigurationReady: errors.length === 0,
    ...(issuer ? { issuer, callbackUri: `${issuer}/oauth2/callback` } : {}),
    providers,
    errors,
    note: "Checks local binding presence and public configuration only; credentials, cloud bindings, and live login are not verified.",
  };
}
