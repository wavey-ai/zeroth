import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { enterprisePreflight, enterprisePublicVars, workspaceDomains } from "../scripts/enterprise-config.mjs";

const fixture = {
  PUBLIC_BASE_URL: "https://id.example.com",
  ENTRA_TENANT_ID: "11111111-2222-3333-4444-555555555555",
  ENTRA_CLIENT_ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  ENTRA_CLIENT_SECRET: "private-entra-test-value",
  GOOGLE_WORKSPACE_CLIENT_ID: "12345-workspace.apps.googleusercontent.com",
  GOOGLE_WORKSPACE_CLIENT_SECRET: "private-workspace-test-value",
  GOOGLE_WORKSPACE_DOMAINS: "Example.com, subsidiary.example",
};

test("local preflight validates both providers and never serializes credentials", () => {
  const result = enterprisePreflight(fixture);
  assert.equal(result.localConfigurationReady, true);
  assert.equal(result.callbackUri, "https://id.example.com/oauth2/callback");
  const encoded = JSON.stringify(result);
  for (const secret of [fixture.ENTRA_CLIENT_SECRET, fixture.GOOGLE_WORKSPACE_CLIENT_SECRET]) {
    assert.equal(encoded.includes(secret), false);
  }
  const missing = enterprisePreflight({ ...fixture, ENTRA_CLIENT_SECRET: undefined }, "entra");
  assert.equal(missing.localConfigurationReady, false);
  assert.ok(missing.errors.includes("ENTRA_CLIENT_SECRET is missing"));
  assert.equal(enterprisePreflight({ ...fixture, DISABLED_PROVIDERS: "entra" }, "entra").localConfigurationReady, false);
});

test("enterprise public configuration rejects tenant aliases and ambiguous domain policies", () => {
  for (const tenant of ["common", "organizations", "consumers", "contoso.onmicrosoft.com", "00000000-0000-0000-0000-000000000000"]) {
    assert.throws(() => enterprisePublicVars({ ...fixture, ENTRA_TENANT_ID: tenant }), /ENTRA_TENANT_ID/);
  }
  for (const domain of ["", "*.example.com", "https://example.com", "user@example.com", ".example.com", "example.com:443", "-bad.example", "127.0.0.1"]) {
    assert.throws(() => workspaceDomains(domain), /GOOGLE_WORKSPACE_DOMAINS/);
  }
  assert.deepEqual(workspaceDomains("Example.com EXAMPLE.COM,subsidiary.example"), ["example.com", "subsidiary.example"]);
  assert.equal(enterprisePreflight({ ...fixture, PUBLIC_BASE_URL: "https://user:password@id.example.com" }).localConfigurationReady, false);
});

test("installer writes only validated public enterprise vars and recognizes disabled providers", (t) => {
  const temp = mkdtempSync(join(tmpdir(), "zeroth-enterprise-config-"));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  const output = join(temp, "wrangler.jsonc");
  const result = spawnSync(process.execPath, [
    "scripts/install-config.mjs", "--d1-id", "12345678-1234-1234-1234-123456789abc",
    "--disabled-providers", "entra,google_workspace", "--out", output,
  ], { cwd: new URL("../", import.meta.url), env: fixture, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const file = readFileSync(output, "utf8");
  const config = JSON.parse(file);
  assert.equal(config.vars.ENTRA_TENANT_ID, fixture.ENTRA_TENANT_ID);
  assert.equal(config.vars.GOOGLE_WORKSPACE_DOMAINS, "example.com,subsidiary.example");
  assert.equal(config.vars.DISABLED_PROVIDERS, "entra,google_workspace");
  assert.equal(config.vars.ENTRA_CLIENT_SECRET, undefined);
  assert.equal(config.vars.GOOGLE_WORKSPACE_CLIENT_SECRET, undefined);
  assert.equal(file.includes(fixture.ENTRA_CLIENT_SECRET), false);
  assert.equal(file.includes(fixture.GOOGLE_WORKSPACE_CLIENT_SECRET), false);
});

test("preflight CLI exits on incomplete configuration without leaking arbitrary input", () => {
  const secret = "sensitive-invalid-config-value";
  const result = spawnSync(process.execPath, ["scripts/check-enterprise-config.mjs", "--provider", "entra"], {
    cwd: new URL("../", import.meta.url), env: { ...fixture, ENTRA_TENANT_ID: secret, ENTRA_CLIENT_SECRET: undefined }, encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.equal((result.stdout + result.stderr).includes(secret), false);
  const body = JSON.parse(result.stdout);
  assert.equal(body.localConfigurationReady, false);
  assert.ok(body.errors.some((error) => error.includes("ENTRA_TENANT_ID")));
});
