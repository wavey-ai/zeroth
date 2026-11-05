#!/usr/bin/env node
import { enterprisePreflight } from "./enterprise-config.mjs";

try {
  const args = process.argv.slice(2);
  let provider = "all";
  const env = { ...process.env };
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (name === "--help" || name === "-h") {
      console.log("usage: node scripts/check-enterprise-config.mjs [--provider entra|google_workspace|all] [--auth-origin HTTPS_ORIGIN]\nReads enterprise provider bindings from the process environment. Never prints secret values or changes cloud configuration.");
      process.exit(0);
    }
    if (!["--provider", "--auth-origin"].includes(name) || !args[index + 1]) {
      throw new Error("expected --provider or --auth-origin followed by a value; use --help");
    }
    const input = args[++index];
    if (name === "--provider") provider = input;
    else env.PUBLIC_BASE_URL = input;
  }
  const result = enterprisePreflight(env, provider);
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.localConfigurationReady ? 0 : 1;
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
}
