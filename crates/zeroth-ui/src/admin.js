(() => {
  const tokenKey = "zeroth.adminToken";
  const clientsEndpoint = "/clients";
  const usersEndpoint = "/users";
  const tenantsEndpoint = "/tenants";
  const providersEndpoint = "/providers/status";
  const localAuthEndpoint = "/local-auth/status";
  const eventsEndpoint = "/events";
  const dbStatusEndpoint = "/__zeroth/db/status";
  const passkeyRegisterOptionsEndpoint = "/passkeys/register/options";
  const passkeyRegisterVerifyEndpoint = "/passkeys/register/verify";
  const passkeyAuthenticateOptionsEndpoint = "/passkeys/authenticate/options";
  const passkeyAuthenticateVerifyEndpoint = "/passkeys/authenticate/verify";
  const $ = (id) => document.getElementById(id);
  const rows = $("zeroth-client-rows");
  const userRows = $("zeroth-user-rows");
  const providerRows = $("zeroth-provider-rows");
  const localAuthRows = $("zeroth-local-auth-rows");
  const eventRows = $("zeroth-event-rows");
  const dbStatusRows = $("zeroth-db-status-rows");
  const count = $("zeroth-client-count");
  const userCount = $("zeroth-user-count");
  const eventCount = $("zeroth-event-count");
  const dbClientCount = $("zeroth-db-client-count");
  const dbStatus = $("zeroth-db-status");
  const status = $("zeroth-admin-status");
  const passkeyStatus = $("zeroth-passkey-status");
  const message = $("zeroth-admin-message");
  const tokenInput = $("zeroth-admin-token");
  const form = $("zeroth-client-form");
  const passkeyForm = $("zeroth-passkey-register-form");
  const eventFilterForm = $("zeroth-events-filter-form");
  const editorMode = $("zeroth-editor-mode");
  const tenantRows = $("zeroth-tenant-rows");
  const tenantForm = $("zeroth-tenant-form");
  const tenantEditor = $("zeroth-tenant-editor");
  const userFilterForm = $("zeroth-users-filter-form");
  let loadedUsers = [];
  let loadedClients = [];
  let loadedTenants = [];
  let eventCursor = null;
  let nextEventCursor = null;
  let eventPage = 1;
  let eventRequestId = 0;
  let appliedEventParams = null;
  let userRequestId = 0;
  let editingTenant = null;

  function setMessage(value, error = false) {
    if (!message) return;
    message.textContent = value;
    message.setAttribute("aria-invalid", error ? "true" : "false");
  }

  function setPasskeyStatus(value, error = false) {
    if (!passkeyStatus) return;
    passkeyStatus.textContent = value;
    passkeyStatus.className = error ? "zeroth-status zeroth-status-warn" : "zeroth-status zeroth-status-ok";
  }

  function token() {
    return tokenInput.value.trim() || sessionStorage.getItem(tokenKey) || "";
  }

  function bindSectionNav() {
    for (const nav of document.querySelectorAll("[data-zeroth-section-nav]")) {
      const links = Array.from(nav.querySelectorAll("a[href^='#']"));
      if (links.length === 0) continue;
      const defaultHash = nav.getAttribute("data-zeroth-default-section") || links[0].getAttribute("href");
      const tabbed = nav.getAttribute("data-zeroth-tabs") === "true";
      const panels = links.map((link) => {
        const hash = link.getAttribute("href");
        return hash ? document.getElementById(hash.slice(1)) : null;
      });
      const relatedPanels = Array.from(document.querySelectorAll("[data-zeroth-panel-for]"));
      const update = () => {
        const requestedHash = window.location.hash || defaultHash;
        const activeHash = links.some((link) => link.getAttribute("href") === requestedHash)
          ? requestedHash
          : defaultHash;
        for (const link of links) {
          if (link.getAttribute("href") === activeHash) {
            link.setAttribute("aria-current", "page");
          } else {
            link.removeAttribute("aria-current");
          }
        }
        if (tabbed) {
          const activeLink = links.find((link) => link.getAttribute("href") === activeHash);
          const pageTitle = document.getElementById("zeroth-page-title");
          if (pageTitle && activeLink) pageTitle.textContent = activeLink.textContent.trim();
          panels.forEach((panel, index) => {
            if (panel) panel.hidden = links[index].getAttribute("href") !== activeHash;
          });
          for (const panel of relatedPanels) {
            panel.hidden = panel.getAttribute("data-zeroth-panel-for") !== activeHash;
          }
        }
      };
      nav.addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const link = target.closest("a[href^='#']");
        if (link) window.setTimeout(update, 0);
      });
      window.addEventListener("hashchange", update);
      update();
    }
  }

  function splitLines(value) {
    return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64urlToBuffer(value) {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
  }

  function creationOptionsFromServer(options) {
    const publicKey = Object.assign({}, options.publicKey);
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
    publicKey.user = Object.assign({}, publicKey.user, {
      id: base64urlToBuffer(publicKey.user.id)
    });
    publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map((credential) => {
      const descriptor = {
        type: credential.type,
        id: base64urlToBuffer(credential.id)
      };
      if (Array.isArray(credential.transports) && credential.transports.length > 0) {
        descriptor.transports = credential.transports;
      }
      return descriptor;
    });
    return publicKey;
  }

  function requestOptionsFromServer(options) {
    const publicKey = Object.assign({}, options.publicKey);
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
    publicKey.allowCredentials = (publicKey.allowCredentials || []).map((credential) => ({
      type: credential.type,
      id: base64urlToBuffer(credential.id)
    }));
    return publicKey;
  }

  function registrationCredentialPayload(credential) {
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        attestationObject: bufferToBase64url(credential.response.attestationObject),
        transports: typeof credential.response.getTransports === "function"
          ? credential.response.getTransports()
          : []
      }
    };
  }

  function authenticationCredentialPayload(credential) {
    return {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      response: {
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        signature: bufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? bufferToBase64url(credential.response.userHandle)
          : null
      }
    };
  }

  function passkeysAvailable() {
    return Boolean(window.PublicKeyCredential && navigator.credentials);
  }

  function setText(parent, value, className) {
    const node = document.createElement("div");
    if (className) node.className = className;
    node.textContent = value;
    parent.appendChild(node);
    return node;
  }

  function setCountLabel(element, value, label) {
    if (!element) return;
    element.textContent = `${value} ${label}`;
  }

  function renderEmptyRows(target, colSpan) {
    target.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = colSpan;
    cell.className = "zeroth-empty";
    cell.textContent = "No matching records. Adjust the filters or refresh the list.";
    row.appendChild(cell);
    target.appendChild(row);
  }

  async function api(path, options = {}) {
    const allowError = Boolean(options.allowError);
    const bearer = token();
    const headers = Object.assign({ "Accept": "application/json" }, options.headers || {});
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const method = String(options.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const host = document.querySelector("[data-zeroth-profile-menu]");
      const csrf = host && host.dataset.csrfToken;
      if (csrf) headers["X-Zeroth-CSRF"] = csrf;
    }
    const fetchOptions = Object.assign({}, options, { headers, credentials: "same-origin" });
    delete fetchOptions.allowError;
    const response = await fetch(path, fetchOptions);
    let body = null;
    try {
      body = await response.json();
    } catch (_) {}
    if (!response.ok && !allowError) {
      throw new Error((body && (body.error_description || body.error)) || `HTTP ${response.status}`);
    }
    return body;
  }

  function clientFromRow(row) {
    return {
      id: row.dataset.clientId || "",
      name: row.dataset.clientName || "",
      confidential: row.dataset.clientConfidential === "true",
      disabled: row.dataset.clientDisabled === "true",
      redirectUris: splitLines(row.dataset.clientRedirects || ""),
      allowedOrigins: splitLines(row.dataset.clientOrigins || ""),
      allowedEmailDomains: splitLines(row.dataset.clientEmailDomains || ""),
      enterpriseProvider: row.dataset.clientEnterpriseProvider || "",
      accountSharingMode: row.dataset.clientAccountSharingMode || "global",
      accountTenantId: row.dataset.clientAccountTenantId || "global",
      accountNamespace: row.dataset.clientAccountNamespace || "global",
      visibleLoginMethods: splitLines(row.dataset.clientVisibleLoginMethods || ""),
      issuerTokenAudience: row.dataset.clientIssuerTokenAudience || "",
      issuerTokenTtlSeconds: row.dataset.clientIssuerTokenTtlSeconds || ""
    };
  }

  function visibleLoginMethodsForClient(client) {
    return client.visibleLoginMethods || client.visible_login_methods || [];
  }

  function visibleLoginMethodLabel(client) {
    const methods = visibleLoginMethodsForClient(client);
    return methods.length > 0 ? methods.join(", ") : "-";
  }

  function hostWithSubdomain(hostname, subdomain) {
    const clean = String(subdomain || "").trim().toLowerCase().replace(/[^a-z0-9-]/g, "");
    if (!clean) return hostname;
    if (!hostname || hostname === "localhost" || /^[\d.]+$/.test(hostname)) return hostname;
    const labels = hostname.split(".");
    if (labels.length < 3) return `${clean}.${hostname}`;
    labels[0] = clean;
    return labels.join(".");
  }

  function rewriteUrlSubdomain(value, subdomain) {
    try {
      const url = new URL(value);
      url.hostname = hostWithSubdomain(url.hostname, subdomain);
      return url.toString();
    } catch (_) {
      return value;
    }
  }

  function cloneClient(client, subdomain) {
    const suffix = String(subdomain || "").trim().toLowerCase().replace(/[^a-z0-9-]/g, "");
    if (!suffix) return null;
    const id = String(client.id || "").trim();
    const name = String(client.name || "").trim();
    return {
      id: id ? `${id}-${suffix}` : suffix,
      name: name ? `${name} ${suffix}` : suffix,
      confidential: Boolean(client.confidential),
      disabled: false,
      redirectUris: (client.redirectUris || client.redirect_uris || []).map((value) => rewriteUrlSubdomain(value, suffix)),
      allowedOrigins: (client.allowedOrigins || client.allowed_origins || []).map((value) => rewriteUrlSubdomain(value, suffix)),
      allowedEmailDomains: client.allowedEmailDomains || client.allowed_email_domains || [],
      enterpriseProvider: client.enterpriseProvider || client.enterprise_provider || "",
      accountSharingMode: client.accountSharingMode || client.account_sharing_mode || "global",
      accountTenantId: client.accountTenantId || client.account_tenant_id || "",
      visibleLoginMethods: visibleLoginMethodsForClient(client),
      issuerTokenAudience: client.issuerTokenAudience || client.issuer_token_audience || "",
      issuerTokenTtlSeconds: client.issuerTokenTtlSeconds || client.issuer_token_ttl_seconds || ""
    };
  }

  function cloneClientFromRow(row) {
    const source = clientFromRow(row);
    const requested = window.prompt("Clone application with env subdomain", "dev");
    if (requested === null) return;
    const client = cloneClient(source, requested);
    if (!client) {
      setMessage("Clone needs a subdomain", true);
      return;
    }
    fillForm(client, true);
    form.elements.id.disabled = false;
    editorMode.textContent = "Clone";
    setMessage("Review cloned env application, then save");
  }

  function fillForm(client, focus = false) {
    form.elements.id.value = client.id || "";
    form.elements.name.value = client.name || "";
    form.elements.type.value = client.confidential ? "confidential" : "public";
    form.elements.redirectUris.value = (client.redirectUris || client.redirect_uris || []).join("\n");
    form.elements.allowedOrigins.value = (client.allowedOrigins || client.allowed_origins || []).join("\n");
    form.elements.allowedEmailDomains.value = (client.allowedEmailDomains || client.allowed_email_domains || []).join("\n");
    form.elements.enterpriseProvider.value = client.enterpriseProvider || client.enterprise_provider || "";
    form.elements.accountSharingMode.value = client.accountSharingMode || client.account_sharing_mode || "global";
    form.elements.accountTenantId.value = client.accountTenantId || client.account_tenant_id || "";
    const visibleMethods = new Set(visibleLoginMethodsForClient(client));
    for (const checkbox of form.querySelectorAll("input[name='visibleLoginMethods']")) {
      checkbox.checked = visibleMethods.has(checkbox.value);
    }
    form.elements.issuerTokenAudience.value = client.issuerTokenAudience || client.issuer_token_audience || "";
    form.elements.issuerTokenTtlSeconds.value = client.issuerTokenTtlSeconds || client.issuer_token_ttl_seconds || "";
    form.elements.clientSecret.value = "";
    form.elements.disabled.checked = Boolean(client.disabled);
    editorMode.textContent = client.id ? "Edit" : "New";
    form.elements.id.disabled = Boolean(client.id);
    if (focus) {
      form.scrollIntoView({ block: "start", behavior: "smooth" });
      form.elements.name.focus({ preventScroll: true });
    }
  }

  function resetClientForm(focus = false) {
    form.reset();
    form.elements.id.disabled = false;
    editorMode.textContent = "New";
    setMessage("");
    if (focus) {
      form.scrollIntoView({ block: "start", behavior: "smooth" });
      form.elements.id.focus({ preventScroll: true });
    }
  }

  function renderRows(clients) {
    loadedClients = clients;
    refreshTenantClientPicker();
    rows.replaceChildren();
    setCountLabel(count, clients.length, "clients");
    if (clients.length === 0) {
      renderEmptyRows(rows, 11);
      return;
    }

    for (const client of clients) {
      const row = document.createElement("tr");
      row.dataset.clientId = client.id;
      row.dataset.clientName = client.name;
      row.dataset.clientConfidential = String(client.confidential);
      row.dataset.clientDisabled = String(client.disabled);
      row.dataset.clientRedirects = (client.redirectUris || client.redirect_uris || []).join("\n");
      row.dataset.clientOrigins = (client.allowedOrigins || client.allowed_origins || []).join("\n");
      row.dataset.clientEmailDomains = (client.allowedEmailDomains || client.allowed_email_domains || []).join("\n");
      row.dataset.clientEnterpriseProvider = client.enterpriseProvider || client.enterprise_provider || "";
      row.dataset.clientAccountSharingMode = client.accountSharingMode || client.account_sharing_mode || "global";
      row.dataset.clientAccountTenantId = client.accountTenantId || client.account_tenant_id || "global";
      row.dataset.clientAccountNamespace = client.accountNamespace || client.account_namespace || "global";
      row.dataset.clientVisibleLoginMethods = visibleLoginMethodsForClient(client).join("\n");
      row.dataset.clientIssuerTokenAudience = client.issuerTokenAudience || client.issuer_token_audience || "";
      row.dataset.clientIssuerTokenTtlSeconds = client.issuerTokenTtlSeconds || client.issuer_token_ttl_seconds || "";

      const name = document.createElement("td");
      setText(name, client.name, "zeroth-row-title");
      setText(name, client.id, "zeroth-row-meta zeroth-code");

      const type = document.createElement("td");
      setText(type, client.confidential ? "Confidential" : "Public");
      setText(type, client.confidential && client.hasSecret ? "Secret set" : client.confidential ? "No secret" : "-", "zeroth-row-meta");

      const state = document.createElement("td");
      const statePill = document.createElement("span");
      statePill.className = client.disabled ? "zeroth-status zeroth-status-warn" : "zeroth-status zeroth-status-ok";
      statePill.textContent = client.disabled ? "Disabled" : "Active";
      state.appendChild(statePill);

      const redirects = document.createElement("td");
      redirects.textContent = (client.redirectUris || client.redirect_uris || []).join(", ") || "-";

      const origins = document.createElement("td");
      origins.textContent = (client.allowedOrigins || client.allowed_origins || []).join(", ") || "-";

      const emailDomains = document.createElement("td");
      emailDomains.textContent = (client.allowedEmailDomains || client.allowed_email_domains || []).join(", ") || "-";

      const enterprise = document.createElement("td");
      const enterpriseProvider = client.enterpriseProvider || client.enterprise_provider || "";
      enterprise.textContent = enterpriseProvider === "entra" ? "Microsoft Entra" : enterpriseProvider === "google_workspace" ? "Google Workspace" : "None";

      const account = document.createElement("td");
      setText(account, client.accountSharingMode || client.account_sharing_mode || "global");
      setText(account, client.accountNamespace || client.account_namespace || "global", "zeroth-row-meta zeroth-code");

      const login = document.createElement("td");
      login.textContent = visibleLoginMethodLabel(client);

      const issuerToken = document.createElement("td");
      const audience = client.issuerTokenAudience || client.issuer_token_audience || "";
      const ttlSeconds = client.issuerTokenTtlSeconds || client.issuer_token_ttl_seconds || "";
      issuerToken.textContent = audience ? `${audience} / ${ttlSeconds || 300}s` : "-";

      const actions = document.createElement("td");
      const edit = document.createElement("button");
      edit.className = "zeroth-action";
      edit.type = "button";
      edit.dataset.zerothEditClient = "true";
      edit.textContent = "Edit";
      actions.appendChild(edit);
      const clone = document.createElement("button");
      clone.className = "zeroth-action";
      clone.type = "button";
      clone.dataset.zerothCloneClient = "true";
      clone.textContent = "Clone with env";
      actions.appendChild(document.createTextNode(" "));
      actions.appendChild(clone);
      if (!client.disabled) {
        const disable = document.createElement("button");
        disable.className = "zeroth-action zeroth-danger";
        disable.type = "button";
        disable.dataset.zerothDisableClient = "true";
        disable.textContent = "Disable";
        actions.appendChild(document.createTextNode(" "));
        actions.appendChild(disable);
      }

      row.append(name, type, state, redirects, origins, emailDomains, enterprise, account, login, issuerToken, actions);
      rows.appendChild(row);
    }
  }

  function renderProviderRows(providers) {
    providerRows.replaceChildren();
    if (providers.length === 0) {
      renderEmptyRows(providerRows, 7);
      return;
    }

    for (const provider of providers) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      setText(name, provider.label || provider.id || "-", "zeroth-row-title");
      setText(name, `${provider.id || "-"} · ${provider.kind || "-"}`, "zeroth-row-meta zeroth-code");

      const state = document.createElement("td");
      const statePill = document.createElement("span");
      const disabled = (provider.notes || []).includes("disabled_by_deployment");
      statePill.className = provider.enabled ? "zeroth-status zeroth-status-ok" : "zeroth-status zeroth-status-warn";
      statePill.textContent = disabled ? "Disabled" : provider.enabled ? "Configured" : "Missing config";
      state.appendChild(statePill);

      const clientId = document.createElement("td");
      clientId.textContent = provider.clientIdConfigured ? "Configured" : "Missing";

      const secret = document.createElement("td");
      secret.textContent = provider.clientSecretConfigured ? "Configured" : "Missing";

      const setup = document.createElement("td");
      setup.className = "zeroth-code";
      setup.textContent = providerSetupText(provider);

      const lastFailure = document.createElement("td");
      lastFailure.textContent = providerFailureText(provider);

      const notes = document.createElement("td");
      notes.textContent = providerNotesText(provider);

      row.append(name, state, clientId, secret, setup, lastFailure, notes);
      providerRows.appendChild(row);
    }
  }

  function providerNotesText(provider) {
    const parts = [...(provider.notes || [])];
    for (const requirement of provider.activationRequirements || provider.activation_requirements || []) {
      if (requirement) parts.push(`requires: ${requirement}`);
    }
    return parts.join(", ") || "-";
  }

  function providerFailureText(provider) {
    const failure = provider.lastFailure || provider.last_failure;
    if (!failure) return "-";
    const parts = [
      failure.createdAt || failure.created_at || "",
      failure.eventType || failure.event_type || "",
      failure.code || "",
      failure.description || ""
    ].filter(Boolean);
    return parts.join(" · ") || "-";
  }

  function renderLocalAuthRows(methods) {
    localAuthRows.replaceChildren();
    if (methods.length === 0) {
      renderEmptyRows(localAuthRows, 6);
      return;
    }

    for (const method of methods) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      setText(name, method.label || method.id || "-", "zeroth-row-title");
      setText(name, method.id || "-", "zeroth-row-meta zeroth-code");

      const state = document.createElement("td");
      const statePill = document.createElement("span");
      const degraded = localAuthDeliveryDegraded(method.notes || []);
      statePill.className = method.enabled && !degraded ? "zeroth-status zeroth-status-ok" : "zeroth-status zeroth-status-warn";
      statePill.textContent = !method.enabled ? "Needs setup" : degraded ? "Needs attention" : "Ready";
      state.appendChild(statePill);

      const storage = document.createElement("td");
      storage.className = "zeroth-code";
      storage.textContent = method.credentialStorage || "-";

      const delivery = document.createElement("td");
      delivery.textContent = method.delivery || "-";

      const evidence = document.createElement("td");
      evidence.className = "zeroth-code";
      evidence.textContent = localAuthDeliveryEvidence(method.deliveryStatus || method.delivery_status);

      const notes = document.createElement("td");
      notes.textContent = (method.notes || []).join(", ") || "-";

      row.append(name, state, storage, delivery, evidence, notes);
      localAuthRows.appendChild(row);
    }
  }

  function localAuthDeliveryDegraded(notes) {
    return notes.includes("delivery_failed_recently") || notes.includes("delivery_not_proven");
  }

  function localAuthDeliveryEvidence(status) {
    if (!status || typeof status !== "object") return "-";
    const parts = [];
    const issued = status.lastIssueAt || status.last_issue_at;
    const sent = status.lastSentAt || status.last_sent_at;
    const failed = status.lastFailedAt || status.last_failed_at;
    const error = status.lastError || status.last_error;
    if (issued) parts.push(`issued ${issued}`);
    if (sent) parts.push(`sent ${sent}`);
    if (failed) parts.push(`failed ${failed}`);
    if (error) parts.push(`error ${error}`);
    return parts.join(", ") || "-";
  }

  function providerSetupText(provider) {
    const parts = [];
    if (provider.webDomain) parts.push(`Domain ${provider.webDomain}`);
    if (provider.callbackUrl) parts.push(`Callback ${provider.callbackUrl}`);
    if (provider.clientIdBinding) parts.push(`Client ID ${provider.clientIdBinding}`);
    const secretSets = (provider.secretBindingSets || [])
      .filter((set) => Array.isArray(set) && set.length > 0)
      .map((set) => set.join(" + "));
    if (secretSets.length > 0) parts.push(`Secrets ${secretSets.join(" or ")}`);
    return parts.join("; ") || "-";
  }

  function renderDbStatus(body) {
    const ok = body && body.ok === true;
    dbStatus.textContent = ok ? "Ready" : "Needs setup";
    dbStatus.className = ok ? "zeroth-status zeroth-status-ok" : "zeroth-status zeroth-status-warn";
    setCountLabel(dbClientCount, (body && body.clientCount) || 0, "clients");
    dbStatusRows.replaceChildren();

    const items = [];
    for (const table of (body && body.tables) || []) {
      items.push({
        name: table.name || "-",
        kind: "Table",
        ready: Boolean(table.present),
        label: table.present ? "Present" : "Missing"
      });
    }
    for (const migration of (body && body.migrations) || []) {
      items.push({
        name: `${migration.version || "-"} ${migration.name || ""}`.trim(),
        kind: "Migration",
        ready: Boolean(migration.applied),
        label: migration.applied ? "Applied" : "Pending"
      });
    }
    for (const column of (body && body.compatibilityColumns) || []) {
      items.push({
        name: `${column.table || "-"}.${column.name || "-"}`,
        kind: "Column",
        ready: Boolean(column.present),
        label: column.present ? "Present" : "Missing"
      });
    }

    if (items.length === 0) {
      renderEmptyRows(dbStatusRows, 3);
      return;
    }

    for (const item of items) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      setText(name, item.name, "zeroth-row-title");
      const kind = document.createElement("td");
      kind.textContent = item.kind;
      const state = document.createElement("td");
      const statePill = document.createElement("span");
      statePill.className = item.ready ? "zeroth-status zeroth-status-ok" : "zeroth-status zeroth-status-warn";
      statePill.textContent = item.label;
      state.appendChild(statePill);
      row.append(name, kind, state);
      dbStatusRows.appendChild(row);
    }
  }

  function renderUserRows(users) {
    userRows.replaceChildren();
    setCountLabel(userCount, users.length, "users");
    if (users.length === 0) {
      renderEmptyRows(userRows, 7);
      return;
    }

    for (const user of users) {
      const row = document.createElement("tr");
      row.dataset.userId = user.id;
      row.dataset.userDisabled = String(user.disabled);
      row.dataset.userAdmin = String(user.admin);

      const profile = document.createElement("td");
      setText(profile, user.displayName || user.email || "Unnamed user", "zeroth-row-title");
      setText(profile, user.email || "No email", "zeroth-row-meta");
      setText(profile, user.id, "zeroth-row-meta zeroth-code");

      const state = document.createElement("td");
      const statePill = document.createElement("span");
      statePill.className = user.disabled ? "zeroth-status zeroth-status-warn" : "zeroth-status zeroth-status-ok";
      statePill.textContent = user.disabled ? "Disabled" : "Active";
      state.appendChild(statePill);

      const admin = document.createElement("td");
      const adminPill = document.createElement("span");
      adminPill.className = user.admin ? "zeroth-status zeroth-status-ok" : "zeroth-status";
      adminPill.textContent = user.admin ? "Administrator" : "Member";
      admin.appendChild(adminPill);

      const identities = document.createElement("td");
      identities.textContent = String(user.identityCount || 0);

      const sessions = document.createElement("td");
      sessions.textContent = String(user.activeSessionCount || 0);

      const updated = document.createElement("td");
      setText(updated, displayTime(user.updatedAt));
      setText(updated, `Created ${displayTime(user.createdAt)}`, "zeroth-row-meta");

      const actions = document.createElement("td");
      actions.className = "zeroth-row-actions";
      const detail = document.createElement("button");
      detail.className = "zeroth-action";
      detail.type = "button";
      detail.dataset.zerothViewUser = "true";
      detail.textContent = "View details";
      actions.appendChild(detail);
      const toggle = document.createElement("button");
      toggle.className = user.disabled ? "zeroth-action" : "zeroth-action zeroth-danger";
      toggle.type = "button";
      toggle.dataset.zerothToggleUser = "true";
      toggle.textContent = user.disabled ? "Enable user" : "Disable user";
      actions.appendChild(toggle);

      const adminToggle = document.createElement("button");
      adminToggle.className = user.admin ? "zeroth-action zeroth-danger" : "zeroth-action";
      adminToggle.type = "button";
      adminToggle.dataset.zerothToggleAdmin = "true";
      adminToggle.textContent = user.admin ? "Revoke admin" : "Grant admin";
      actions.appendChild(document.createTextNode(" "));
      actions.appendChild(adminToggle);

      row.append(profile, state, admin, identities, sessions, updated, actions);
      userRows.appendChild(row);
    }
  }

  function displayTime(value) {
    if (value === null || value === undefined || value === "") return "Not recorded";
    const numeric = Number(value);
    const date = /^\d+$/.test(String(value)) && Number.isFinite(numeric)
      ? new Date(numeric * 1000) : new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  function renderEventRows(events) {
    eventRows.replaceChildren();
    setCountLabel(eventCount, events.length, "events");
    if (events.length === 0) { renderEmptyRows(eventRows, 5); return; }
    for (const event of events) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      setText(name, event.eventType || "Unknown event", "zeroth-row-title");
      setText(name, displayTime(event.recordedAt ?? event.createdAt), "zeroth-row-meta");
      setText(name, event.id || "", "zeroth-row-meta zeroth-code");
      const actor = document.createElement("td");
      setText(actor, event.actorId || "Actor not recorded", "zeroth-code");
      if (event.actorType) setText(actor, event.actorType, "zeroth-row-meta");
      if (event.userId) setText(actor, `Subject: ${event.userId}`, "zeroth-row-meta zeroth-code");
      const scope = document.createElement("td");
      setText(scope, event.organizationId || "Deployment / legacy", "zeroth-code");
      if (event.clientId) setText(scope, event.clientId, "zeroth-row-meta zeroth-code");
      if (event.targetId) setText(scope, `Target: ${event.targetId}`, "zeroth-row-meta zeroth-code");
      const outcome = document.createElement("td");
      const label = event.outcome || "unknown";
      setText(outcome, label.charAt(0).toUpperCase() + label.slice(1), label === "success" ? "zeroth-text-success" : label === "unknown" ? "zeroth-row-meta" : "zeroth-text-warning");
      if (event.reasonCode) setText(outcome, event.reasonCode, "zeroth-row-meta zeroth-code");
      const evidence = document.createElement("td");
      const disclosure = document.createElement("details");
      disclosure.className = "zeroth-audit-evidence";
      const summary = document.createElement("summary");
      summary.textContent = "View event details";
      const pre = document.createElement("pre");
      pre.textContent = JSON.stringify(event.event || event.details || {}, null, 2);
      disclosure.append(summary, pre);
      evidence.appendChild(disclosure);
      if (event.requestId) setText(evidence, `Request: ${event.requestId}`, "zeroth-row-meta zeroth-code");
      row.append(name, actor, scope, outcome, evidence);
      eventRows.appendChild(row);
    }
  }

  function eventFilterPath(cursor = eventCursor, format = "json", useApplied = false) {
    const params = new URLSearchParams(useApplied && appliedEventParams ? appliedEventParams : undefined);
    params.delete("cursor"); params.delete("format");
    if (!(useApplied && appliedEventParams) && eventFilterForm) {
      for (const [key, value] of new FormData(eventFilterForm).entries()) {
        const trimmed = String(value || "").trim();
        if (!trimmed) continue;
        if (key === "from" || key === "until") {
          const seconds = Math.floor(new Date(trimmed).getTime() / 1000);
          if (!Number.isFinite(seconds) || seconds < 0) throw new Error("Enter a valid audit time range");
          params.set(key, String(seconds));
        } else params.set(key, trimmed);
      }
    }
    if (cursor) params.set("cursor", cursor);
    if (format !== "json") params.set("format", format);
    return `${eventsEndpoint}?${params.toString()}`;
  }

  async function exportEvents() {
    const button = $("zeroth-events-export");
    button.disabled = true;
    try {
      const headers = { Accept: "text/csv" };
      const bearer = token();
      if (bearer) headers.Authorization = `Bearer ${bearer}`;
      const response = await fetch(eventFilterPath(eventCursor, "csv", true), { headers, credentials: "same-origin" });
      if (!response.ok) {
        let body = {}; try { body = await response.json(); } catch (_) {}
        throw new Error(body.error_description || body.error || `Export failed (HTTP ${response.status})`);
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url; link.download = "zeroth-audit-events.csv";
      document.body.appendChild(link); link.click(); link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage("Exported the current audit page. Use Older events to continue through history.");
    } finally { button.disabled = false; }
  }

  function applyUserFilters() {
    const search = userFilterForm.elements.search.value.trim().toLowerCase();
    const state = userFilterForm.elements.status.value;
    const role = userFilterForm.elements.role.value;
    const selected = loadedUsers.filter((user) => {
      const searchable = [user.id, user.displayName, user.email].filter(Boolean).join(" ").toLowerCase();
      return (!search || searchable.includes(search))
        && (!state || (state === "disabled") === Boolean(user.disabled))
        && (!role || (role === "admin") === Boolean(user.admin));
    });
    renderUserRows(selected);
    $("zeroth-users-summary").textContent = `${selected.length} of ${loadedUsers.length} loaded users · Search applies to this list, not the full directory.`;
  }

  async function viewUser(row) {
    const dialog = $("zeroth-user-detail");
    const body = $("zeroth-user-detail-body");
    body.replaceChildren(); setText(body, "Loading account details…");
    dialog.showModal();
    try {
      const result = await api(`${usersEndpoint}?user_id=${encodeURIComponent(row.dataset.userId)}`);
      const user = result.user || {};
      body.replaceChildren();
      setText(body, user.displayName || user.email || user.id || "User", "zeroth-row-title");
      setText(body, user.email || "No email recorded", "zeroth-row-meta");
      setText(body, user.id || "", "zeroth-row-meta zeroth-code");
      setText(body, `${user.disabled ? "Disabled" : "Active"} · ${user.admin ? "Deployment administrator" : "Member"}`, "zeroth-row-meta");
      for (const [label, entries, describe] of [
        ["Linked identities", result.identities || [], (identity) => `${identity.providerId || "Identity"} · ${identity.email || identity.providerSubject || "No email"}${identity.emailVerified ? " · Email verified" : ""}`],
        ["Active sessions", result.activeSessions || [], (session) => `${session.clientId || "Browser session"} · Expires ${displayTime(session.expiresAt)}`]
      ]) {
        const section = document.createElement("section"); section.className = "zeroth-detail-section";
        const heading = document.createElement("h3"); heading.textContent = `${label} (${entries.length})`; section.appendChild(heading);
        if (!entries.length) setText(section, "None recorded", "zeroth-row-meta");
        for (const entry of entries) setText(section, describe(entry), "zeroth-detail-line zeroth-code");
        body.appendChild(section);
      }
    } catch (error) { body.replaceChildren(); setText(body, error.message, "zeroth-text-warning"); }
  }

  function syncTenantProvider() {
    const provider = tenantForm.elements.enterpriseProvider.value;
    for (const section of tenantForm.querySelectorAll("[data-tenant-provider]")) {
      section.hidden = section.dataset.tenantProvider !== provider;
    }
  }

  function refreshTenantClientPicker() {
    const picker = $("zeroth-tenant-client-picker");
    picker.replaceChildren(new Option("Choose an application", ""));
    const tenantId = (editingTenant && editingTenant.id) || tenantForm.elements.id.value.trim();
    for (const client of loadedClients) {
      const foreignTenant = (client.accountSharingMode || client.account_sharing_mode) === "tenant"
        && (client.accountTenantId || client.account_tenant_id) !== tenantId;
      const option = new Option(`${client.name} (${client.id})${foreignTenant ? " · Bound to another tenant" : ""}`, client.id);
      option.disabled = foreignTenant || Boolean(client.disabled);
      picker.add(option);
    }
  }

  function editTenant(tenant = null) {
    editingTenant = tenant;
    refreshTenantClientPicker();
    tenantForm.reset();
    for (const name of ["id", "name", "entraTenantId", "oidcClientId", "clientSecretBinding", "retentionDays"]) {
      tenantForm.elements[name].value = tenant && tenant[name] != null ? tenant[name] : "";
    }
    tenantForm.elements.id.disabled = Boolean(tenant);
    tenantForm.elements.disabled.checked = Boolean(tenant && tenant.disabled);
    tenantForm.elements.enterpriseProvider.value = (tenant && tenant.enterpriseProvider) || "";
    tenantForm.elements.clientIds.value = ((tenant && tenant.clientIds) || []).join("\n");
    tenantForm.elements.googleWorkspaceDomains.value = ((tenant && tenant.googleWorkspaceDomains) || []).join("\n");
    const readers = (tenant && tenant.auditReaders) || [];
    tenantForm.elements.auditReaderIds.value = readers.filter((reader) => !reader.canExport).map((reader) => reader.userId).join("\n");
    tenantForm.elements.auditExportReaderIds.value = readers.filter((reader) => reader.canExport).map((reader) => reader.userId).join("\n");
    $("zeroth-tenant-editor-title").textContent = tenant ? `Edit ${tenant.name}` : "Add tenant";
    $("zeroth-tenant-connection-status").textContent = tenant && tenant.connectionConfigured
      ? "Provider credentials are configured. This confirms configuration presence; it does not prove a successful sign-in."
      : "Awaiting provider settings or deployment credentials. Saving a draft does not enable corporate sign-in.";
    syncTenantProvider();
    tenantEditor.hidden = false;
    tenantEditor.scrollIntoView({ block: "start", behavior: "smooth" });
    tenantForm.elements[tenant ? "name" : "id"].focus({ preventScroll: true });
  }

  function renderTenantRows(tenants) {
    tenantRows.replaceChildren();
    if (!tenants.length) { renderEmptyRows(tenantRows, 5); return; }
    for (const tenant of tenants) {
      const row = document.createElement("tr"); row.dataset.tenantId = tenant.id;
      const name = document.createElement("td"); setText(name, tenant.name, "zeroth-row-title"); setText(name, tenant.id, "zeroth-row-meta zeroth-code");
      const connection = document.createElement("td");
      setText(connection, tenant.enterpriseProvider === "entra" ? "Microsoft Entra" : tenant.enterpriseProvider === "google_workspace" ? "Google Workspace" : "No provider selected");
      setText(connection, tenant.disabled ? "Tenant disabled" : tenant.connectionConfigured ? "Credentials configured" : "Awaiting configuration", tenant.connectionConfigured && !tenant.disabled ? "zeroth-row-meta zeroth-text-success" : "zeroth-row-meta zeroth-text-warning");
      const clients = document.createElement("td"); setText(clients, (tenant.clientIds || []).join(", ") || "No applications bound", "zeroth-code");
      const readers = document.createElement("td"); setText(readers, String((tenant.auditReaders || []).length));
      const actions = document.createElement("td"); actions.className = "zeroth-row-actions";
      for (const [label, data] of [["Edit tenant", "zerothEditTenant"], ["Audit history", "zerothTenantAudit"]]) {
        const button = document.createElement("button"); button.type = "button"; button.className = "zeroth-action"; button.textContent = label; button.dataset[data] = "true"; actions.appendChild(button);
      }
      row.append(name, connection, clients, readers, actions); tenantRows.appendChild(row);
    }
  }

  async function loadTenants() {
    const body = await api(tenantsEndpoint);
    loadedTenants = body.tenants || [];
    renderTenantRows(loadedTenants);
    const select = userFilterForm.elements.tenant_id;
    const current = select.value; select.replaceChildren(new Option("All tenants", ""));
    for (const tenant of loadedTenants) select.add(new Option(tenant.name, tenant.id));
    select.value = current;
  }

  async function saveTenant(event) {
    event.preventDefault();
    const data = new FormData(tenantForm);
    const clientIds = [...new Set(splitLines(String(data.get("clientIds") || "")))];
    if (editingTenant && (editingTenant.clientIds || []).some((id) => !clientIds.includes(id))) {
      throw new Error("Existing application bindings cannot be removed. Disable the application to withdraw access.");
    }
    const readers = new Map();
    for (const userId of splitLines(String(data.get("auditReaderIds") || ""))) readers.set(userId, { userId, canExport: false });
    for (const userId of splitLines(String(data.get("auditExportReaderIds") || ""))) readers.set(userId, { userId, canExport: true });
    const optional = (name) => String(data.get(name) || "").trim() || null;
    const payload = {
      id: tenantForm.elements.id.value.trim(), name: String(data.get("name") || "").trim(),
      disabled: tenantForm.elements.disabled.checked, clientIds, auditReaders: Array.from(readers.values()),
      enterpriseProvider: optional("enterpriseProvider"), entraTenantId: optional("entraTenantId"),
      googleWorkspaceDomains: splitLines(String(data.get("googleWorkspaceDomains") || "")),
      oidcClientId: optional("oidcClientId"), clientSecretBinding: optional("clientSecretBinding"),
      retentionDays: optional("retentionDays") === null ? null : Number(data.get("retentionDays"))
    };
    if (payload.enterpriseProvider !== "entra") payload.entraTenantId = null;
    if (payload.enterpriseProvider !== "google_workspace") payload.googleWorkspaceDomains = [];
    if (clientIds.length && !payload.enterpriseProvider) throw new Error("Choose a corporate provider before binding applications.");
    if (payload.clientSecretBinding && !/^TENANT_[A-Z0-9_]+_CLIENT_SECRET$/.test(payload.clientSecretBinding)) throw new Error("Use a deployment secret binding such as TENANT_ACME_CLIENT_SECRET. Do not paste a secret value.");
    const button = tenantForm.querySelector("button[type=submit]"); button.disabled = true;
    try {
      await api(tenantsEndpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      await Promise.all([loadTenants(), loadClients()]);
      tenantEditor.hidden = true;
      setMessage(`Saved tenant ${payload.name}. ${payload.clientIds.length} application binding(s). Connection readiness is shown in the tenant list.`);
    } finally { button.disabled = false; }
  }

  async function loadClients() {
    const body = await api(clientsEndpoint);
    renderRows(body.clients || []);
    status.textContent = "Connected";
  }

  async function loadProviders() {
    const body = await api(providersEndpoint);
    renderProviderRows(body.providers || []);
    status.textContent = "Connected";
  }

  async function loadLocalAuth() {
    const body = await api(localAuthEndpoint);
    renderLocalAuthRows(body.methods || []);
    status.textContent = "Connected";
  }

  async function loadDbStatus() {
    const body = await api(dbStatusEndpoint, { allowError: true });
    if (body && (body.error || body.error_description)) {
      throw new Error(body.error_description || body.error);
    }
    renderDbStatus(body || {});
    status.textContent = "Connected";
    return Boolean(body && body.ok);
  }

  async function loadUsers() {
    const requestId = ++userRequestId;
    const tenant = userFilterForm.elements.tenant_id.value;
    const body = await api(tenant ? `${usersEndpoint}?tenant_id=${encodeURIComponent(tenant)}` : usersEndpoint);
    if (requestId !== userRequestId) return;
    loadedUsers = body.users || [];
    applyUserFilters(); status.textContent = "Connected";
  }

  async function loadEvents(cursor = null, useApplied = false) {
    const requestId = ++eventRequestId;
    $("zeroth-events-next").disabled = true;
    const path = eventFilterPath(cursor, "json", useApplied || Boolean(cursor));
    let body;
    try { body = await api(path); }
    catch (error) { if (requestId === eventRequestId) $("zeroth-events-next").disabled = !nextEventCursor; throw error; }
    if (requestId !== eventRequestId) return;
    appliedEventParams = new URL(path, window.location.origin).searchParams;
    eventCursor = cursor;
    if (!cursor) eventPage = 1; else eventPage += 1;
    nextEventCursor = body.hasMore ? body.nextCursor || null : null;
    renderEventRows(body.events || []);
    $("zeroth-events-next").disabled = !nextEventCursor;
    $("zeroth-events-export").disabled = false;
    $("zeroth-events-latest").disabled = !eventCursor;
    $("zeroth-events-page-status").textContent = `Page ${eventPage} · ${(body.events || []).length} events${nextEventCursor ? " · More history available" : " · End of matching history"}`;
    status.textContent = "Connected";
  }

  async function loadAdmin() {
    const dbReady = await loadDbStatus();
    await Promise.all([loadProviders(), loadLocalAuth()]);
    if (!dbReady) {
      setMessage("Database setup incomplete", true);
      return;
    }
    await Promise.all([loadUsers(), loadEvents(), loadClients(), loadTenants()]);
    setMessage("");
  }

  async function saveClient(event) {
    event.preventDefault();
    const data = new FormData(form);
    const payload = {
      id: form.elements.id.value.trim(),
      name: data.get("name"),
      redirectUris: splitLines(data.get("redirectUris") || ""),
      allowedOrigins: splitLines(data.get("allowedOrigins") || ""),
      allowedEmailDomains: splitLines(data.get("allowedEmailDomains") || ""),
      enterpriseProvider: String(data.get("enterpriseProvider") || ""),
      accountSharingMode: String(data.get("accountSharingMode") || "global"),
      accountTenantId: String(data.get("accountTenantId") || "").trim() || undefined,
      visibleLoginMethods: data.getAll("visibleLoginMethods").map((value) => String(value)),
      issuerTokenAudience: String(data.get("issuerTokenAudience") || "").trim() || undefined,
      issuerTokenTtlSeconds: (() => {
        const raw = String(data.get("issuerTokenTtlSeconds") || "").trim();
        if (!raw) return undefined;
        const value = Number.parseInt(raw, 10);
        return Number.isInteger(value) ? value : undefined;
      })(),
      confidential: data.get("type") === "confidential",
      disabled: form.elements.disabled.checked
    };
    const secret = (data.get("clientSecret") || "").trim();
    if (secret) payload.clientSecret = secret;
    await api(clientsEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    form.elements.clientSecret.value = "";
    setMessage("Saved");
    await loadClients();
  }

  async function disableClient(row) {
    const client = clientFromRow(row);
    await api(`${clientsEndpoint}?client_id=${encodeURIComponent(client.id)}`, { method: "DELETE" });
    setMessage("Disabled");
    await loadClients();
  }

  async function toggleUser(row) {
    const userId = row.dataset.userId || "";
    const disabled = row.dataset.userDisabled === "true";
    const userLabel = row.querySelector(".zeroth-row-title").textContent;
    if (!window.confirm(disabled ? `Enable ${userLabel}? The user will be able to sign in again.` : `Disable ${userLabel}? Active sessions and refresh tokens will be revoked. Existing short-lived access tokens may remain valid until expiry.`)) return;
    await api(`${usersEndpoint}?user_id=${encodeURIComponent(userId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ disabled: !disabled })
    });
    setMessage(disabled ? "User enabled. They can sign in again." : "User disabled. Active sessions and refresh tokens were revoked.");
    await loadUsers();
  }

  async function toggleAdmin(row) {
    const userId = row.dataset.userId || "";
    const admin = row.dataset.userAdmin === "true";
    const userLabel = row.querySelector(".zeroth-row-title").textContent;
    if (!window.confirm(admin ? `Revoke deployment administrator access for ${userLabel}?` : `Grant ${userLabel} administrator access to the entire Zeroth deployment? This includes all tenants, users, and audit history.`)) return;
    await api(`${usersEndpoint}?user_id=${encodeURIComponent(userId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ admin: !admin })
    });
    setMessage(admin ? "Deployment administrator access revoked." : "Deployment administrator access granted.");
    await loadUsers();
  }

  async function registerPasskey(event) {
    event.preventDefault();
    if (!passkeysAvailable()) {
      throw new Error("Passkeys are not available in this browser");
    }
    const data = new FormData(passkeyForm);
    const payload = {
      email: String(data.get("email") || "").trim() || undefined,
      displayName: String(data.get("displayName") || "").trim() || undefined,
      label: String(data.get("label") || "").trim() || undefined,
      returnTo: `${window.location.origin}/admin`
    };
    setPasskeyStatus("Registering");
    const options = await api(passkeyRegisterOptionsEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const credential = await navigator.credentials.create({
      publicKey: creationOptionsFromServer(options)
    });
    if (!credential) throw new Error("Passkey registration was cancelled");
    await api(passkeyRegisterVerifyEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(registrationCredentialPayload(credential))
    });
    setPasskeyStatus("Registered");
    setMessage("Passkey registered");
    await loadAdmin();
  }

  async function signInWithPasskey() {
    if (!passkeysAvailable()) {
      throw new Error("Passkeys are not available in this browser");
    }
    setPasskeyStatus("Signing in");
    const options = await api(passkeyAuthenticateOptionsEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ returnTo: `${window.location.origin}/admin` })
    });
    const credential = await navigator.credentials.get({
      publicKey: requestOptionsFromServer(options)
    });
    if (!credential) throw new Error("Passkey sign in was cancelled");
    const result = await api(passkeyAuthenticateVerifyEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(authenticationCredentialPayload(credential))
    });
    setPasskeyStatus("Signed in");
    setMessage("Signed in");
    window.location.assign((result && result.returnTo) || "/admin");
  }

  document.addEventListener("DOMContentLoaded", () => {
    bindSectionNav();
    window.addEventListener("hashchange", () => setMessage(""));
    const stored = sessionStorage.getItem(tokenKey) || "";
    if (stored) {
      tokenInput.value = stored;
    }
    loadAdmin().catch((error) => {
      status.textContent = "Disconnected";
      setMessage(error.message, true);
      if (rows && !rows.children.length) {
        renderRows([]);
        renderDbStatus({});
        renderUserRows([]);
        renderProviderRows([]);
        renderEventRows([]);
      }
    });
  });

  if (passkeyForm) {
    passkeyForm.addEventListener("submit", (event) => {
      registerPasskey(event).catch((error) => {
        setPasskeyStatus("Failed", true);
        setMessage(error.message, true);
      });
    });
  }

  const passkeyLogin = $("zeroth-passkey-login");
  if (passkeyLogin) {
    passkeyLogin.addEventListener("click", () => {
      signInWithPasskey().catch((error) => {
        setPasskeyStatus("Failed", true);
        setMessage(error.message, true);
      });
    });
  }

  $("zeroth-admin-token-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = tokenInput.value.trim();
    if (value) sessionStorage.setItem(tokenKey, value);
    loadAdmin().catch((error) => {
      status.textContent = "Disconnected";
      setMessage(error.message, true);
    });
  });

  $("zeroth-admin-clear").addEventListener("click", () => {
    sessionStorage.removeItem(tokenKey);
    tokenInput.value = "";
    status.textContent = "Disconnected";
    if (eventFilterForm) eventFilterForm.reset();
    setMessage("");
    loadAdmin().catch((error) => {
      status.textContent = "Disconnected";
      setMessage(error.message, true);
      renderRows([]);
      renderDbStatus({});
      renderUserRows([]);
      renderProviderRows([]);
      renderEventRows([]);
    });
  });

  $("zeroth-db-refresh").addEventListener("click", () => {
    loadDbStatus().catch((error) => setMessage(error.message, true));
  });

  $("zeroth-providers-refresh").addEventListener("click", () => {
    loadProviders().catch((error) => setMessage(error.message, true));
  });

  $("zeroth-local-auth-refresh").addEventListener("click", () => {
    loadLocalAuth().catch((error) => setMessage(error.message, true));
  });

  $("zeroth-users-refresh").addEventListener("click", () => {
    loadUsers().catch((error) => setMessage(error.message, true));
  });

  $("zeroth-events-refresh").addEventListener("click", () => {
    loadEvents(null, true).catch((error) => setMessage(error.message, true));
  });

  if (eventFilterForm) {
    eventFilterForm.addEventListener("input", () => {
      $("zeroth-events-page-status").textContent = "Filters changed. Apply filters to update history; export uses the displayed page.";
    });
    eventFilterForm.addEventListener("submit", (event) => {
      event.preventDefault();
      loadEvents().catch((error) => setMessage(error.message, true));
    });

    $("zeroth-events-filter-reset").addEventListener("click", () => {
      eventFilterForm.reset();
      loadEvents().catch((error) => setMessage(error.message, true));
    });
  }

  $("zeroth-clients-refresh").addEventListener("click", () => {
    loadClients().catch((error) => setMessage(error.message, true));
  });

  $("zeroth-client-new").addEventListener("click", () => {
    resetClientForm(true);
  });

  userRows.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const button = target && target.closest("button");
    if (!button || (!button.dataset.zerothToggleUser && !button.dataset.zerothToggleAdmin && !button.dataset.zerothViewUser)) return;
    const row = button.closest("tr");
    if (!row) return;
    if (button.dataset.zerothViewUser) { viewUser(row); return; }
    button.disabled = true;
    const operation = button.dataset.zerothToggleAdmin ? toggleAdmin(row) : toggleUser(row);
    operation.catch((error) => setMessage(error.message, true)).finally(() => { button.disabled = false; });
  });

  rows.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const button = target && target.closest("button");
    if (!button) return;
    const row = button.closest("tr");
    if (!row) return;
    if (button.dataset.zerothEditClient) {
      fillForm(clientFromRow(row), true);
    } else if (button.dataset.zerothCloneClient) {
      cloneClientFromRow(row);
    } else if (button.dataset.zerothDisableClient) {
      disableClient(row).catch((error) => setMessage(error.message, true));
    }
  });

  $("zeroth-tenants-refresh").addEventListener("click", () => loadTenants().catch((error) => setMessage(error.message, true)));
  $("zeroth-tenant-new").addEventListener("click", () => editTenant());
  $("zeroth-tenant-add-client").addEventListener("click", () => {
    const picker = $("zeroth-tenant-client-picker");
    if (!picker.value) return;
    tenantForm.elements.clientIds.value = [...new Set([...splitLines(tenantForm.elements.clientIds.value), picker.value])].join("\n");
    picker.value = "";
  });
  for (const id of ["zeroth-tenant-close", "zeroth-tenant-cancel"]) $(id).addEventListener("click", () => { tenantEditor.hidden = true; });
  tenantForm.elements.id.addEventListener("input", refreshTenantClientPicker);
  tenantForm.elements.enterpriseProvider.addEventListener("change", () => {
    syncTenantProvider();
    $("zeroth-tenant-connection-status").textContent = "Unsaved settings. Credential availability will be checked after saving.";
  });
  tenantForm.addEventListener("submit", (event) => saveTenant(event).catch((error) => setMessage(error.message, true)));
  tenantRows.addEventListener("click", (event) => {
    const button = event.target instanceof Element && event.target.closest("button"); if (!button) return;
    const row = button.closest("tr"); if (!row) return;
    const tenant = loadedTenants.find((item) => item.id === row.dataset.tenantId);
    if (button.dataset.zerothEditTenant) { if (tenant) editTenant(tenant); else setMessage("Refresh the tenant list before editing.", true); }
    if (button.dataset.zerothTenantAudit) {
      eventFilterForm.reset(); eventFilterForm.elements.organization_id.value = row.dataset.tenantId;
      window.location.hash = "events"; loadEvents().catch((error) => setMessage(error.message, true));
    }
  });
  userFilterForm.addEventListener("submit", (event) => event.preventDefault());
  for (const name of ["search", "status", "role"]) userFilterForm.elements[name].addEventListener("input", applyUserFilters);
  userFilterForm.elements.tenant_id.addEventListener("change", () => loadUsers().catch((error) => setMessage(error.message, true)));
  $("zeroth-events-next").addEventListener("click", () => { if (nextEventCursor) loadEvents(nextEventCursor).catch((error) => setMessage(error.message, true)); });
  $("zeroth-events-latest").addEventListener("click", () => loadEvents(null, true).catch((error) => setMessage(error.message, true)));
  $("zeroth-events-export").addEventListener("click", () => exportEvents().catch((error) => setMessage(error.message, true)));

  form.addEventListener("submit", (event) => {
    saveClient(event).catch((error) => setMessage(error.message, true));
  });

  $("zeroth-client-reset").addEventListener("click", () => {
    resetClientForm();
  });
})();
