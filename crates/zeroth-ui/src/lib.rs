//! Leptos UI primitives for hosted Zeroth login and account management.
//!
//! This crate is generic on purpose: deployments pass branding, provider state,
//! client state, profile data, and session data in through typed structs.

use leptos::prelude::*;
use url::{form_urlencoded, Url};
use zeroth_providers::well_known;

/// Stylesheet for the default Zeroth account UI.
pub const ZEROTH_UI_CSS: &str = r#"
:root {
  color-scheme: light;
  --z-bg: #f6f8fa;
  --z-panel: #ffffff;
  --z-text: #24292f;
  --z-muted: #57606a;
  --z-line: #d0d7de;
  --z-line-strong: #afb8c1;
  --z-blue: #0969da;
  --z-blue-soft: #ddf4ff;
  --z-green: #1a7f37;
  --z-green-soft: #dafbe1;
  --z-orange: #bc4c00;
  --z-orange-soft: #fff1e5;
  --z-red: #cf222e;
  --z-ink: #1f2328;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--z-bg);
  color: var(--z-text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.45;
}

a {
  color: var(--z-blue);
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

.zeroth-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr);
}

.zeroth-sidebar {
  border-right: 1px solid var(--z-line);
  background: #ffffff;
  padding: 18px 14px;
}

.zeroth-brand {
  display: flex;
  align-items: center;
  gap: 9px;
  margin-bottom: 18px;
  font-size: 16px;
  font-weight: 700;
  color: var(--z-ink);
}

.zeroth-mark {
  display: inline-grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border-radius: 6px;
  background: var(--z-ink);
  color: #ffffff;
  font-weight: 800;
}

.zeroth-nav {
  display: grid;
  gap: 4px;
}

.zeroth-nav a {
  border-radius: 6px;
  color: var(--z-text);
  padding: 7px 9px;
}

.zeroth-nav a[aria-current="page"] {
  background: var(--z-blue-soft);
  color: #0550ae;
  font-weight: 600;
}

.zeroth-main {
  min-width: 0;
  padding: 18px 22px 28px;
}

.zeroth-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 14px;
}

.zeroth-title {
  margin: 0;
  font-size: 21px;
  line-height: 1.2;
  letter-spacing: 0;
}

.zeroth-subtitle {
  margin-top: 3px;
  color: var(--z-muted);
  font-size: 13px;
}

.zeroth-grid {
  display: grid;
  grid-template-columns: minmax(320px, 0.9fr) minmax(380px, 1.35fr);
  gap: 14px;
  align-items: start;
}

.zeroth-stack {
  display: grid;
  gap: 14px;
}

.zeroth-panel {
  background: var(--z-panel);
  border: 1px solid var(--z-line);
  border-radius: 8px;
  overflow: hidden;
}

.zeroth-panel-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  min-height: 43px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--z-line);
}

.zeroth-panel-title {
  margin: 0;
  font-size: 14px;
  font-weight: 700;
  letter-spacing: 0;
}

.zeroth-panel-body {
  padding: 12px;
}

.zeroth-provider-list,
.zeroth-row-list {
  display: grid;
}

.zeroth-provider,
.zeroth-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 10px;
  align-items: center;
  padding: 10px 0;
  border-top: 1px solid var(--z-line);
}

.zeroth-provider:first-child,
.zeroth-row:first-child {
  border-top: 0;
}

.zeroth-provider-badge {
  display: inline-grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border-radius: 6px;
  background: var(--z-bg);
  border: 1px solid var(--z-line);
  color: var(--z-ink);
  font-weight: 800;
}

.provider-apple .zeroth-provider-badge {
  background: #1f2328;
  border-color: #1f2328;
  color: #ffffff;
}

.provider-google .zeroth-provider-badge {
  background: #fff8c5;
  border-color: #f0db4f;
  color: #24292f;
}

.provider-spotify .zeroth-provider-badge {
  background: var(--z-green-soft);
  border-color: #aceebb;
  color: var(--z-green);
}

.zeroth-provider-name,
.zeroth-row-title {
  min-width: 0;
  overflow-wrap: anywhere;
  font-weight: 600;
}

.zeroth-provider-meta,
.zeroth-row-meta {
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--z-muted);
  font-size: 12px;
}

.zeroth-action {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 30px;
  min-width: 78px;
  border-radius: 6px;
  border: 1px solid var(--z-line-strong);
  background: #ffffff;
  color: var(--z-text);
  padding: 5px 9px;
  font-weight: 600;
  white-space: nowrap;
}

.zeroth-action:hover {
  border-color: var(--z-blue);
  color: var(--z-blue);
  text-decoration: none;
}

.zeroth-action[aria-disabled="true"],
.zeroth-action:disabled {
  border-color: var(--z-line);
  color: var(--z-muted);
  background: var(--z-bg);
  cursor: default;
}

.zeroth-action[aria-disabled="true"]:hover {
  border-color: var(--z-line);
  color: var(--z-muted);
}

.zeroth-primary {
  border-color: var(--z-blue);
  background: var(--z-blue);
  color: #ffffff;
}

.zeroth-primary:hover {
  color: #ffffff;
  background: #0550ae;
}

.zeroth-danger:hover {
  border-color: var(--z-red);
  color: var(--z-red);
}

.zeroth-status {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--z-line);
  border-radius: 999px;
  padding: 2px 8px;
  color: var(--z-muted);
  background: var(--z-bg);
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}

.zeroth-status-ok {
  border-color: #aceebb;
  color: var(--z-green);
  background: var(--z-green-soft);
}

.zeroth-status-warn {
  border-color: #ffd8b5;
  color: var(--z-orange);
  background: var(--z-orange-soft);
}

.zeroth-status-row {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 6px;
}

.zeroth-profile {
  display: grid;
  grid-template-columns: 58px minmax(0, 1fr);
  gap: 12px;
  align-items: center;
}

.zeroth-avatar {
  display: grid;
  place-items: center;
  width: 58px;
  height: 58px;
  border: 1px solid var(--z-line);
  border-radius: 8px;
  background: var(--z-bg);
  color: var(--z-muted);
  font-weight: 800;
  overflow: hidden;
}

.zeroth-avatar img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.zeroth-avatar-hidden {
  display: none;
}

.zeroth-form {
  display: grid;
  gap: 10px;
}

.zeroth-field {
  display: grid;
  gap: 4px;
}

.zeroth-field label {
  font-size: 12px;
  font-weight: 700;
  color: var(--z-muted);
}

.zeroth-field input,
.zeroth-field textarea,
.zeroth-field select {
  width: 100%;
  min-height: 34px;
  border: 1px solid var(--z-line-strong);
  border-radius: 6px;
  background: #ffffff;
  color: var(--z-text);
  padding: 6px 8px;
  font: inherit;
}

.zeroth-field textarea {
  min-height: 86px;
  resize: vertical;
}

.zeroth-field input[type="checkbox"] {
  width: 16px;
  min-height: 16px;
  padding: 0;
}

.zeroth-checkbox-field {
  display: flex;
  align-items: center;
  gap: 8px;
}

.zeroth-field input:disabled,
.zeroth-field textarea:disabled,
.zeroth-field select:disabled {
  background: var(--z-bg);
  color: var(--z-muted);
}

.zeroth-form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 2px;
}

.zeroth-table {
  width: 100%;
  border-collapse: collapse;
}

.zeroth-table th,
.zeroth-table td {
  border-top: 1px solid var(--z-line);
  padding: 8px 10px;
  text-align: left;
  vertical-align: middle;
}

.zeroth-table th {
  color: var(--z-muted);
  font-size: 12px;
  font-weight: 700;
}

.zeroth-table tr:first-child th {
  border-top: 0;
}

.zeroth-table td {
  overflow-wrap: anywhere;
}

.zeroth-wide {
  grid-template-columns: minmax(0, 1fr);
}

.zeroth-client-layout {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.75fr);
  gap: 14px;
  align-items: start;
}

.zeroth-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: end;
}

.zeroth-toolbar .zeroth-field {
  flex: 1 1 260px;
}

.zeroth-filter-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(130px, 1fr)) auto;
  gap: 8px;
  align-items: end;
}

.zeroth-message {
  min-height: 20px;
  color: var(--z-muted);
  font-size: 12px;
}

.zeroth-message[aria-invalid="true"] {
  color: var(--z-red);
}

.zeroth-code {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px;
}

.zeroth-empty {
  color: var(--z-muted);
}

@media (max-width: 880px) {
  .zeroth-shell {
    grid-template-columns: 1fr;
  }

  .zeroth-sidebar {
    border-right: 0;
    border-bottom: 1px solid var(--z-line);
  }

  .zeroth-nav {
    grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
  }

  .zeroth-grid {
    grid-template-columns: 1fr;
  }

  .zeroth-client-layout {
    grid-template-columns: 1fr;
  }

  .zeroth-filter-grid {
    grid-template-columns: repeat(2, minmax(130px, 1fr));
  }
}

@media (max-width: 560px) {
  .zeroth-main {
    padding: 14px 12px 20px;
  }

  .zeroth-topbar,
  .zeroth-panel-header {
    align-items: flex-start;
    flex-direction: column;
  }

  .zeroth-provider,
  .zeroth-row {
    grid-template-columns: auto minmax(0, 1fr);
  }

  .zeroth-provider .zeroth-action,
  .zeroth-row .zeroth-action,
  .zeroth-row form {
    grid-column: 2;
    justify-self: start;
  }

  .zeroth-table {
    display: block;
    overflow-x: auto;
  }

  .zeroth-filter-grid {
    grid-template-columns: 1fr;
  }
}
"#;

/// Runtime configuration needed to build Zeroth authorization and account links.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothUiConfig {
    pub issuer_base_url: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub max_age: Option<i32>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub return_to: Option<String>,
    pub csrf_token: Option<String>,
    pub link_identities: bool,
    pub provider_authorize_path: String,
}

impl ZerothUiConfig {
    pub fn new(
        issuer_base_url: impl Into<String>,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            issuer_base_url: issuer_base_url.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: "openid email profile".to_owned(),
            state: None,
            nonce: None,
            max_age: None,
            code_challenge: None,
            code_challenge_method: Some("S256".to_owned()),
            return_to: None,
            csrf_token: None,
            link_identities: true,
            provider_authorize_path: "/authorize".to_owned(),
        }
    }
}

/// Supported upstream provider family for default styling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Apple,
    Google,
    Spotify,
    Custom,
}

/// UI row for a configured upstream provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderUi {
    pub id: String,
    pub label: String,
    pub kind: ProviderKind,
    pub connected: bool,
    pub enabled: bool,
}

impl ProviderUi {
    pub fn apple(connected: bool) -> Self {
        Self {
            id: well_known::APPLE.to_owned(),
            label: "Apple".to_owned(),
            kind: ProviderKind::Apple,
            connected,
            enabled: true,
        }
    }

    pub fn google(connected: bool) -> Self {
        Self {
            id: well_known::GOOGLE.to_owned(),
            label: "Google".to_owned(),
            kind: ProviderKind::Google,
            connected,
            enabled: true,
        }
    }

    pub fn spotify(connected: bool) -> Self {
        Self {
            id: well_known::SPOTIFY.to_owned(),
            label: "Spotify".to_owned(),
            kind: ProviderKind::Spotify,
            connected,
            enabled: true,
        }
    }
}

/// Current user's profile data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileUi {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

/// Linked upstream identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityUi {
    pub provider_id: String,
    pub provider_subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub unlink_disabled: bool,
}

/// Browser session shown in the account UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionUi {
    pub id: String,
    pub client_id: Option<String>,
    pub current: bool,
    pub created_at: Option<String>,
    pub expires_at: Option<String>,
}

/// OIDC application/client shown in the compact admin view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationUi {
    pub client_id: String,
    pub name: String,
    pub public_client: bool,
    pub redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_email_domains: Vec<String>,
}

/// Registered client row shown in the Zeroth management UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAdminUi {
    pub client_id: String,
    pub name: String,
    pub confidential: bool,
    pub redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub disabled: bool,
    pub has_secret: bool,
}

/// Upstream provider readiness row shown in the Zeroth management UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAdminUi {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub enabled: bool,
    pub client_id_configured: bool,
    pub client_secret_configured: bool,
    pub client_id_binding: String,
    pub secret_binding_sets: Vec<Vec<String>>,
    pub callback_url: String,
    pub web_domain: Option<String>,
    pub notes: Vec<String>,
}

/// User row shown in the Zeroth management UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserAdminUi {
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub disabled: bool,
    pub admin: bool,
    pub identity_count: i32,
    pub active_session_count: i32,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Audit event row shown in the Zeroth management UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventAdminUi {
    pub event_id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub provider_id: Option<String>,
    pub created_at: Option<String>,
    pub details: Option<String>,
}

/// Complete state for the Zeroth registered-client management UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientsAdminUiState {
    pub issuer_base_url: String,
    pub product_name: String,
    pub admin_login_url: String,
    pub clients: Vec<ClientAdminUi>,
    pub providers: Vec<ProviderAdminUi>,
    pub users: Vec<UserAdminUi>,
    pub events: Vec<EventAdminUi>,
}

impl ClientsAdminUiState {
    pub fn new(issuer_base_url: impl Into<String>) -> Self {
        let issuer_base_url = issuer_base_url.into();
        let admin_login_url = hosted_login_url(&issuer_base_url, "/admin");
        Self {
            issuer_base_url,
            product_name: "Zeroth".to_owned(),
            admin_login_url,
            clients: Vec::new(),
            providers: Vec::new(),
            users: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn with_product_name(mut self, product_name: impl Into<String>) -> Self {
        self.product_name = product_name.into();
        self
    }

    pub fn with_admin_login_url(mut self, admin_login_url: impl Into<String>) -> Self {
        self.admin_login_url = admin_login_url.into();
        self
    }
}

/// Complete state for the default Zeroth UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothUiState {
    pub config: ZerothUiConfig,
    pub product_name: String,
    pub profile: Option<ProfileUi>,
    pub providers: Vec<ProviderUi>,
    pub identities: Vec<IdentityUi>,
    pub sessions: Vec<SessionUi>,
    pub applications: Vec<ApplicationUi>,
}

impl ZerothUiState {
    pub fn new(config: ZerothUiConfig) -> Self {
        Self {
            config,
            product_name: "Zeroth".to_owned(),
            profile: None,
            providers: vec![
                ProviderUi::apple(false),
                ProviderUi::google(false),
                ProviderUi::spotify(false),
            ],
            identities: Vec::new(),
            sessions: Vec::new(),
            applications: Vec::new(),
        }
    }

    pub fn with_product_name(mut self, product_name: impl Into<String>) -> Self {
        self.product_name = product_name.into();
        self
    }
}

/// Builds the provider-specific Zeroth authorization URL.
pub fn provider_authorize_url(config: &ZerothUiConfig, provider_id: &str) -> String {
    build_provider_authorize_url(config, provider_id).unwrap_or_else(|| "#".to_owned())
}

/// Builds the provider-specific Zeroth identity-link URL for signed-in users.
pub fn provider_link_url(config: &ZerothUiConfig, provider_id: &str) -> String {
    build_provider_link_url(config, provider_id).unwrap_or_else(|| "#".to_owned())
}

/// Renders the default Zeroth UI body as server-side HTML.
pub fn render_account_html(state: ZerothUiState) -> String {
    view! { <AccountApp state=state /> }.to_html()
}

/// Renders a complete HTML document with the default Zeroth stylesheet.
pub fn render_account_document(state: ZerothUiState) -> String {
    format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>{}</title><style>{}</style></head><body>{}<script>{}</script></body></html>"
        ),
        escape_text(&state.product_name),
        ZEROTH_UI_CSS,
        render_account_html(state),
        ZEROTH_UI_SCRIPT
    )
}

/// Renders the registered-client management UI body as server-side HTML.
pub fn render_clients_admin_html(state: ClientsAdminUiState) -> String {
    view! { <ClientsAdminApp state=state /> }.to_html()
}

/// Renders a complete registered-client management document.
pub fn render_clients_admin_document(state: ClientsAdminUiState) -> String {
    format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>{} Clients</title><style>{}</style></head><body>{}<script>{}</script></body></html>"
        ),
        escape_text(&state.product_name),
        ZEROTH_UI_CSS,
        render_clients_admin_html(state),
        ZEROTH_CLIENTS_ADMIN_SCRIPT
    )
}

/// Default Leptos account/login surface.
#[component]
pub fn AccountApp(state: ZerothUiState) -> impl IntoView {
    let ZerothUiState {
        config,
        product_name,
        profile,
        providers,
        identities,
        sessions,
        applications,
    } = state;

    let signed_in = profile.is_some();
    let profile_name = profile
        .as_ref()
        .and_then(|profile| profile.display_name.clone())
        .unwrap_or_else(|| "Not signed in".to_owned());
    let profile_email = profile
        .as_ref()
        .and_then(|profile| profile.email.clone())
        .unwrap_or_else(|| "No email".to_owned());
    let profile_subject = profile
        .as_ref()
        .map(|profile| profile.sub.clone())
        .unwrap_or_else(|| "-".to_owned());
    let profile_picture = profile
        .as_ref()
        .and_then(|profile| profile.picture_url.clone())
        .unwrap_or_default();
    let email_verified = profile
        .as_ref()
        .map(|profile| profile.email_verified)
        .unwrap_or(false);
    let email_status = if email_verified {
        "Verified".to_owned()
    } else {
        "Unverified".to_owned()
    };
    let email_status_class = if email_verified {
        "zeroth-status zeroth-status-ok"
    } else {
        "zeroth-status zeroth-status-warn"
    };
    let auth_status = if signed_in {
        "Signed in".to_owned()
    } else {
        "Signed out".to_owned()
    };
    let auth_status_class = if signed_in {
        "zeroth-status zeroth-status-ok"
    } else {
        "zeroth-status"
    };
    let avatar_initial = avatar_initial(&profile_name);
    let avatar_image_class = if profile_picture.is_empty() {
        "zeroth-avatar-hidden"
    } else {
        ""
    };
    let avatar_text_class = if profile_picture.is_empty() {
        ""
    } else {
        "zeroth-avatar-hidden"
    };
    let profile_action = endpoint_url(&config, "/profile");
    let logout_action = endpoint_url(&config, "/logout");
    let csrf_token = config.csrf_token.clone().unwrap_or_default();

    let provider_rows = providers
        .into_iter()
        .map(|provider| provider_row(&config, provider, signed_in))
        .collect_view();
    let identity_rows = identities
        .into_iter()
        .map(|identity| identity_row(&config, identity, csrf_token.clone()))
        .collect_view();
    let session_rows = sessions
        .into_iter()
        .map(|session| session_row(&logout_action, &csrf_token, session))
        .collect_view();
    let application_rows = applications.into_iter().map(application_row).collect_view();

    view! {
        <div class="zeroth-shell">
            <aside class="zeroth-sidebar">
                <div class="zeroth-brand">
                    <span class="zeroth-mark">"Z"</span>
                    <span>{product_name.clone()}</span>
                </div>
                <nav class="zeroth-nav" aria-label="Account sections">
                    <a href="#login" aria-current="page">"Login"</a>
                    <a href="#profile">"Profile"</a>
                    <a href="#identities">"Identities"</a>
                    <a href="#applications">"Applications"</a>
                </nav>
            </aside>

            <main class="zeroth-main">
                <header class="zeroth-topbar">
                    <div>
                        <h1 class="zeroth-title">{product_name}</h1>
                        <div class="zeroth-subtitle">{config.issuer_base_url.clone()}</div>
                    </div>
                    <span class=auth_status_class>{auth_status}</span>
                </header>

                <div class="zeroth-grid">
                    <div class="zeroth-stack">
                        <section id="login" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Login"</h2>
                                <span class="zeroth-status">{config.client_id.clone()}</span>
                            </div>
                            <div class="zeroth-panel-body">
                                <div class="zeroth-provider-list">{provider_rows}</div>
                            </div>
                        </section>

                        <section id="sessions" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Sessions"</h2>
                                <span class="zeroth-status">{profile_subject.clone()}</span>
                            </div>
                            <div class="zeroth-panel-body">
                                <div class="zeroth-row-list">{session_rows}</div>
                            </div>
                        </section>
                    </div>

                    <div class="zeroth-stack">
                        <section id="profile" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Profile"</h2>
                                <span class=email_status_class>{email_status}</span>
                            </div>
                            <div class="zeroth-panel-body zeroth-stack">
                                <div class="zeroth-profile">
                                    <div class="zeroth-avatar">
                                        <img class=avatar_image_class src=profile_picture.clone() alt="" />
                                        <span class=avatar_text_class>{avatar_initial}</span>
                                    </div>
                                    <div>
                                        <div class="zeroth-row-title">{profile_name.clone()}</div>
                                        <div class="zeroth-row-meta">{profile_email.clone()}</div>
                                        <div class="zeroth-row-meta">{profile_subject}</div>
                                    </div>
                                </div>

                                <form class="zeroth-form" method="post" action=profile_action data-zeroth-method="PATCH">
                                    <input type="hidden" name="_csrf" value=csrf_token.clone() />
                                    <div class="zeroth-field">
                                        <label for="zeroth-profile-name">"Display name"</label>
                                        <input id="zeroth-profile-name" name="displayName" value=profile_name disabled=!signed_in />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-profile-picture">"Picture URL"</label>
                                        <input id="zeroth-profile-picture" name="pictureUrl" value=profile_picture disabled=!signed_in />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-profile-email">"Email"</label>
                                        <input id="zeroth-profile-email" name="email" value=profile_email disabled=true />
                                    </div>
                                    <div class="zeroth-form-actions">
                                        <button class="zeroth-action zeroth-primary" type="submit" disabled=!signed_in>"Save profile"</button>
                                    </div>
                                </form>
                            </div>
                        </section>

                        <section id="identities" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Identities"</h2>
                                <span class="zeroth-status">"Linked providers"</span>
                            </div>
                            <div class="zeroth-panel-body">
                                <div class="zeroth-row-list">{identity_rows}</div>
                            </div>
                        </section>

                        <section id="applications" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Applications"</h2>
                                <span class="zeroth-status">"OIDC"</span>
                            </div>
                            <table class="zeroth-table">
                                <thead>
                                    <tr>
                                        <th>"Client"</th>
                                        <th>"Type"</th>
                                        <th>"Redirect URIs"</th>
                                        <th>"Origins"</th>
                                        <th>"Email domains"</th>
                                    </tr>
                                </thead>
                                <tbody>{application_rows}</tbody>
                            </table>
                        </section>
                    </div>
                </div>
            </main>
        </div>
    }
}

/// Default Zeroth registered-client management surface.
#[component]
pub fn ClientsAdminApp(state: ClientsAdminUiState) -> impl IntoView {
    let ClientsAdminUiState {
        issuer_base_url,
        product_name,
        admin_login_url,
        clients,
        providers,
        users,
        events,
    } = state;
    let client_count = clients.len().to_string();
    let user_count = users.len().to_string();
    let event_count = events.len().to_string();
    let provider_rows = providers.into_iter().map(provider_admin_row).collect_view();
    let user_rows = users.into_iter().map(user_admin_row).collect_view();
    let event_rows = events.into_iter().map(event_admin_row).collect_view();
    let client_rows = clients.into_iter().map(client_admin_row).collect_view();

    view! {
        <div class="zeroth-shell">
            <aside class="zeroth-sidebar">
                <div class="zeroth-brand">
                    <span class="zeroth-mark">"Z"</span>
                    <span>{product_name.clone()}</span>
                </div>
                <nav class="zeroth-nav" aria-label="Management sections">
                    <a href="#database">"Database"</a>
                    <a href="#providers">"Providers"</a>
                    <a href="#users">"Users"</a>
                    <a href="#events">"Events"</a>
                    <a href="#clients" aria-current="page">"Clients"</a>
                    <a href="/account">"Account"</a>
                </nav>
            </aside>

            <main class="zeroth-main">
                <header class="zeroth-topbar">
                    <div>
                        <h1 class="zeroth-title">"Admin"</h1>
                        <div class="zeroth-subtitle" id="zeroth-admin-issuer">{issuer_base_url}</div>
                    </div>
                    <div class="zeroth-status-row">
                        <span class="zeroth-status"><span id="zeroth-user-count">{user_count}</span> " users"</span>
                        <span class="zeroth-status"><span id="zeroth-event-count">{event_count}</span> " events"</span>
                        <span class="zeroth-status"><span id="zeroth-client-count">{client_count}</span> " clients"</span>
                    </div>
                </header>

                <div class="zeroth-client-layout">
                    <div class="zeroth-stack">
                        <section class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Admin token"</h2>
                                <span class="zeroth-status" id="zeroth-admin-status">"Disconnected"</span>
                            </div>
                            <div class="zeroth-panel-body">
                                <form class="zeroth-toolbar" id="zeroth-admin-token-form">
                                    <div class="zeroth-field">
                                        <label for="zeroth-admin-token">"Bearer token"</label>
                                        <input id="zeroth-admin-token" name="token" type="password" autocomplete="off" />
                                    </div>
                                    <a class="zeroth-action" href=admin_login_url>"Sign in"</a>
                                    <button class="zeroth-action zeroth-primary" type="submit">"Connect"</button>
                                    <button class="zeroth-action" id="zeroth-admin-clear" type="button">"Clear"</button>
                                </form>
                            </div>
                        </section>

                        <section class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Passkey"</h2>
                                <span class="zeroth-status" id="zeroth-passkey-status">"Ready"</span>
                            </div>
                            <div class="zeroth-panel-body zeroth-stack">
                                <form class="zeroth-form" id="zeroth-passkey-register-form">
                                    <div class="zeroth-field">
                                        <label for="zeroth-passkey-email">"Email"</label>
                                        <input id="zeroth-passkey-email" name="email" type="email" autocomplete="email" />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-passkey-display-name">"Name"</label>
                                        <input id="zeroth-passkey-display-name" name="displayName" type="text" autocomplete="name" />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-passkey-label">"Label"</label>
                                        <input id="zeroth-passkey-label" name="label" type="text" autocomplete="off" />
                                    </div>
                                    <div class="zeroth-form-actions">
                                        <button class="zeroth-action" id="zeroth-passkey-login" type="button">"Sign in"</button>
                                        <button class="zeroth-action zeroth-primary" type="submit">"Register"</button>
                                    </div>
                                </form>
                            </div>
                        </section>

                        <section id="database" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Database"</h2>
                                <div class="zeroth-status-row">
                                    <span class="zeroth-status" id="zeroth-db-status">"Unknown"</span>
                                    <span class="zeroth-status"><span id="zeroth-db-client-count">"0"</span> " clients"</span>
                                    <button class="zeroth-action" id="zeroth-db-refresh" type="button">"Refresh"</button>
                                </div>
                            </div>
                            <table class="zeroth-table">
                                <thead>
                                    <tr>
                                        <th>"Item"</th>
                                        <th>"Type"</th>
                                        <th>"Status"</th>
                                    </tr>
                                </thead>
                                <tbody id="zeroth-db-status-rows"></tbody>
                            </table>
                        </section>

                        <section id="providers" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Providers"</h2>
                                <button class="zeroth-action" id="zeroth-providers-refresh" type="button">"Refresh"</button>
                            </div>
                            <table class="zeroth-table">
                                <thead>
                                    <tr>
                                        <th>"Provider"</th>
                                        <th>"Status"</th>
                                        <th>"Client ID"</th>
                                        <th>"Client secret"</th>
                                        <th>"Setup"</th>
                                        <th>"Notes"</th>
                                    </tr>
                                </thead>
                                <tbody id="zeroth-provider-rows">{provider_rows}</tbody>
                            </table>
                        </section>

                        <section id="users" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Users"</h2>
                                <button class="zeroth-action" id="zeroth-users-refresh" type="button">"Refresh"</button>
                            </div>
                            <table class="zeroth-table">
                                <thead>
                                    <tr>
                                        <th>"User"</th>
                                        <th>"Status"</th>
                                        <th>"Admin"</th>
                                        <th>"Identities"</th>
                                        <th>"Sessions"</th>
                                        <th>"Updated"</th>
                                        <th>"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody id="zeroth-user-rows">{user_rows}</tbody>
                            </table>
                        </section>

                        <section id="events" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Events"</h2>
                                <button class="zeroth-action" id="zeroth-events-refresh" type="button">"Refresh"</button>
                            </div>
                            <div class="zeroth-panel-body">
                                <form class="zeroth-filter-grid" id="zeroth-events-filter-form">
                                    <div class="zeroth-field">
                                        <label for="zeroth-event-type-filter">"Event type"</label>
                                        <input id="zeroth-event-type-filter" name="event_type" autocomplete="off" />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-event-user-filter">"User ID"</label>
                                        <input id="zeroth-event-user-filter" name="user_id" autocomplete="off" />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-event-client-filter">"Client ID"</label>
                                        <input id="zeroth-event-client-filter" name="client_id" autocomplete="off" />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-event-provider-filter">"Provider ID"</label>
                                        <input id="zeroth-event-provider-filter" name="provider_id" autocomplete="off" />
                                    </div>
                                    <div class="zeroth-form-actions">
                                        <button class="zeroth-action" id="zeroth-events-filter-reset" type="button">"Reset"</button>
                                        <button class="zeroth-action zeroth-primary" type="submit">"Apply"</button>
                                    </div>
                                </form>
                            </div>
                            <table class="zeroth-table">
                                <thead>
                                    <tr>
                                        <th>"Event"</th>
                                        <th>"User"</th>
                                        <th>"Client"</th>
                                        <th>"Provider"</th>
                                        <th>"Details"</th>
                                    </tr>
                                </thead>
                                <tbody id="zeroth-event-rows">{event_rows}</tbody>
                            </table>
                        </section>

                        <section id="clients" class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Registered clients"</h2>
                                <button class="zeroth-action" id="zeroth-clients-refresh" type="button">"Refresh"</button>
                            </div>
                            <table class="zeroth-table">
                                <thead>
                                    <tr>
                                        <th>"Client"</th>
                                        <th>"Type"</th>
                                        <th>"Status"</th>
                                        <th>"Redirect URIs"</th>
                                        <th>"Origins"</th>
                                        <th>"Email domains"</th>
                                        <th>"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody id="zeroth-client-rows">{client_rows}</tbody>
                            </table>
                        </section>
                    </div>

                    <aside class="zeroth-stack">
                        <section class="zeroth-panel">
                            <div class="zeroth-panel-header">
                                <h2 class="zeroth-panel-title">"Client editor"</h2>
                                <span class="zeroth-status" id="zeroth-editor-mode">"New"</span>
                            </div>
                            <div class="zeroth-panel-body">
                                <form class="zeroth-form" id="zeroth-client-form">
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-id">"Client ID"</label>
                                        <input id="zeroth-client-id" name="id" autocomplete="off" required=true />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-name">"Name"</label>
                                        <input id="zeroth-client-name" name="name" autocomplete="off" required=true />
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-type">"Type"</label>
                                        <select id="zeroth-client-type" name="type">
                                            <option value="public">"Public"</option>
                                            <option value="confidential">"Confidential"</option>
                                        </select>
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-redirects">"Redirect URIs"</label>
                                        <textarea id="zeroth-client-redirects" name="redirectUris" spellcheck="false"></textarea>
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-origins">"Allowed origins"</label>
                                        <textarea id="zeroth-client-origins" name="allowedOrigins" spellcheck="false"></textarea>
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-email-domains">"Email domains"</label>
                                        <textarea id="zeroth-client-email-domains" name="allowedEmailDomains" spellcheck="false"></textarea>
                                    </div>
                                    <div class="zeroth-field">
                                        <label for="zeroth-client-secret">"Client secret"</label>
                                        <input id="zeroth-client-secret" name="clientSecret" type="password" autocomplete="new-password" />
                                    </div>
                                    <div class="zeroth-field zeroth-checkbox-field">
                                        <input id="zeroth-client-disabled" name="disabled" type="checkbox" />
                                        <label for="zeroth-client-disabled">"Disabled"</label>
                                    </div>
                                    <div class="zeroth-form-actions">
                                        <button class="zeroth-action" id="zeroth-client-reset" type="button">"Reset"</button>
                                        <button class="zeroth-action zeroth-primary" type="submit">"Save client"</button>
                                    </div>
                                    <div class="zeroth-message" id="zeroth-admin-message" role="status"></div>
                                </form>
                            </div>
                        </section>
                    </aside>
                </div>
            </main>
        </div>
    }
}

fn provider_row(config: &ZerothUiConfig, provider: ProviderUi, signed_in: bool) -> impl IntoView {
    let linking = signed_in && config.link_identities;
    let href = if !provider.enabled || (provider.connected && linking) {
        "#".to_owned()
    } else if linking {
        provider_link_url(config, &provider.id)
    } else {
        provider_authorize_url(config, &provider.id)
    };
    let action = if provider.connected && linking {
        "Connected"
    } else if linking {
        "Link"
    } else {
        "Continue"
    };
    let status = if provider.connected {
        "Connected"
    } else if provider.enabled {
        "Enabled"
    } else {
        "Disabled"
    };
    let disabled = (!provider.enabled || (provider.connected && linking)).to_string();
    let class = format!(
        "zeroth-provider {}",
        provider_kind_class(&provider.kind, provider.connected)
    );
    let initial = provider_initial(&provider);

    view! {
        <div class=class>
            <span class="zeroth-provider-badge">{initial}</span>
            <div>
                <div class="zeroth-provider-name">{provider.label}</div>
                <div class="zeroth-provider-meta">{status}</div>
            </div>
            <a class="zeroth-action" href=href aria-disabled=disabled>{action}</a>
        </div>
    }
}

fn identity_row(
    config: &ZerothUiConfig,
    identity: IdentityUi,
    csrf_token: String,
) -> impl IntoView {
    let action = identity_action_url(config, &identity);
    let verification = if identity.email_verified {
        "Verified"
    } else {
        "Unverified"
    };
    let email = identity.email.unwrap_or_else(|| "No email".to_owned());

    view! {
        <div class="zeroth-row">
            <span class="zeroth-provider-badge">{provider_initial_by_id(&identity.provider_id)}</span>
            <div>
                <div class="zeroth-row-title">{identity.provider_id}</div>
                <div class="zeroth-row-meta">{identity.provider_subject}</div>
                <div class="zeroth-row-meta">{email} " · " {verification}</div>
            </div>
            <form method="post" action=action data-zeroth-method="DELETE">
                <input type="hidden" name="_csrf" value=csrf_token />
                <button class="zeroth-action zeroth-danger" type="submit" disabled=identity.unlink_disabled>"Unlink"</button>
            </form>
        </div>
    }
}

fn session_row(logout_action: &str, csrf_token: &str, session: SessionUi) -> impl IntoView {
    let client = session.client_id.unwrap_or_else(|| "Browser".to_owned());
    let status = if session.current { "Current" } else { "Active" };
    let created_at = session.created_at.unwrap_or_else(|| "-".to_owned());
    let expires_at = session.expires_at.unwrap_or_else(|| "-".to_owned());

    view! {
        <div class="zeroth-row">
            <span class="zeroth-provider-badge">"S"</span>
            <div>
                <div class="zeroth-row-title">{client}</div>
                <div class="zeroth-row-meta">{session.id}</div>
                <div class="zeroth-row-meta">{created_at} " to " {expires_at} " · " {status}</div>
            </div>
            <form method="post" action=logout_action.to_owned() data-zeroth-method="POST">
                <input type="hidden" name="_csrf" value=csrf_token.to_owned() />
                <button class="zeroth-action" type="submit" disabled=!session.current>"Sign out"</button>
            </form>
        </div>
    }
}

fn application_row(application: ApplicationUi) -> impl IntoView {
    let kind = if application.public_client {
        "Public"
    } else {
        "Confidential"
    };
    let redirects = join_or_dash(application.redirect_uris);
    let origins = join_or_dash(application.allowed_origins);
    let email_domains = join_or_dash(application.allowed_email_domains);

    view! {
        <tr>
            <td>
                <div class="zeroth-row-title">{application.name}</div>
                <div class="zeroth-row-meta">{application.client_id}</div>
            </td>
            <td>{kind}</td>
            <td>{redirects}</td>
            <td>{origins}</td>
            <td>{email_domains}</td>
        </tr>
    }
}

fn provider_admin_row(provider: ProviderAdminUi) -> impl IntoView {
    let status = if provider.enabled {
        "Ready"
    } else {
        "Missing config"
    };
    let status_class = if provider.enabled {
        "zeroth-status zeroth-status-ok"
    } else {
        "zeroth-status zeroth-status-warn"
    };
    let client_id = if provider.client_id_configured {
        "Configured"
    } else {
        "Missing"
    };
    let client_secret = if provider.client_secret_configured {
        "Configured"
    } else {
        "Missing"
    };
    let notes = join_or_dash(provider.notes);
    let initial = provider_initial_by_id(&provider.id);
    let setup = provider_setup_text(
        provider.web_domain.as_deref(),
        &provider.callback_url,
        &provider.client_id_binding,
        &provider.secret_binding_sets,
    );

    view! {
        <tr>
            <td>
                <div class="zeroth-row-title">{provider.label}</div>
                <div class="zeroth-row-meta zeroth-code">{provider.id} " · " {provider.kind}</div>
            </td>
            <td><span class=status_class>{status}</span></td>
            <td>{client_id}</td>
            <td>{client_secret}</td>
            <td class="zeroth-code">{setup}</td>
            <td>
                <span class="zeroth-provider-badge">{initial}</span>
                " "
                {notes}
            </td>
        </tr>
    }
}

fn provider_setup_text(
    web_domain: Option<&str>,
    callback_url: &str,
    client_id_binding: &str,
    secret_binding_sets: &[Vec<String>],
) -> String {
    let mut parts = Vec::new();
    if let Some(web_domain) = web_domain.filter(|value| !value.trim().is_empty()) {
        parts.push(format!("Domain {web_domain}"));
    }
    if !callback_url.trim().is_empty() {
        parts.push(format!("Callback {callback_url}"));
    }
    if !client_id_binding.trim().is_empty() {
        parts.push(format!("Client ID {client_id_binding}"));
    }
    let secret_sets = secret_binding_sets
        .iter()
        .filter(|set| !set.is_empty())
        .map(|set| set.join(" + "))
        .collect::<Vec<_>>();
    if !secret_sets.is_empty() {
        parts.push(format!("Secrets {}", secret_sets.join(" or ")));
    }
    join_or_dash(parts)
}

fn user_admin_row(user: UserAdminUi) -> impl IntoView {
    let status = if user.disabled { "Disabled" } else { "Active" };
    let status_class = if user.disabled {
        "zeroth-status zeroth-status-warn"
    } else {
        "zeroth-status zeroth-status-ok"
    };
    let admin_status = if user.admin { "Admin" } else { "Member" };
    let admin_status_class = if user.admin {
        "zeroth-status zeroth-status-ok"
    } else {
        "zeroth-status"
    };
    let admin_action = if user.admin {
        "Revoke admin"
    } else {
        "Grant admin"
    };
    let admin_action_class = if user.admin {
        "zeroth-action zeroth-danger"
    } else {
        "zeroth-action"
    };
    let action = if user.disabled { "Enable" } else { "Disable" };
    let action_class = if user.disabled {
        "zeroth-action"
    } else {
        "zeroth-action zeroth-danger"
    };
    let name = user
        .display_name
        .clone()
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "Unnamed user".to_owned());
    let email = user.email.unwrap_or_else(|| "No email".to_owned());
    let updated_at = user.updated_at.unwrap_or_else(|| "-".to_owned());
    let created_at = user.created_at.unwrap_or_else(|| "-".to_owned());
    let disabled = user.disabled.to_string();
    let admin = user.admin.to_string();
    let user_id = user.user_id;
    let user_id_attr = user_id.clone();

    view! {
        <tr data-user-id=user_id_attr data-user-disabled=disabled data-user-admin=admin>
            <td>
                <div class="zeroth-row-title">{name}</div>
                <div class="zeroth-row-meta">{email}</div>
                <div class="zeroth-row-meta zeroth-code">{user_id}</div>
            </td>
            <td><span class=status_class>{status}</span></td>
            <td><span class=admin_status_class>{admin_status}</span></td>
            <td>{user.identity_count.to_string()}</td>
            <td>{user.active_session_count.to_string()}</td>
            <td>
                <div>{updated_at}</div>
                <div class="zeroth-row-meta">"Created " {created_at}</div>
            </td>
            <td>
                <button class=action_class type="button" data-zeroth-toggle-user="true">{action}</button>
                " "
                <button class=admin_action_class type="button" data-zeroth-toggle-admin="true">{admin_action}</button>
            </td>
        </tr>
    }
}

fn event_admin_row(event: EventAdminUi) -> impl IntoView {
    let created_at = event.created_at.unwrap_or_else(|| "-".to_owned());
    let user_id = event.user_id.unwrap_or_else(|| "-".to_owned());
    let client_id = event.client_id.unwrap_or_else(|| "-".to_owned());
    let provider_id = event.provider_id.unwrap_or_else(|| "-".to_owned());
    let details = event.details.unwrap_or_else(|| "{}".to_owned());

    view! {
        <tr>
            <td>
                <div class="zeroth-row-title">{event.event_type}</div>
                <div class="zeroth-row-meta zeroth-code">{event.event_id}</div>
                <div class="zeroth-row-meta">{created_at}</div>
            </td>
            <td class="zeroth-code">{user_id}</td>
            <td class="zeroth-code">{client_id}</td>
            <td>{provider_id}</td>
            <td class="zeroth-code">{details}</td>
        </tr>
    }
}

fn client_admin_row(client: ClientAdminUi) -> impl IntoView {
    let kind = if client.confidential {
        "Confidential"
    } else {
        "Public"
    };
    let status = if client.disabled {
        "Disabled"
    } else {
        "Active"
    };
    let status_class = if client.disabled {
        "zeroth-status zeroth-status-warn"
    } else {
        "zeroth-status zeroth-status-ok"
    };
    let secret = if client.confidential && client.has_secret {
        "Secret set"
    } else if client.confidential {
        "No secret"
    } else {
        "-"
    };
    let redirects = join_or_dash(client.redirect_uris.clone());
    let origins = join_or_dash(client.allowed_origins.clone());
    let email_domains = join_or_dash(client.allowed_email_domains.clone());
    let redirect_lines = client.redirect_uris.join("\n");
    let origin_lines = client.allowed_origins.join("\n");
    let email_domain_lines = client.allowed_email_domains.join("\n");
    let disabled = client.disabled.to_string();
    let confidential = client.confidential.to_string();
    let client_id = client.client_id;
    let client_name = client.name;
    let client_id_attr = client_id.clone();
    let client_name_attr = client_name.clone();

    view! {
        <tr
            data-client-id=client_id_attr
            data-client-name=client_name_attr
            data-client-confidential=confidential
            data-client-disabled=disabled
            data-client-redirects=redirect_lines
            data-client-origins=origin_lines
            data-client-email-domains=email_domain_lines
        >
            <td>
                <div class="zeroth-row-title">{client_name}</div>
                <div class="zeroth-row-meta zeroth-code">{client_id}</div>
            </td>
            <td>
                <div>{kind}</div>
                <div class="zeroth-row-meta">{secret}</div>
            </td>
            <td><span class=status_class>{status}</span></td>
            <td>{redirects}</td>
            <td>{origins}</td>
            <td>{email_domains}</td>
            <td>
                <button class="zeroth-action" type="button" data-zeroth-edit-client="true">"Edit"</button>
            </td>
        </tr>
    }
}

fn build_provider_authorize_url(config: &ZerothUiConfig, provider_id: &str) -> Option<String> {
    let mut url = Url::parse(&endpoint_url(config, &config.provider_authorize_path)).ok()?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("client_id", &config.client_id);
        pairs.append_pair("provider", provider_id);

        if config.provider_authorize_path == "/login" {
            pairs.append_pair(
                "return_to",
                config.return_to.as_deref().unwrap_or(&config.redirect_uri),
            );
            if let Some(state) = &config.state {
                pairs.append_pair("state", state);
            }
        } else {
            pairs.append_pair("redirect_uri", &config.redirect_uri);
            pairs.append_pair("response_type", "code");
            pairs.append_pair("scope", &config.scope);

            if let Some(state) = &config.state {
                pairs.append_pair("state", state);
            }
            if let Some(nonce) = &config.nonce {
                pairs.append_pair("nonce", nonce);
            }
            if let Some(max_age) = config.max_age {
                pairs.append_pair("max_age", &max_age.to_string());
            }
            if let Some(code_challenge) = &config.code_challenge {
                pairs.append_pair("code_challenge", code_challenge);
                if let Some(method) = &config.code_challenge_method {
                    pairs.append_pair("code_challenge_method", method);
                }
            }
            if let Some(return_to) = &config.return_to {
                pairs.append_pair("return_to", return_to);
            }
        }
    }
    Some(url.to_string())
}

fn build_provider_link_url(config: &ZerothUiConfig, provider_id: &str) -> Option<String> {
    let mut url = Url::parse(&endpoint_url(config, "/identities/link")).ok()?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("provider", provider_id);
        pairs.append_pair(
            "return_to",
            config.return_to.as_deref().unwrap_or(&config.redirect_uri),
        );

        if let Some(state) = &config.state {
            pairs.append_pair("state", state);
        }
    }
    Some(url.to_string())
}

fn endpoint_url(config: &ZerothUiConfig, path: &str) -> String {
    let base = config.issuer_base_url.trim_end_matches('/');
    if base.is_empty() {
        path.to_owned()
    } else {
        format!("{base}{path}")
    }
}

fn hosted_login_url(issuer_base_url: &str, return_to_path: &str) -> String {
    let base = issuer_base_url.trim_end_matches('/');
    let return_to = if base.is_empty() {
        return_to_path.to_owned()
    } else {
        format!("{base}{return_to_path}")
    };
    let encoded_return_to =
        form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>();
    if base.is_empty() {
        format!("/login?return_to={encoded_return_to}")
    } else {
        format!("{base}/login?return_to={encoded_return_to}")
    }
}

fn identity_action_url(config: &ZerothUiConfig, identity: &IdentityUi) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("provider_id", &identity.provider_id)
        .append_pair("provider_subject", &identity.provider_subject)
        .finish();
    format!("{}?{}", endpoint_url(config, "/identities"), query)
}

fn provider_kind_class(kind: &ProviderKind, connected: bool) -> &'static str {
    if connected {
        return "provider-connected";
    }

    match kind {
        ProviderKind::Apple => "provider-apple",
        ProviderKind::Google => "provider-google",
        ProviderKind::Spotify => "provider-spotify",
        ProviderKind::Custom => "provider-custom",
    }
}

fn provider_initial(provider: &ProviderUi) -> String {
    provider_initial_by_id(&provider.id)
}

fn provider_initial_by_id(provider_id: &str) -> String {
    match provider_id {
        well_known::APPLE => "A".to_owned(),
        well_known::GOOGLE => "G".to_owned(),
        well_known::SPOTIFY => "S".to_owned(),
        _ => provider_id
            .chars()
            .next()
            .map(|ch| ch.to_uppercase().to_string())
            .unwrap_or_else(|| "?".to_owned()),
    }
}

fn avatar_initial(display_name: &str) -> String {
    display_name
        .chars()
        .find(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "Z".to_owned())
}

fn join_or_dash(values: Vec<String>) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(", ")
    }
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const ZEROTH_UI_SCRIPT: &str = r#"
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.dataset.zerothMethod) {
    return;
  }
  event.preventDefault();
  const method = form.dataset.zerothMethod.toUpperCase();
  const options = {
    method,
    credentials: "include",
    headers: { "Accept": "application/json" }
  };
  if (method === "PATCH") {
    const data = new FormData(form);
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify({
      displayName: data.get("displayName"),
      pictureUrl: data.get("pictureUrl")
    });
  }
  const response = await fetch(form.action, options);
  if (response.ok) {
    window.location.reload();
    return;
  }
  let message = "Request failed";
  try {
    const body = await response.json();
    message = body.error_description || body.error || message;
  } catch (_) {}
  window.alert(message);
});
"#;

const ZEROTH_CLIENTS_ADMIN_SCRIPT: &str = r#"
(() => {
  const tokenKey = "zeroth.adminToken";
  const clientsEndpoint = "/clients";
  const usersEndpoint = "/users";
  const providersEndpoint = "/providers/status";
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
    publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map((credential) => ({
      type: credential.type,
      id: base64urlToBuffer(credential.id)
    }));
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

  function renderEmptyRows(target, colSpan) {
    target.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = colSpan;
    cell.className = "zeroth-empty";
    cell.textContent = "-";
    row.appendChild(cell);
    target.appendChild(row);
  }

  async function api(path, options = {}) {
    const allowError = Boolean(options.allowError);
    const bearer = token();
    const headers = Object.assign({ "Accept": "application/json" }, options.headers || {});
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
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
      allowedEmailDomains: splitLines(row.dataset.clientEmailDomains || "")
    };
  }

  function fillForm(client) {
    form.elements.id.value = client.id || "";
    form.elements.name.value = client.name || "";
    form.elements.type.value = client.confidential ? "confidential" : "public";
    form.elements.redirectUris.value = (client.redirectUris || client.redirect_uris || []).join("\n");
    form.elements.allowedOrigins.value = (client.allowedOrigins || client.allowed_origins || []).join("\n");
    form.elements.allowedEmailDomains.value = (client.allowedEmailDomains || client.allowed_email_domains || []).join("\n");
    form.elements.clientSecret.value = "";
    form.elements.disabled.checked = Boolean(client.disabled);
    editorMode.textContent = client.id ? "Edit" : "New";
    form.elements.id.disabled = Boolean(client.id);
  }

  function renderRows(clients) {
    rows.replaceChildren();
    count.textContent = String(clients.length);
    if (clients.length === 0) {
      renderEmptyRows(rows, 7);
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

      const actions = document.createElement("td");
      const edit = document.createElement("button");
      edit.className = "zeroth-action";
      edit.type = "button";
      edit.dataset.zerothEditClient = "true";
      edit.textContent = "Edit";
      actions.appendChild(edit);
      if (!client.disabled) {
        const disable = document.createElement("button");
        disable.className = "zeroth-action zeroth-danger";
        disable.type = "button";
        disable.dataset.zerothDisableClient = "true";
        disable.textContent = "Disable";
        actions.appendChild(document.createTextNode(" "));
        actions.appendChild(disable);
      }

      row.append(name, type, state, redirects, origins, emailDomains, actions);
      rows.appendChild(row);
    }
  }

  function renderProviderRows(providers) {
    providerRows.replaceChildren();
    if (providers.length === 0) {
      renderEmptyRows(providerRows, 6);
      return;
    }

    for (const provider of providers) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      setText(name, provider.label || provider.id || "-", "zeroth-row-title");
      setText(name, `${provider.id || "-"} · ${provider.kind || "-"}`, "zeroth-row-meta zeroth-code");

      const state = document.createElement("td");
      const statePill = document.createElement("span");
      statePill.className = provider.enabled ? "zeroth-status zeroth-status-ok" : "zeroth-status zeroth-status-warn";
      statePill.textContent = provider.enabled ? "Ready" : "Missing config";
      state.appendChild(statePill);

      const clientId = document.createElement("td");
      clientId.textContent = provider.clientIdConfigured ? "Configured" : "Missing";

      const secret = document.createElement("td");
      secret.textContent = provider.clientSecretConfigured ? "Configured" : "Missing";

      const setup = document.createElement("td");
      setup.className = "zeroth-code";
      setup.textContent = providerSetupText(provider);

      const notes = document.createElement("td");
      notes.textContent = (provider.notes || []).join(", ") || "-";

      row.append(name, state, clientId, secret, setup, notes);
      providerRows.appendChild(row);
    }
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
    dbClientCount.textContent = String((body && body.clientCount) || 0);
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
    userCount.textContent = String(users.length);
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
      adminPill.textContent = user.admin ? "Admin" : "Member";
      admin.appendChild(adminPill);

      const identities = document.createElement("td");
      identities.textContent = String(user.identityCount || 0);

      const sessions = document.createElement("td");
      sessions.textContent = String(user.activeSessionCount || 0);

      const updated = document.createElement("td");
      setText(updated, String(user.updatedAt || "-"));
      setText(updated, `Created ${user.createdAt || "-"}`, "zeroth-row-meta");

      const actions = document.createElement("td");
      const toggle = document.createElement("button");
      toggle.className = user.disabled ? "zeroth-action" : "zeroth-action zeroth-danger";
      toggle.type = "button";
      toggle.dataset.zerothToggleUser = "true";
      toggle.textContent = user.disabled ? "Enable" : "Disable";
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

  function renderEventRows(events) {
    eventRows.replaceChildren();
    eventCount.textContent = String(events.length);
    if (events.length === 0) {
      renderEmptyRows(eventRows, 5);
      return;
    }

    for (const event of events) {
      const row = document.createElement("tr");
      const name = document.createElement("td");
      setText(name, event.eventType || "-", "zeroth-row-title");
      setText(name, event.id || "-", "zeroth-row-meta zeroth-code");
      setText(name, String(event.createdAt || "-"), "zeroth-row-meta");

      const user = document.createElement("td");
      user.className = "zeroth-code";
      user.textContent = event.userId || "-";

      const client = document.createElement("td");
      client.className = "zeroth-code";
      client.textContent = event.clientId || "-";

      const provider = document.createElement("td");
      provider.textContent = event.providerId || "-";

      const details = document.createElement("td");
      details.className = "zeroth-code";
      details.textContent = JSON.stringify(event.details || {});

      row.append(name, user, client, provider, details);
      eventRows.appendChild(row);
    }
  }

  function eventFilterPath() {
    const params = new URLSearchParams();
    if (eventFilterForm) {
      for (const [key, value] of new FormData(eventFilterForm).entries()) {
        const trimmed = String(value || "").trim();
        if (trimmed) params.set(key, trimmed);
      }
    }
    const query = params.toString();
    return query ? `${eventsEndpoint}?${query}` : eventsEndpoint;
  }

  async function loadClients() {
    const body = await api(clientsEndpoint);
    renderRows(body.clients || []);
    status.textContent = "Connected";
    setMessage("Loaded");
  }

  async function loadProviders() {
    const body = await api(providersEndpoint);
    renderProviderRows(body.providers || []);
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
    const body = await api(usersEndpoint);
    renderUserRows(body.users || []);
    status.textContent = "Connected";
  }

  async function loadEvents() {
    const body = await api(eventFilterPath());
    renderEventRows(body.events || []);
    status.textContent = "Connected";
  }

  async function loadAdmin() {
    const dbReady = await loadDbStatus();
    await loadProviders();
    if (!dbReady) {
      setMessage("Database setup incomplete", true);
      return;
    }
    await Promise.all([loadUsers(), loadEvents(), loadClients()]);
    setMessage("Loaded");
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
    await api(`${usersEndpoint}?user_id=${encodeURIComponent(userId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ disabled: !disabled })
    });
    setMessage(disabled ? "Enabled" : "Disabled");
    await loadUsers();
  }

  async function toggleAdmin(row) {
    const userId = row.dataset.userId || "";
    const admin = row.dataset.userAdmin === "true";
    await api(`${usersEndpoint}?user_id=${encodeURIComponent(userId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ admin: !admin })
    });
    setMessage(admin ? "Admin revoked" : "Admin granted");
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

  $("zeroth-passkey-login").addEventListener("click", () => {
    signInWithPasskey().catch((error) => {
      setPasskeyStatus("Failed", true);
      setMessage(error.message, true);
    });
  });

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

  $("zeroth-users-refresh").addEventListener("click", () => {
    loadUsers().catch((error) => setMessage(error.message, true));
  });

  $("zeroth-events-refresh").addEventListener("click", () => {
    loadEvents().catch((error) => setMessage(error.message, true));
  });

  if (eventFilterForm) {
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

  userRows.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const button = target && target.closest("button");
    if (!button || (!button.dataset.zerothToggleUser && !button.dataset.zerothToggleAdmin)) return;
    const row = button.closest("tr");
    if (!row) return;
    if (button.dataset.zerothToggleAdmin) {
      toggleAdmin(row).catch((error) => setMessage(error.message, true));
    } else {
      toggleUser(row).catch((error) => setMessage(error.message, true));
    }
  });

  rows.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    const button = target && target.closest("button");
    if (!button) return;
    const row = button.closest("tr");
    if (!row) return;
    if (button.dataset.zerothEditClient) {
      fillForm(clientFromRow(row));
    } else if (button.dataset.zerothDisableClient) {
      disableClient(row).catch((error) => setMessage(error.message, true));
    }
  });

  form.addEventListener("submit", (event) => {
    saveClient(event).catch((error) => setMessage(error.message, true));
  });

  $("zeroth-client-reset").addEventListener("click", () => {
    form.reset();
    form.elements.id.disabled = false;
    editorMode.textContent = "New";
    setMessage("");
  });
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_url_preserves_authorize_context() {
        let mut config = ZerothUiConfig::new(
            "https://id.example.com",
            "ios-client",
            "wavey://auth/callback",
        );
        config.state = Some("state-1".to_owned());
        config.nonce = Some("nonce-1".to_owned());
        config.max_age = Some(300);
        config.code_challenge = Some("challenge-1".to_owned());

        let url = Url::parse(&provider_authorize_url(&config, well_known::APPLE)).unwrap();

        assert_eq!(url.path(), "/authorize");
        assert_eq!(query(&url, "client_id"), Some("ios-client".to_owned()));
        assert_eq!(
            query(&url, "redirect_uri"),
            Some("wavey://auth/callback".to_owned())
        );
        assert_eq!(query(&url, "provider"), Some("apple".to_owned()));
        assert_eq!(query(&url, "state"), Some("state-1".to_owned()));
        assert_eq!(query(&url, "nonce"), Some("nonce-1".to_owned()));
        assert_eq!(query(&url, "max_age"), Some("300".to_owned()));
        assert_eq!(
            query(&url, "code_challenge_method"),
            Some("S256".to_owned())
        );
    }

    #[test]
    fn provider_url_can_target_hosted_login() {
        let mut config = ZerothUiConfig::new(
            "https://id.example.com",
            "browser-client",
            "https://app.example.com/home",
        );
        config.provider_authorize_path = "/login".to_owned();
        config.return_to = Some("https://app.example.com/home".to_owned());

        let url = Url::parse(&provider_authorize_url(&config, well_known::GOOGLE)).unwrap();

        assert_eq!(url.path(), "/login");
        assert_eq!(query(&url, "client_id"), Some("browser-client".to_owned()));
        assert_eq!(
            query(&url, "return_to"),
            Some("https://app.example.com/home".to_owned())
        );
        assert_eq!(query(&url, "provider"), Some("google".to_owned()));
        assert_eq!(query(&url, "response_type"), None);
        assert_eq!(query(&url, "code_challenge"), None);
    }

    #[test]
    fn provider_link_url_preserves_return_context() {
        let mut config = ZerothUiConfig::new(
            "https://id.example.com",
            "web-client",
            "https://app.example.com/auth/callback",
        );
        config.state = Some("state-1".to_owned());
        config.return_to = Some("https://app.example.com/settings".to_owned());

        let url = Url::parse(&provider_link_url(&config, well_known::SPOTIFY)).unwrap();

        assert_eq!(url.path(), "/identities/link");
        assert_eq!(query(&url, "provider"), Some("spotify".to_owned()));
        assert_eq!(
            query(&url, "return_to"),
            Some("https://app.example.com/settings".to_owned())
        );
        assert_eq!(query(&url, "state"), Some("state-1".to_owned()));
        assert_eq!(query(&url, "code_challenge"), None);
    }

    #[test]
    fn login_mode_keeps_connected_providers_clickable() {
        let mut state = ZerothUiState::new(ZerothUiConfig::new(
            "https://id.example.com",
            "ios-client",
            "wavey://auth/callback",
        ));
        state.config.link_identities = false;
        state.profile = Some(ProfileUi {
            sub: "usr_123".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            display_name: Some("Example User".to_owned()),
            picture_url: None,
        });
        state.providers = vec![ProviderUi::google(true)];

        let html = render_account_html(state);

        assert!(html.contains("Continue"));
        assert!(html.contains("/authorize"));
        assert!(!html.contains("Connected</a>"));
    }

    #[test]
    fn account_html_contains_core_surfaces() {
        let mut state = ZerothUiState::new(ZerothUiConfig::new(
            "https://id.example.com",
            "browser-client",
            "https://app.example.com/callback",
        ));
        state.profile = Some(ProfileUi {
            sub: "usr_123".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            display_name: Some("Example User".to_owned()),
            picture_url: None,
        });
        state.identities.push(IdentityUi {
            provider_id: well_known::GOOGLE.to_owned(),
            provider_subject: "google-user".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            unlink_disabled: true,
        });
        state.sessions.push(SessionUi {
            id: "ses_123".to_owned(),
            client_id: Some("browser-client".to_owned()),
            current: true,
            created_at: None,
            expires_at: None,
        });
        state.applications.push(ApplicationUi {
            client_id: "browser-client".to_owned(),
            name: "Browser".to_owned(),
            public_client: true,
            redirect_uris: vec!["https://app.example.com/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec!["example.com".to_owned()],
        });

        let html = render_account_html(state);

        assert!(html.contains("Link"));
        assert!(html.contains("/identities/link"));
        assert!(html.contains("Profile"));
        assert!(html.contains("Identities"));
        assert!(html.contains("Sessions"));
        assert!(html.contains("Applications"));
        assert!(html.contains("Example User"));
        assert!(html.contains("google-user"));
    }

    #[test]
    fn clients_admin_html_contains_management_surfaces_without_token() {
        let mut state =
            ClientsAdminUiState::new("https://id.example.com").with_product_name("Zeroth");
        state.clients.push(ClientAdminUi {
            client_id: "wavey-ios".to_owned(),
            name: "Wavey iOS".to_owned(),
            confidential: false,
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: Vec::new(),
            allowed_email_domains: Vec::new(),
            disabled: false,
            has_secret: false,
        });
        state.providers.push(ProviderAdminUi {
            id: well_known::APPLE.to_owned(),
            label: "Apple".to_owned(),
            kind: "oidc".to_owned(),
            enabled: true,
            client_id_configured: true,
            client_secret_configured: true,
            client_id_binding: "APPLE_CLIENT_ID".to_owned(),
            secret_binding_sets: vec![vec![
                "APPLE_TEAM_ID".to_owned(),
                "APPLE_KEY_ID".to_owned(),
                "APPLE_PRIVATE_KEY".to_owned(),
            ]],
            callback_url: "https://id.example.com/oauth2/callback".to_owned(),
            web_domain: Some("id.example.com".to_owned()),
            notes: Vec::new(),
        });
        state.users.push(UserAdminUi {
            user_id: "usr_123".to_owned(),
            email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            disabled: false,
            admin: true,
            identity_count: 1,
            active_session_count: 1,
            created_at: Some("1780000000".to_owned()),
            updated_at: Some("1780000100".to_owned()),
        });
        state.events.push(EventAdminUi {
            event_id: "evt_123".to_owned(),
            event_type: "session.login".to_owned(),
            user_id: Some("usr_123".to_owned()),
            client_id: Some("wavey-ios".to_owned()),
            provider_id: Some(well_known::APPLE.to_owned()),
            created_at: Some("1780000200".to_owned()),
            details: Some(r#"{"mode":"hosted"}"#.to_owned()),
        });

        let html = render_clients_admin_html(state);

        assert!(html.contains("Admin token"));
        assert!(html.contains("Sign in"));
        assert!(html.contains(
            "https://id.example.com/login?return_to=https%3A%2F%2Fid.example.com%2Fadmin"
        ));
        assert!(html.contains("Providers"));
        assert!(html.contains("Database"));
        assert!(html.contains("zeroth-db-status-rows"));
        assert!(html.contains("Users"));
        assert!(html.contains("Events"));
        assert!(html.contains("zeroth-events-filter-form"));
        assert!(html.contains("Event type"));
        assert!(html.contains("Provider ID"));
        assert!(html.contains("Registered clients"));
        assert!(html.contains("Client editor"));
        assert!(html.contains("Apple"));
        assert!(html.contains("usr_123"));
        assert!(html.contains("session.login"));
        assert!(html.contains("wavey-ios"));
        assert!(html.contains("wavey://auth/callback"));
        assert!(!html.contains("super-secret-admin-token"));
    }

    #[test]
    fn clients_admin_document_includes_client_management_script() {
        let document = render_clients_admin_document(
            ClientsAdminUiState::new("https://id.example.com").with_product_name("Zeroth"),
        );

        assert!(document.contains("zeroth.adminToken"));
        assert!(document.contains("fetch(path"));
        assert!(document.contains("loadAdmin().catch"));
        assert!(document.contains("/__zeroth/db/status"));
        assert!(document.contains("allowError"));
        assert!(document.contains("Database setup incomplete"));
        assert!(document.contains("renderDbStatus"));
        assert!(document.contains("/clients"));
        assert!(document.contains("/users"));
        assert!(document.contains("/providers/status"));
        assert!(document.contains("/events"));
        assert!(document.contains("URLSearchParams"));
        assert!(document.contains("event_type"));
    }

    #[test]
    fn clients_admin_state_builds_hosted_login_url() {
        let state = ClientsAdminUiState::new("https://id.example.com/");

        assert_eq!(
            state.admin_login_url,
            "https://id.example.com/login?return_to=https%3A%2F%2Fid.example.com%2Fadmin"
        );

        let state = ClientsAdminUiState::new("https://id.example.com")
            .with_admin_login_url("https://id.example.com/login?return_to=custom");
        assert_eq!(
            state.admin_login_url,
            "https://id.example.com/login?return_to=custom"
        );
    }

    fn query(url: &Url, key: &str) -> Option<String> {
        url.query_pairs()
            .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
    }
}
