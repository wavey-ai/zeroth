use leptos::prelude::*;

use crate::TenantAdminUi;

/// A machine identity's public configuration. Private keys never belong in this state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceClientAdminUi {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub audiences: Vec<String>,
    pub scopes: Vec<String>,
    pub public_jwks_json: String,
    pub disabled: bool,
    pub revision: i64,
    pub token_ttl_seconds: i32,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[component]
pub(super) fn ServiceClientsAdminPanel(
    clients: Vec<ServiceClientAdminUi>,
    tenants: Vec<TenantAdminUi>,
) -> impl IntoView {
    let count = clients.len();
    let has_clients = count != 0;
    let no_tenants = !tenants.iter().any(|tenant| !tenant.disabled);
    let tenant_options = tenants
        .iter()
        .map(|tenant| {
            let name = if tenant.disabled {
                format!("{} (disabled)", tenant.name)
            } else {
                tenant.name.clone()
            };
            view! { <option value=tenant.id.clone() disabled=tenant.disabled>{name}</option> }
        })
        .collect_view();
    let filter_options = tenants
        .iter()
        .map(|tenant| view! { <option value=tenant.id.clone()>{tenant.name.clone()}</option> })
        .collect_view();
    let rows = clients
        .into_iter()
        .map(|client| {
            let tenant = tenants.iter().find(|tenant| tenant.id == client.tenant_id);
            let tenant_name = tenant
                .map(|tenant| tenant.name.clone())
                .unwrap_or_else(|| client.tenant_id.clone());
            let status = if client.disabled {
                "Disabled"
            } else if tenant.is_some_and(|tenant| tenant.disabled) {
                "Tenant disabled"
            } else {
                "Enabled"
            };
            let status_class = if status == "Enabled" {
                "zeroth-status zeroth-status-ok"
            } else {
                "zeroth-status zeroth-status-warn"
            };
            // Render identifiers only. Never embed a raw JSON document in HTML or script.
            let key_ids = public_key_ids(&client.public_jwks_json).join(", ");
            let audiences = client.audiences.join("\n");
            let scopes = client.scopes.join("\n");
            let revision = format!("Revision {} · {}s tokens", client.revision, client.token_ttl_seconds);
            view! {
                <tr data-service-client-id=client.id.clone()>
                    <td><div class="zeroth-row-title">{client.name}</div><div class="zeroth-row-meta zeroth-code">{client.id.clone()}</div></td>
                    <td><div>{tenant_name}</div><div class="zeroth-row-meta zeroth-code">{client.tenant_id}</div></td>
                    <td><span class=status_class>{status}</span><div class="zeroth-row-meta">{revision}</div></td>
                    <td class="zeroth-code zeroth-service-values">{audiences}</td>
                    <td class="zeroth-code zeroth-service-values">{scopes}</td>
                    <td class="zeroth-code zeroth-service-values">{if key_ids.is_empty() { "No valid public keys".to_owned() } else { key_ids }}</td>
                    <td class="zeroth-row-actions"><button class="zeroth-action" data-zeroth-edit-service="true" type="button">"Edit / rotate keys"</button></td>
                </tr>
            }
        })
        .collect_view();

    view! {
        <section id="service-clients" class="zeroth-panel">
            <div class="zeroth-panel-header">
                <div><h2 class="zeroth-panel-title">"Service clients"</h2><p class="zeroth-section-description">"Machine identities for services and agents. Each client belongs to one tenant and exchanges a signed assertion for a short-lived access token. No human login is involved."</p></div>
                <div class="zeroth-actions"><button class="zeroth-action zeroth-primary" id="zeroth-service-new" type="button" disabled=no_tenants>"Register service client"</button><button class="zeroth-action" id="zeroth-services-refresh" type="button">"Refresh"</button></div>
            </div>
            <div class="zeroth-panel-body zeroth-service-intro">
                <p class="zeroth-help">"Register public ES256 signing keys only. Keep private keys in the service's secret store. Audiences identify APIs; scopes limit the actions the client may request."</p>
                <div class="zeroth-field"><label for="zeroth-service-tenant-filter">"Tenant"</label><select id="zeroth-service-tenant-filter"><option value="">"All tenants"</option>{filter_options}</select></div>
                <p class="zeroth-help" id="zeroth-service-tenant-help">{if no_tenants { "Create and enable a tenant before registering a service client." } else { "Tenant ownership cannot be changed after registration." }}</p>
            </div>
            <div class="zeroth-table-scroll"><table class="zeroth-table"><thead><tr><th>"Service client"</th><th>"Tenant"</th><th>"Status"</th><th>"Allowed audiences"</th><th>"Allowed scopes"</th><th>"Signing key IDs"</th><th>"Actions"</th></tr></thead><tbody id="zeroth-service-rows">
                {rows}
                <tr id="zeroth-service-empty" hidden=has_clients><td colspan="7" class="zeroth-empty">"No service clients registered. Register a machine identity to grant a service access to tenant APIs."</td></tr>
            </tbody></table></div>
            <div class="zeroth-list-summary" id="zeroth-service-summary" role="status" aria-live="polite">{format!("{count} service clients")}</div>

            <section id="zeroth-service-editor" class="zeroth-tenant-editor" hidden=true>
                <div class="zeroth-panel-header"><h3 class="zeroth-panel-title" id="zeroth-service-editor-title">"Register service client"</h3><button class="zeroth-action" id="zeroth-service-close" type="button">"Close"</button></div>
                <div class="zeroth-panel-body">
                    <form id="zeroth-service-form" class="zeroth-settings-form">
                        <fieldset><legend>"1. Machine identity"</legend><div class="zeroth-settings-fields">
                            <div class="zeroth-field"><label for="zeroth-service-id">"Service client ID"</label><input id="zeroth-service-id" name="id" placeholder="svc_deploy_agent" pattern="svc_[A-Za-z0-9_.:\\-]+" maxlength="128" autocomplete="off" required=true /><small>"A stable ID starting with svc_. It cannot be changed after registration."</small></div>
                            <div class="zeroth-field"><label for="zeroth-service-name">"Display name"</label><input id="zeroth-service-name" name="name" maxlength="128" autocomplete="off" required=true /></div>
                            <div class="zeroth-field"><label for="zeroth-service-tenant">"Owning tenant"</label><select id="zeroth-service-tenant" name="tenantId" required=true><option value="">"Choose a tenant"</option>{tenant_options}</select><small>"Access remains within this tenant. A disabled tenant cannot issue service tokens."</small></div>
                            <div class="zeroth-field"><label for="zeroth-service-ttl">"Access token lifetime (seconds)"</label><input id="zeroth-service-ttl" name="tokenTtlSeconds" type="number" min="60" max="600" step="1" value="600" required=true /><small>"60–600 seconds. No refresh token is issued."</small></div>
                        </div></fieldset>
                        <fieldset><legend>"2. Access policy"</legend><div class="zeroth-settings-fields">
                            <div class="zeroth-field"><label for="zeroth-service-audiences">"Allowed audiences"</label><textarea id="zeroth-service-audiences" name="audiences" rows="4" maxlength="4096" spellcheck="false" placeholder="https://api.example.com/releases" required=true></textarea><small>"One audience per line. Register the exact audience expected by each API."</small></div>
                            <div class="zeroth-field"><label for="zeroth-service-scopes">"Allowed scopes"</label><textarea id="zeroth-service-scopes" name="scopes" rows="4" maxlength="8192" spellcheck="false" placeholder="releases:read\nrollouts:report" required=true></textarea><small>"One scope per line. Grant only the actions this service requires."</small></div>
                        </div></fieldset>
                        <fieldset><legend>"3. Public signing keys"</legend>
                            <div class="zeroth-field"><label for="zeroth-service-jwks">"Public JWKS"</label><textarea id="zeroth-service-jwks" name="publicJwks" class="zeroth-code zeroth-service-jwks" rows="11" maxlength="16384" spellcheck="false" autocomplete="off" required=true placeholder=r#"{"keys":[{"kid":"deploy-2026-11","kty":"EC","crv":"P-256","x":"…","y":"…","alg":"ES256","use":"sig"}]}"#></textarea><small>"1–8 public keys with distinct key IDs (kid); up to 16 KiB. Never paste a private JWK or PEM key. For rotation, add the new public key, update the service, then remove the old key."</small></div>
                        </fieldset>
                        <div class="zeroth-service-revocation"><p class="zeroth-help">"Every saved change advances the client revision. Introspection rejects tokens from earlier revisions and disabled clients. APIs that verify JWTs offline can accept an issued token until it expires; revocation is not instantaneous there."</p><label class="zeroth-checkbox-field"><input name="disabled" type="checkbox" />"Disable this service client"</label></div>
                        <div class="zeroth-form-footer"><div class="zeroth-actions"><button class="zeroth-action" id="zeroth-service-revoke" type="button" hidden=true>"Revoke issued tokens"</button><span class="zeroth-help" id="zeroth-service-revision"></span></div><div class="zeroth-form-actions"><button class="zeroth-action" id="zeroth-service-cancel" type="button">"Cancel"</button><button class="zeroth-action zeroth-primary" id="zeroth-service-save" type="submit">"Register service client"</button></div></div>
                    </form>
                </div>
            </section>
        </section>
    }
}

fn public_key_ids(json: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| value.get("keys").and_then(|keys| keys.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|key| key.get("kid").and_then(|id| id.as_str()).map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{render_service_clients_admin_document, ServiceClientsAdminUiState};

    #[test]
    fn service_client_document_selects_screen_and_escapes_untrusted_configuration() {
        let mut state = ServiceClientsAdminUiState::new("https://id.example.com")
            .with_csrf_token(Some("csrf-fixture".into()));
        state.service_clients.push(ServiceClientAdminUi {
            id: "svc_release".into(), tenant_id: "acme".into(),
            name: "<img src=x onerror=alert(1)>".into(), audiences: vec!["releases".into()],
            scopes: vec!["releases:read".into()],
            public_jwks_json: r#"{"keys":[{"kid":"<script>bad()</script>","d":"PRIVATE_MATERIAL_MUST_NOT_RENDER"}]}"#.into(),
            disabled: true, revision: 3, token_ttl_seconds: 120,
            created_at: None, updated_at: None,
        });
        let document = render_service_clients_admin_document(state);
        assert!(document.contains("data-zeroth-default-section=\"#service-clients\""));
        assert!(document
            .contains("<h1 id=\"zeroth-page-title\" class=\"zeroth-title\">Service clients</h1>"));
        assert!(document.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(document.contains("&lt;script&gt;bad()&lt;/script&gt;"));
        assert!(!document.contains("PRIVATE_MATERIAL_MUST_NOT_RENDER"));
        assert!(!document.contains("<img src=x"));
        assert!(document.contains("Revision 3 · 120s tokens"));
        assert!(document.contains("X-Zeroth-CSRF"));
        assert!(document.contains("No human login is involved"));
        assert!(document.contains("until it expires"));
    }

    #[test]
    fn service_client_empty_state_explains_tenant_prerequisite() {
        let document = render_service_clients_admin_document(ServiceClientsAdminUiState::new(
            "https://id.example.com",
        ));
        assert!(document.contains("No service clients registered"));
        assert!(document.contains("Create and enable a tenant"));
        assert!(document.contains("id=\"zeroth-service-new\" type=\"button\" disabled"));
        assert!(public_key_ids("invalid json").is_empty());
    }
}
