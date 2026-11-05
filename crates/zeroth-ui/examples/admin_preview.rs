//! Local, non-production fixture for reviewing administration layouts.
use zeroth_ui::{
    render_clients_admin_document, render_tenants_admin_document, ClientAdminUi,
    ClientsAdminUiState, EventAdminUi, ProviderAdminUi, TenantAdminUi, TenantAuditReaderUi,
    UserAdminUi,
};

fn main() {
    let mut state = ClientsAdminUiState::new("https://id.example.com")
        .with_csrf_token(Some("preview-csrf".to_owned()));
    state.tenants = vec![
        TenantAdminUi {
            id: "acme".into(),
            name: "Acme Corporation".into(),
            disabled: false,
            client_ids: vec!["acme-portal".into()],
            audit_readers: vec![TenantAuditReaderUi {
                user_id: "usr_morgan".into(),
                can_export: true,
            }],
            enterprise_provider: Some("entra".into()),
            entra_tenant_id: Some("8f00f3d0-00a1-4b33-8c17-12c34567d890".into()),
            google_workspace_domains: vec![],
            oidc_client_id: None,
            client_secret_binding: None,
            connection_configured: false,
            created_at: Some("1793836800".into()),
            updated_at: Some("1793836800".into()),
            retention_days: Some(365),
        },
        TenantAdminUi {
            id: "northstar".into(),
            name: "Northstar Studio".into(),
            disabled: false,
            client_ids: vec![],
            audit_readers: vec![],
            enterprise_provider: Some("google_workspace".into()),
            entra_tenant_id: None,
            google_workspace_domains: vec!["northstar.example".into()],
            oidc_client_id: None,
            client_secret_binding: None,
            connection_configured: false,
            created_at: Some("1793836800".into()),
            updated_at: Some("1793836800".into()),
            retention_days: None,
        },
    ];
    state.clients = vec![ClientAdminUi {
        client_id: "acme-portal".into(),
        name: "Acme employee portal".into(),
        confidential: true,
        redirect_uris: vec!["https://portal.acme.example/callback".into()],
        allowed_origins: vec!["https://portal.acme.example".into()],
        allowed_email_domains: vec!["acme.example".into()],
        enterprise_provider: Some("entra".into()),
        issuer_token_audience: None,
        issuer_token_ttl_seconds: None,
        account_sharing_mode: "tenant".into(),
        account_tenant_id: "acme".into(),
        account_namespace: "tenant:acme".into(),
        visible_login_methods: vec![],
        disabled: false,
        has_secret: true,
    }];
    for (id, name, email, disabled, admin) in [
        (
            "usr_morgan",
            "Morgan Chen",
            "morgan@acme.example",
            false,
            true,
        ),
        (
            "usr_samira",
            "Samira Patel",
            "samira@acme.example",
            false,
            false,
        ),
        (
            "usr_alex",
            "Alex Rivera",
            "alex@northstar.example",
            true,
            false,
        ),
    ] {
        state.users.push(UserAdminUi {
            user_id: id.into(),
            email: Some(email.into()),
            display_name: Some(name.into()),
            disabled,
            admin,
            identity_count: 1,
            active_session_count: if disabled { 0 } else { 2 },
            created_at: Some("1793750400".into()),
            updated_at: Some("1793871000".into()),
        });
    }
    state.events.push(EventAdminUi {
        event_id: "evt_preview".into(),
        event_type: "tenant.update".into(),
        user_id: Some("usr_morgan".into()),
        client_id: None,
        provider_id: Some("entra".into()),
        created_at: Some("1793871000".into()),
        details: Some("{\"changedFields\":[\"name\"]}".into()),
    });
    state.providers.push(ProviderAdminUi {
        id: "entra".into(),
        label: "Microsoft Entra".into(),
        kind: "oidc".into(),
        enabled: false,
        client_id_configured: false,
        client_secret_configured: false,
        client_id_binding: "ENTRA_CLIENT_ID".into(),
        secret_binding_sets: vec![vec!["ENTRA_CLIENT_SECRET".into()]],
        callback_url: "https://id.example.com/oauth2/callback".into(),
        web_domain: None,
        notes: vec!["Awaiting deployment credentials".into()],
        activation_requirements: vec![],
        last_failure: None,
    });
    let document = if std::env::args().any(|arg| arg == "tenants") {
        render_tenants_admin_document(state)
    } else {
        render_clients_admin_document(state)
    };
    print!("{document}");
}
