use zeroth_providers::well_known;
use zeroth_ui::{
    render_account_document, ApplicationUi, IdentityUi, ProfileUi, ProviderUi, SessionUi,
    ZerothUiConfig, ZerothUiState,
};

fn main() {
    let mut config = ZerothUiConfig::new(
        "https://id.wavey.local",
        "wavey-ios",
        "wavey://auth/callback",
    );
    config.state = Some("preview-state".to_owned());
    config.code_challenge = Some("preview-code-challenge".to_owned());
    config.csrf_token = Some("preview-csrf".to_owned());

    let mut state = ZerothUiState::new(config).with_product_name("Zeroth");
    state.providers = vec![
        ProviderUi::apple(false),
        ProviderUi::google(true),
        ProviderUi::spotify(false),
    ];
    state.profile = Some(ProfileUi {
        sub: "usr_preview".to_owned(),
        email: Some("jamie@example.com".to_owned()),
        email_verified: true,
        display_name: Some("Jamie".to_owned()),
        picture_url: None,
    });
    state.identities = vec![IdentityUi {
        provider_id: well_known::GOOGLE.to_owned(),
        provider_subject: "google-preview-subject".to_owned(),
        email: Some("jamie@example.com".to_owned()),
        email_verified: true,
        unlink_disabled: true,
    }];
    state.sessions = vec![SessionUi {
        id: "ses_preview".to_owned(),
        client_id: Some("wavey-ios".to_owned()),
        current: true,
        created_at: Some("2026-06-04T10:00:00Z".to_owned()),
        expires_at: Some("2026-06-11T10:00:00Z".to_owned()),
    }];
    state.applications = vec![
        ApplicationUi {
            client_id: "wavey-ios".to_owned(),
            name: "Wavey iOS".to_owned(),
            public_client: true,
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: Vec::new(),
            allowed_email_domains: Vec::new(),
        },
        ApplicationUi {
            client_id: "wavey-web".to_owned(),
            name: "Wavey Web".to_owned(),
            public_client: true,
            redirect_uris: vec!["https://app.wavey.local/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.wavey.local".to_owned()],
            allowed_email_domains: vec!["wavey.local".to_owned()],
        },
    ];

    print!("{}", render_account_document(state));
}
