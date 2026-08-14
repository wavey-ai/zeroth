use zeroth_ui::{
    render_account_document, ProviderUi, ZerothUiConfig, ZerothUiState, ZerothUiTheme,
};

fn main() {
    let mut config = ZerothUiConfig::new("https://id.yl.vin", "yl-web", "https://yl.vin/admin/");
    config.provider_authorize_path = "/login".to_owned();
    config.return_to = Some("https://yl.vin/admin/".to_owned());
    config.link_identities = false;

    let mut state = ZerothUiState::new(config)
        .with_product_name("YL.VIN")
        .with_theme(ZerothUiTheme {
            brand_icon: Some("https://yl.vin/appicon.png".to_owned()),
            login_style: Some("yl-vin".to_owned()),
            ..ZerothUiTheme::default()
        });
    state.providers = vec![ProviderUi::apple(false)];

    print!("{}", render_account_document(state));
}
