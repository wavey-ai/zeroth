use zeroth_ui::{render_account_document, ProviderUi, ZerothUiConfig, ZerothUiState};

fn main() {
    let mut config = ZerothUiConfig::new("https://id.yl.vin", "yl-web", "https://yl.vin/admin/");
    config.provider_authorize_path = "/login".to_owned();
    config.return_to = Some("https://yl.vin/admin/".to_owned());
    config.link_identities = false;

    let mut state = ZerothUiState::new(config).with_product_name("YL.VIN");
    state.providers = vec![ProviderUi::apple(false)];

    print!("{}", render_account_document(state));
}
