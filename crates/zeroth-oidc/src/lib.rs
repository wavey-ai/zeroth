//! OIDC protocol surface for Zeroth.

use url::Url;
use zeroth_core::{Client, ClientId, ScopeSet, UserId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcIssuer {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scope: ScopeSet,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub prompt: AuthorizationPrompt,
    pub max_age: Option<i32>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<PkceChallengeMethod>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequestError {
    pub code: &'static str,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PkceChallengeMethod {
    Plain,
    S256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum AuthorizationPrompt {
    #[default]
    Default,
    None,
    Login,
    Consent,
    SelectAccount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenRequest {
    pub grant_type: GrantType,
    pub client_id: ClientId,
    pub redirect_uri: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserInfo {
    pub sub: String,
    pub user_id: UserId,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
}

impl OidcIssuer {
    pub fn from_base_url(base_url: impl AsRef<str>) -> Self {
        let base_url = base_url.as_ref().trim_end_matches('/');
        Self {
            issuer: base_url.to_owned(),
            authorization_endpoint: format!("{base_url}/authorize"),
            token_endpoint: format!("{base_url}/oauth/token"),
            userinfo_endpoint: format!("{base_url}/userinfo"),
            jwks_uri: format!("{base_url}/.well-known/jwks.json"),
        }
    }

    pub fn provider_callback_endpoint(&self) -> String {
        format!("{}/oauth2/callback", self.issuer)
    }
}

pub fn parse_authorization_request(
    url: &Url,
) -> Result<AuthorizationRequest, AuthorizationRequestError> {
    let response_type = required_query_param(url, "response_type")?;
    if response_type != "code" {
        return Err(AuthorizationRequestError::invalid_request(
            "response_type must be code",
        ));
    }
    if let Some(response_mode) = query_param(url, "response_mode") {
        validate_response_mode(&response_mode)?;
    }

    let scope = query_param(url, "scope").unwrap_or_else(|| "openid profile email".to_owned());
    let scope = ScopeSet::new(scope.split_whitespace());
    if !scope.contains("openid") {
        return Err(AuthorizationRequestError::invalid_scope(
            "scope must include openid",
        ));
    }

    let code_challenge = query_param(url, "code_challenge");
    let code_challenge_method = match query_param(url, "code_challenge_method").as_deref() {
        Some("plain") => Some(PkceChallengeMethod::Plain),
        Some("S256") => Some(PkceChallengeMethod::S256),
        Some(_) => {
            return Err(AuthorizationRequestError::invalid_request(
                "code_challenge_method must be S256",
            ))
        }
        None => None,
    };
    let prompt = match query_param(url, "prompt") {
        Some(prompt) => parse_prompt(&prompt)?,
        None => AuthorizationPrompt::Default,
    };
    let max_age = match query_param(url, "max_age") {
        Some(max_age) => Some(parse_max_age(&max_age)?),
        None => None,
    };

    Ok(AuthorizationRequest {
        client_id: ClientId(required_query_param(url, "client_id")?),
        redirect_uri: required_query_param(url, "redirect_uri")?,
        scope,
        state: query_param(url, "state"),
        nonce: query_param(url, "nonce"),
        prompt,
        max_age,
        code_challenge,
        code_challenge_method,
    })
}

pub fn validate_authorization_request_for_client(
    request: &AuthorizationRequest,
    client: &Client,
) -> Result<(), AuthorizationRequestError> {
    if request.client_id != client.id {
        return Err(AuthorizationRequestError::unauthorized_client(
            "client_id does not match registered client",
        ));
    }

    if !redirect_uri_registered_for_client(&request.redirect_uri, client) {
        return Err(AuthorizationRequestError::invalid_request(
            "redirect_uri is not registered for this client",
        ));
    }

    if let Some(method) = &request.code_challenge_method {
        if method != &PkceChallengeMethod::S256 {
            return Err(AuthorizationRequestError::invalid_request(
                "code_challenge_method must be S256",
            ));
        }
    }

    if request.code_challenge.is_some() && request.code_challenge_method.is_none() {
        return Err(AuthorizationRequestError::invalid_request(
            "code_challenge_method is required when code_challenge is present",
        ));
    }

    if !client.confidential && request.code_challenge.is_none() {
        return Err(AuthorizationRequestError::invalid_request(
            "public clients must use PKCE",
        ));
    }

    Ok(())
}

pub fn authorization_request_redirect_uri_registered_for_client(
    request: &AuthorizationRequest,
    client: &Client,
) -> bool {
    request.client_id == client.id
        && redirect_uri_registered_for_client(&request.redirect_uri, client)
}

fn redirect_uri_registered_for_client(request_uri: &str, client: &Client) -> bool {
    client.redirect_uris.iter().any(|registered_uri| {
        registered_uri == request_uri || loopback_redirect_uri_matches(registered_uri, request_uri)
    })
}

fn loopback_redirect_uri_matches(registered_uri: &str, request_uri: &str) -> bool {
    let Ok(registered) = Url::parse(registered_uri) else {
        return false;
    };
    let Ok(requested) = Url::parse(request_uri) else {
        return false;
    };

    registered.scheme() == "http"
        && requested.scheme() == "http"
        && loopback_host(registered.host_str())
        && loopback_host(requested.host_str())
        && registered.host_str() == requested.host_str()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
        && match registered.port() {
            Some(port) => requested.port() == Some(port),
            None => requested.port().is_some(),
        }
}

fn loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

impl AuthorizationRequestError {
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            description: description.into(),
        }
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_scope",
            description: description.into(),
        }
    }

    pub fn unauthorized_client(description: impl Into<String>) -> Self {
        Self {
            code: "unauthorized_client",
            description: description.into(),
        }
    }
}

impl PkceChallengeMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }
}

impl AuthorizationPrompt {
    pub fn allows_session_reuse(&self) -> bool {
        !matches!(self, Self::Login | Self::SelectAccount)
    }
}

fn parse_prompt(raw: &str) -> Result<AuthorizationPrompt, AuthorizationRequestError> {
    let values = raw.split_whitespace().collect::<Vec<_>>();
    if values.is_empty() {
        return Err(AuthorizationRequestError::invalid_request(
            "prompt must not be empty",
        ));
    }
    if values.contains(&"none") {
        if values.len() == 1 {
            return Ok(AuthorizationPrompt::None);
        }
        return Err(AuthorizationRequestError::invalid_request(
            "prompt none cannot be combined with other values",
        ));
    }
    if values.iter().any(|value| *value == "login") {
        return Ok(AuthorizationPrompt::Login);
    }
    if !values
        .iter()
        .all(|value| matches!(*value, "consent" | "select_account"))
    {
        return Err(AuthorizationRequestError::invalid_request(
            "prompt must be none, login, consent, or select_account",
        ));
    }
    if values.iter().any(|value| *value == "select_account") {
        return Ok(AuthorizationPrompt::SelectAccount);
    }
    Ok(AuthorizationPrompt::Consent)
}

fn parse_max_age(raw: &str) -> Result<i32, AuthorizationRequestError> {
    let max_age = raw.parse::<i64>().map_err(|_| {
        AuthorizationRequestError::invalid_request("max_age must be a non-negative integer")
    })?;
    if max_age < 0 || max_age > i32::MAX as i64 {
        return Err(AuthorizationRequestError::invalid_request(
            "max_age must be a non-negative integer",
        ));
    }
    Ok(max_age as i32)
}

fn validate_response_mode(raw: &str) -> Result<(), AuthorizationRequestError> {
    if raw == "query" {
        return Ok(());
    }
    Err(AuthorizationRequestError::invalid_request(
        "response_mode must be query",
    ))
}

fn required_query_param(url: &Url, name: &str) -> Result<String, AuthorizationRequestError> {
    query_param(url, name).ok_or_else(|| {
        AuthorizationRequestError::invalid_request(format!(
            "missing required query parameter: {name}"
        ))
    })
}

fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroth_core::ClientId;

    #[test]
    fn parses_authorization_code_request_with_pkce() {
        let url = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid%20email&state=app-state&nonce=n&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();

        let request = parse_authorization_request(&url).unwrap();

        assert_eq!(request.client_id, ClientId("ios".to_owned()));
        assert_eq!(request.redirect_uri, "wavey://auth/callback");
        assert!(request.scope.contains("openid"));
        assert_eq!(request.state, Some("app-state".to_owned()));
        assert_eq!(request.prompt, AuthorizationPrompt::Default);
        assert_eq!(request.max_age, None);
        assert_eq!(
            request.code_challenge_method,
            Some(PkceChallengeMethod::S256)
        );
    }

    #[test]
    fn accepts_explicit_query_response_mode() {
        let url = Url::parse(
            "https://id.example.com/authorize?response_type=code&response_mode=query&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();

        parse_authorization_request(&url).unwrap();
    }

    #[test]
    fn rejects_unsupported_response_mode() {
        for response_mode in ["fragment", "form_post", ""] {
            let url = Url::parse(&format!(
                "https://id.example.com/authorize?response_type=code&response_mode={response_mode}&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&code_challenge=abc&code_challenge_method=S256"
            ))
            .unwrap();

            let error = parse_authorization_request(&url).unwrap_err();

            assert_eq!(error.code, "invalid_request");
            assert_eq!(error.description, "response_mode must be query");
        }
    }

    #[test]
    fn parses_prompt_none_for_silent_sso() {
        let url = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&prompt=none&max_age=0&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();

        let request = parse_authorization_request(&url).unwrap();

        assert_eq!(request.prompt, AuthorizationPrompt::None);
        assert_eq!(request.max_age, Some(0));
    }

    #[test]
    fn parses_interactive_prompt_values() {
        let consent = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&prompt=consent&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();
        let select_account = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&prompt=select_account&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();
        let combined = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&prompt=consent%20select_account&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();

        assert_eq!(
            parse_authorization_request(&consent).unwrap().prompt,
            AuthorizationPrompt::Consent
        );
        assert_eq!(
            parse_authorization_request(&select_account).unwrap().prompt,
            AuthorizationPrompt::SelectAccount
        );
        assert_eq!(
            parse_authorization_request(&combined).unwrap().prompt,
            AuthorizationPrompt::SelectAccount
        );
    }

    #[test]
    fn rejects_invalid_max_age_values() {
        for max_age in ["-1", "abc", "2147483648"] {
            let url = Url::parse(&format!(
                "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&max_age={max_age}&code_challenge=abc&code_challenge_method=S256"
            ))
            .unwrap();

            let error = parse_authorization_request(&url).unwrap_err();

            assert_eq!(error.code, "invalid_request");
            assert_eq!(error.description, "max_age must be a non-negative integer");
        }
    }

    #[test]
    fn rejects_prompt_none_combined_with_interactive_values() {
        let url = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=ios&redirect_uri=wavey://auth/callback&scope=openid&prompt=none%20login&code_challenge=abc&code_challenge_method=S256",
        )
        .unwrap();

        let error = parse_authorization_request(&url).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "prompt none cannot be combined with other values"
        );
    }

    #[test]
    fn defaults_scope_to_openid_profile_email() {
        let url = Url::parse(
            "https://id.example.com/authorize?response_type=code&client_id=web&redirect_uri=https://app.example.com/callback",
        )
        .unwrap();

        let request = parse_authorization_request(&url).unwrap();

        assert!(request.scope.contains("openid"));
        assert!(request.scope.contains("profile"));
        assert!(request.scope.contains("email"));
    }

    #[test]
    fn public_clients_must_use_s256_pkce() {
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: ScopeSet::new(["openid"]),
            state: None,
            nonce: None,
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let client = Client {
            id: ClientId("ios".to_owned()),
            name: "iOS".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let error = validate_authorization_request_for_client(&request, &client).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.description, "public clients must use PKCE");
    }

    #[test]
    fn native_loopback_redirect_allows_ephemeral_port() {
        let request = AuthorizationRequest {
            client_id: ClientId("infidelity-macos".to_owned()),
            redirect_uri: "http://localhost:49231/oidc-callback".to_owned(),
            scope: ScopeSet::new(["openid"]),
            state: None,
            nonce: None,
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        };
        let client = Client {
            id: ClientId("infidelity-macos".to_owned()),
            name: "Infidelity macOS".to_owned(),
            redirect_uris: vec!["http://localhost/oidc-callback".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec![],
            confidential: false,
        };

        validate_authorization_request_for_client(&request, &client).unwrap();
        assert!(authorization_request_redirect_uri_registered_for_client(
            &request, &client
        ));
    }

    #[test]
    fn native_loopback_redirect_keeps_host_and_path_bounded() {
        let client = Client {
            id: ClientId("infidelity-macos".to_owned()),
            name: "Infidelity macOS".to_owned(),
            redirect_uris: vec!["http://localhost/oidc-callback".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec![],
            confidential: false,
        };

        for redirect_uri in [
            "http://127.0.0.1:49231/oidc-callback",
            "http://localhost:49231/other",
            "https://localhost:49231/oidc-callback",
            "http://localhost.evil.test:49231/oidc-callback",
        ] {
            let request = AuthorizationRequest {
                client_id: ClientId("infidelity-macos".to_owned()),
                redirect_uri: redirect_uri.to_owned(),
                scope: ScopeSet::new(["openid"]),
                state: None,
                nonce: None,
                prompt: AuthorizationPrompt::Default,
                max_age: None,
                code_challenge: Some("challenge".to_owned()),
                code_challenge_method: Some(PkceChallengeMethod::S256),
            };

            let error = validate_authorization_request_for_client(&request, &client).unwrap_err();
            assert!(!authorization_request_redirect_uri_registered_for_client(
                &request, &client
            ));
            assert_eq!(error.code, "invalid_request");
            assert_eq!(
                error.description,
                "redirect_uri is not registered for this client"
            );
        }
    }
}
