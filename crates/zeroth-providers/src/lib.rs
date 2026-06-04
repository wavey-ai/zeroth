//! Upstream provider adapters for Zeroth.
//!
//! Providers are responsible for constructing upstream OAuth authorization and
//! token-exchange requests, then normalizing upstream identity into Zeroth's
//! internal profile shape. Network I/O is intentionally left to the server or
//! Worker layer so this crate stays portable.

use url::Url;
use zeroth_core::{ProviderId, Subject};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConfig {
    pub id: ProviderId,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub profile_endpoint: Option<String>,
    pub default_scopes: Vec<String>,
    pub response_mode: Option<String>,
    pub token_auth: TokenAuth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenAuth {
    None,
    ClientSecretPost,
    AppleClientSecretJwt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAuthorizeRequest<'a> {
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub nonce: Option<&'a str>,
    pub code_challenge: Option<&'a str>,
    pub scopes: Option<&'a [&'a str]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAuthorization {
    pub url: String,
    pub state: String,
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenExchangeRequest {
    pub endpoint: String,
    pub params: Vec<(String, String)>,
    pub token_auth: TokenAuth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderTokenSet {
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderProfileSource {
    OidcClaims {
        sub: String,
        email: Option<String>,
        email_verified: bool,
        name: Option<String>,
        picture: Option<String>,
    },
    SpotifyProfile {
        id: String,
        email: Option<String>,
        display_name: Option<String>,
        image_url: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProfile {
    pub provider_id: ProviderId,
    pub subject: Subject,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderError {
    pub code: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthProvider {
    config: ProviderConfig,
}

pub trait Provider {
    fn id(&self) -> &ProviderId;

    fn authorize_url(
        &self,
        request: ProviderAuthorizeRequest<'_>,
    ) -> Result<ProviderAuthorization, ProviderError>;

    fn token_exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
        client_secret: Option<&str>,
    ) -> Result<TokenExchangeRequest, ProviderError>;

    fn normalize_profile(
        &self,
        source: ProviderProfileSource,
    ) -> Result<ProviderProfile, ProviderError>;
}

impl OAuthProvider {
    pub fn new(config: ProviderConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    pub fn google(client_id: impl Into<String>) -> Self {
        Self::new(ProviderConfig {
            id: ProviderId(well_known::GOOGLE.to_owned()),
            client_id: client_id.into(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_owned(),
            profile_endpoint: None,
            default_scopes: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
            response_mode: None,
            token_auth: TokenAuth::ClientSecretPost,
        })
    }

    pub fn apple(client_id: impl Into<String>) -> Self {
        Self::new(ProviderConfig {
            id: ProviderId(well_known::APPLE.to_owned()),
            client_id: client_id.into(),
            authorization_endpoint: "https://appleid.apple.com/auth/authorize".to_owned(),
            token_endpoint: "https://appleid.apple.com/auth/token".to_owned(),
            profile_endpoint: None,
            default_scopes: vec!["email".to_owned(), "name".to_owned()],
            response_mode: Some("form_post".to_owned()),
            token_auth: TokenAuth::AppleClientSecretJwt,
        })
    }

    pub fn spotify(client_id: impl Into<String>) -> Self {
        Self::new(ProviderConfig {
            id: ProviderId(well_known::SPOTIFY.to_owned()),
            client_id: client_id.into(),
            authorization_endpoint: "https://accounts.spotify.com/authorize".to_owned(),
            token_endpoint: "https://accounts.spotify.com/api/token".to_owned(),
            profile_endpoint: Some("https://api.spotify.com/v1/me".to_owned()),
            default_scopes: vec!["user-read-email".to_owned(), "user-read-private".to_owned()],
            response_mode: None,
            token_auth: TokenAuth::ClientSecretPost,
        })
    }
}

impl Provider for OAuthProvider {
    fn id(&self) -> &ProviderId {
        &self.config.id
    }

    fn authorize_url(
        &self,
        request: ProviderAuthorizeRequest<'_>,
    ) -> Result<ProviderAuthorization, ProviderError> {
        let mut url = Url::parse(&self.config.authorization_endpoint)
            .map_err(|_| ProviderError::invalid_config("authorization_endpoint is not a URL"))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", "code");
            pairs.append_pair("client_id", &self.config.client_id);
            pairs.append_pair("redirect_uri", request.redirect_uri);
            pairs.append_pair("state", request.state);
            pairs.append_pair("scope", &self.scope_string(request.scopes));
            if let Some(nonce) = request.nonce {
                pairs.append_pair("nonce", nonce);
            }
            if let Some(code_challenge) = request.code_challenge {
                pairs.append_pair("code_challenge", code_challenge);
                pairs.append_pair("code_challenge_method", "S256");
            }
            if let Some(response_mode) = &self.config.response_mode {
                pairs.append_pair("response_mode", response_mode);
            }
        }

        Ok(ProviderAuthorization {
            url: url.to_string(),
            state: request.state.to_owned(),
            nonce: request.nonce.map(str::to_owned),
        })
    }

    fn token_exchange_request(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
        client_secret: Option<&str>,
    ) -> Result<TokenExchangeRequest, ProviderError> {
        let mut params = vec![
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("client_id".to_owned(), self.config.client_id.clone()),
            ("code".to_owned(), code.to_owned()),
            ("redirect_uri".to_owned(), redirect_uri.to_owned()),
        ];

        if let Some(code_verifier) = code_verifier {
            params.push(("code_verifier".to_owned(), code_verifier.to_owned()));
        }

        if matches!(
            self.config.token_auth,
            TokenAuth::ClientSecretPost | TokenAuth::AppleClientSecretJwt
        ) {
            let client_secret = client_secret.ok_or_else(|| {
                ProviderError::invalid_request("provider token exchange requires client_secret")
            })?;
            params.push(("client_secret".to_owned(), client_secret.to_owned()));
        }

        Ok(TokenExchangeRequest {
            endpoint: self.config.token_endpoint.clone(),
            params,
            token_auth: self.config.token_auth.clone(),
        })
    }

    fn normalize_profile(
        &self,
        source: ProviderProfileSource,
    ) -> Result<ProviderProfile, ProviderError> {
        match source {
            ProviderProfileSource::OidcClaims {
                sub,
                email,
                email_verified,
                name,
                picture,
            } => Ok(ProviderProfile {
                provider_id: self.config.id.clone(),
                subject: Subject(sub),
                email,
                email_verified,
                display_name: name,
                picture_url: picture,
            }),
            ProviderProfileSource::SpotifyProfile {
                id,
                email,
                display_name,
                image_url,
            } => {
                if self.config.id.0 != well_known::SPOTIFY {
                    return Err(ProviderError::invalid_request(
                        "spotify profile source used with non-spotify provider",
                    ));
                }
                Ok(ProviderProfile {
                    provider_id: self.config.id.clone(),
                    subject: Subject(id),
                    email,
                    email_verified: false,
                    display_name,
                    picture_url: image_url,
                })
            }
        }
    }
}

impl OAuthProvider {
    fn scope_string(&self, scopes: Option<&[&str]>) -> String {
        scopes
            .map(|scopes| scopes.iter().map(|scope| (*scope).to_owned()).collect())
            .unwrap_or_else(|| self.config.default_scopes.clone())
            .join(" ")
    }
}

impl ProviderError {
    pub fn invalid_config(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_provider_config".to_owned(),
            description: description.into(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_provider_request".to_owned(),
            description: description.into(),
        }
    }
}

pub mod well_known {
    pub const APPLE: &str = "apple";
    pub const GOOGLE: &str = "google";
    pub const SPOTIFY: &str = "spotify";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_authorize_url_uses_oidc_pkce() {
        let provider = OAuthProvider::google("google-client");
        let auth = provider
            .authorize_url(ProviderAuthorizeRequest {
                redirect_uri: "https://id.example.com/oauth2/callback",
                state: "state-1",
                nonce: Some("nonce-1"),
                code_challenge: Some("challenge-1"),
                scopes: None,
            })
            .unwrap();

        let url = Url::parse(&auth.url).unwrap();
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        assert_eq!(param(&url, "response_type"), Some("code".to_owned()));
        assert_eq!(param(&url, "client_id"), Some("google-client".to_owned()));
        assert_eq!(
            param(&url, "scope"),
            Some("openid email profile".to_owned())
        );
        assert_eq!(
            param(&url, "code_challenge_method"),
            Some("S256".to_owned())
        );
    }

    #[test]
    fn apple_authorize_url_requests_form_post() {
        let provider = OAuthProvider::apple("apple-service-id");
        let auth = provider
            .authorize_url(ProviderAuthorizeRequest {
                redirect_uri: "https://id.example.com/oauth2/callback",
                state: "state-1",
                nonce: None,
                code_challenge: None,
                scopes: None,
            })
            .unwrap();

        let url = Url::parse(&auth.url).unwrap();
        assert_eq!(url.host_str(), Some("appleid.apple.com"));
        assert_eq!(param(&url, "response_mode"), Some("form_post".to_owned()));
        assert_eq!(param(&url, "scope"), Some("email name".to_owned()));
    }

    #[test]
    fn spotify_normalizes_profile() {
        let provider = OAuthProvider::spotify("spotify-client");
        let profile = provider
            .normalize_profile(ProviderProfileSource::SpotifyProfile {
                id: "spotify-user".to_owned(),
                email: Some("user@example.com".to_owned()),
                display_name: Some("Example User".to_owned()),
                image_url: Some("https://i.scdn.co/image/example".to_owned()),
            })
            .unwrap();

        assert_eq!(profile.provider_id.0, "spotify");
        assert_eq!(profile.subject.0, "spotify-user");
        assert!(!profile.email_verified);
    }

    fn param(url: &Url, name: &str) -> Option<String> {
        url.query_pairs()
            .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
    }
}
