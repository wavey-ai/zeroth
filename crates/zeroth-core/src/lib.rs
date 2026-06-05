//! Core domain model for Zeroth.

use std::fmt;
use std::time::SystemTime;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserId(pub String);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientId(pub String);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProviderId(pub String);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Subject(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub id: UserId,
    pub primary_email: Option<String>,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
    pub created_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub provider_id: ProviderId,
    pub subject: Subject,
    pub user_id: UserId,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    pub id: ClientId,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub confidential: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: String,
    pub user_id: UserId,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationCodeGrant {
    pub code: String,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub user_id: UserId,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub expires_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthTransaction {
    pub provider_state: String,
    pub client_id: ClientId,
    pub provider_id: ProviderId,
    pub redirect_uri: String,
    pub provider_redirect_uri: String,
    pub app_state: Option<String>,
    pub nonce: Option<String>,
    pub provider_nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub scope: ScopeSet,
    pub link_user_id: Option<UserId>,
    pub link_session_id: Option<String>,
    pub session_return_to: Option<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshTokenGrant {
    pub token_id: String,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub expires_at: SystemTime,
    pub revoked_at: Option<SystemTime>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeSet {
    scopes: Vec<String>,
}

impl ScopeSet {
    pub fn new(scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.scopes.iter().any(|candidate| candidate == scope)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.scopes
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
