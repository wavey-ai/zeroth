//! OIDC protocol surface for Zeroth.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::ecdsa::{
    signature::Verifier as _, Signature as Es256Signature, VerifyingKey as Es256VerifyingKey,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{form_urlencoded, Url};
use zeroth_core::{Client, ClientId, ScopeSet, UserId};

pub const PKCE_CODE_VERIFIER_MIN_LEN: usize = 43;
pub const PKCE_CODE_VERIFIER_MAX_LEN: usize = 128;

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
pub struct RelyingPartyAuthorizationRequest {
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scope: ScopeSet,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub prompt: AuthorizationPrompt,
    pub max_age: Option<i32>,
    pub code_challenge: String,
    pub provider: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequestError {
    pub code: &'static str,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationResponseError {
    pub code: &'static str,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationResponse {
    Code(AuthorizationCodeResponse),
    Error(AuthorizationErrorResponse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationCodeResponse {
    pub code: String,
    pub state: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub state: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkceVerifierError {
    pub description: &'static str,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "id_token")]
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    #[serde(rename = "token_type")]
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZerothJwks {
    pub keys: Vec<ZerothJwk>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZerothJwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub alg: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZerothJwtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub token_use: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZerothIssuedAccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub client_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothTokenValidation {
    pub issuer: String,
    pub audience: Option<String>,
    pub token_use: ZerothTokenUse,
    pub nonce: Option<String>,
    pub now: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZerothTokenUse {
    Access,
    Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothTokenError {
    pub code: &'static str,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothProtectedPath {
    pub pattern: ZerothPathPattern,
    pub allowed_roles: Vec<String>,
    pub required_scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZerothPathPattern {
    Exact(String),
    Prefix(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZerothPathAuthorizationError {
    pub code: &'static str,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct SignedJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
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

impl RelyingPartyAuthorizationRequest {
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        code_challenge: impl Into<String>,
    ) -> Self {
        Self {
            client_id: ClientId(client_id.into()),
            redirect_uri: redirect_uri.into(),
            scope: ScopeSet::new(["openid", "profile", "email"]),
            state: None,
            nonce: None,
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: code_challenge.into(),
            provider: None,
        }
    }

    pub fn with_scope(mut self, scope: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scope = ScopeSet::new(scope);
        self
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    pub fn with_prompt(mut self, prompt: AuthorizationPrompt) -> Self {
        self.prompt = prompt;
        self
    }

    pub fn with_max_age(mut self, max_age: i32) -> Self {
        self.max_age = Some(max_age);
        self
    }
}

impl TokenRequest {
    pub fn authorization_code(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        code: impl Into<String>,
        code_verifier: impl Into<String>,
    ) -> Self {
        Self {
            grant_type: GrantType::AuthorizationCode,
            client_id: ClientId(client_id.into()),
            redirect_uri: Some(redirect_uri.into()),
            code: Some(code.into()),
            code_verifier: Some(code_verifier.into()),
            refresh_token: None,
        }
    }

    pub fn refresh_token(client_id: impl Into<String>, refresh_token: impl Into<String>) -> Self {
        Self {
            grant_type: GrantType::RefreshToken,
            client_id: ClientId(client_id.into()),
            redirect_uri: None,
            code: None,
            code_verifier: None,
            refresh_token: Some(refresh_token.into()),
        }
    }

    pub fn to_form_urlencoded(&self) -> String {
        token_request_form(self)
    }
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        }
    }
}

pub fn relying_party_authorization_url(
    issuer: &OidcIssuer,
    request: &RelyingPartyAuthorizationRequest,
) -> Result<Url, AuthorizationRequestError> {
    validate_pkce_code_challenge(&request.code_challenge)?;
    if let Some(max_age) = request.max_age {
        if max_age < 0 {
            return Err(AuthorizationRequestError::invalid_request(
                "max_age must be a non-negative integer",
            ));
        }
    }

    let mut url = Url::parse(&issuer.authorization_endpoint).map_err(|error| {
        AuthorizationRequestError::invalid_request(format!(
            "invalid authorization endpoint: {error}"
        ))
    })?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", &request.client_id.0);
        pairs.append_pair("redirect_uri", &request.redirect_uri);
        pairs.append_pair("scope", &request.scope.as_slice().join(" "));
        pairs.append_pair("code_challenge", &request.code_challenge);
        pairs.append_pair("code_challenge_method", PkceChallengeMethod::S256.as_str());
        if let Some(state) = &request.state {
            pairs.append_pair("state", state);
        }
        if let Some(nonce) = &request.nonce {
            pairs.append_pair("nonce", nonce);
        }
        if let Some(provider) = &request.provider {
            pairs.append_pair("provider", provider);
        }
        if !matches!(request.prompt, AuthorizationPrompt::Default) {
            pairs.append_pair("prompt", request.prompt.as_str());
        }
        if let Some(max_age) = request.max_age {
            pairs.append_pair("max_age", &max_age.to_string());
        }
    }
    Ok(url)
}

pub fn parse_authorization_response(
    url: &Url,
    expected_issuer: Option<&str>,
    expected_state: Option<&str>,
) -> Result<AuthorizationResponse, AuthorizationResponseError> {
    let state = query_param(url, "state");
    validate_authorization_response_state(state.as_deref(), expected_state)?;
    let issuer = query_param(url, "iss");
    validate_authorization_response_issuer(issuer.as_deref(), expected_issuer)?;

    if let Some(error) = query_param(url, "error") {
        if error.is_empty() {
            return Err(AuthorizationResponseError::invalid_response(
                "authorization error code must not be empty",
            ));
        }
        return Ok(AuthorizationResponse::Error(AuthorizationErrorResponse {
            error,
            error_description: query_param(url, "error_description"),
            state,
            issuer,
        }));
    }

    let code = query_param(url, "code").ok_or_else(|| {
        AuthorizationResponseError::invalid_response(
            "authorization response must include code or error",
        )
    })?;
    if code.is_empty() {
        return Err(AuthorizationResponseError::invalid_response(
            "authorization code must not be empty",
        ));
    }
    Ok(AuthorizationResponse::Code(AuthorizationCodeResponse {
        code,
        state,
        issuer,
    }))
}

pub fn token_request_form(request: &TokenRequest) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", request.grant_type.as_str());
    serializer.append_pair("client_id", &request.client_id.0);
    if let Some(redirect_uri) = &request.redirect_uri {
        serializer.append_pair("redirect_uri", redirect_uri);
    }
    if let Some(code) = &request.code {
        serializer.append_pair("code", code);
    }
    if let Some(code_verifier) = &request.code_verifier {
        serializer.append_pair("code_verifier", code_verifier);
    }
    if let Some(refresh_token) = &request.refresh_token {
        serializer.append_pair("refresh_token", refresh_token);
    }
    serializer.finish()
}

pub fn validate_pkce_code_verifier(code_verifier: &str) -> Result<(), PkceVerifierError> {
    let len = code_verifier.len();
    if !(PKCE_CODE_VERIFIER_MIN_LEN..=PKCE_CODE_VERIFIER_MAX_LEN).contains(&len) {
        return Err(PkceVerifierError {
            description: "code_verifier must be 43 to 128 characters",
        });
    }
    if !code_verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(PkceVerifierError {
            description: "code_verifier contains unsupported characters",
        });
    }
    Ok(())
}

pub fn pkce_s256_challenge(code_verifier: &str) -> Result<String, PkceVerifierError> {
    validate_pkce_code_verifier(code_verifier)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes())))
}

impl ZerothTokenValidation {
    pub fn access_token(issuer: impl Into<String>, audience: impl Into<String>, now: i64) -> Self {
        Self {
            issuer: issuer.into(),
            audience: Some(audience.into()),
            token_use: ZerothTokenUse::Access,
            nonce: None,
            now,
        }
    }

    pub fn id_token(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        nonce: impl Into<String>,
        now: i64,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: Some(audience.into()),
            token_use: ZerothTokenUse::Id,
            nonce: Some(nonce.into()),
            now,
        }
    }

    pub fn id_token_without_nonce(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        now: i64,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: Some(audience.into()),
            token_use: ZerothTokenUse::Id,
            nonce: None,
            now,
        }
    }

    pub fn issuer_token(issuer: impl Into<String>, token_use: ZerothTokenUse, now: i64) -> Self {
        Self {
            issuer: issuer.into(),
            audience: None,
            token_use,
            nonce: None,
            now,
        }
    }
}

impl ZerothTokenUse {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Id => "id",
        }
    }
}

impl ZerothTokenError {
    pub fn invalid_token(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_token",
            description: description.into(),
        }
    }

    pub fn invalid_key(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_key",
            description: description.into(),
        }
    }
}

impl ZerothProtectedPath {
    pub fn exact(path: impl Into<String>) -> Self {
        Self {
            pattern: ZerothPathPattern::Exact(path.into()),
            allowed_roles: Vec::new(),
            required_scopes: Vec::new(),
        }
    }

    pub fn prefix(path_prefix: impl Into<String>) -> Self {
        Self {
            pattern: ZerothPathPattern::Prefix(path_prefix.into()),
            allowed_roles: Vec::new(),
            required_scopes: Vec::new(),
        }
    }

    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allowed_roles = roles.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.required_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    pub fn matches(&self, path: &str) -> bool {
        self.pattern.matches(path)
    }

    pub fn authorize(&self, claims: &ZerothJwtClaims) -> Result<(), ZerothPathAuthorizationError> {
        if !self.allowed_roles.is_empty()
            && !self
                .allowed_roles
                .iter()
                .any(|role| zeroth_claims_have_role(claims, role))
        {
            return Err(ZerothPathAuthorizationError {
                code: "missing_role",
                description: "Zeroth token did not include an accepted role".to_owned(),
            });
        }

        for scope in &self.required_scopes {
            if !zeroth_claims_have_scope(claims, scope) {
                return Err(ZerothPathAuthorizationError {
                    code: "missing_scope",
                    description: format!("Zeroth token did not include required scope: {scope}"),
                });
            }
        }

        Ok(())
    }
}

impl ZerothPathPattern {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(expected) => path == expected,
            Self::Prefix(prefix) => path_prefix_matches(prefix, path),
        }
    }
}

pub fn matching_protected_path<'a>(
    path: &str,
    protected_paths: &'a [ZerothProtectedPath],
) -> Option<&'a ZerothProtectedPath> {
    protected_paths.iter().find(|rule| rule.matches(path))
}

pub fn authorize_protected_path<'a>(
    path: &str,
    protected_paths: &'a [ZerothProtectedPath],
    claims: &ZerothJwtClaims,
) -> Result<Option<&'a ZerothProtectedPath>, ZerothPathAuthorizationError> {
    let Some(rule) = matching_protected_path(path, protected_paths) else {
        return Ok(None);
    };
    rule.authorize(claims)?;
    Ok(Some(rule))
}

pub fn zeroth_claims_have_role(claims: &ZerothJwtClaims, role: &str) -> bool {
    claims.roles.iter().any(|candidate| candidate == role)
}

pub fn zeroth_claims_have_scope(claims: &ZerothJwtClaims, scope: &str) -> bool {
    claims
        .scope
        .as_deref()
        .map(|scope_claim| {
            scope_claim
                .split_whitespace()
                .any(|candidate| candidate == scope)
        })
        .unwrap_or(false)
}

fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return false;
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .map(|remaining| remaining.starts_with('/'))
            .unwrap_or(false)
}

pub fn verify_zeroth_access_token(
    token: &str,
    jwks: &ZerothJwks,
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<ZerothJwtClaims, ZerothTokenError> {
    let validation = ZerothTokenValidation::access_token(issuer, audience, now);
    let claims = verify_zeroth_signed_token(
        token,
        jwks,
        &validation,
    )?;
    validate_zeroth_claims(&claims, &validation)?;
    Ok(claims)
}

pub fn verify_zeroth_id_token(
    token: &str,
    jwks: &ZerothJwks,
    issuer: &str,
    audience: &str,
    expected_nonce: Option<&str>,
    now: i64,
) -> Result<ZerothJwtClaims, ZerothTokenError> {
    let mut validation = ZerothTokenValidation::id_token_without_nonce(issuer, audience, now);
    validation.nonce = expected_nonce.map(ToOwned::to_owned);
    let claims = verify_zeroth_signed_token(token, jwks, &validation)?;
    validate_zeroth_claims(&claims, &validation)?;
    Ok(claims)
}

pub fn verify_zeroth_issued_access_token(
    token: &str,
    jwks: &ZerothJwks,
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<ZerothIssuedAccessTokenClaims, ZerothTokenError> {
    let claims = verify_zeroth_signed_token(
        token,
        jwks,
        &ZerothTokenValidation::access_token(issuer, audience, now),
    )?;
    validate_zeroth_issued_access_token_claims(&claims, issuer, audience, now)?;
    Ok(claims)
}

pub fn verify_zeroth_token(
    token: &str,
    jwks: &ZerothJwks,
    validation: &ZerothTokenValidation,
) -> Result<ZerothJwtClaims, ZerothTokenError> {
    let claims = verify_zeroth_signed_token(token, jwks, validation)?;
    validate_zeroth_claims(&claims, validation)?;
    Ok(claims)
}

fn verify_zeroth_signed_token<T: DeserializeOwned>(
    token: &str,
    jwks: &ZerothJwks,
    _validation: &ZerothTokenValidation,
) -> Result<T, ZerothTokenError> {
    let segments = token.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(ZerothTokenError::invalid_token(
            "JWT must have three non-empty segments",
        ));
    }

    let header = decode_jwt_segment::<SignedJwtHeader>(segments[0])?;
    if header.alg != "ES256" {
        return Err(ZerothTokenError::invalid_token(format!(
            "unsupported JWT alg: {}",
            header.alg
        )));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| ZerothTokenError::invalid_token("JWT kid is missing"))?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or_else(|| ZerothTokenError::invalid_token("JWT kid did not match JWKS"))?;
    let verifying_key = es256_verifying_key_from_jwk(key)?;

    let signature_bytes = decode_jwt_segment_bytes(segments[2])?;
    let signature = Es256Signature::try_from(signature_bytes.as_slice()).map_err(|error| {
        ZerothTokenError::invalid_token(format!("invalid ES256 signature: {error}"))
    })?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| ZerothTokenError::invalid_token("JWT signature did not verify"))?;

    let claims = decode_jwt_segment::<T>(segments[1])?;
    Ok(claims)
}

pub fn validate_zeroth_jwks(jwks: &ZerothJwks) -> Result<(), ZerothTokenError> {
    if jwks.keys.is_empty() {
        return Err(ZerothTokenError::invalid_key(
            "JWKS must include at least one key",
        ));
    }
    for key in &jwks.keys {
        validate_zeroth_jwk(key)?;
    }
    Ok(())
}

fn validate_zeroth_claims(
    claims: &ZerothJwtClaims,
    validation: &ZerothTokenValidation,
) -> Result<(), ZerothTokenError> {
    if claims.iss != validation.issuer {
        return Err(ZerothTokenError::invalid_token(
            "JWT issuer did not match expected Zeroth issuer",
        ));
    }
    if let Some(audience) = &validation.audience {
        if claims.aud != *audience {
            return Err(ZerothTokenError::invalid_token(
                "JWT audience did not match expected client",
            ));
        }
    } else if claims.aud.is_empty() {
        return Err(ZerothTokenError::invalid_token("JWT audience is empty"));
    }
    if claims.exp <= validation.now {
        return Err(ZerothTokenError::invalid_token("JWT has expired"));
    }
    if claims.token_use != validation.token_use.as_str() {
        return Err(ZerothTokenError::invalid_token(format!(
            "JWT token_use was not {}",
            validation.token_use.as_str()
        )));
    }
    if claims.sub.is_empty() {
        return Err(ZerothTokenError::invalid_token("JWT subject is empty"));
    }
    match validation.token_use {
        ZerothTokenUse::Access => {
            if claims.client_id.as_deref() != Some(&claims.aud) {
                return Err(ZerothTokenError::invalid_token(
                    "access token client_id did not match audience",
                ));
            }
        }
        ZerothTokenUse::Id => {
            if let Some(expected_nonce) = &validation.nonce {
                if claims.nonce.as_deref() != Some(expected_nonce) {
                    return Err(ZerothTokenError::invalid_token(
                        "ID token nonce did not match",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_zeroth_issued_access_token_claims(
    claims: &ZerothIssuedAccessTokenClaims,
    issuer: &str,
    audience: &str,
    now: i64,
) -> Result<(), ZerothTokenError> {
    if claims.iss != issuer {
        return Err(ZerothTokenError::invalid_token(
            "JWT issuer did not match expected Zeroth issuer",
        ));
    }
    if claims.aud != audience {
        return Err(ZerothTokenError::invalid_token(
            "JWT audience did not match expected issuer token audience",
        ));
    }
    if claims.exp <= now {
        return Err(ZerothTokenError::invalid_token("JWT has expired"));
    }
    if claims.exp <= claims.iat {
        return Err(ZerothTokenError::invalid_token(
            "JWT expiry must be after issued-at",
        ));
    }
    if claims.sub.is_empty() {
        return Err(ZerothTokenError::invalid_token("JWT subject is empty"));
    }
    if claims.client_id.is_empty() {
        return Err(ZerothTokenError::invalid_token("JWT client_id is empty"));
    }
    if claims.jti.is_empty() {
        return Err(ZerothTokenError::invalid_token("JWT jti is empty"));
    }
    Ok(())
}

fn es256_verifying_key_from_jwk(key: &ZerothJwk) -> Result<Es256VerifyingKey, ZerothTokenError> {
    validate_zeroth_jwk(key)?;
    let x = decode_public_jwk_coordinate(&key.x, "x")?;
    let y = decode_public_jwk_coordinate(&key.y, "y")?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    Es256VerifyingKey::from_sec1_bytes(&point).map_err(|error| {
        ZerothTokenError::invalid_key(format!("invalid ES256 public key {}: {error}", key.kid))
    })
}

fn validate_zeroth_jwk(key: &ZerothJwk) -> Result<(), ZerothTokenError> {
    if key.kty != "EC" {
        return Err(ZerothTokenError::invalid_key("JWKS key kty must be EC"));
    }
    if key.key_use != "sig" {
        return Err(ZerothTokenError::invalid_key("JWKS key use must be sig"));
    }
    if key.alg != "ES256" {
        return Err(ZerothTokenError::invalid_key("JWKS key alg must be ES256"));
    }
    if key.crv != "P-256" {
        return Err(ZerothTokenError::invalid_key("JWKS key crv must be P-256"));
    }
    if key.kid.trim().is_empty() {
        return Err(ZerothTokenError::invalid_key("JWKS key kid is missing"));
    }
    decode_public_jwk_coordinate(&key.x, "x")?;
    decode_public_jwk_coordinate(&key.y, "y")?;
    Ok(())
}

fn decode_public_jwk_coordinate(
    value: &str,
    field_name: &str,
) -> Result<Vec<u8>, ZerothTokenError> {
    decode_base64url(value)
        .map_err(|error| {
            ZerothTokenError::invalid_key(format!(
                "JWKS key {field_name} must be base64url: {error}"
            ))
        })
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(ZerothTokenError::invalid_key(format!(
                    "JWKS key {field_name} must decode to 32 bytes"
                )))
            }
        })
}

fn decode_jwt_segment<T: serde::de::DeserializeOwned>(
    segment: &str,
) -> Result<T, ZerothTokenError> {
    let bytes = decode_jwt_segment_bytes(segment)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ZerothTokenError::invalid_token(format!("invalid JWT JSON: {error}")))
}

fn decode_jwt_segment_bytes(segment: &str) -> Result<Vec<u8>, ZerothTokenError> {
    decode_base64url(segment).map_err(|error| {
        ZerothTokenError::invalid_token(format!("invalid JWT base64url segment: {error}"))
    })
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
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

impl AuthorizationResponseError {
    pub fn invalid_response(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_response",
            description: description.into(),
        }
    }

    pub fn invalid_state(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_state",
            description: description.into(),
        }
    }

    pub fn invalid_issuer(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_issuer",
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
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "",
            Self::None => "none",
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
        }
    }

    pub fn allows_session_reuse(&self) -> bool {
        !matches!(self, Self::Login | Self::SelectAccount)
    }
}

fn validate_pkce_code_challenge(code_challenge: &str) -> Result<(), AuthorizationRequestError> {
    let len = code_challenge.len();
    if !(PKCE_CODE_VERIFIER_MIN_LEN..=PKCE_CODE_VERIFIER_MAX_LEN).contains(&len) {
        return Err(AuthorizationRequestError::invalid_request(
            "code_challenge must be 43 to 128 characters",
        ));
    }
    if !code_challenge
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(AuthorizationRequestError::invalid_request(
            "code_challenge contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_authorization_response_state(
    actual: Option<&str>,
    expected: Option<&str>,
) -> Result<(), AuthorizationResponseError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if actual == Some(expected) {
        return Ok(());
    }
    Err(AuthorizationResponseError::invalid_state(
        "authorization response state did not match",
    ))
}

fn validate_authorization_response_issuer(
    actual: Option<&str>,
    expected: Option<&str>,
) -> Result<(), AuthorizationResponseError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let Some(actual) = actual else {
        return Err(AuthorizationResponseError::invalid_issuer(
            "authorization response issuer is missing",
        ));
    };
    if actual == expected {
        return Ok(());
    }
    Err(AuthorizationResponseError::invalid_issuer(
        "authorization response issuer did not match",
    ))
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
    use p256::ecdsa::{signature::Signer as _, Signature as TestSignature, SigningKey};
    use zeroth_core::ClientId;

    #[test]
    fn pkce_s256_challenge_matches_rfc7636_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let challenge = pkce_s256_challenge(verifier).unwrap();

        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn pkce_verifier_validation_is_bounded_and_unreserved() {
        let short = "short";
        let invalid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!";

        assert_eq!(
            pkce_s256_challenge(short).unwrap_err().description,
            "code_verifier must be 43 to 128 characters"
        );
        assert_eq!(
            pkce_s256_challenge(invalid).unwrap_err().description,
            "code_verifier contains unsupported characters"
        );
    }

    #[test]
    fn relying_party_authorization_url_builds_public_pkce_request() {
        let issuer = OidcIssuer::from_base_url("https://id.example.com/");
        let request = RelyingPartyAuthorizationRequest::new(
            "wavey-browser",
            "https://wavey.ai/auth/callback",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .with_state("state-1")
        .with_nonce("nonce-1")
        .with_provider("google")
        .with_prompt(AuthorizationPrompt::Login)
        .with_max_age(0);

        let url = relying_party_authorization_url(&issuer, &request).unwrap();

        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://id.example.com/authorize")
        );
        assert_eq!(query_param(&url, "response_type"), Some("code".to_owned()));
        assert_eq!(
            query_param(&url, "client_id"),
            Some("wavey-browser".to_owned())
        );
        assert_eq!(
            query_param(&url, "redirect_uri"),
            Some("https://wavey.ai/auth/callback".to_owned())
        );
        assert_eq!(
            query_param(&url, "scope"),
            Some("openid profile email".to_owned())
        );
        assert_eq!(
            query_param(&url, "code_challenge"),
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned())
        );
        assert_eq!(
            query_param(&url, "code_challenge_method"),
            Some("S256".to_owned())
        );
        assert_eq!(query_param(&url, "state"), Some("state-1".to_owned()));
        assert_eq!(query_param(&url, "nonce"), Some("nonce-1".to_owned()));
        assert_eq!(query_param(&url, "provider"), Some("google".to_owned()));
        assert_eq!(query_param(&url, "prompt"), Some("login".to_owned()));
        assert_eq!(query_param(&url, "max_age"), Some("0".to_owned()));
    }

    #[test]
    fn authorization_response_validates_state_and_issuer() {
        let url = Url::parse(
            "https://wavey.ai/auth/callback?code=code-1&state=state-1&iss=https%3A%2F%2Fid.example.com",
        )
        .unwrap();

        let response =
            parse_authorization_response(&url, Some("https://id.example.com"), Some("state-1"))
                .unwrap();

        assert_eq!(
            response,
            AuthorizationResponse::Code(AuthorizationCodeResponse {
                code: "code-1".to_owned(),
                state: Some("state-1".to_owned()),
                issuer: Some("https://id.example.com".to_owned())
            })
        );
    }

    #[test]
    fn authorization_response_preserves_error_response() {
        let url = Url::parse(
            "https://wavey.ai/auth/callback?error=login_required&error_description=No%20session&state=state-1&iss=https%3A%2F%2Fid.example.com",
        )
        .unwrap();

        let response =
            parse_authorization_response(&url, Some("https://id.example.com"), Some("state-1"))
                .unwrap();

        assert_eq!(
            response,
            AuthorizationResponse::Error(AuthorizationErrorResponse {
                error: "login_required".to_owned(),
                error_description: Some("No session".to_owned()),
                state: Some("state-1".to_owned()),
                issuer: Some("https://id.example.com".to_owned())
            })
        );
    }

    #[test]
    fn authorization_response_rejects_state_or_issuer_mismatch() {
        let url = Url::parse(
            "https://wavey.ai/auth/callback?code=code-1&state=state-1&iss=https%3A%2F%2Fid.example.com",
        )
        .unwrap();

        let state_error =
            parse_authorization_response(&url, Some("https://id.example.com"), Some("other"))
                .unwrap_err();
        let issuer_error =
            parse_authorization_response(&url, Some("https://id.other"), Some("state-1"))
                .unwrap_err();

        assert_eq!(state_error.code, "invalid_state");
        assert_eq!(
            state_error.description,
            "authorization response state did not match"
        );
        assert_eq!(issuer_error.code, "invalid_issuer");
        assert_eq!(
            issuer_error.description,
            "authorization response issuer did not match"
        );
    }

    #[test]
    fn token_request_form_encodes_code_and_refresh_grants() {
        let code = TokenRequest::authorization_code(
            "wavey-browser",
            "https://wavey.ai/auth/callback",
            "code-1",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )
        .to_form_urlencoded();
        let refresh =
            TokenRequest::refresh_token("wavey-browser", "refresh-1").to_form_urlencoded();

        let code_pairs = form_urlencoded::parse(code.as_bytes()).collect::<Vec<_>>();
        let refresh_pairs = form_urlencoded::parse(refresh.as_bytes()).collect::<Vec<_>>();

        assert!(code_pairs.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(code_pairs.contains(&("client_id".into(), "wavey-browser".into())));
        assert!(code_pairs.contains(&(
            "redirect_uri".into(),
            "https://wavey.ai/auth/callback".into()
        )));
        assert!(code_pairs.contains(&("code".into(), "code-1".into())));
        assert!(code_pairs.contains(&(
            "code_verifier".into(),
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into()
        )));
        assert!(refresh_pairs.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(refresh_pairs.contains(&("client_id".into(), "wavey-browser".into())));
        assert!(refresh_pairs.contains(&("refresh_token".into(), "refresh-1".into())));
    }

    #[test]
    fn token_response_deserializes_oidc_json() {
        let response: TokenResponse = serde_json::from_str(
            r#"{
              "access_token": "access-1",
              "id_token": "id-1",
              "refresh_token": "refresh-1",
              "expires_in": 3600,
              "token_type": "Bearer"
            }"#,
        )
        .unwrap();

        assert_eq!(response.access_token, "access-1");
        assert_eq!(response.id_token, "id-1");
        assert_eq!(response.refresh_token, Some("refresh-1".to_owned()));
        assert_eq!(response.expires_in, 3600);
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.scope, None);
    }

    #[test]
    fn zeroth_access_token_verifier_accepts_es256_jwks() {
        let signing_key = test_signing_key();
        let jwks = test_jwks(&signing_key, "test-key");
        let claims = access_token_claims(1_780_000_100);
        let token = signed_test_token(&signing_key, "test-key", &claims);

        let verified = verify_zeroth_access_token(
            &token,
            &jwks,
            "https://id.example.com",
            "wavey-browser",
            1_780_000_200,
        )
        .unwrap();

        assert_eq!(verified.sub, "usr_123");
        assert_eq!(verified.scope, Some("openid profile email".to_owned()));
        assert_eq!(verified.client_id, Some("wavey-browser".to_owned()));
    }

    #[test]
    fn zeroth_access_token_verifier_rejects_wrong_use_audience_and_expiry() {
        let signing_key = test_signing_key();
        let jwks = test_jwks(&signing_key, "test-key");
        let mut id_claims = access_token_claims(1_780_000_100);
        id_claims.token_use = "id".to_owned();
        id_claims.client_id = None;
        let id_token = signed_test_token(&signing_key, "test-key", &id_claims);
        let wrong_audience = signed_test_token(
            &signing_key,
            "test-key",
            &access_token_claims(1_780_000_100),
        );
        let expired = signed_test_token(
            &signing_key,
            "test-key",
            &access_token_claims(1_780_000_100),
        );

        let use_error = verify_zeroth_access_token(
            &id_token,
            &jwks,
            "https://id.example.com",
            "wavey-browser",
            1_780_000_200,
        )
        .unwrap_err();
        let aud_error = verify_zeroth_access_token(
            &wrong_audience,
            &jwks,
            "https://id.example.com",
            "other-client",
            1_780_000_200,
        )
        .unwrap_err();
        let expired_error = verify_zeroth_access_token(
            &expired,
            &jwks,
            "https://id.example.com",
            "wavey-browser",
            1_780_004_000,
        )
        .unwrap_err();

        assert_eq!(use_error.description, "JWT token_use was not access");
        assert_eq!(
            aud_error.description,
            "JWT audience did not match expected client"
        );
        assert_eq!(expired_error.description, "JWT has expired");
    }

    #[test]
    fn zeroth_issued_access_token_verifier_accepts_es256_jwks() {
        let signing_key = test_signing_key();
        let jwks = test_jwks(&signing_key, "test-key");
        let claims = issued_access_token_claims(1_780_000_100);
        let token = signed_test_token(&signing_key, "test-key", &claims);

        let verified = verify_zeroth_issued_access_token(
            &token,
            &jwks,
            "https://id.example.com",
            "yl-record-issuer",
            1_780_000_200,
        )
        .unwrap();

        assert_eq!(verified.iss, "https://id.example.com");
        assert_eq!(verified.sub, "usr_123");
        assert_eq!(verified.aud, "yl-record-issuer");
        assert_eq!(verified.client_id, "yl-web");
        assert_eq!(verified.jti, "jti-123");
        assert_eq!(verified.exp - verified.iat, 300);
    }

    #[test]
    fn zeroth_id_token_verifier_checks_nonce() {
        let signing_key = test_signing_key();
        let jwks = test_jwks(&signing_key, "test-key");
        let claims = id_token_claims(1_780_000_100);
        let token = signed_test_token(&signing_key, "test-key", &claims);

        let verified = verify_zeroth_id_token(
            &token,
            &jwks,
            "https://id.example.com",
            "wavey-browser",
            Some("nonce-1"),
            1_780_000_200,
        )
        .unwrap();
        let nonce_error = verify_zeroth_id_token(
            &token,
            &jwks,
            "https://id.example.com",
            "wavey-browser",
            Some("other-nonce"),
            1_780_000_200,
        )
        .unwrap_err();

        assert_eq!(verified.token_use, "id");
        assert_eq!(verified.email, Some("user@example.com".to_owned()));
        assert_eq!(nonce_error.description, "ID token nonce did not match");
    }

    #[test]
    fn zeroth_token_verifier_can_defer_audience_check_to_issuer() {
        let signing_key = test_signing_key();
        let jwks = test_jwks(&signing_key, "test-key");
        let claims = access_token_claims(1_780_000_100);
        let token = signed_test_token(&signing_key, "test-key", &claims);

        let verified = verify_zeroth_token(
            &token,
            &jwks,
            &ZerothTokenValidation::issuer_token(
                "https://id.example.com",
                ZerothTokenUse::Access,
                1_780_000_200,
            ),
        )
        .unwrap();

        assert_eq!(verified.aud, "wavey-browser");
        assert_eq!(verified.client_id, Some("wavey-browser".to_owned()));
    }

    #[test]
    fn protected_path_matching_supports_multiple_exact_and_prefix_rules() {
        let rules = vec![
            ZerothProtectedPath::exact("/account"),
            ZerothProtectedPath::prefix("/admin").with_roles(["admin"]),
            ZerothProtectedPath::prefix("/api/private").with_scopes(["email"]),
        ];

        assert_eq!(
            matching_protected_path("/account", &rules).unwrap().pattern,
            ZerothPathPattern::Exact("/account".to_owned())
        );
        assert_eq!(
            matching_protected_path("/admin/users", &rules)
                .unwrap()
                .pattern,
            ZerothPathPattern::Prefix("/admin".to_owned())
        );
        assert!(matching_protected_path("/administrator", &rules).is_none());
        assert!(matching_protected_path("/public", &rules).is_none());
    }

    #[test]
    fn protected_path_authorization_checks_roles_and_scopes() {
        let mut claims = access_token_claims(1_780_000_100);
        claims.roles = vec!["user".to_owned(), "admin".to_owned()];
        let rules = vec![
            ZerothProtectedPath::prefix("/admin").with_roles(["admin"]),
            ZerothProtectedPath::prefix("/api/private").with_scopes(["email"]),
        ];

        assert!(authorize_protected_path("/admin", &rules, &claims)
            .unwrap()
            .is_some());
        assert!(
            authorize_protected_path("/api/private/report", &rules, &claims)
                .unwrap()
                .is_some()
        );

        claims.roles = vec!["user".to_owned()];
        let role_error = authorize_protected_path("/admin", &rules, &claims).unwrap_err();
        assert_eq!(role_error.code, "missing_role");

        claims.scope = Some("openid profile".to_owned());
        let scope_error =
            authorize_protected_path("/api/private/report", &rules, &claims).unwrap_err();
        assert_eq!(scope_error.code, "missing_scope");
    }

    #[test]
    fn zeroth_token_verifier_rejects_bad_signature_or_key() {
        let signing_key = test_signing_key();
        let jwks = test_jwks(&signing_key, "test-key");
        let claims = access_token_claims(1_780_000_100);
        let token = token_with_bad_signature(signed_test_token(&signing_key, "test-key", &claims));
        let invalid_jwks = ZerothJwks {
            keys: vec![ZerothJwk {
                kty: "EC".to_owned(),
                key_use: "sig".to_owned(),
                kid: "test-key".to_owned(),
                alg: "ES256".to_owned(),
                crv: "P-256".to_owned(),
                x: "short".to_owned(),
                y: "short".to_owned(),
            }],
        };

        let signature_error = verify_zeroth_access_token(
            &token,
            &jwks,
            "https://id.example.com",
            "wavey-browser",
            1_780_000_200,
        )
        .unwrap_err();
        let key_error = validate_zeroth_jwks(&invalid_jwks).unwrap_err();

        assert_eq!(signature_error.code, "invalid_token");
        assert!(signature_error.description.contains("signature"));
        assert_eq!(key_error.code, "invalid_key");
        assert!(key_error.description.contains("base64url"));
    }

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

    fn test_signing_key() -> SigningKey {
        SigningKey::from_slice(&[1u8; 32]).unwrap()
    }

    fn test_jwks(signing_key: &SigningKey, kid: &str) -> ZerothJwks {
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        ZerothJwks {
            keys: vec![ZerothJwk {
                kty: "EC".to_owned(),
                key_use: "sig".to_owned(),
                kid: kid.to_owned(),
                alg: "ES256".to_owned(),
                crv: "P-256".to_owned(),
                x: URL_SAFE_NO_PAD.encode(x),
                y: URL_SAFE_NO_PAD.encode(y),
            }],
        }
    }

    fn signed_test_token<T: Serialize>(
        signing_key: &SigningKey,
        kid: &str,
        claims: &T,
    ) -> String {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": kid,
            "typ": "JWT"
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header}.{claims}");
        let signature: TestSignature = signing_key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn token_with_bad_signature(token: String) -> String {
        let mut segments = token.split('.').map(ToOwned::to_owned).collect::<Vec<_>>();
        let signature = segments.last_mut().unwrap();
        let replacement = if signature.ends_with('A') { 'B' } else { 'A' };
        signature.pop();
        signature.push(replacement);
        segments.join(".")
    }

    fn access_token_claims(iat: i64) -> ZerothJwtClaims {
        ZerothJwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "wavey-browser".to_owned(),
            exp: iat + 3_600,
            iat,
            auth_time: None,
            sid: Some("ses_123".to_owned()),
            nonce: None,
            scope: Some("openid profile email".to_owned()),
            client_id: Some("wavey-browser".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
            roles: vec!["user".to_owned()],
        }
    }

    fn id_token_claims(iat: i64) -> ZerothJwtClaims {
        ZerothJwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "wavey-browser".to_owned(),
            exp: iat + 3_600,
            iat,
            auth_time: Some(iat),
            sid: Some("ses_123".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            scope: None,
            client_id: None,
            token_use: "id".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: Some(true),
            name: Some("Example User".to_owned()),
            picture: None,
            roles: vec!["user".to_owned()],
        }
    }

    fn issued_access_token_claims(iat: i64) -> ZerothIssuedAccessTokenClaims {
        ZerothIssuedAccessTokenClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "yl-record-issuer".to_owned(),
            iat,
            exp: iat + 300,
            jti: "jti-123".to_owned(),
            client_id: "yl-web".to_owned(),
        }
    }
}
