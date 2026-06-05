#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature, SigningKey, VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
#[cfg(any(test, not(target_arch = "wasm32")))]
use rsa::{
    pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey},
    BigUint, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroth_core::{AuthTransaction, Client, ClientId, ProviderId, ScopeSet, Subject, UserId};
use zeroth_oidc::authorization_request_redirect_uri_registered_for_client;
#[cfg(target_arch = "wasm32")]
use zeroth_oidc::parse_authorization_request;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_oidc::validate_authorization_request_for_client;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_oidc::AuthorizationPrompt;
use zeroth_oidc::{AuthorizationRequest, AuthorizationRequestError};
use zeroth_providers::well_known;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_providers::TokenAuth;
use zeroth_providers::{
    ProviderProfile, ProviderProfileSource, ProviderTokenSet, TokenExchangeRequest,
};
use zeroth_server::ZerothServerConfig;
#[cfg(target_arch = "wasm32")]
use zeroth_ui::ProviderAdminUi;
#[cfg(target_arch = "wasm32")]
use zeroth_ui::{render_account_document, ZerothUiConfig, ZerothUiState};
#[cfg(target_arch = "wasm32")]
use zeroth_ui::{render_clients_admin_document, ClientsAdminUiState};
use zeroth_ui::{
    ApplicationUi, ClientAdminUi, EventAdminUi, IdentityUi, ProfileUi, ProviderKind, ProviderUi,
    SessionUi, UserAdminUi,
};

#[cfg(target_arch = "wasm32")]
use zeroth_providers::{OAuthProvider, Provider, ProviderAuthorizeRequest};

#[cfg(target_arch = "wasm32")]
use zeroth_server::ROUTES;

pub const D1_BINDING: &str = "ZEROTH_DB";
const AUTH_TRANSACTION_TTL_SECONDS: i32 = 10 * 60;
const AUTH_CODE_TTL_SECONDS: i32 = 10 * 60;
const ACCESS_TOKEN_TTL_SECONDS: i32 = 60 * 60;
const ID_TOKEN_TTL_SECONDS: i32 = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS: i32 = 60 * 60 * 24 * 30;
const SESSION_TTL_SECONDS: i32 = 60 * 60 * 24 * 30;
const AUTH_TRANSACTION_CLEANUP_LIMIT: i32 = 64;
const CORS_ORIGIN_SCAN_LIMIT: i32 = 256;
const CLIENT_LIST_LIMIT: i32 = 256;
const CLIENT_MANAGEMENT_BODY_LIMIT: usize = 8 * 1024;
const CLIENT_ID_MAX_CHARS: usize = 128;
const CLIENT_NAME_MAX_CHARS: usize = 128;
const CLIENT_URI_MAX_BYTES: usize = 2048;
const CLIENT_URI_LIST_LIMIT: usize = 32;
const CLIENT_EMAIL_DOMAIN_MAX_BYTES: usize = 253;
const USER_LIST_LIMIT: i32 = 100;
const USER_MANAGEMENT_BODY_LIMIT: usize = 1024;
const USER_ID_MAX_CHARS: usize = 128;
const AUDIT_EVENT_LIST_LIMIT: i32 = 100;
const AUDIT_EVENT_TYPE_MAX_CHARS: usize = 96;
const AUDIT_EVENT_DETAILS_MAX_BYTES: usize = 1024;
const SESSION_LIST_LIMIT: i32 = 100;
const IDENTITY_LIST_LIMIT: i32 = 16;
const PASSKEY_CHALLENGE_TTL_SECONDS: i32 = 5 * 60;
const PASSKEY_CHALLENGE_CLEANUP_LIMIT: i32 = 64;
const PASSKEY_CREDENTIAL_LIST_LIMIT: i32 = 64;
const PASSKEY_BODY_LIMIT: usize = 16 * 1024;
const PASSKEY_LABEL_MAX_CHARS: usize = 128;
const PASSKEY_EMAIL_MAX_BYTES: usize = 320;
const PROFILE_PATCH_BODY_LIMIT: usize = 4 * 1024;
const PROFILE_NAME_MAX_CHARS: usize = 128;
const PROFILE_PICTURE_MAX_BYTES: usize = 2048;
const APPLE_CLIENT_SECRET_DEFAULT_TTL_SECONDS: i64 = 60 * 60 * 24 * 180;
const APPLE_CLIENT_SECRET_MAX_TTL_SECONDS: i64 = 60 * 60 * 24 * 180;
const APPLE_CLIENT_SECRET_CACHE_REFRESH_SECONDS: i64 = 60 * 60;
const PROVIDER_JWKS_CACHE_TTL_SECONDS: i32 = 60 * 60;
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ID_TOKEN_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
const ACCESS_TOKEN_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const DEFAULT_NATIVE_TOKEN_SCOPE: &str = "openid profile email";
const CORS_ALLOW_METHODS: &str = "GET, POST, PATCH, DELETE, OPTIONS";
const CORS_ALLOW_HEADERS: &str = "Authorization, Content-Type";
const CORS_MAX_AGE_SECONDS: &str = "600";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderResponse {
    id: &'static str,
    kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    introspection_endpoint: String,
    end_session_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    response_modes_supported: Vec<&'static str>,
    prompt_values_supported: Vec<&'static str>,
    grant_types_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
    revocation_endpoint_auth_methods_supported: Vec<&'static str>,
    introspection_endpoint_auth_methods_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
    authorization_response_iss_parameter_supported: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JwkKey {
    kty: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    alg: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Clone, Serialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    token_type: &'static str,
    expires_in: i32,
    scope: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct JwtHeader {
    alg: &'static str,
    kid: String,
    typ: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct AppleClientSecretHeader {
    alg: &'static str,
    kid: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct AppleClientSecretClaims {
    iss: String,
    iat: i64,
    exp: i64,
    aud: &'static str,
    sub: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i32,
    iat: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    token_use: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Clone)]
struct Es256SigningKey {
    kid: String,
    signing_key: SigningKey,
}

#[derive(Clone)]
struct Es256VerificationKey {
    kid: String,
    verifying_key: VerifyingKey,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct CachedSigningMaterial {
    kid: String,
    private_key: String,
    previous_public_jwks: Option<String>,
    signing_key: Es256SigningKey,
    verification_keys: Vec<Es256VerificationKey>,
    jwks: JwksResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppleClientSecretConfig {
    team_id: String,
    key_id: String,
    client_id: String,
    private_key_pem: String,
    ttl_seconds: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct CachedAppleClientSecret {
    config: AppleClientSecretConfig,
    token: String,
    expires_at: i64,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static SIGNING_MATERIAL_CACHE: RefCell<Option<CachedSigningMaterial>> = const { RefCell::new(None) };
    static APPLE_CLIENT_SECRET_CACHE: RefCell<Option<CachedAppleClientSecret>> = const { RefCell::new(None) };
    static PROVIDER_JWKS_CACHE: RefCell<ProviderJwksCache> = const {
        RefCell::new(ProviderJwksCache { entries: Vec::new() })
    };
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutesResponse {
    routes: Vec<RouteResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteResponse {
    method: &'static str,
    path: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationResponse {
    ok: bool,
    binding: &'static str,
    migrations_applied: Vec<&'static str>,
    migrations_skipped: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbSchemaStatusResponse {
    ok: bool,
    binding: &'static str,
    tables: Vec<DbTableStatus>,
    migrations: Vec<DbMigrationStatus>,
    compatibility_columns: Vec<DbCompatibilityColumnStatus>,
    client_count: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbTableStatus {
    name: &'static str,
    present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbMigrationStatus {
    version: i32,
    name: &'static str,
    applied: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbCompatibilityColumnStatus {
    table: &'static str,
    name: &'static str,
    present: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuthErrorResponse {
    error: String,
    error_description: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientRow {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    secret_hash: Option<String>,
    #[serde(default)]
    redirect_uris_json: String,
    #[serde(default)]
    allowed_origins_json: String,
    #[serde(default)]
    allowed_email_domains_json: String,
    #[serde(default)]
    confidential: i32,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientOriginsRow {
    #[serde(default)]
    allowed_origins_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientResponse {
    id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_origins: Vec<String>,
    allowed_email_domains: Vec<String>,
    confidential: bool,
    disabled: bool,
    has_secret: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientsResponse {
    clients: Vec<ClientResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderStatusResponse {
    providers: Vec<ProviderStatus>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessResponse {
    ready: bool,
    service: &'static str,
    issuer: String,
    issuer_check: ReadinessCheck,
    signing: ReadinessCheck,
    providers: Vec<ProviderReadiness>,
    apple_app_site_association: ReadinessCheck,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessCheck {
    configured: bool,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderReadiness {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    configured: bool,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderStatus {
    id: &'static str,
    label: &'static str,
    kind: &'static str,
    enabled: bool,
    client_id_configured: bool,
    client_secret_configured: bool,
    client_id_binding: &'static str,
    secret_binding_sets: Vec<Vec<&'static str>>,
    callback_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_domain: Option<String>,
    notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct ClientUpsertRequest {
    id: String,
    name: String,
    #[serde(default, alias = "redirect_uris")]
    redirect_uris: Vec<String>,
    #[serde(default, alias = "allowed_origins")]
    allowed_origins: Vec<String>,
    #[serde(default, alias = "allowed_email_domains")]
    allowed_email_domains: Vec<String>,
    #[serde(default)]
    confidential: bool,
    #[serde(default, alias = "client_secret")]
    client_secret: Option<String>,
    #[serde(default, alias = "secret_hash")]
    secret_hash: Option<String>,
    #[serde(default)]
    disabled: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ValidatedClientUpsert {
    id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_origins: Vec<String>,
    allowed_email_domains: Vec<String>,
    confidential: bool,
    secret_hash: Option<String>,
    disabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct AdminUserRow {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
    #[serde(default)]
    disabled_at: Option<i32>,
    #[serde(default)]
    email_verified: i32,
    #[serde(default)]
    admin_membership_active: i32,
    identity_count: i32,
    active_session_count: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct AdminMembershipProbeRow {
    user_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUserResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
    disabled: bool,
    admin: bool,
    identity_count: i32,
    active_session_count: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUsersResponse {
    users: Vec<AdminUserResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUserDetailResponse {
    user: AdminUserResponse,
    identities: Vec<IdentityResponse>,
    active_sessions: Vec<SessionInfoResponse>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AdminUserPatchRequest {
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    admin: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct AuditEventRow {
    id: String,
    event_type: String,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    provider_id: Option<String>,
    created_at: i32,
    #[serde(default)]
    ip_hash: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
    details_json: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventResponse {
    id: String,
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_id: Option<String>,
    created_at: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventsResponse {
    events: Vec<AuditEventResponse>,
}

#[derive(Debug, Clone, Default)]
struct AuditRequestContext {
    ip_hash: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct AuditEventFilter {
    event_type: Option<String>,
    user_id: Option<String>,
    client_id: Option<String>,
    provider_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthTransactionRow {
    provider_state: String,
    client_id: String,
    provider_id: String,
    redirect_uri: String,
    provider_redirect_uri: String,
    #[serde(default)]
    app_state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    provider_nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    scope: String,
    #[serde(default)]
    link_user_id: Option<String>,
    #[serde(default)]
    link_session_id: Option<String>,
    #[serde(default)]
    session_return_to: Option<String>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct StoredAuthTransaction {
    transaction: AuthTransaction,
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderCallback {
    state: String,
    code: Option<String>,
    provider_error: Option<ProviderCallbackError>,
    apple_user_json: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderCallbackError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ProviderTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderTokenExchangeError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SpotifyApiProfile {
    id: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    images: Vec<SpotifyApiImage>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SpotifyApiImage {
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct AppleCallbackUser {
    #[serde(default)]
    name: Option<AppleCallbackUserName>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct AppleCallbackUserName {
    #[serde(default, rename = "firstName")]
    first_name: Option<String>,
    #[serde(default, rename = "lastName")]
    last_name: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ResolvedProviderProfile {
    profile: ProviderProfile,
    raw_profile_json: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderProfileError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProfilePatch {
    display_name: Option<Option<String>>,
    picture_url: Option<Option<String>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProfilePatchError {
    description: String,
    status: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct IdentityReference {
    provider_id: String,
    provider_subject: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct IdentityLinkError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct ProviderJwksCache {
    entries: Vec<CachedProviderJwks>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct CachedProviderJwks {
    provider_id: String,
    jwks: ProviderJwksResponse,
    expires_at: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct ProviderJwksResponse {
    keys: Vec<ProviderJwk>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
struct ProviderJwk {
    kty: String,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProviderJwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProviderIdTokenClaims {
    iss: String,
    sub: String,
    aud: AudienceClaim,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ProviderIdTokenValidation<'a> {
    provider_id: &'a str,
    client_id: &'a str,
    nonce: Option<&'a str>,
    now: i32,
}

#[derive(Debug, Clone)]
struct VerifiedProviderIdToken {
    claims: ProviderIdTokenClaims,
    raw_claims_json: String,
}

#[derive(Debug, Clone, Deserialize)]
struct IdentityUserRow {
    user_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct IdentityCountRow {
    count: i32,
}

#[derive(Debug, Clone, Deserialize)]
struct TableColumnRow {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SchemaMigrationRow {
    version: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct IdentityRow {
    provider_id: String,
    provider_subject: String,
    #[serde(default)]
    email: Option<String>,
    email_verified: i32,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PasskeyCredentialRow {
    credential_id: String,
    user_id: String,
    #[serde(default)]
    label: Option<String>,
    public_key_x: String,
    public_key_y: String,
    sign_count: i32,
    created_at: i32,
    updated_at: i32,
    #[serde(default)]
    last_used_at: Option<i32>,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct PasskeyChallengeRow {
    challenge_hash: String,
    kind: String,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    label: Option<String>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterOptionsRequest {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticateOptionsRequest {
    #[serde(default)]
    return_to: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterVerifyRequest {
    id: String,
    raw_id: String,
    response: PasskeyRegisterCredentialResponse,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyRegisterCredentialResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticateVerifyRequest {
    id: String,
    raw_id: String,
    response: PasskeyAuthenticateCredentialResponse,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticateCredentialResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    #[serde(default)]
    user_handle: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: Option<bool>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyPublicKeyCredentialCreationOptions {
    challenge: String,
    rp: PasskeyRpEntity,
    user: PasskeyUserEntity,
    pub_key_cred_params: Vec<PasskeyPubKeyCredParam>,
    timeout: u32,
    authenticator_selection: PasskeyAuthenticatorSelection,
    attestation: &'static str,
    exclude_credentials: Vec<PasskeyCredentialDescriptor>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyPublicKeyCredentialRequestOptions {
    challenge: String,
    rp_id: String,
    timeout: u32,
    user_verification: &'static str,
    allow_credentials: Vec<PasskeyCredentialDescriptor>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyRpEntity {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyUserEntity {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyPubKeyCredParam {
    #[serde(rename = "type")]
    credential_type: &'static str,
    alg: i32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyAuthenticatorSelection {
    resident_key: &'static str,
    require_resident_key: bool,
    user_verification: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PasskeyCredentialDescriptor {
    #[serde(rename = "type")]
    credential_type: &'static str,
    id: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyOptionsResponse<T> {
    public_key: T,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyVerifyResponse {
    ok: bool,
    return_to: String,
    user: UserInfoResponse,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PasskeyCredentialPublicKey {
    x: Vec<u8>,
    y: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ParsedAuthenticatorData {
    rp_id_hash: Vec<u8>,
    flags: u8,
    sign_count: i32,
    credential_id: Option<Vec<u8>>,
    public_key: Option<PasskeyCredentialPublicKey>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ValidatedPasskeyRegistration {
    credential_id: String,
    public_key_x: String,
    public_key_y: String,
    sign_count: i32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum CborValue {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct AuthCodeRow {
    code_hash: String,
    client_id: String,
    redirect_uri: String,
    user_id: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    scope: String,
    #[serde(default)]
    auth_time: Option<i32>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    consumed_at: Option<i32>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenExchangeForm {
    grant_type: String,
    client_id: String,
    client_auth: ClientAuth,
    redirect_uri: Option<String>,
    code: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    provider: Option<String>,
    provider_client_id: Option<String>,
    nonce: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenRevocationForm {
    client_id: String,
    client_auth: ClientAuth,
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenIntrospectionForm {
    client_id: String,
    client_auth: ClientAuth,
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ClientAuth {
    None,
    SecretPost(String),
    SecretBasic(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ClientBasicAuth {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RegisteredClient {
    client: Client,
    secret_hash: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ClientManagementError {
    code: String,
    description: String,
    status: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenExchangeError {
    code: String,
    description: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AuthorizationCodeFields<'a> {
    client_id: &'a str,
    redirect_uri: &'a str,
    code: &'a str,
    code_verifier: Option<&'a str>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct NativeProviderTokenFields<'a> {
    provider_id: &'a str,
    scope: Option<&'a str>,
    subject_token: &'a str,
    subject_token_type: &'a str,
    provider_client_id: Option<&'a str>,
    nonce: Option<&'a str>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct RefreshTokenRow {
    token_hash: String,
    client_id: String,
    user_id: String,
    #[serde(default)]
    session_id: Option<String>,
    scope: String,
    #[serde(default)]
    auth_time: Option<i32>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    rotated_at: Option<i32>,
    #[serde(default)]
    revoked_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct SessionRow {
    id: String,
    user_id: String,
    #[serde(default)]
    client_id: Option<String>,
    created_at: i32,
    expires_at: i32,
    #[serde(default)]
    revoked_at: Option<i32>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    ip_hash: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct TokenIssue {
    client_id: String,
    user_id: String,
    session_id: Option<String>,
    scope: String,
    auth_time: Option<i32>,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct UserRow {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    #[serde(default)]
    disabled_at: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct UserTokenClaimsRow {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    picture_url: Option<String>,
    #[serde(default)]
    disabled_at: Option<i32>,
    #[serde(default)]
    email_verified: i32,
}

#[derive(Debug, Clone, Serialize)]
struct UserInfoResponse {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInfoResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    created_at: i32,
    expires_at: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionInfoResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserInfoResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionListItemResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    created_at: i32,
    expires_at: i32,
    current: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionsResponse {
    sessions: Vec<SessionListItemResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityResponse {
    provider_id: String,
    provider_subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    email_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    picture_url: Option<String>,
    created_at: i32,
    updated_at: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentitiesResponse {
    identities: Vec<IdentityResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateResponse {
    valid: bool,
    kind: &'static str,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionInfoResponse>,
    user: UserInfoResponse,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct TokenIntrospectionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_use: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
}

impl TokenIntrospectionResponse {
    fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            token_type: None,
            token_use: None,
            sub: None,
            aud: None,
            iss: None,
            iat: None,
            exp: None,
            sid: None,
        }
    }

    fn active_access_token(claims: &JwtClaims) -> Self {
        Self {
            active: true,
            scope: claims.scope.clone(),
            client_id: Some(claims.aud.clone()),
            token_type: Some("Bearer"),
            token_use: Some("access_token"),
            sub: Some(claims.sub.clone()),
            aud: Some(claims.aud.clone()),
            iss: Some(claims.iss.clone()),
            iat: Some(claims.iat),
            exp: Some(claims.exp),
            sid: claims.sid.clone(),
        }
    }

    fn active_refresh_token(row: &RefreshTokenRow) -> Self {
        Self {
            active: true,
            scope: Some(row.scope.clone()),
            client_id: Some(row.client_id.clone()),
            token_type: None,
            token_use: Some("refresh_token"),
            sub: Some(row.user_id.clone()),
            aud: Some(row.client_id.clone()),
            iss: None,
            iat: Some(row.created_at),
            exp: Some(row.expires_at),
            sid: row.session_id.clone(),
        }
    }
}

impl ProviderJwksCache {
    fn get(&mut self, provider_id: &str, now: i32) -> Option<ProviderJwksResponse> {
        self.entries.retain(|entry| entry.expires_at > now);
        self.entries
            .iter()
            .find(|entry| entry.provider_id == provider_id)
            .map(|entry| entry.jwks.clone())
    }

    fn put(&mut self, provider_id: &str, jwks: ProviderJwksResponse, now: i32) {
        let expires_at = now.saturating_add(PROVIDER_JWKS_CACHE_TTL_SECONDS);
        self.entries
            .retain(|entry| entry.provider_id != provider_id);
        self.entries.push(CachedProviderJwks {
            provider_id: provider_id.to_owned(),
            jwks,
            expires_at,
        });
    }
}

#[derive(Debug, Clone)]
struct CurrentSession {
    session: SessionRow,
    user: UserRow,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AdminAuthorization {
    BootstrapToken,
    Session { user_id: String },
}

#[cfg(target_arch = "wasm32")]
use worker::wasm_bindgen::{JsCast as _, JsValue};
#[cfg(target_arch = "wasm32")]
use worker::wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn main(request: Request, env: Env, _ctx: worker::Context) -> worker::Result<Response> {
    console_error_panic_hook::set_once();
    handle_request(request, env).await
}

#[cfg(target_arch = "wasm32")]
async fn handle_request(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;

    match (request.method(), url.path()) {
        (Method::Options, path) if cors_path(path) => cors_preflight(request, env).await,
        (Method::Get, "/") => redirect_to_path(&url, "/admin"),
        (Method::Get, "/health") => json(&HealthResponse {
            ok: true,
            service: "zeroth",
        }),
        (Method::Get, "/ready") => ready(request, env),
        (Method::Get, "/providers") => json(&vec![
            ProviderResponse {
                id: well_known::APPLE,
                kind: "oidc",
            },
            ProviderResponse {
                id: well_known::GOOGLE,
                kind: "oidc",
            },
            ProviderResponse {
                id: well_known::SPOTIFY,
                kind: "oauth2",
            },
        ]),
        (Method::Get, "/providers/status") => provider_status(request, env).await,
        (Method::Get | Method::Post | Method::Delete, "/clients") => clients(request, env).await,
        (Method::Get | Method::Patch, "/users") => users(request, env).await,
        (Method::Get, "/events") => events(request, env).await,
        (Method::Get, "/routes") => json(&RoutesResponse {
            routes: ROUTES
                .iter()
                .map(|route| RouteResponse {
                    method: route.method,
                    path: route.path,
                })
                .collect(),
        }),
        (Method::Get, "/.well-known/openid-configuration") => {
            json(&discovery_response(&server_config(&env, &url)))
        }
        (Method::Get, "/.well-known/oauth-authorization-server") => {
            json(&discovery_response(&server_config(&env, &url)))
        }
        (Method::Get, "/.well-known/jwks.json") => jwks(env),
        (Method::Get, "/.well-known/apple-app-site-association") => apple_app_site_association(env),
        (Method::Get, "/login") => hosted_login(request, env).await,
        (Method::Get, "/account") => hosted_account(request, env).await,
        (Method::Get, "/admin") => hosted_clients_admin(request, env).await,
        (Method::Get, "/admin/clients") => hosted_clients_admin(request, env).await,
        (Method::Get, "/authorize") => authorize(request, env).await,
        (Method::Get, "/__zeroth/db/status") => d1_schema_status(request, env).await,
        (Method::Post, "/__zeroth/db/ensure") => ensure_d1_schema(request, env).await,
        (Method::Get | Method::Post, "/oauth2/callback") => provider_callback(request, env).await,
        (Method::Post, "/oauth/token") => oauth_token(request, env).await,
        (Method::Post, "/oauth/revoke") => oauth_revoke(request, env).await,
        (Method::Post, "/oauth/introspect") => oauth_introspect(request, env).await,
        (Method::Get, "/userinfo") => userinfo(request, env).await,
        (Method::Get, "/session") => session(request, env).await,
        (Method::Get | Method::Delete, "/sessions") => sessions(request, env).await,
        (Method::Get | Method::Patch, "/profile") => profile(request, env).await,
        (Method::Get, "/identities/link") => identity_link(request, env).await,
        (Method::Get | Method::Delete, "/identities") => identities(request, env).await,
        (Method::Post, "/passkeys/register/options") => {
            passkey_register_options(request, env).await
        }
        (Method::Post, "/passkeys/register/verify") => passkey_register_verify(request, env).await,
        (Method::Post, "/passkeys/authenticate/options") => {
            passkey_authenticate_options(request, env).await
        }
        (Method::Post, "/passkeys/authenticate/verify") => {
            passkey_authenticate_verify(request, env).await
        }
        (Method::Get, "/validate") => validate(request, env).await,
        (Method::Get | Method::Post, "/logout") => logout(request, env).await,
        _ => json_status(&serde_json::json!({ "error": "not_found" }), 404),
    }
}

#[cfg(target_arch = "wasm32")]
async fn provider_callback(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let callback = match provider_callback_from_request(&mut request, &url).await {
        Ok(callback) => callback,
        Err(error) => return provider_callback_error_json(&error, 400),
    };

    let db = env.d1(D1_BINDING)?;
    let record = match get_auth_transaction(&db, &callback.state).await? {
        Some(record) => record,
        None => {
            return provider_callback_error_json(
                &ProviderCallbackError::invalid_request("unknown provider callback state"),
                400,
            )
        }
    };

    let now = unix_timestamp_seconds();
    if let Err(error) = validate_stored_auth_transaction(&record, now) {
        return provider_callback_error_json(&error, 400);
    }
    let transaction_cookie_state =
        transaction_state_from_request(&request, &config.transaction_cookie_name)?;
    if let Err(error) = provider_callback_state_matches_transaction_cookie(
        &callback.state,
        transaction_cookie_state.as_deref(),
    ) {
        return provider_callback_error_json(&error, 400);
    }
    if !consume_auth_transaction(&db, &callback.state, now).await? {
        return provider_callback_error_json(
            &ProviderCallbackError::invalid_request(
                "provider callback state has already been consumed",
            ),
            400,
        );
    }

    if let Some(provider_error) = callback.provider_error.as_ref() {
        record_audit_event(
            &db,
            &request,
            "provider.callback.error",
            None,
            Some(&record.transaction.client_id.0),
            Some(&record.transaction.provider_id.0),
            serde_json::json!({
                "code": &provider_error.code,
                "description": &provider_error.description
            }),
            now,
        )
        .await;
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            provider_error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }
    let Some(provider_code) = callback.code.as_deref() else {
        let response = provider_callback_error_json(
            &ProviderCallbackError::invalid_request("missing code"),
            400,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    };

    let provider = provider_from_env(&env, &record.transaction.provider_id.0)?;
    let client_secret = provider_client_secret_from_env(&env, &record.transaction.provider_id.0)?;
    let token_request = provider
        .token_exchange_request(
            provider_code,
            &record.transaction.provider_redirect_uri,
            None,
            client_secret.as_deref(),
        )
        .map_err(|error| worker::Error::RustError(error.description))?;
    let token_set = match exchange_provider_code(token_request).await {
        Ok(token_set) => token_set,
        Err(error) => {
            record_audit_event(
                &db,
                &request,
                "provider.token_exchange.failed",
                None,
                Some(&record.transaction.client_id.0),
                Some(&record.transaction.provider_id.0),
                serde_json::json!({
                    "code": &error.code,
                    "description": &error.description
                }),
                now,
            )
            .await;
            let response = provider_token_exchange_error_json(&error, 502)?;
            return with_set_cookie(
                response,
                &clear_transaction_cookie(&config.transaction_cookie_name),
            );
        }
    };
    let resolved_profile =
        match resolve_provider_profile(&provider, &token_set, &record.transaction, &callback).await
        {
            Ok(profile) => profile,
            Err(error) => {
                record_audit_event(
                    &db,
                    &request,
                    "provider.profile.failed",
                    None,
                    Some(&record.transaction.client_id.0),
                    Some(&record.transaction.provider_id.0),
                    serde_json::json!({
                        "code": &error.code,
                        "description": &error.description
                    }),
                    now,
                )
                .await;
                let response = provider_profile_error_json(&error, 502)?;
                return with_set_cookie(
                    response,
                    &clear_transaction_cookie(&config.transaction_cookie_name),
                );
            }
        };

    if let Some(link_user_id) = record.transaction.link_user_id.as_ref() {
        let link_result = complete_provider_identity_link(
            &db,
            link_user_id,
            record.transaction.link_session_id.as_deref(),
            &resolved_profile.profile,
            resolved_profile.raw_profile_json.as_deref(),
            now,
        )
        .await?;

        let response = match link_result {
            Ok(()) => {
                record_audit_event(
                    &db,
                    &request,
                    "identity.link",
                    Some(&link_user_id.0),
                    Some(&record.transaction.client_id.0),
                    Some(&resolved_profile.profile.provider_id.0),
                    serde_json::json!({}),
                    now,
                )
                .await;
                redirect_to_identity_link_return(&record.transaction, &resolved_profile.profile)
            }
            Err(error) => {
                record_audit_event(
                    &db,
                    &request,
                    "identity.link.failed",
                    Some(&link_user_id.0),
                    Some(&record.transaction.client_id.0),
                    Some(&resolved_profile.profile.provider_id.0),
                    serde_json::json!({
                        "code": &error.code,
                        "description": &error.description
                    }),
                    now,
                )
                .await;
                redirect_to_identity_link_error(&record.transaction, &error)
            }
        }?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }

    let Some(client) = get_client(&db, &record.transaction.client_id.0).await? else {
        let error = ProviderCallbackError::invalid_request("client is disabled or not found");
        record_audit_event(
            &db,
            &request,
            "client.login.denied",
            None,
            Some(&record.transaction.client_id.0),
            Some(&resolved_profile.profile.provider_id.0),
            serde_json::json!({ "reason": "client_inactive" }),
            now,
        )
        .await;
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            &error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    };
    if let Err(error) = validate_client_email_domain_policy(&client, &resolved_profile.profile) {
        record_audit_event(
            &db,
            &request,
            "client.login.denied",
            None,
            Some(&record.transaction.client_id.0),
            Some(&resolved_profile.profile.provider_id.0),
            serde_json::json!({
                "reason": "email_domain_policy",
                "emailVerified": resolved_profile.profile.email_verified
            }),
            now,
        )
        .await;
        let response = redirect_to_provider_callback_error(
            &record.transaction,
            &config.issuer().issuer,
            &error,
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }

    if record.transaction.session_return_to.is_some() {
        let user_id = upsert_provider_profile(
            &db,
            &resolved_profile.profile,
            resolved_profile.raw_profile_json.as_deref(),
            now,
        )
        .await?;
        let session_id = format!("sess_{}", random_token()?);
        let user_agent = request_header(&request, "User-Agent")?;
        let ip_hash = request_header(&request, "CF-Connecting-IP")?.map(|ip| hash_secret(&ip));
        put_session(
            &db,
            &session_id,
            &user_id,
            &record.transaction.client_id.0,
            now,
            user_agent.as_deref(),
            ip_hash.as_deref(),
        )
        .await?;
        record_audit_event(
            &db,
            &request,
            "session.login",
            Some(&user_id),
            Some(&record.transaction.client_id.0),
            Some(&resolved_profile.profile.provider_id.0),
            serde_json::json!({ "mode": "hosted" }),
            now,
        )
        .await;

        let response = redirect_to_session_login_return(&record.transaction)?;
        let response = with_set_cookie(
            response,
            &session_cookie(
                &config.cookie_name,
                &session_id,
                SESSION_TTL_SECONDS,
                config.cookie_domain.as_deref(),
            ),
        )?;
        return with_set_cookie(
            response,
            &clear_transaction_cookie(&config.transaction_cookie_name),
        );
    }

    let user_id = upsert_provider_profile(
        &db,
        &resolved_profile.profile,
        resolved_profile.raw_profile_json.as_deref(),
        now,
    )
    .await?;
    let zeroth_code = random_token()?;
    let session_id = format!("sess_{}", random_token()?);
    put_authorization_code(
        &db,
        &zeroth_code,
        &record.transaction,
        &user_id,
        Some(&session_id),
        now,
        now,
    )
    .await?;
    let user_agent = request_header(&request, "User-Agent")?;
    let ip_hash = request_header(&request, "CF-Connecting-IP")?.map(|ip| hash_secret(&ip));
    put_session(
        &db,
        &session_id,
        &user_id,
        &record.transaction.client_id.0,
        now,
        user_agent.as_deref(),
        ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        &db,
        &request,
        "authorization.code.issue",
        Some(&user_id),
        Some(&record.transaction.client_id.0),
        Some(&resolved_profile.profile.provider_id.0),
        serde_json::json!({
            "scope": record.transaction.scope.as_slice().join(" ")
        }),
        now,
    )
    .await;

    let response = redirect_to_client(&record.transaction, &config.issuer().issuer, &zeroth_code)?;
    let response = with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )?;
    with_set_cookie(
        response,
        &clear_transaction_cookie(&config.transaction_cookie_name),
    )
}

#[cfg(target_arch = "wasm32")]
async fn clients(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &request_url);
    let now = unix_timestamp_seconds();
    if let Err(error) = validate_admin_request(&request, &env, &db, &config, now).await {
        return client_management_error_json(&error);
    }

    match request.method() {
        Method::Get => {
            if let Some(client_id) = query_param(&request_url, "client_id") {
                let client_id = match validate_client_id(&client_id) {
                    Ok(client_id) => client_id,
                    Err(error) => return client_management_error_json(&error),
                };
                let Some(row) = get_client_row_for_admin(&db, &client_id).await? else {
                    return client_management_error_json(&ClientManagementError::not_found(
                        "client was not found",
                    ));
                };
                return match client_response_from_row(row) {
                    Ok(client) => json(&client),
                    Err(error) => {
                        client_management_error_json(&ClientManagementError::invalid_request(error))
                    }
                };
            }

            let rows = list_client_rows_for_admin(&db).await?;
            let clients = match rows
                .into_iter()
                .map(client_response_from_row)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(clients) => clients,
                Err(error) => {
                    return client_management_error_json(&ClientManagementError::invalid_request(
                        error,
                    ))
                }
            };
            json(&ClientsResponse { clients })
        }
        Method::Post => {
            let upsert = match client_upsert_from_request(&mut request).await {
                Ok(upsert) => upsert,
                Err(error) => return client_management_error_json(&error),
            };
            if upsert.confidential && upsert.secret_hash.is_none() {
                let existing = get_client_row_for_admin(&db, &upsert.id).await?;
                if existing.and_then(|row| row.secret_hash).is_none() {
                    return client_management_error_json(&ClientManagementError::invalid_request(
                        "confidential clients require clientSecret or secretHash",
                    ));
                }
            }

            upsert_client(&db, &upsert, now).await?;
            let row = get_client_row_for_admin(&db, &upsert.id)
                .await?
                .ok_or_else(|| {
                    worker::Error::RustError("client upsert did not return a row".to_owned())
                })?;
            record_audit_event(
                &db,
                &request,
                "client.upsert",
                None,
                Some(&upsert.id),
                None,
                serde_json::json!({
                    "confidential": upsert.confidential,
                    "disabled": upsert.disabled,
                    "redirectUriCount": upsert.redirect_uris.len(),
                    "allowedOriginCount": upsert.allowed_origins.len(),
                    "secretUpdated": upsert.secret_hash.is_some()
                }),
                now,
            )
            .await;
            match client_response_from_row(row) {
                Ok(client) => json(&client),
                Err(error) => {
                    client_management_error_json(&ClientManagementError::invalid_request(error))
                }
            }
        }
        Method::Delete => {
            let Some(client_id) = query_param(&request_url, "client_id") else {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "missing client_id",
                ));
            };
            let client_id = match validate_client_id(&client_id) {
                Ok(client_id) => client_id,
                Err(error) => return client_management_error_json(&error),
            };
            if get_client_row_for_admin(&db, &client_id).await?.is_none() {
                return client_management_error_json(&ClientManagementError::not_found(
                    "client was not found",
                ));
            }
            disable_client(&db, &client_id, now).await?;
            record_audit_event(
                &db,
                &request,
                "client.disable",
                None,
                Some(&client_id),
                None,
                serde_json::json!({}),
                now,
            )
            .await;
            json(&serde_json::json!({ "ok": true }))
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn users(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &request_url);
    let now = unix_timestamp_seconds();
    let admin_authorization = match authorize_admin_request(&request, &env, &db, &config, now).await
    {
        Ok(admin_authorization) => admin_authorization,
        Err(error) => return client_management_error_json(&error),
    };

    match request.method() {
        Method::Get => {
            if let Some(user_id) = query_param(&request_url, "user_id") {
                let user_id = match validate_admin_user_id(&user_id) {
                    Ok(user_id) => user_id,
                    Err(error) => return client_management_error_json(&error),
                };
                let Some(response) = admin_user_detail_response(&db, &user_id, now).await? else {
                    return client_management_error_json(&ClientManagementError::not_found(
                        "user was not found",
                    ));
                };
                return json(&response);
            }

            let rows = list_admin_user_rows(&db, now).await?;
            let users = rows.into_iter().map(admin_user_response_from_row).collect();
            json(&AdminUsersResponse { users })
        }
        Method::Patch => {
            let Some(user_id) = query_param(&request_url, "user_id") else {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "missing user_id",
                ));
            };
            let user_id = match validate_admin_user_id(&user_id) {
                Ok(user_id) => user_id,
                Err(error) => return client_management_error_json(&error),
            };
            if get_admin_user_row(&db, &user_id, now).await?.is_none() {
                return client_management_error_json(&ClientManagementError::not_found(
                    "user was not found",
                ));
            }
            let patch = match admin_user_patch_from_request(&mut request).await {
                Ok(patch) => patch,
                Err(error) => return client_management_error_json(&error),
            };
            if patch.disabled.is_none() && patch.admin.is_none() {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "user patch must include disabled or admin",
                ));
            }
            if matches!(
                (&admin_authorization, patch.admin),
                (AdminAuthorization::Session { user_id: current_user_id }, Some(false))
                    if current_user_id.as_str() == user_id.as_str()
            ) {
                return client_management_error_json(&ClientManagementError::invalid_request(
                    "cannot revoke the active admin session membership",
                ));
            }

            if let Some(disabled) = patch.disabled {
                set_admin_user_disabled(&db, &user_id, disabled, now).await?;
                if disabled {
                    revoke_active_sessions_for_user(&db, &user_id, now).await?;
                    revoke_active_refresh_tokens_for_user(&db, &user_id, now).await?;
                }
                record_audit_event(
                    &db,
                    &request,
                    if disabled {
                        "user.disable"
                    } else {
                        "user.enable"
                    },
                    Some(&user_id),
                    None,
                    None,
                    serde_json::json!({}),
                    now,
                )
                .await;
            }
            if let Some(admin) = patch.admin {
                if admin {
                    let granted_by = admin_authorization_granted_by(&admin_authorization);
                    upsert_admin_membership(&db, &user_id, &granted_by, now).await?;
                    record_audit_event(
                        &db,
                        &request,
                        "admin.membership.grant",
                        Some(&user_id),
                        None,
                        None,
                        serde_json::json!({ "grantedBy": granted_by, "mode": "admin_ui" }),
                        now,
                    )
                    .await;
                } else {
                    disable_admin_membership(&db, &user_id, now).await?;
                    record_audit_event(
                        &db,
                        &request,
                        "admin.membership.revoke",
                        Some(&user_id),
                        None,
                        None,
                        serde_json::json!({ "mode": "admin_ui" }),
                        now,
                    )
                    .await;
                }
            }

            let response = admin_user_detail_response(&db, &user_id, now)
                .await?
                .ok_or_else(|| worker_error("user update did not return a row".to_owned()))?;
            json(&response)
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn provider_status(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    json(&ProviderStatusResponse {
        providers: provider_status_rows(&env, &config),
    })
}

#[cfg(target_arch = "wasm32")]
fn ready(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let response = readiness_response(&env, &server_config(&env, &url));
    let status = if response.ready { 200 } else { 503 };
    json_status(&response, status)
}

#[cfg(target_arch = "wasm32")]
async fn events(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    let filter = match audit_event_filter_from_url(&url) {
        Ok(filter) => filter,
        Err(error) => return client_management_error_json(&error),
    };
    let rows = list_audit_event_rows(&db, &filter).await?;
    let events = rows
        .into_iter()
        .map(audit_event_response_from_row)
        .collect();
    json(&AuditEventsResponse { events })
}

#[cfg(target_arch = "wasm32")]
async fn oauth_token(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let form = match token_exchange_form_from_request(&mut request).await {
        Ok(form) => form,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    if let Err(error) = validate_token_exchange_form(&form) {
        return token_exchange_error_json(&error, 400);
    }

    let db = env.d1(D1_BINDING)?;
    let registered_client = match get_registered_client(&db, &form.client_id).await? {
        Some(client) => client,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_client("client is not registered"),
                401,
            )
        }
    };
    if let Err(error) =
        validate_token_client_auth(&registered_client, &form.client_id, &form.client_auth)
    {
        return token_exchange_error_json(&error, 401);
    }
    if let Err(error) =
        validate_cors_origin(origin.as_deref(), &registered_client.client.allowed_origins)
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let now = unix_timestamp_seconds();
    let signing_key = signing_key_from_env(&env)?;
    let config = server_config(&env, &request_url);
    let response = match form.grant_type.as_str() {
        "authorization_code" => {
            authorization_code_token(&db, &config, &signing_key, &form, now).await
        }
        "refresh_token" => refresh_token_token(&db, &config, &signing_key, &form, now).await,
        TOKEN_EXCHANGE_GRANT_TYPE => {
            native_provider_token(
                &db,
                &env,
                &config,
                &signing_key,
                &registered_client.client,
                &form,
                now,
            )
            .await
        }
        _ => token_exchange_error_json(
            &TokenExchangeError::unsupported_grant_type(
                "grant_type must be authorization_code, refresh_token, or token exchange",
            ),
            400,
        ),
    }?;
    record_audit_event(
        &db,
        &request,
        "token.issue",
        None,
        Some(&form.client_id),
        None,
        serde_json::json!({ "grantType": form.grant_type }),
        now,
    )
    .await;

    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn authorization_code_token(
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    form: &TokenExchangeForm,
    now: i32,
) -> worker::Result<Response> {
    let fields =
        authorization_code_fields(form).map_err(|error| worker_error(error.description))?;
    let auth_code = match get_authorization_code(db, fields.code).await? {
        Some(auth_code) => auth_code,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("authorization code was not found"),
                400,
            )
        }
    };

    if let Err(error) = validate_authorization_code_exchange(&auth_code, &fields, now) {
        return token_exchange_error_json(&error, 400);
    }
    if !consume_authorization_code(db, &auth_code.code_hash, now).await? {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("authorization code has already been consumed"),
            400,
        );
    }

    let user_claims = match get_user_token_claims(db, &auth_code.user_id).await? {
        Some(user_claims) => user_claims,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("authorization code user was not found"),
                400,
            )
        }
    };
    if user_claims.disabled_at.is_some() {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("authorization code user is disabled"),
            400,
        );
    }

    let refresh_token = if auth_code
        .scope
        .split_whitespace()
        .any(|scope| scope == "offline_access")
    {
        let token = random_token()?;
        put_refresh_token(&db, &token, &auth_code, now).await?;
        Some(token)
    } else {
        None
    };

    let response = token_response(
        config,
        signing_key,
        &TokenIssue::from_auth_code(&auth_code).with_user_claims(&user_claims),
        refresh_token,
        now,
    )
    .map_err(worker_error)?;
    json(&response)
}

#[cfg(target_arch = "wasm32")]
async fn refresh_token_token(
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    form: &TokenExchangeForm,
    now: i32,
) -> worker::Result<Response> {
    let refresh_token =
        refresh_token_field(form).map_err(|error| worker_error(error.description))?;
    let refresh_token_row = match get_refresh_token(db, refresh_token).await? {
        Some(refresh_token_row) => refresh_token_row,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("refresh token was not found"),
                400,
            )
        }
    };

    if let Err(error) = validate_refresh_token_exchange(&refresh_token_row, &form.client_id, now) {
        if refresh_token_replay_detected(&refresh_token_row, &form.client_id) {
            revoke_refresh_token_family(db, &refresh_token_row, now).await?;
        }
        return token_exchange_error_json(&error, 400);
    }
    let user_claims = match get_user_token_claims(db, &refresh_token_row.user_id).await? {
        Some(user_claims) => user_claims,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("refresh token user was not found"),
                400,
            )
        }
    };
    if user_claims.disabled_at.is_some() {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("refresh token user is disabled"),
            400,
        );
    }

    if !rotate_refresh_token(db, &refresh_token_row.token_hash, now).await? {
        revoke_refresh_token_family(db, &refresh_token_row, now).await?;
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("refresh token has already been rotated"),
            400,
        );
    }
    let new_refresh_token = random_token()?;
    put_rotated_refresh_token(db, &new_refresh_token, &refresh_token_row, now).await?;

    let response = token_response(
        config,
        signing_key,
        &TokenIssue::from_refresh_token(&refresh_token_row).with_user_claims(&user_claims),
        Some(new_refresh_token),
        now,
    )
    .map_err(worker_error)?;
    json(&response)
}

#[cfg(target_arch = "wasm32")]
async fn native_provider_token(
    db: &worker::d1::D1Database,
    env: &Env,
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    client: &Client,
    form: &TokenExchangeForm,
    now: i32,
) -> worker::Result<Response> {
    let fields = match native_provider_token_fields(form) {
        Ok(fields) => fields,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    let scope = match native_token_scope(fields.scope) {
        Ok(scope) => scope,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    let provider_client_id =
        match native_provider_client_id(env, fields.provider_id, fields.provider_client_id) {
            Ok(provider_client_id) => provider_client_id,
            Err(error) => return token_exchange_error_json(&error, 400),
        };

    let resolved = match resolve_native_provider_profile(&fields, &provider_client_id, now).await {
        Ok(resolved) => resolved,
        Err((error, status)) => return provider_profile_error_json(&error, status),
    };
    if let Err(error) = validate_client_email_domain_policy(client, &resolved.profile) {
        return provider_callback_error_json(&error, 403);
    }

    let user_id = upsert_provider_profile(
        db,
        &resolved.profile,
        resolved.raw_profile_json.as_deref(),
        now,
    )
    .await?;
    let user_claims = match get_user_token_claims(db, &user_id).await? {
        Some(user_claims) => user_claims,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_grant("provider identity user was not found"),
                400,
            )
        }
    };
    if user_claims.disabled_at.is_some() {
        return token_exchange_error_json(
            &TokenExchangeError::invalid_grant("provider identity user is disabled"),
            400,
        );
    }

    let issue = TokenIssue::from_native_provider(&form.client_id, &user_id, &scope, now)
        .with_user_claims(&user_claims);
    let refresh_token = if scope_contains(Some(&scope), "offline_access") {
        let token = random_token()?;
        put_refresh_token_row(db, &hash_secret(&token), &issue, now).await?;
        Some(token)
    } else {
        None
    };
    let response =
        token_response(config, signing_key, &issue, refresh_token, now).map_err(worker_error)?;
    json(&response)
}

#[cfg(target_arch = "wasm32")]
async fn resolve_native_provider_profile(
    fields: &NativeProviderTokenFields<'_>,
    provider_client_id: &str,
    now: i32,
) -> Result<ResolvedProviderProfile, (ProviderProfileError, u16)> {
    match fields.provider_id {
        well_known::APPLE | well_known::GOOGLE => {
            resolve_native_oidc_provider_profile(fields, provider_client_id, now).await
        }
        well_known::SPOTIFY => resolve_native_spotify_profile(fields, provider_client_id).await,
        provider_id => Err((
            ProviderProfileError::invalid_response(format!(
                "unsupported native provider: {provider_id}"
            )),
            400,
        )),
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_native_oidc_provider_profile(
    fields: &NativeProviderTokenFields<'_>,
    provider_client_id: &str,
    now: i32,
) -> Result<ResolvedProviderProfile, (ProviderProfileError, u16)> {
    let jwks = cached_provider_jwks(fields.provider_id, now)
        .await
        .map_err(|error| {
            (
                ProviderProfileError::invalid_response(format!(
                    "could not load {} JWKS: {}",
                    provider_label(fields.provider_id),
                    error.description
                )),
                502,
            )
        })?;
    let verified = verify_provider_id_token_with_web_crypto(
        fields.subject_token,
        &jwks,
        ProviderIdTokenValidation {
            provider_id: fields.provider_id,
            client_id: provider_client_id,
            nonce: fields.nonce,
            now,
        },
    )
    .await
    .map_err(|error| (error, 401))?;

    Ok(native_oidc_profile_from_verified_token(
        fields.provider_id,
        verified,
    ))
}

#[cfg(target_arch = "wasm32")]
async fn resolve_native_spotify_profile(
    fields: &NativeProviderTokenFields<'_>,
    provider_client_id: &str,
) -> Result<ResolvedProviderProfile, (ProviderProfileError, u16)> {
    let provider = OAuthProvider::spotify(provider_client_id);
    let token_set = ProviderTokenSet {
        access_token: Some(fields.subject_token.to_owned()),
        id_token: None,
        refresh_token: None,
        expires_in: None,
    };

    fetch_spotify_profile(&provider, &token_set)
        .await
        .map_err(|error| (error, 401))
}

#[cfg(target_arch = "wasm32")]
async fn oauth_revoke(mut request: Request, env: Env) -> worker::Result<Response> {
    let origin = request_origin(&request)?;
    let form = match token_revocation_form_from_request(&mut request).await {
        Ok(form) => form,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    if let Err(error) = validate_token_revocation_form(&form) {
        return token_exchange_error_json(&error, 400);
    }

    let db = env.d1(D1_BINDING)?;
    let registered_client = match get_registered_client(&db, &form.client_id).await? {
        Some(client) => client,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_client("client is not registered"),
                401,
            )
        }
    };
    if let Err(error) =
        validate_token_client_auth(&registered_client, &form.client_id, &form.client_auth)
    {
        return token_exchange_error_json(&error, 401);
    }
    if let Err(error) =
        validate_cors_origin(origin.as_deref(), &registered_client.client.allowed_origins)
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    if should_attempt_refresh_token_revocation(form.token_type_hint.as_deref()) {
        if let Some(refresh_token) = get_refresh_token(&db, &form.token).await? {
            if refresh_token.client_id == form.client_id {
                revoke_refresh_token(&db, &refresh_token.token_hash, unix_timestamp_seconds())
                    .await?;
            }
        }
    }
    record_audit_event(
        &db,
        &request,
        "token.revoke",
        None,
        Some(&form.client_id),
        None,
        serde_json::json!({
            "tokenTypeHint": form.token_type_hint.as_deref().unwrap_or("")
        }),
        unix_timestamp_seconds(),
    )
    .await;

    let response = Response::empty()?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn oauth_introspect(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let form = match token_introspection_form_from_request(&mut request).await {
        Ok(form) => form,
        Err(error) => return token_exchange_error_json(&error, 400),
    };
    if let Err(error) = validate_token_introspection_form(&form) {
        return token_exchange_error_json(&error, 400);
    }

    let db = env.d1(D1_BINDING)?;
    let registered_client = match get_registered_client(&db, &form.client_id).await? {
        Some(client) => client,
        None => {
            return token_exchange_error_json(
                &TokenExchangeError::invalid_client("client is not registered"),
                401,
            )
        }
    };
    if let Err(error) =
        validate_introspection_client_auth(&registered_client, &form.client_id, &form.client_auth)
    {
        return token_exchange_error_json(&error, 401);
    }
    if let Err(error) =
        validate_cors_origin(origin.as_deref(), &registered_client.client.allowed_origins)
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let config = server_config(&env, &request_url);
    let material = signing_material_from_env(&env)?;
    let response = introspection_response_for_token(
        &db,
        &config,
        &material.verification_keys,
        &form,
        unix_timestamp_seconds(),
    )
    .await?;
    let response = json(&response)?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn userinfo(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let bearer_token = match bearer_token_from_request(&request) {
        Ok(token) => token,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };
    let material = signing_material_from_env(&env)?;
    let config = server_config(&env, &request_url);
    let now = unix_timestamp_seconds();
    let claims = match verify_zeroth_access_token(
        &bearer_token,
        &config,
        &material.verification_keys,
        now,
    ) {
        Ok(claims) => claims,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };

    let db = env.d1(D1_BINDING)?;
    let user = match get_user(&db, &claims.sub).await? {
        Some(user) => user,
        None => return oauth_error_json("invalid_token", "user was not found", 401),
    };
    if user.disabled_at.is_some() {
        return oauth_error_json("invalid_token", "user is disabled", 401);
    }
    if let Err(error) = validate_access_token_session(&db, &claims, now).await? {
        return oauth_error_json("invalid_token", error, 401);
    }
    let allowed_origins = match active_client_allowed_origins(&db, &claims.aud).await? {
        Ok(allowed_origins) => allowed_origins,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };
    if let Err(error) = validate_cors_origin(origin.as_deref(), &allowed_origins) {
        return oauth_error_json("invalid_request", error, 403);
    }

    let response = json(&userinfo_response(&user, claims.scope.as_deref()))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn session(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let current =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?;

    if let Some(current) = &current {
        if let Err(error) =
            validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
        {
            return oauth_error_json("invalid_request", error, 403);
        }
    } else {
        if let Err(error) = validate_any_client_cors_origin(&db, origin.as_deref()).await? {
            return oauth_error_json("invalid_request", error, 403);
        }
    }

    let response = json(&session_response(
        current
            .as_ref()
            .map(|current| (&current.session, &current.user)),
    ))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn sessions(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let Some(current) =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?
    else {
        return oauth_error_json(
            "login_required",
            "active browser session was not found",
            401,
        );
    };
    if let Err(error) =
        validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    match request.method() {
        Method::Get => {
            let sessions =
                list_active_sessions_for_user(&db, &current.user.id, unix_timestamp_seconds())
                    .await?;
            let response = json(&sessions_response(&sessions, &current.session.id))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        Method::Delete => {
            let Some(session_id) =
                query_param(&request_url, "session_id").filter(|id| !id.is_empty())
            else {
                return oauth_error_json("invalid_request", "missing session_id", 400);
            };
            let now = unix_timestamp_seconds();
            revoke_user_session(&db, &session_id, &current.user.id, now).await?;
            revoke_refresh_token_family_for_session(&db, &session_id, &current.user.id, now)
                .await?;
            record_audit_event(
                &db,
                &request,
                "session.revoke",
                Some(&current.user.id),
                current.session.client_id.as_deref(),
                None,
                serde_json::json!({
                    "current": session_id == current.session.id
                }),
                now,
            )
            .await;

            let response = json(&serde_json::json!({ "ok": true }))?;
            let response = if session_id == current.session.id {
                with_set_cookie(
                    response,
                    &clear_session_cookie(&config.cookie_name, config.cookie_domain.as_deref()),
                )?
            } else {
                response
            };
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn profile(mut request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let origin = request_origin_for_config(&request, &config)?;
    let db = env.d1(D1_BINDING)?;
    let Some(current) =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?
    else {
        return oauth_error_json(
            "login_required",
            "active browser session was not found",
            401,
        );
    };
    if let Err(error) =
        validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    match request.method() {
        Method::Get => {
            let response = json(&userinfo_response(&current.user, Some("email profile")))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        Method::Patch => {
            let patch = match profile_patch_from_request(&mut request).await {
                Ok(patch) => patch,
                Err(error) => {
                    return oauth_error_json("invalid_request", error.description, error.status)
                }
            };
            let now = unix_timestamp_seconds();
            update_user_profile_patch(&db, &current.user.id, &patch, now).await?;
            record_audit_event(
                &db,
                &request,
                "user.profile.update",
                Some(&current.user.id),
                current.session.client_id.as_deref(),
                None,
                serde_json::json!({
                    "displayName": patch.display_name.is_some(),
                    "pictureUrl": patch.picture_url.is_some()
                }),
                now,
            )
            .await;
            let updated_user = user_with_profile_patch(&current.user, &patch);
            let response = json(&userinfo_response(&updated_user, Some("email profile")))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn identities(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let origin = request_origin_for_config(&request, &config)?;
    let db = env.d1(D1_BINDING)?;
    let Some(current) =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?
    else {
        return oauth_error_json(
            "login_required",
            "active browser session was not found",
            401,
        );
    };
    if let Err(error) =
        validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    match request.method() {
        Method::Get => {
            let identities = list_identities_for_user(&db, &current.user.id).await?;
            let response = json(&identities_response(&identities))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        Method::Delete => {
            let identity = match identity_reference_from_url(&request_url) {
                Ok(identity) => identity,
                Err(error) => return oauth_error_json("invalid_request", error, 400),
            };
            if !identity_exists_for_user(
                &db,
                &current.user.id,
                &identity.provider_id,
                &identity.provider_subject,
            )
            .await?
            {
                return oauth_error_json("invalid_request", "identity was not found", 404);
            }
            if count_identities_for_user(&db, &current.user.id).await? <= 1 {
                return oauth_error_json("invalid_request", "cannot unlink the last identity", 400);
            }

            if !delete_user_identity(
                &db,
                &current.user.id,
                &identity.provider_id,
                &identity.provider_subject,
            )
            .await?
            {
                return oauth_error_json("invalid_request", "identity could not be unlinked", 409);
            }
            if identity.provider_id == "passkey" {
                disable_passkey_credential(
                    &db,
                    &identity.provider_subject,
                    unix_timestamp_seconds(),
                )
                .await?;
            }
            record_audit_event(
                &db,
                &request,
                "identity.unlink",
                Some(&current.user.id),
                current.session.client_id.as_deref(),
                Some(&identity.provider_id),
                serde_json::json!({}),
                unix_timestamp_seconds(),
            )
            .await;
            let response = json(&serde_json::json!({ "ok": true }))?;
            with_cors_actual_headers(response, origin.as_deref())
        }
        _ => json_status(&serde_json::json!({ "error": "method_not_allowed" }), 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn passkey_register_options(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    if let Err(error) = validate_admin_request(&request, &env, &db, &config, now).await {
        return client_management_error_json(&error);
    }
    let body = match passkey_json_from_request::<PasskeyRegisterOptionsRequest>(&mut request).await
    {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };

    let current = current_session_from_request(&request, &db, &config, now).await?;
    let (user_id, email, display_name) = match passkey_registration_subject(current.as_ref(), &body)
    {
        Ok(subject) => subject,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let client_id = match passkey_client_id_from_request(&env, body.client_id.as_deref()) {
        Ok(client_id) => client_id,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let client = match get_client(&db, &client_id).await? {
        Some(client) => client,
        None => {
            return oauth_error_json(
                "invalid_request",
                "passkey session client is not registered",
                400,
            )
        }
    };
    let return_to = match passkey_return_to(&url, body.return_to.as_deref(), &client, &config) {
        Ok(return_to) => return_to,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let label = match validate_passkey_label(body.label.as_deref()) {
        Ok(label) => label,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let challenge = random_token()?;

    cleanup_expired_passkey_challenges(&db, now).await?;
    put_passkey_challenge(
        &db,
        &challenge,
        "registration",
        user_id.as_deref(),
        Some(&client_id),
        Some(&return_to),
        Some(&email),
        display_name.as_deref(),
        label.as_deref(),
        now,
    )
    .await?;

    let exclude_credentials = if let Some(user_id) = user_id.as_deref() {
        list_passkey_credentials_for_user(&db, user_id)
            .await?
            .into_iter()
            .map(|credential| PasskeyCredentialDescriptor {
                credential_type: "public-key",
                id: credential.credential_id,
            })
            .collect()
    } else {
        Vec::new()
    };
    let options = match passkey_creation_options(
        &config,
        &challenge,
        user_id.as_deref().unwrap_or(&email),
        &email,
        display_name.as_deref().unwrap_or(&email),
        exclude_credentials,
    ) {
        Ok(options) => options,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };

    json(&PasskeyOptionsResponse {
        public_key: options,
    })
}

#[cfg(target_arch = "wasm32")]
async fn passkey_register_verify(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let body = match passkey_json_from_request::<PasskeyRegisterVerifyRequest>(&mut request).await {
        Ok(body) => body,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let validation = match validate_passkey_registration_response(&config, &body) {
        Ok(validation) => validation,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let admin_authorization = authorize_admin_request(&request, &env, &db, &config, now)
        .await
        .ok();
    let challenge_hash =
        match passkey_challenge_hash_from_client_data(&body.response.client_data_json) {
            Ok(challenge_hash) => challenge_hash,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };
    let Some(challenge) = get_passkey_challenge_by_hash(&db, &challenge_hash).await? else {
        return oauth_error_json("invalid_request", "passkey challenge was not found", 400);
    };
    if let Err(error) = validate_passkey_challenge(&challenge, "registration", now) {
        return oauth_error_json("invalid_request", error, 400);
    }
    if !passkey_challenge_matches_client_data(
        &challenge.challenge_hash,
        &body.response.client_data_json,
    ) {
        return oauth_error_json("invalid_request", "passkey challenge did not match", 400);
    }
    if !consume_passkey_challenge(&db, &challenge.challenge_hash, now).await? {
        return oauth_error_json("invalid_request", "passkey challenge was already used", 400);
    }

    let (user_id, email, display_name) =
        ensure_passkey_registration_user(&db, &challenge, now).await?;
    put_passkey_credential(&db, &validation, &user_id, challenge.label.as_deref(), now).await?;
    upsert_passkey_identity(
        &db,
        &user_id,
        &validation.credential_id,
        Some(&email),
        display_name.as_deref(),
        now,
    )
    .await?;
    if let Some(admin_authorization) = admin_authorization {
        let granted_by = admin_authorization_granted_by(&admin_authorization);
        upsert_admin_membership(&db, &user_id, &granted_by, now).await?;
        record_audit_event(
            &db,
            &request,
            "admin.membership.grant",
            Some(&user_id),
            challenge.client_id.as_deref(),
            Some("passkey"),
            serde_json::json!({
                "grantedBy": granted_by,
                "mode": "passkey_registration"
            }),
            now,
        )
        .await;
    }
    record_audit_event(
        &db,
        &request,
        "passkey.register",
        Some(&user_id),
        challenge.client_id.as_deref(),
        Some("passkey"),
        serde_json::json!({
            "credentialIdHash": hash_secret(&validation.credential_id),
            "label": challenge.label.as_deref().unwrap_or("")
        }),
        now,
    )
    .await;

    let Some(user) = get_user(&db, &user_id).await? else {
        return oauth_error_json("invalid_request", "passkey user was not found", 400);
    };
    json(&serde_json::json!({
        "ok": true,
        "user": userinfo_response(&user, Some("email profile"))
    }))
}

#[cfg(target_arch = "wasm32")]
async fn passkey_authenticate_options(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let body =
        match passkey_json_from_request::<PasskeyAuthenticateOptionsRequest>(&mut request).await {
            Ok(body) => body,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };
    let db = env.d1(D1_BINDING)?;
    let client_id = match passkey_client_id_from_request(&env, body.client_id.as_deref()) {
        Ok(client_id) => client_id,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let client = match get_client(&db, &client_id).await? {
        Some(client) => client,
        None => {
            return oauth_error_json(
                "invalid_request",
                "passkey session client is not registered",
                400,
            )
        }
    };
    let return_to = match passkey_return_to(&url, body.return_to.as_deref(), &client, &config) {
        Ok(return_to) => return_to,
        Err(error) => return oauth_error_json("invalid_request", error.to_string(), 400),
    };
    let now = unix_timestamp_seconds();
    let challenge = random_token()?;
    cleanup_expired_passkey_challenges(&db, now).await?;
    put_passkey_challenge(
        &db,
        &challenge,
        "authentication",
        None,
        Some(&client_id),
        Some(&return_to),
        None,
        None,
        None,
        now,
    )
    .await?;
    let allow_credentials = list_active_passkey_credentials(&db)
        .await?
        .into_iter()
        .map(|credential| PasskeyCredentialDescriptor {
            credential_type: "public-key",
            id: credential.credential_id,
        })
        .collect();
    let options = match passkey_request_options(&config, &challenge, allow_credentials) {
        Ok(options) => options,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };

    json(&PasskeyOptionsResponse {
        public_key: options,
    })
}

#[cfg(target_arch = "wasm32")]
async fn passkey_authenticate_verify(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let body =
        match passkey_json_from_request::<PasskeyAuthenticateVerifyRequest>(&mut request).await {
            Ok(body) => body,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };
    let challenge_hash =
        match passkey_challenge_hash_from_client_data(&body.response.client_data_json) {
            Ok(challenge_hash) => challenge_hash,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };
    let Some(challenge) = get_passkey_challenge_by_hash(&db, &challenge_hash).await? else {
        return oauth_error_json("invalid_request", "passkey challenge was not found", 400);
    };
    if let Err(error) = validate_passkey_challenge(&challenge, "authentication", now) {
        return oauth_error_json("invalid_request", error, 400);
    }
    let credential_id = match passkey_raw_id(&body.raw_id) {
        Ok(credential_id) => credential_id,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    let Some(credential) = get_passkey_credential(&db, &credential_id).await? else {
        return oauth_error_json("invalid_request", "passkey credential was not found", 400);
    };
    if credential.disabled_at.is_some() {
        return oauth_error_json("invalid_request", "passkey credential is disabled", 400);
    }
    if let Err(error) =
        validate_passkey_authentication_response(&config, &body, &credential, &challenge)
    {
        return oauth_error_json("invalid_request", error, 400);
    }
    if !consume_passkey_challenge(&db, &challenge.challenge_hash, now).await? {
        return oauth_error_json("invalid_request", "passkey challenge was already used", 400);
    }
    update_passkey_credential_use(
        &db,
        &credential.credential_id,
        passkey_authenticator_sign_count(&body.response.authenticator_data)?,
        now,
    )
    .await?;
    let Some(user) = get_user(&db, &credential.user_id).await? else {
        return oauth_error_json("invalid_request", "passkey user was not found", 400);
    };
    if user.disabled_at.is_some() {
        return oauth_error_json("invalid_request", "passkey user is disabled", 400);
    }
    let client_id = challenge
        .client_id
        .as_deref()
        .ok_or_else(|| worker_error("passkey challenge did not include a client_id".to_owned()))?;
    let session_id = format!("sess_{}", random_token()?);
    let audit_context = audit_request_context(&request).unwrap_or_default();
    put_session(
        &db,
        &session_id,
        &user.id,
        client_id,
        now,
        audit_context.user_agent.as_deref(),
        audit_context.ip_hash.as_deref(),
    )
    .await?;
    record_audit_event(
        &db,
        &request,
        "session.login",
        Some(&user.id),
        Some(client_id),
        Some("passkey"),
        serde_json::json!({
            "mode": "passkey",
            "credentialIdHash": hash_secret(&credential.credential_id)
        }),
        now,
    )
    .await;

    let return_to = challenge
        .return_to
        .unwrap_or_else(|| format!("{}/admin", config.issuer().issuer));
    let response = json(&PasskeyVerifyResponse {
        ok: true,
        return_to,
        user: userinfo_response(&user, Some("email profile")),
    })?;
    with_set_cookie(
        response,
        &session_cookie(
            &config.cookie_name,
            &session_id,
            SESSION_TTL_SECONDS,
            config.cookie_domain.as_deref(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn identity_link(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let provider_id = match provider_id_from_url(&request_url) {
        Ok(provider_id) => provider_id,
        Err(error) => return auth_error_json(&error, 400),
    };
    let config = server_config(&env, &request_url);
    let db = env.d1(D1_BINDING)?;
    let Some(current) =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?
    else {
        return oauth_error_json(
            "login_required",
            "active browser session was not found",
            401,
        );
    };
    if let Err(error) =
        validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let Some(client_id) = current.session.client_id.as_deref() else {
        return oauth_error_json(
            "invalid_request",
            "active browser session is not associated with a client",
            400,
        );
    };
    let client = match get_client(&db, client_id).await? {
        Some(client) => client,
        None => {
            return oauth_error_json(
                "unauthorized_client",
                "session client is not registered",
                400,
            )
        }
    };
    let return_to = match identity_link_return_to_from_url(
        &request_url,
        &client,
        Some(&config.public_base_url),
    ) {
        Ok(return_to) => return_to,
        Err(error) => return oauth_error_json("invalid_request", error, 400),
    };
    if !provider_configured_for_login(&env, &provider_id) {
        return oauth_error_json(
            "invalid_request",
            format!("provider is not fully configured: {provider_id}"),
            400,
        );
    }

    let provider = provider_from_env(&env, &provider_id)?;
    let provider_redirect_uri = config.issuer().provider_callback_endpoint();
    let provider_state = random_token()?;
    let provider_nonce = random_token()?;
    let now = unix_timestamp_seconds();
    cleanup_expired_auth_transactions(&db, now).await?;
    let transaction = auth_transaction_from_link_request(
        &client,
        &provider_id,
        provider_state,
        provider_nonce,
        provider_redirect_uri,
        return_to,
        query_param(&request_url, "state"),
        &current.user.id,
        &current.session.id,
        now,
    );
    put_auth_transaction(&db, &transaction).await?;

    let auth = provider
        .authorize_url(ProviderAuthorizeRequest {
            redirect_uri: &transaction.provider_redirect_uri,
            state: &transaction.provider_state,
            nonce: provider_authorize_nonce(&transaction),
            code_challenge: None,
            scopes: None,
        })
        .map_err(|error| worker::Error::RustError(error.description))?;

    let target = url::Url::parse(&auth.url)
        .map_err(|error| worker::Error::RustError(format!("invalid authorize URL: {error}")))?;
    let response = Response::redirect(target)?;
    with_set_cookie(
        response,
        &transaction_cookie(
            &config.transaction_cookie_name,
            &transaction.provider_state,
            AUTH_TRANSACTION_TTL_SECONDS,
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn validate(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let origin = request_origin(&request)?;
    let authorization = request_header(&request, "Authorization")?;
    let bearer_token = match bearer_token_from_authorization_header(authorization.as_deref()) {
        Ok(token) => token,
        Err(error) => return oauth_error_json("invalid_token", error, 401),
    };
    let db = env.d1(D1_BINDING)?;

    if let Some(bearer_token) = bearer_token {
        let material = signing_material_from_env(&env)?;
        let config = server_config(&env, &request_url);
        let now = unix_timestamp_seconds();
        let claims = match verify_zeroth_access_token(
            &bearer_token,
            &config,
            &material.verification_keys,
            now,
        ) {
            Ok(claims) => claims,
            Err(error) => return oauth_error_json("invalid_token", error, 401),
        };
        let user = match get_user(&db, &claims.sub).await? {
            Some(user) => user,
            None => return oauth_error_json("invalid_token", "user was not found", 401),
        };
        if user.disabled_at.is_some() {
            return oauth_error_json("invalid_token", "user is disabled", 401);
        }
        if let Err(error) = validate_access_token_session(&db, &claims, now).await? {
            return oauth_error_json("invalid_token", error, 401);
        }
        let allowed_origins = match active_client_allowed_origins(&db, &claims.aud).await? {
            Ok(allowed_origins) => allowed_origins,
            Err(error) => return oauth_error_json("invalid_token", error, 401),
        };
        if let Err(error) = validate_cors_origin(origin.as_deref(), &allowed_origins) {
            return oauth_error_json("invalid_request", error, 403);
        }

        let response = json(&validate_access_token_response(&claims, &user))?;
        return with_cors_actual_headers(response, origin.as_deref());
    }

    let config = server_config(&env, &request_url);
    let Some(current) =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?
    else {
        return oauth_error_json(
            "invalid_token",
            "bearer token or active browser session is required",
            401,
        );
    };
    if let Err(error) =
        validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
    {
        return oauth_error_json("invalid_request", error, 403);
    }

    let response = json(&validate_session_response(&current.session, &current.user))?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn logout(request: Request, env: Env) -> worker::Result<Response> {
    let request_url = request.url()?;
    let config = server_config(&env, &request_url);
    let origin = request_origin_for_config(&request, &config)?;
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let current = current_session_from_request(&request, &db, &config, now).await?;
    if let Some(current) = &current {
        if let Err(error) =
            validate_session_cors_origin(&db, origin.as_deref(), &current.session).await?
        {
            return oauth_error_json("invalid_request", error, 403);
        }
        revoke_session(&db, &current.session.id, now).await?;
        revoke_refresh_token_family_for_session(&db, &current.session.id, &current.user.id, now)
            .await?;
        record_audit_event(
            &db,
            &request,
            "session.logout",
            Some(&current.user.id),
            current.session.client_id.as_deref(),
            None,
            serde_json::json!({}),
            now,
        )
        .await;
    } else {
        if let Err(error) = validate_any_client_cors_origin(&db, origin.as_deref()).await? {
            return oauth_error_json("invalid_request", error, 403);
        }
    }

    let redirect_target =
        match logout_redirect_target(&request_url, current.as_ref(), &db, &config, &env, now)
            .await?
        {
            Ok(redirect_target) => redirect_target,
            Err(error) => return oauth_error_json("invalid_request", error, 400),
        };

    if let Some(target) = redirect_target {
        let response = Response::redirect(target)?;
        return with_set_cookie(
            response,
            &clear_session_cookie(&config.cookie_name, config.cookie_domain.as_deref()),
        );
    }

    let response = json(&serde_json::json!({ "ok": true }))?;
    let response = with_set_cookie(
        response,
        &clear_session_cookie(&config.cookie_name, config.cookie_domain.as_deref()),
    )?;
    with_cors_actual_headers(response, origin.as_deref())
}

#[cfg(target_arch = "wasm32")]
async fn cors_preflight(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let origin = match request_origin(&request)? {
        Some(origin) => origin,
        None => return Response::empty().map(|response| response.with_status(400)),
    };
    let requested_method = request_header(&request, "Access-Control-Request-Method")?
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !cors_method_allowed(url.path(), &requested_method) {
        return Response::empty().map(|response| response.with_status(405));
    }

    let db = env.d1(D1_BINDING)?;
    if !origin_allowed_by_any_client(&db, &origin).await? {
        return Response::empty().map(|response| response.with_status(403));
    }

    let response = Response::empty()?.with_status(204);
    with_cors_preflight_headers(response, &origin)
}

#[cfg(target_arch = "wasm32")]
fn jwks(env: Env) -> worker::Result<Response> {
    let material = signing_material_from_env(&env)?;
    json(&material.jwks)
}

#[cfg(target_arch = "wasm32")]
fn apple_app_site_association(env: Env) -> worker::Result<Response> {
    let Some(payload) = secret_string(&env, "APPLE_APP_SITE_ASSOCIATION_JSON")
        .or_else(|| env_string(&env, "APPLE_APP_SITE_ASSOCIATION_JSON"))
    else {
        return json_status(
            &OAuthErrorResponse {
                error: "not_configured".to_owned(),
                error_description: "APPLE_APP_SITE_ASSOCIATION_JSON is not configured".to_owned(),
            },
            404,
        );
    };

    let response = Response::ok(payload)?;
    response
        .headers()
        .set("Content-Type", "application/json; charset=utf-8")?;
    response
        .headers()
        .set("Cache-Control", "public, max-age=3600")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn hosted_login(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    if !authorization_login_request_present(&url) {
        return hosted_session_login(request, env).await;
    }

    let authorization_request = match parse_authorization_request(&url) {
        Ok(request) => request,
        Err(error) => return auth_error_json(&error, 400),
    };

    let db = env.d1(D1_BINDING)?;
    let client = match get_client(&db, &authorization_request.client_id.0).await? {
        Some(client) => client,
        None => {
            return auth_error_json(
                &AuthorizationRequestError::unauthorized_client("client is not registered"),
                400,
            )
        }
    };
    if let Err(error) = validate_authorization_request_for_client(&authorization_request, &client) {
        return auth_error_json(&error, 400);
    }

    hosted_authorization_document(&request, &env, &url, &db, &authorization_request, &client).await
}

#[cfg(target_arch = "wasm32")]
async fn hosted_session_login(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let provider_id = match optional_provider_id_from_url(&url) {
        Ok(provider_id) => provider_id,
        Err(error) => return auth_error_json(&error, 400),
    };
    let client_id = match session_login_client_id_from_url(&env, &url) {
        Ok(client_id) => client_id,
        Err(error) => return auth_error_json(&error, 400),
    };

    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let client = match get_client(&db, &client_id).await? {
        Some(client) => client,
        None => {
            return auth_error_json(
                &AuthorizationRequestError::unauthorized_client("client is not registered"),
                400,
            )
        }
    };
    let return_to = match client_return_to_from_url(&url, &client, Some(&config.public_base_url)) {
        Ok(return_to) => return_to,
        Err(error) => {
            return auth_error_json(&AuthorizationRequestError::invalid_request(error), 400)
        }
    };

    let Some(provider_id) = provider_id else {
        return hosted_session_login_document(&request, &env, &url, &db, &client, return_to).await;
    };
    if !provider_configured_for_login(&env, &provider_id) {
        return auth_error_json(
            &AuthorizationRequestError::invalid_request(format!(
                "provider is not fully configured: {provider_id}"
            )),
            400,
        );
    }

    let provider = provider_from_env(&env, &provider_id)?;
    let provider_redirect_uri = config.issuer().provider_callback_endpoint();
    let provider_state = random_token()?;
    let provider_nonce = random_token()?;
    let now = unix_timestamp_seconds();
    cleanup_expired_auth_transactions(&db, now).await?;
    let transaction = auth_transaction_from_session_login_request(
        &client,
        &provider_id,
        provider_state,
        provider_nonce,
        provider_redirect_uri,
        return_to,
        query_param(&url, "state"),
        now,
    );
    put_auth_transaction(&db, &transaction).await?;

    let auth = provider
        .authorize_url(ProviderAuthorizeRequest {
            redirect_uri: &transaction.provider_redirect_uri,
            state: &transaction.provider_state,
            nonce: provider_authorize_nonce(&transaction),
            code_challenge: None,
            scopes: None,
        })
        .map_err(|error| worker::Error::RustError(error.description))?;

    let target = url::Url::parse(&auth.url)
        .map_err(|error| worker::Error::RustError(format!("invalid authorize URL: {error}")))?;
    let response = Response::redirect(target)?;
    with_set_cookie(
        response,
        &transaction_cookie(
            &config.transaction_cookie_name,
            &transaction.provider_state,
            AUTH_TRANSACTION_TTL_SECONDS,
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn hosted_account(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let current =
        current_session_from_request(&request, &db, &config, unix_timestamp_seconds()).await?;

    let mut client = None;
    if let Some(current) = &current {
        if let Some(client_id) = current.session.client_id.as_deref() {
            client = get_client(&db, client_id).await?;
        }
    }

    let identities = if let Some(current) = &current {
        list_identities_for_user(&db, &current.user.id).await?
    } else {
        Vec::new()
    };
    let sessions = if let Some(current) = &current {
        list_active_sessions_for_user(&db, &current.user.id, unix_timestamp_seconds()).await?
    } else {
        Vec::new()
    };

    let account_url = config.issuer().issuer + "/account";
    let mut ui_config = if let Some(client) = &client {
        ZerothUiConfig::new(
            config.issuer().issuer.clone(),
            client.id.0.clone(),
            client
                .redirect_uris
                .first()
                .cloned()
                .unwrap_or_else(|| account_url.clone()),
        )
    } else {
        ZerothUiConfig::new(config.issuer().issuer.clone(), "", account_url.clone())
    };
    ui_config.return_to = Some(query_param(&url, "return_to").unwrap_or(account_url));
    ui_config.code_challenge = None;
    ui_config.code_challenge_method = None;
    ui_config.link_identities = true;

    let mut state = ZerothUiState::new(ui_config).with_product_name(product_name_from_env(&env));
    state.providers = provider_ui_rows(&env, &identities, client.is_some());
    state.profile = current
        .as_ref()
        .map(|current| profile_ui_from_user(&current.user, &identities));
    state.identities = identity_ui_rows(&identities);
    state.sessions = current
        .as_ref()
        .map(|current| session_ui_rows(&sessions, &current.session.id))
        .unwrap_or_default();
    state.applications = client
        .as_ref()
        .map(|client| vec![application_ui_from_client(client)])
        .unwrap_or_default();

    html(render_account_document(state))
}

#[cfg(target_arch = "wasm32")]
async fn hosted_clients_admin(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let mut state = ClientsAdminUiState::new(config.issuer().issuer)
        .with_product_name(product_name_from_env(&env));
    state.providers = provider_admin_ui_rows(&env, &config);
    let db = env.d1(D1_BINDING)?;

    if validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds())
        .await
        .is_ok()
    {
        let rows = list_client_rows_for_admin(&db).await?;
        state.clients = rows
            .into_iter()
            .map(client_admin_ui_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(worker_error)?;
        state.users = list_admin_user_rows(&db, unix_timestamp_seconds())
            .await?
            .into_iter()
            .map(user_admin_ui_from_row)
            .collect();
        state.events = list_audit_event_rows(&db, &AuditEventFilter::default())
            .await?
            .into_iter()
            .map(audit_event_admin_ui_from_row)
            .collect();
    }

    html(render_clients_admin_document(state))
}

#[cfg(target_arch = "wasm32")]
async fn authorize(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let authorization_request = match parse_authorization_request(&url) {
        Ok(request) => request,
        Err(error) => return auth_error_json(&error, 400),
    };

    let db = env.d1(D1_BINDING)?;
    let client = match get_client(&db, &authorization_request.client_id.0).await? {
        Some(client) => client,
        None => {
            return auth_error_json(
                &AuthorizationRequestError::unauthorized_client("client is not registered"),
                400,
            )
        }
    };

    if let Err(error) = validate_authorization_request_for_client(&authorization_request, &client) {
        if let Some(redirect_url) = authorization_request_error_redirect_url_for_client(
            &authorization_request,
            &client,
            &config.issuer().issuer,
            &error,
        )
        .map_err(worker::Error::RustError)?
        {
            return Response::redirect(redirect_url);
        }
        return auth_error_json(&error, 400);
    }
    let provider_id = match optional_provider_id_from_url(&url) {
        Ok(provider_id) => provider_id,
        Err(error) => {
            return redirect_to_authorization_request_error(
                &authorization_request,
                &config.issuer().issuer,
                error.code,
                &error.description,
            )
        }
    };
    if authorization_request.prompt == AuthorizationPrompt::None {
        let now = unix_timestamp_seconds();
        let Some(current) = current_session_from_request(&request, &db, &config, now).await? else {
            return redirect_to_authorization_request_error(
                &authorization_request,
                &config.issuer().issuer,
                "login_required",
                "active browser session was not found",
            );
        };
        if !authorization_request_session_is_fresh(&authorization_request, &current.session, now) {
            return redirect_to_authorization_request_error(
                &authorization_request,
                &config.issuer().issuer,
                "login_required",
                "active browser session is older than max_age",
            );
        }

        let zeroth_code = random_token()?;
        put_authorization_code_for_request(
            &db,
            &zeroth_code,
            &authorization_request,
            &current.user.id,
            Some(&current.session.id),
            current.session.created_at,
            now,
        )
        .await?;
        record_audit_event(
            &db,
            &request,
            "authorization.code.issue",
            Some(&current.user.id),
            Some(&authorization_request.client_id.0),
            None,
            serde_json::json!({
                "scope": authorization_request.scope.as_slice().join(" "),
                "mode": "prompt_none"
            }),
            now,
        )
        .await;

        return redirect_to_authorization_request_client(
            &authorization_request,
            &config.issuer().issuer,
            &zeroth_code,
        );
    }
    let Some(provider_id) = provider_id else {
        return hosted_authorization_document(
            &request,
            &env,
            &url,
            &db,
            &authorization_request,
            &client,
        )
        .await;
    };
    if !provider_configured_for_login(&env, &provider_id) {
        return redirect_to_authorization_request_error(
            &authorization_request,
            &config.issuer().issuer,
            "invalid_request",
            &format!("provider is not fully configured: {provider_id}"),
        );
    }

    let provider = provider_from_env(&env, &provider_id)?;
    let provider_redirect_uri = config.issuer().provider_callback_endpoint();
    let provider_state = random_token()?;
    let provider_nonce = random_token()?;
    let now = unix_timestamp_seconds();
    cleanup_expired_auth_transactions(&db, now).await?;
    let transaction = auth_transaction_from_request(
        &authorization_request,
        &provider_id,
        provider_state,
        provider_nonce,
        provider_redirect_uri,
        now,
    );
    put_auth_transaction(&db, &transaction).await?;

    let auth = provider
        .authorize_url(ProviderAuthorizeRequest {
            redirect_uri: &transaction.provider_redirect_uri,
            state: &transaction.provider_state,
            nonce: provider_authorize_nonce(&transaction),
            code_challenge: None,
            scopes: None,
        })
        .map_err(|error| worker::Error::RustError(error.description))?;

    let target = url::Url::parse(&auth.url)
        .map_err(|error| worker::Error::RustError(format!("invalid authorize URL: {error}")))?;
    let response = Response::redirect(target)?;
    with_set_cookie(
        response,
        &transaction_cookie(
            &config.transaction_cookie_name,
            &transaction.provider_state,
            AUTH_TRANSACTION_TTL_SECONDS,
        ),
    )
}

#[cfg(target_arch = "wasm32")]
async fn hosted_session_login_document(
    request: &Request,
    env: &Env,
    url: &url::Url,
    db: &worker::d1::D1Database,
    client: &Client,
    return_to: String,
) -> worker::Result<Response> {
    let config = server_config(env, url);
    let current =
        current_session_from_request(request, db, &config, unix_timestamp_seconds()).await?;
    let identities = if let Some(current) = &current {
        list_identities_for_user(db, &current.user.id).await?
    } else {
        Vec::new()
    };

    let mut ui_config = ZerothUiConfig::new(
        config.issuer().issuer,
        client.id.0.clone(),
        return_to.clone(),
    );
    ui_config.return_to = Some(return_to);
    ui_config.state = query_param(url, "state");
    ui_config.nonce = None;
    ui_config.code_challenge = None;
    ui_config.code_challenge_method = None;
    ui_config.link_identities = false;
    ui_config.provider_authorize_path = "/login".to_owned();

    let mut state = ZerothUiState::new(ui_config).with_product_name(product_name_from_env(env));
    state.providers = provider_ui_rows(env, &identities, true);
    state.profile = current
        .as_ref()
        .map(|current| profile_ui_from_user(&current.user, &identities));
    state.identities = identity_ui_rows(&identities);
    state.applications = vec![application_ui_from_client(client)];

    html(render_account_document(state))
}

#[cfg(target_arch = "wasm32")]
async fn hosted_authorization_document(
    request: &Request,
    env: &Env,
    url: &url::Url,
    db: &worker::d1::D1Database,
    authorization_request: &AuthorizationRequest,
    client: &Client,
) -> worker::Result<Response> {
    let config = server_config(env, url);
    let now = unix_timestamp_seconds();
    let current = current_session_from_request(request, db, &config, now).await?;
    let current = current.filter(|current| {
        authorization_request_may_reuse_session(authorization_request, &current.session, now)
    });
    let identities = if let Some(current) = &current {
        list_identities_for_user(db, &current.user.id).await?
    } else {
        Vec::new()
    };

    let mut ui_config = ui_config_from_authorization_request(&config, authorization_request);
    ui_config.return_to = query_param(url, "return_to");
    ui_config.link_identities = false;

    let mut state = ZerothUiState::new(ui_config).with_product_name(product_name_from_env(env));
    state.providers = provider_ui_rows(env, &identities, true);
    state.profile = current
        .as_ref()
        .map(|current| profile_ui_from_user(&current.user, &identities));
    state.identities = identity_ui_rows(&identities);
    state.applications = vec![application_ui_from_client(client)];

    html(render_account_document(state))
}

#[cfg(target_arch = "wasm32")]
fn ui_config_from_authorization_request(
    config: &ZerothServerConfig,
    request: &AuthorizationRequest,
) -> ZerothUiConfig {
    let mut ui_config = ZerothUiConfig::new(
        config.issuer().issuer,
        request.client_id.0.clone(),
        request.redirect_uri.clone(),
    );
    ui_config.scope = request.scope.as_slice().join(" ");
    ui_config.state = request.state.clone();
    ui_config.nonce = request.nonce.clone();
    ui_config.max_age = request.max_age;
    ui_config.code_challenge = request.code_challenge.clone();
    ui_config.code_challenge_method = request
        .code_challenge_method
        .as_ref()
        .map(|method| method.as_str().to_owned());
    ui_config
}

#[cfg(target_arch = "wasm32")]
fn provider_ui_rows(
    env: &Env,
    identities: &[IdentityRow],
    actions_enabled: bool,
) -> Vec<ProviderUi> {
    let mut providers = vec![
        provider_ui(well_known::APPLE, "Apple", ProviderKind::Apple, identities),
        provider_ui(
            well_known::GOOGLE,
            "Google",
            ProviderKind::Google,
            identities,
        ),
        provider_ui(
            well_known::SPOTIFY,
            "Spotify",
            ProviderKind::Spotify,
            identities,
        ),
    ];
    for provider in &mut providers {
        provider.enabled = actions_enabled && provider_configured_for_login(env, &provider.id);
    }
    providers
}

fn provider_ui(
    id: &str,
    label: &str,
    kind: ProviderKind,
    identities: &[IdentityRow],
) -> ProviderUi {
    ProviderUi {
        id: id.to_owned(),
        label: label.to_owned(),
        kind,
        connected: identities.iter().any(|identity| identity.provider_id == id),
        enabled: true,
    }
}

#[cfg(target_arch = "wasm32")]
fn provider_client_id_configured(env: &Env, provider_id: &str) -> bool {
    provider_client_id_binding(provider_id)
        .and_then(|binding| binding_value_from_env(env, binding))
        .is_some_and(|value| config_value_configured(Some(&value)))
}

fn provider_client_id_binding(provider_id: &str) -> Option<&'static str> {
    Some(match provider_id {
        well_known::APPLE => "APPLE_CLIENT_ID",
        well_known::GOOGLE => "GOOGLE_CLIENT_ID",
        well_known::SPOTIFY => "SPOTIFY_CLIENT_ID",
        _ => return None,
    })
}

#[cfg(target_arch = "wasm32")]
fn provider_configured_for_login(env: &Env, provider_id: &str) -> bool {
    provider_client_id_configured(env, provider_id)
        && provider_client_secret_configured(env, provider_id)
}

#[cfg(target_arch = "wasm32")]
fn provider_status_rows(env: &Env, config: &ZerothServerConfig) -> Vec<ProviderStatus> {
    [well_known::APPLE, well_known::GOOGLE, well_known::SPOTIFY]
        .into_iter()
        .filter_map(|provider_id| provider_status_row(env, config, provider_id))
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn readiness_response(env: &Env, config: &ZerothServerConfig) -> ReadinessResponse {
    let issuer_check = issuer_readiness(config);
    let signing = signing_readiness(env);
    let providers = provider_readiness_rows(env, config);
    let apple_app_site_association = apple_app_site_association_readiness(env);
    let ready = readiness_is_ready(&issuer_check, &signing, &providers);
    let mut notes = Vec::new();
    if !ready {
        notes.push("not_ready");
    }
    if !apple_app_site_association.configured {
        notes.push("apple_app_site_association_optional");
    }

    ReadinessResponse {
        ready,
        service: "zeroth",
        issuer: config.issuer().issuer,
        issuer_check,
        signing,
        providers,
        apple_app_site_association,
        notes,
    }
}

fn readiness_is_ready(
    issuer_check: &ReadinessCheck,
    signing: &ReadinessCheck,
    providers: &[ProviderReadiness],
) -> bool {
    issuer_check.configured
        && signing.configured
        && !providers.is_empty()
        && providers.iter().all(|provider| provider.configured)
}

fn issuer_readiness(config: &ZerothServerConfig) -> ReadinessCheck {
    let mut notes = Vec::new();
    let configured = match url::Url::parse(&config.public_base_url) {
        Ok(url) if url.scheme() == "https" && url.host_str().is_some() => true,
        Ok(url) if url.host_str().is_none() => {
            notes.push("missing_issuer_host");
            false
        }
        Ok(_) => {
            notes.push("issuer_not_https");
            false
        }
        Err(_) => {
            notes.push("invalid_issuer_url");
            false
        }
    };

    ReadinessCheck { configured, notes }
}

#[cfg(target_arch = "wasm32")]
fn signing_readiness(env: &Env) -> ReadinessCheck {
    let key_id_configured =
        binding_value_from_env(env, "JWT_KEY_ID").is_some_and(|value| !value.trim().is_empty());
    let private_key_configured = binding_value_from_env(env, "JWT_ES256_PRIVATE_KEY")
        .is_some_and(|value| !value.trim().is_empty());
    let mut notes = Vec::new();
    if !key_id_configured {
        notes.push("missing_jwt_key_id");
    }
    if !private_key_configured {
        notes.push("missing_jwt_es256_private_key");
    }
    let signing_material_valid =
        key_id_configured && private_key_configured && signing_material_from_env(env).is_ok();
    if key_id_configured && private_key_configured && !signing_material_valid {
        notes.push("invalid_signing_material");
    }

    ReadinessCheck {
        configured: signing_material_valid,
        notes,
    }
}

#[cfg(target_arch = "wasm32")]
fn provider_readiness_rows(env: &Env, config: &ZerothServerConfig) -> Vec<ProviderReadiness> {
    provider_status_rows(env, config)
        .into_iter()
        .map(|status| ProviderReadiness {
            id: status.id,
            label: status.label,
            kind: status.kind,
            configured: status.enabled,
            notes: status.notes,
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
fn apple_app_site_association_readiness(env: &Env) -> ReadinessCheck {
    apple_app_site_association_readiness_from_payload(
        binding_value_from_env(env, "APPLE_APP_SITE_ASSOCIATION_JSON").as_deref(),
    )
}

fn apple_app_site_association_readiness_from_payload(value: Option<&str>) -> ReadinessCheck {
    let mut notes = Vec::new();
    let configured = match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => match serde_json::from_str::<serde_json::Value>(value) {
            Ok(serde_json::Value::Object(_)) => true,
            Ok(_) => {
                notes.push("apple_app_site_association_not_object");
                false
            }
            Err(_) => {
                notes.push("invalid_apple_app_site_association_json");
                false
            }
        },
        None => {
            notes.push("missing_apple_app_site_association_json");
            false
        }
    };

    ReadinessCheck { configured, notes }
}

fn config_value_configured(value: Option<&str>) -> bool {
    config_value_note(value, "missing", "placeholder").is_none()
}

fn config_value_note(
    value: Option<&str>,
    missing_note: &'static str,
    placeholder_note: &'static str,
) -> Option<&'static str> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Some(missing_note);
    };
    if config_value_is_placeholder(value) {
        Some(placeholder_note)
    } else {
        None
    }
}

fn config_value_is_placeholder(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("replace-with-")
        || value == "changeme"
        || value == "change-me"
        || value == "todo"
        || (value.starts_with('<') && value.ends_with('>'))
}

#[cfg(target_arch = "wasm32")]
fn provider_status_row(
    env: &Env,
    config: &ZerothServerConfig,
    provider_id: &str,
) -> Option<ProviderStatus> {
    let (id, label, kind) = match provider_id {
        well_known::APPLE => (well_known::APPLE, "Apple", "oidc"),
        well_known::GOOGLE => (well_known::GOOGLE, "Google", "oidc"),
        well_known::SPOTIFY => (well_known::SPOTIFY, "Spotify", "oauth2"),
        _ => return None,
    };
    let client_id_binding = provider_client_id_binding(provider_id)?;
    let client_id_value = binding_value_from_env(env, client_id_binding);
    let client_id_configured = config_value_configured(client_id_value.as_deref());
    let client_secret_configured = provider_client_secret_configured(env, provider_id);
    let mut notes = Vec::new();
    if let Some(note) = config_value_note(
        client_id_value.as_deref(),
        "missing_client_id",
        "placeholder_client_id",
    ) {
        notes.push(note);
    }
    if !client_secret_configured {
        notes.push("missing_client_secret");
    }

    Some(ProviderStatus {
        id,
        label,
        kind,
        enabled: client_id_configured && client_secret_configured,
        client_id_configured,
        client_secret_configured,
        client_id_binding,
        secret_binding_sets: provider_secret_binding_sets(provider_id),
        callback_url: config.issuer().provider_callback_endpoint(),
        web_domain: provider_web_domain(provider_id, config),
        notes,
    })
}

fn provider_secret_binding_sets(provider_id: &str) -> Vec<Vec<&'static str>> {
    match provider_id {
        well_known::APPLE => vec![
            vec!["APPLE_CLIENT_SECRET"],
            vec!["APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY"],
            vec!["APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_PRIVATE_KEY_PEM"],
        ],
        well_known::GOOGLE => vec![vec!["GOOGLE_CLIENT_SECRET"]],
        well_known::SPOTIFY => vec![vec!["SPOTIFY_CLIENT_SECRET"]],
        _ => Vec::new(),
    }
}

fn provider_web_domain(provider_id: &str, config: &ZerothServerConfig) -> Option<String> {
    if provider_id != well_known::APPLE {
        return None;
    }
    url::Url::parse(&config.issuer().issuer)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
}

#[cfg(target_arch = "wasm32")]
fn provider_client_secret_configured(env: &Env, provider_id: &str) -> bool {
    match provider_id {
        well_known::APPLE => apple_client_secret_configured(env),
        well_known::GOOGLE => provider_secret_binding_configured(env, "GOOGLE_CLIENT_SECRET"),
        well_known::SPOTIFY => provider_secret_binding_configured(env, "SPOTIFY_CLIENT_SECRET"),
        _ => false,
    }
}

#[cfg(target_arch = "wasm32")]
fn apple_client_secret_configured(env: &Env) -> bool {
    provider_secret_binding_configured(env, "APPLE_CLIENT_SECRET")
        || (provider_secret_binding_configured(env, "APPLE_TEAM_ID")
            && provider_secret_binding_configured(env, "APPLE_KEY_ID")
            && provider_client_id_configured(env, well_known::APPLE)
            && (provider_secret_binding_configured(env, "APPLE_PRIVATE_KEY")
                || provider_secret_binding_configured(env, "APPLE_PRIVATE_KEY_PEM")))
}

#[cfg(target_arch = "wasm32")]
fn provider_secret_binding_configured(env: &Env, name: &str) -> bool {
    config_value_configured(binding_value_from_env(env, name).as_deref())
}

#[cfg(target_arch = "wasm32")]
fn provider_admin_ui_rows(env: &Env, config: &ZerothServerConfig) -> Vec<ProviderAdminUi> {
    provider_status_rows(env, config)
        .into_iter()
        .map(|status| ProviderAdminUi {
            id: status.id.to_owned(),
            label: status.label.to_owned(),
            kind: status.kind.to_owned(),
            enabled: status.enabled,
            client_id_configured: status.client_id_configured,
            client_secret_configured: status.client_secret_configured,
            client_id_binding: status.client_id_binding.to_owned(),
            secret_binding_sets: status
                .secret_binding_sets
                .iter()
                .map(|set| set.iter().map(|name| (*name).to_owned()).collect())
                .collect(),
            callback_url: status.callback_url,
            web_domain: status.web_domain,
            notes: status.notes.iter().map(|note| (*note).to_owned()).collect(),
        })
        .collect()
}

fn profile_ui_from_user(user: &UserRow, identities: &[IdentityRow]) -> ProfileUi {
    let email_verified = user.primary_email.as_ref().is_some_and(|email| {
        identities
            .iter()
            .any(|identity| identity.email.as_ref() == Some(email) && identity.email_verified != 0)
    });

    ProfileUi {
        sub: user.id.clone(),
        email: user.primary_email.clone(),
        email_verified,
        display_name: user.display_name.clone(),
        picture_url: user.picture_url.clone(),
    }
}

fn identity_ui_rows(identities: &[IdentityRow]) -> Vec<IdentityUi> {
    let unlink_disabled = identities.len() <= 1;
    identities
        .iter()
        .map(|identity| IdentityUi {
            provider_id: identity.provider_id.clone(),
            provider_subject: identity.provider_subject.clone(),
            email: identity.email.clone(),
            email_verified: identity.email_verified != 0,
            unlink_disabled,
        })
        .collect()
}

fn session_ui_rows(sessions: &[SessionRow], current_session_id: &str) -> Vec<SessionUi> {
    sessions
        .iter()
        .map(|session| SessionUi {
            id: session.id.clone(),
            client_id: session.client_id.clone(),
            current: session.id == current_session_id,
            created_at: Some(session.created_at.to_string()),
            expires_at: Some(session.expires_at.to_string()),
        })
        .collect()
}

fn application_ui_from_client(client: &Client) -> ApplicationUi {
    ApplicationUi {
        client_id: client.id.0.clone(),
        name: client.name.clone(),
        public_client: !client.confidential,
        redirect_uris: client.redirect_uris.clone(),
        allowed_origins: client.allowed_origins.clone(),
        allowed_email_domains: client.allowed_email_domains.clone(),
    }
}

fn client_admin_ui_from_row(row: ClientRow) -> Result<ClientAdminUi, String> {
    let response = client_response_from_row(row)?;
    Ok(ClientAdminUi {
        client_id: response.id,
        name: response.name,
        confidential: response.confidential,
        redirect_uris: response.redirect_uris,
        allowed_origins: response.allowed_origins,
        allowed_email_domains: response.allowed_email_domains,
        disabled: response.disabled,
        has_secret: response.has_secret,
    })
}

#[cfg(target_arch = "wasm32")]
fn product_name_from_env(env: &Env) -> String {
    env_string(env, "PRODUCT_NAME").unwrap_or_else(|| "Zeroth".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn html(document: String) -> worker::Result<Response> {
    let response = Response::from_html(document)?;
    response.headers().set("Cache-Control", "no-store")?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_path(request_url: &url::Url, path: &str) -> worker::Result<Response> {
    let mut target = request_url.clone();
    target.set_path(path);
    target.set_query(None);
    target.set_fragment(None);
    Response::redirect(target)
}

#[cfg(target_arch = "wasm32")]
async fn provider_callback_from_request(
    request: &mut Request,
    url: &url::Url,
) -> Result<ProviderCallback, ProviderCallbackError> {
    match request.method() {
        Method::Get => provider_callback_from_values(
            query_param(url, "code"),
            query_param(url, "state"),
            query_param(url, "error"),
            query_param(url, "error_description"),
            None,
        ),
        Method::Post => {
            let form = request.form_data().await.map_err(|error| {
                ProviderCallbackError::invalid_request(format!(
                    "could not parse provider callback form: {error}"
                ))
            })?;
            provider_callback_from_values(
                form.get_field("code"),
                form.get_field("state"),
                form.get_field("error"),
                form.get_field("error_description"),
                form.get_field("user"),
            )
        }
        _ => Err(ProviderCallbackError::invalid_request(
            "unsupported callback method",
        )),
    }
}

fn provider_callback_from_values(
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    apple_user_json: Option<String>,
) -> Result<ProviderCallback, ProviderCallbackError> {
    if let Some(error) = error {
        if error.is_empty() {
            return Err(ProviderCallbackError::invalid_request("missing error"));
        }
        let state = state.ok_or_else(|| ProviderCallbackError::invalid_request("missing state"))?;
        if state.is_empty() {
            return Err(ProviderCallbackError::invalid_request("missing state"));
        }
        return Ok(ProviderCallback {
            state,
            code: None,
            provider_error: Some(ProviderCallbackError {
                code: error,
                description: error_description
                    .unwrap_or_else(|| "provider returned an authorization error".to_owned()),
            }),
            apple_user_json: None,
        });
    }

    let code = code.ok_or_else(|| ProviderCallbackError::invalid_request("missing code"))?;
    let state = state.ok_or_else(|| ProviderCallbackError::invalid_request("missing state"))?;
    if code.is_empty() {
        return Err(ProviderCallbackError::invalid_request("missing code"));
    }
    if state.is_empty() {
        return Err(ProviderCallbackError::invalid_request("missing state"));
    }

    Ok(ProviderCallback {
        state,
        code: Some(code),
        provider_error: None,
        apple_user_json: apple_user_json.filter(|value| !value.trim().is_empty()),
    })
}

#[cfg(target_arch = "wasm32")]
async fn get_client(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<Client>> {
    get_registered_client(db, client_id)
        .await
        .map(|client| client.map(|registered_client| registered_client.client))
}

#[cfg(target_arch = "wasm32")]
async fn get_registered_client(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<RegisteredClient>> {
    let args = [worker::d1::D1Type::Text(client_id)];
    let row = db
        .prepare(
            "SELECT id, name, secret_hash, redirect_uris_json, allowed_origins_json,
                    allowed_email_domains_json,
                    confidential, disabled_at
             FROM zeroth_clients
             WHERE id = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<ClientRow>(None)
        .await?;

    row.map(registered_client_from_row)
        .transpose()
        .map(|client| client.flatten())
        .map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
async fn get_client_row_for_admin(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<ClientRow>> {
    let args = [worker::d1::D1Type::Text(client_id)];
    db.prepare(
        "SELECT id, name, secret_hash, redirect_uris_json, allowed_origins_json,
                allowed_email_domains_json,
                confidential, disabled_at
         FROM zeroth_clients
         WHERE id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<ClientRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_client_rows_for_admin(db: &worker::d1::D1Database) -> worker::Result<Vec<ClientRow>> {
    let args = [worker::d1::D1Type::Integer(CLIENT_LIST_LIMIT)];
    db.prepare(
        "SELECT id, name, secret_hash, redirect_uris_json, allowed_origins_json,
                allowed_email_domains_json,
                confidential, disabled_at
         FROM zeroth_clients
         ORDER BY id
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<ClientRow>()
}

#[cfg(target_arch = "wasm32")]
async fn upsert_client(
    db: &worker::d1::D1Database,
    client: &ValidatedClientUpsert,
    now: i32,
) -> worker::Result<()> {
    let redirect_uris_json = serde_json::to_string(&client.redirect_uris).map_err(|error| {
        worker::Error::RustError(format!("could not serialize redirect URIs: {error}"))
    })?;
    let allowed_origins_json = serde_json::to_string(&client.allowed_origins).map_err(|error| {
        worker::Error::RustError(format!("could not serialize allowed origins: {error}"))
    })?;
    let allowed_email_domains_json =
        serde_json::to_string(&client.allowed_email_domains).map_err(|error| {
            worker::Error::RustError(format!(
                "could not serialize allowed email domains: {error}"
            ))
        })?;
    let secret_hash = d1_optional_text(client.secret_hash.as_deref());
    let disabled_at = if client.disabled {
        worker::d1::D1Type::Integer(now)
    } else {
        worker::d1::D1Type::Null
    };
    let confidential = if client.confidential { 1 } else { 0 };
    let args = [
        worker::d1::D1Type::Text(&client.id),
        worker::d1::D1Type::Text(&client.name),
        secret_hash,
        worker::d1::D1Type::Integer(confidential),
        worker::d1::D1Type::Text(&redirect_uris_json),
        worker::d1::D1Type::Text(&allowed_origins_json),
        worker::d1::D1Type::Text(&allowed_email_domains_json),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
        disabled_at,
    ];

    db.prepare(
        "INSERT INTO zeroth_clients (
             id, name, secret_hash, confidential, redirect_uris_json,
             allowed_origins_json, allowed_email_domains_json, created_at, updated_at,
             disabled_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             secret_hash = CASE
                 WHEN excluded.confidential = 0 THEN NULL
                 WHEN excluded.secret_hash IS NOT NULL THEN excluded.secret_hash
                 ELSE zeroth_clients.secret_hash
             END,
             confidential = excluded.confidential,
             redirect_uris_json = excluded.redirect_uris_json,
             allowed_origins_json = excluded.allowed_origins_json,
             allowed_email_domains_json = excluded.allowed_email_domains_json,
             updated_at = excluded.updated_at,
             disabled_at = excluded.disabled_at",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn disable_client(
    db: &worker::d1::D1Database,
    client_id: &str,
    disabled_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Text(client_id),
    ];
    db.prepare(
        "UPDATE zeroth_clients
         SET disabled_at = ?, updated_at = ?
         WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn active_client_allowed_origins(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Result<Vec<String>, String>> {
    Ok(active_client_allowed_origins_from_client(
        get_client(db, client_id).await?,
    ))
}

#[cfg(target_arch = "wasm32")]
async fn origin_allowed_by_any_client(
    db: &worker::d1::D1Database,
    origin: &str,
) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Integer(CORS_ORIGIN_SCAN_LIMIT)];
    let rows = db
        .prepare(
            "SELECT allowed_origins_json
             FROM zeroth_clients
             WHERE disabled_at IS NULL
             ORDER BY id
             LIMIT ?",
        )
        .bind_refs(&args)?
        .all()
        .await?
        .results::<ClientOriginsRow>()?;

    origin_allowed_in_client_origin_rows(&rows, origin).map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
async fn get_auth_transaction(
    db: &worker::d1::D1Database,
    provider_state: &str,
) -> worker::Result<Option<StoredAuthTransaction>> {
    let args = [worker::d1::D1Type::Text(provider_state)];
    let row = db
        .prepare(
            "SELECT provider_state, client_id, provider_id, redirect_uri, provider_redirect_uri,
                    app_state, nonce, provider_nonce, code_challenge, code_challenge_method, scope,
                    link_user_id, link_session_id, session_return_to, created_at, expires_at,
                    consumed_at
             FROM zeroth_auth_transactions
             WHERE provider_state = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<AuthTransactionRow>(None)
        .await?;

    row.map(auth_transaction_from_row)
        .transpose()
        .map_err(worker_error)
}

#[cfg(target_arch = "wasm32")]
async fn consume_auth_transaction(
    db: &worker::d1::D1Database,
    provider_state: &str,
    consumed_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(consumed_at),
        worker::d1::D1Type::Text(provider_state),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_auth_transactions
         SET consumed_at = ?
         WHERE provider_state = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn get_identity_user_id(
    db: &worker::d1::D1Database,
    profile: &ProviderProfile,
) -> worker::Result<Option<String>> {
    let args = [
        worker::d1::D1Type::Text(&profile.provider_id.0),
        worker::d1::D1Type::Text(&profile.subject.0),
    ];
    let row = db
        .prepare(
            "SELECT user_id
             FROM zeroth_identities
             WHERE provider_id = ? AND provider_subject = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<IdentityUserRow>(None)
        .await?;

    Ok(row.map(|row| row.user_id))
}

#[cfg(target_arch = "wasm32")]
async fn complete_provider_identity_link(
    db: &worker::d1::D1Database,
    link_user_id: &UserId,
    link_session_id: Option<&str>,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<Result<(), IdentityLinkError>> {
    let Some(link_session_id) = link_session_id else {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link transaction is missing session binding",
        )));
    };
    let Some(session) = get_session(db, link_session_id).await? else {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link session was not found",
        )));
    };
    if session.user_id != link_user_id.0 || !session_row_is_active(&session, now) {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link session is no longer active",
        )));
    }

    let Some(user) = get_user(db, &link_user_id.0).await? else {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link user was not found",
        )));
    };
    if user.disabled_at.is_some() {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link user is disabled",
        )));
    }

    if let Some(existing_user_id) = get_identity_user_id(db, profile).await? {
        if existing_user_id != link_user_id.0 {
            return Ok(Err(IdentityLinkError::conflict(
                "identity is already linked to another user",
            )));
        }
    } else if count_identities_for_user(db, &link_user_id.0).await? >= IDENTITY_LIST_LIMIT {
        return Ok(Err(IdentityLinkError::invalid_request(
            "identity link limit has been reached",
        )));
    }

    update_user_from_profile(db, &link_user_id.0, profile, now).await?;
    upsert_identity_from_profile(db, &link_user_id.0, profile, raw_profile_json, now).await?;

    match get_identity_user_id(db, profile).await? {
        Some(user_id) if user_id == link_user_id.0 => Ok(Ok(())),
        Some(_) => Ok(Err(IdentityLinkError::conflict(
            "identity is already linked to another user",
        ))),
        None => Ok(Err(IdentityLinkError::invalid_request(
            "identity could not be linked",
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
async fn list_identities_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<Vec<IdentityRow>> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Integer(IDENTITY_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT provider_id, provider_subject, email, email_verified, display_name,
                picture_url, created_at, updated_at
         FROM zeroth_identities
         WHERE user_id = ?
         ORDER BY provider_id, created_at
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<IdentityRow>()
}

#[cfg(target_arch = "wasm32")]
async fn identity_exists_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    provider_id: &str,
    provider_subject: &str,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(provider_id),
        worker::d1::D1Type::Text(provider_subject),
    ];
    let row = db
        .prepare(
            "SELECT user_id
             FROM zeroth_identities
             WHERE user_id = ? AND provider_id = ? AND provider_subject = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<IdentityUserRow>(None)
        .await?;
    Ok(row.is_some())
}

#[cfg(target_arch = "wasm32")]
async fn count_identities_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<i32> {
    let args = [worker::d1::D1Type::Text(user_id)];
    let row = db
        .prepare(
            "SELECT COUNT(*) AS count
             FROM zeroth_identities
             WHERE user_id = ?",
        )
        .bind_refs(&args)?
        .first::<IdentityCountRow>(None)
        .await?;
    Ok(row.map(|row| row.count).unwrap_or(0))
}

#[cfg(target_arch = "wasm32")]
async fn delete_user_identity(
    db: &worker::d1::D1Database,
    user_id: &str,
    provider_id: &str,
    provider_subject: &str,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(provider_id),
        worker::d1::D1Type::Text(provider_subject),
        worker::d1::D1Type::Text(user_id),
    ];
    let result = db
        .prepare(
            "DELETE FROM zeroth_identities
         WHERE user_id = ? AND provider_id = ? AND provider_subject = ?
           AND (SELECT COUNT(*) FROM zeroth_identities WHERE user_id = ?) > 1",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn get_user_by_primary_email(
    db: &worker::d1::D1Database,
    email: &str,
) -> worker::Result<Option<UserRow>> {
    let args = [worker::d1::D1Type::Text(email)];
    db.prepare(
        "SELECT id, primary_email, display_name, picture_url, disabled_at
         FROM zeroth_users
         WHERE lower(primary_email) = lower(?)
         ORDER BY updated_at DESC
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<UserRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn insert_passkey_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    email: &str,
    display_name: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let display_name = d1_optional_text(display_name);
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(email),
        display_name,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_users (
             id, primary_email, display_name, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_passkey_registration_user(
    db: &worker::d1::D1Database,
    challenge: &PasskeyChallengeRow,
    now: i32,
) -> worker::Result<(String, String, Option<String>)> {
    if let Some(user_id) = challenge.user_id.as_deref() {
        let Some(user) = get_user(db, user_id).await? else {
            return Err(worker_error(
                "passkey registration user was not found".to_owned(),
            ));
        };
        let email = user
            .primary_email
            .or_else(|| challenge.email.clone())
            .ok_or_else(|| worker_error("passkey registration user has no email".to_owned()))?;
        let display_name = challenge.display_name.clone().or(user.display_name);
        return Ok((user_id.to_owned(), email, display_name));
    }

    let email = challenge
        .email
        .as_deref()
        .ok_or_else(|| worker_error("passkey registration challenge has no email".to_owned()))?;
    if let Some(user) = get_user_by_primary_email(db, email).await? {
        return Ok((user.id, email.to_owned(), challenge.display_name.clone()));
    }

    let user_id = format!("usr_{}", random_token()?);
    insert_passkey_user(db, &user_id, email, challenge.display_name.as_deref(), now).await?;
    Ok((user_id, email.to_owned(), challenge.display_name.clone()))
}

#[cfg(target_arch = "wasm32")]
async fn upsert_passkey_identity(
    db: &worker::d1::D1Database,
    user_id: &str,
    credential_id: &str,
    email: Option<&str>,
    display_name: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let email = d1_optional_text(email);
    let display_name = d1_optional_text(display_name);
    let raw_profile_json = serde_json::json!({
        "kind": "passkey",
        "credentialIdHash": hash_secret(credential_id)
    })
    .to_string();
    let args = [
        worker::d1::D1Type::Text("passkey"),
        worker::d1::D1Type::Text(credential_id),
        worker::d1::D1Type::Text(user_id),
        email,
        worker::d1::D1Type::Integer(1),
        display_name,
        worker::d1::D1Type::Text(&raw_profile_json),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_identities (
             provider_id, provider_subject, user_id, email, email_verified,
             display_name, raw_profile_json, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(provider_id, provider_subject) DO UPDATE SET
             email = excluded.email,
             email_verified = excluded.email_verified,
             display_name = excluded.display_name,
             raw_profile_json = excluded.raw_profile_json,
             updated_at = excluded.updated_at
         WHERE zeroth_identities.user_id = excluded.user_id",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_passkey_challenge(
    db: &worker::d1::D1Database,
    challenge: &str,
    kind: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    return_to: Option<&str>,
    email: Option<&str>,
    display_name: Option<&str>,
    label: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let challenge_hash = hash_secret(challenge);
    let user_id = d1_optional_text(user_id);
    let client_id = d1_optional_text(client_id);
    let return_to = d1_optional_text(return_to);
    let email = d1_optional_text(email);
    let display_name = d1_optional_text(display_name);
    let label = d1_optional_text(label);
    let args = [
        worker::d1::D1Type::Text(&challenge_hash),
        worker::d1::D1Type::Text(kind),
        user_id,
        client_id,
        return_to,
        email,
        display_name,
        label,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + PASSKEY_CHALLENGE_TTL_SECONDS),
    ];
    db.prepare(
        "INSERT INTO zeroth_passkey_challenges (
             challenge_hash, kind, user_id, client_id, return_to, email,
             display_name, label, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_passkey_challenge_by_hash(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
) -> worker::Result<Option<PasskeyChallengeRow>> {
    let args = [worker::d1::D1Type::Text(challenge_hash)];
    db.prepare(
        "SELECT challenge_hash, kind, user_id, client_id, return_to, email,
                display_name, label, created_at, expires_at, consumed_at
         FROM zeroth_passkey_challenges
         WHERE challenge_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<PasskeyChallengeRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn consume_passkey_challenge(
    db: &worker::d1::D1Database,
    challenge_hash: &str,
    consumed_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(consumed_at),
        worker::d1::D1Type::Text(challenge_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_passkey_challenges
             SET consumed_at = ?
             WHERE challenge_hash = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn cleanup_expired_passkey_challenges(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(PASSKEY_CHALLENGE_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_passkey_challenges
         WHERE challenge_hash IN (
             SELECT challenge_hash
             FROM zeroth_passkey_challenges
             WHERE expires_at <= ?
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

fn validate_passkey_challenge(
    challenge: &PasskeyChallengeRow,
    expected_kind: &str,
    now: i32,
) -> Result<(), String> {
    if challenge.kind != expected_kind {
        return Err("passkey challenge kind did not match".to_owned());
    }
    if challenge.consumed_at.is_some() {
        return Err("passkey challenge has already been consumed".to_owned());
    }
    if challenge.expires_at <= now {
        return Err("passkey challenge has expired".to_owned());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_passkey_credential(
    db: &worker::d1::D1Database,
    credential: &ValidatedPasskeyRegistration,
    user_id: &str,
    label: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let label = d1_optional_text(label);
    let args = [
        worker::d1::D1Type::Text(&credential.credential_id),
        worker::d1::D1Type::Text(user_id),
        label,
        worker::d1::D1Type::Text(&credential.public_key_x),
        worker::d1::D1Type::Text(&credential.public_key_y),
        worker::d1::D1Type::Integer(credential.sign_count),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_passkey_credentials (
             credential_id, user_id, label, public_key_x, public_key_y,
             sign_count, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_passkey_credential(
    db: &worker::d1::D1Database,
    credential_id: &str,
) -> worker::Result<Option<PasskeyCredentialRow>> {
    let args = [worker::d1::D1Type::Text(credential_id)];
    db.prepare(
        "SELECT credential_id, user_id, label, public_key_x, public_key_y,
                sign_count, created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_passkey_credentials
         WHERE credential_id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<PasskeyCredentialRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_active_passkey_credentials(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<PasskeyCredentialRow>> {
    let args = [worker::d1::D1Type::Integer(PASSKEY_CREDENTIAL_LIST_LIMIT)];
    db.prepare(
        "SELECT credential_id, user_id, label, public_key_x, public_key_y,
                sign_count, created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_passkey_credentials
         WHERE disabled_at IS NULL
         ORDER BY created_at DESC
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<PasskeyCredentialRow>()
}

#[cfg(target_arch = "wasm32")]
async fn list_passkey_credentials_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<Vec<PasskeyCredentialRow>> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Integer(PASSKEY_CREDENTIAL_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT credential_id, user_id, label, public_key_x, public_key_y,
                sign_count, created_at, updated_at, last_used_at, disabled_at
         FROM zeroth_passkey_credentials
         WHERE user_id = ? AND disabled_at IS NULL
         ORDER BY created_at DESC
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<PasskeyCredentialRow>()
}

#[cfg(target_arch = "wasm32")]
async fn update_passkey_credential_use(
    db: &worker::d1::D1Database,
    credential_id: &str,
    sign_count: i32,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(sign_count),
        worker::d1::D1Type::Integer(sign_count),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(credential_id),
    ];
    db.prepare(
        "UPDATE zeroth_passkey_credentials
         SET sign_count = CASE WHEN ? > sign_count THEN ? ELSE sign_count END,
             last_used_at = ?,
             updated_at = ?
         WHERE credential_id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn disable_passkey_credential(
    db: &worker::d1::D1Database,
    credential_id: &str,
    disabled_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Integer(disabled_at),
        worker::d1::D1Type::Text(credential_id),
    ];
    db.prepare(
        "UPDATE zeroth_passkey_credentials
         SET disabled_at = COALESCE(disabled_at, ?),
             updated_at = ?
         WHERE credential_id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_user(db: &worker::d1::D1Database, user_id: &str) -> worker::Result<Option<UserRow>> {
    let args = [worker::d1::D1Type::Text(user_id)];
    db.prepare(
        "SELECT id, primary_email, display_name, picture_url, disabled_at
         FROM zeroth_users
         WHERE id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<UserRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn get_user_token_claims(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<Option<UserTokenClaimsRow>> {
    let args = [worker::d1::D1Type::Text(user_id)];
    db.prepare(
        "SELECT u.id, u.primary_email, u.display_name, u.picture_url, u.disabled_at,
                EXISTS (
                    SELECT 1
                    FROM zeroth_identities i
                    WHERE i.user_id = u.id
                      AND i.email = u.primary_email
                      AND i.email_verified != 0
                    LIMIT 1
                ) AS email_verified
         FROM zeroth_users u
         WHERE u.id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<UserTokenClaimsRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn get_admin_user_row(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<Option<AdminUserRow>> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "SELECT u.id, u.primary_email, u.display_name, u.picture_url, u.created_at,
                u.updated_at, u.disabled_at,
                (SELECT COUNT(*)
                   FROM zeroth_identities i
                  WHERE i.user_id = u.id) AS identity_count,
                (SELECT COUNT(*)
                   FROM zeroth_sessions s
                  WHERE s.user_id = u.id
                    AND s.revoked_at IS NULL
                    AND s.expires_at > ?) AS active_session_count,
                EXISTS (
                    SELECT 1
                    FROM zeroth_identities i
                    WHERE i.user_id = u.id
                      AND i.email = u.primary_email
                      AND i.email_verified != 0
                    LIMIT 1
                ) AS email_verified,
                EXISTS (
                    SELECT 1
                    FROM zeroth_admin_memberships am
                    WHERE am.user_id = u.id
                      AND am.disabled_at IS NULL
                    LIMIT 1
                ) AS admin_membership_active
           FROM zeroth_users u
          WHERE u.id = ?
          LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<AdminUserRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_admin_user_rows(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<Vec<AdminUserRow>> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(USER_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT u.id, u.primary_email, u.display_name, u.picture_url, u.created_at,
                u.updated_at, u.disabled_at,
                (SELECT COUNT(*)
                   FROM zeroth_identities i
                  WHERE i.user_id = u.id) AS identity_count,
                (SELECT COUNT(*)
                   FROM zeroth_sessions s
                  WHERE s.user_id = u.id
                    AND s.revoked_at IS NULL
                    AND s.expires_at > ?) AS active_session_count,
                EXISTS (
                    SELECT 1
                    FROM zeroth_identities i
                    WHERE i.user_id = u.id
                      AND i.email = u.primary_email
                      AND i.email_verified != 0
                    LIMIT 1
                ) AS email_verified,
                EXISTS (
                    SELECT 1
                    FROM zeroth_admin_memberships am
                    WHERE am.user_id = u.id
                      AND am.disabled_at IS NULL
                    LIMIT 1
                ) AS admin_membership_active
           FROM zeroth_users u
          ORDER BY u.updated_at DESC, u.id
          LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<AdminUserRow>()
}

#[cfg(target_arch = "wasm32")]
async fn user_has_active_admin_membership(
    db: &worker::d1::D1Database,
    user_id: &str,
) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Text(user_id)];
    Ok(db
        .prepare(
            "SELECT user_id
             FROM zeroth_admin_memberships
             WHERE user_id = ? AND disabled_at IS NULL
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<AdminMembershipProbeRow>(None)
        .await?
        .is_some())
}

#[cfg(target_arch = "wasm32")]
async fn upsert_admin_membership(
    db: &worker::d1::D1Database,
    user_id: &str,
    granted_by: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text("admin"),
        worker::d1::D1Type::Text(granted_by),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];
    db.prepare(
        "INSERT INTO zeroth_admin_memberships (
             user_id, role, granted_by, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
             role = excluded.role,
             granted_by = excluded.granted_by,
             updated_at = excluded.updated_at,
             disabled_at = NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn disable_admin_membership(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_admin_memberships
         SET disabled_at = COALESCE(disabled_at, ?),
             updated_at = ?
         WHERE user_id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn admin_user_detail_response(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<Option<AdminUserDetailResponse>> {
    let Some(row) = get_admin_user_row(db, user_id, now).await? else {
        return Ok(None);
    };
    let identities = list_identities_for_user(db, user_id).await?;
    let active_sessions = list_active_sessions_for_user(db, user_id, now).await?;

    Ok(Some(AdminUserDetailResponse {
        user: admin_user_response_from_row(row),
        identities: identities_response(&identities).identities,
        active_sessions: active_sessions.iter().map(session_info_response).collect(),
    }))
}

#[cfg(target_arch = "wasm32")]
async fn set_admin_user_disabled(
    db: &worker::d1::D1Database,
    user_id: &str,
    disabled: bool,
    now: i32,
) -> worker::Result<()> {
    let disabled_at = if disabled {
        worker::d1::D1Type::Integer(now)
    } else {
        worker::d1::D1Type::Null
    };
    let args = [
        disabled_at,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_users
            SET disabled_at = ?, updated_at = ?
          WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_active_sessions_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_sessions
            SET revoked_at = ?
          WHERE user_id = ?
            AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_active_refresh_tokens_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
            SET revoked_at = ?
          WHERE user_id = ?
            AND revoked_at IS NULL
            AND rotated_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn list_audit_event_rows(
    db: &worker::d1::D1Database,
    filter: &AuditEventFilter,
) -> worker::Result<Vec<AuditEventRow>> {
    let mut conditions = Vec::new();
    let mut args = Vec::new();
    if let Some(event_type) = &filter.event_type {
        conditions.push("event_type = ?");
        args.push(worker::d1::D1Type::Text(event_type));
    }
    if let Some(user_id) = &filter.user_id {
        conditions.push("user_id = ?");
        args.push(worker::d1::D1Type::Text(user_id));
    }
    if let Some(client_id) = &filter.client_id {
        conditions.push("client_id = ?");
        args.push(worker::d1::D1Type::Text(client_id));
    }
    if let Some(provider_id) = &filter.provider_id {
        conditions.push("provider_id = ?");
        args.push(worker::d1::D1Type::Text(provider_id));
    }
    args.push(worker::d1::D1Type::Integer(AUDIT_EVENT_LIST_LIMIT));

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "SELECT id, event_type, user_id, client_id, provider_id, created_at,
                ip_hash, user_agent, details_json
           FROM zeroth_audit_events
          {where_clause}
          ORDER BY created_at DESC, id DESC
          LIMIT ?"
    );
    db.prepare(sql)
        .bind_refs(&args)?
        .all()
        .await?
        .results::<AuditEventRow>()
}

#[cfg(target_arch = "wasm32")]
async fn put_audit_event(
    db: &worker::d1::D1Database,
    context: &AuditRequestContext,
    event_type: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    provider_id: Option<&str>,
    details: serde_json::Value,
    now: i32,
) -> worker::Result<()> {
    let id = format!("evt_{}", random_token()?);
    let details_json = audit_details_json(details).map_err(worker_error)?;
    let user_id = d1_optional_text(user_id);
    let client_id = d1_optional_text(client_id);
    let provider_id = d1_optional_text(provider_id);
    let ip_hash = d1_optional_text(context.ip_hash.as_deref());
    let user_agent = d1_optional_text(context.user_agent.as_deref());
    let args = [
        worker::d1::D1Type::Text(&id),
        worker::d1::D1Type::Text(event_type),
        user_id,
        client_id,
        provider_id,
        worker::d1::D1Type::Integer(now),
        ip_hash,
        user_agent,
        worker::d1::D1Type::Text(&details_json),
    ];

    db.prepare(
        "INSERT INTO zeroth_audit_events (
             id, event_type, user_id, client_id, provider_id, created_at,
             ip_hash, user_agent, details_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn record_audit_event(
    db: &worker::d1::D1Database,
    request: &Request,
    event_type: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    provider_id: Option<&str>,
    details: serde_json::Value,
    now: i32,
) {
    let context = audit_request_context(request).unwrap_or_default();
    let _ = put_audit_event(
        db,
        &context,
        event_type,
        user_id,
        client_id,
        provider_id,
        details,
        now,
    )
    .await;
}

#[cfg(target_arch = "wasm32")]
async fn upsert_provider_profile(
    db: &worker::d1::D1Database,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<String> {
    let user_id = match get_identity_user_id(db, profile).await? {
        Some(user_id) => {
            update_user_from_profile(db, &user_id, profile, now).await?;
            user_id
        }
        None => {
            let user_id = format!("usr_{}", random_token()?);
            insert_user_from_profile(db, &user_id, profile, now).await?;
            user_id
        }
    };

    upsert_identity_from_profile(db, &user_id, profile, raw_profile_json, now).await?;
    let identity_user_id = get_identity_user_id(db, profile).await?;
    validate_provider_identity_attached_to_user(identity_user_id.as_deref(), &user_id)
        .map_err(worker_error)?;
    Ok(user_id)
}

#[cfg(any(test, target_arch = "wasm32"))]
fn validate_provider_identity_attached_to_user(
    actual_user_id: Option<&str>,
    expected_user_id: &str,
) -> Result<(), String> {
    match actual_user_id {
        Some(actual_user_id) if actual_user_id == expected_user_id => Ok(()),
        Some(_) => Err("provider identity is already linked to another user".to_owned()),
        None => Err("provider identity could not be linked to the user".to_owned()),
    }
}

#[cfg(target_arch = "wasm32")]
async fn insert_user_from_profile(
    db: &worker::d1::D1Database,
    user_id: &str,
    profile: &ProviderProfile,
    now: i32,
) -> worker::Result<()> {
    let primary_email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let args = [
        worker::d1::D1Type::Text(user_id),
        primary_email,
        display_name,
        picture_url,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];

    db.prepare(
        "INSERT INTO zeroth_users (
             id, primary_email, display_name, picture_url, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn update_user_from_profile(
    db: &worker::d1::D1Database,
    user_id: &str,
    profile: &ProviderProfile,
    now: i32,
) -> worker::Result<()> {
    let primary_email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let args = [
        primary_email,
        display_name,
        picture_url,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];

    db.prepare(
        "UPDATE zeroth_users
         SET primary_email = COALESCE(?, primary_email),
             display_name = COALESCE(display_name, ?),
             picture_url = COALESCE(picture_url, ?),
             updated_at = ?
         WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn update_user_profile_patch(
    db: &worker::d1::D1Database,
    user_id: &str,
    patch: &ProfilePatch,
    now: i32,
) -> worker::Result<()> {
    let display_name_present = i32::from(patch.display_name.is_some());
    let picture_url_present = i32::from(patch.picture_url.is_some());
    let display_name = d1_optional_text(patch.display_name.as_ref().and_then(|value| {
        value
            .as_ref()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }));
    let picture_url = d1_optional_text(patch.picture_url.as_ref().and_then(|value| {
        value
            .as_ref()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }));
    let args = [
        worker::d1::D1Type::Integer(display_name_present),
        display_name,
        worker::d1::D1Type::Integer(picture_url_present),
        picture_url,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Text(user_id),
    ];

    db.prepare(
        "UPDATE zeroth_users
         SET display_name = CASE WHEN ? THEN ? ELSE display_name END,
             picture_url = CASE WHEN ? THEN ? ELSE picture_url END,
             updated_at = ?
         WHERE id = ?",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn upsert_identity_from_profile(
    db: &worker::d1::D1Database,
    user_id: &str,
    profile: &ProviderProfile,
    raw_profile_json: Option<&str>,
    now: i32,
) -> worker::Result<()> {
    let email = d1_optional_text(profile.email.as_deref());
    let display_name = d1_optional_text(profile.display_name.as_deref());
    let picture_url = d1_optional_text(profile.picture_url.as_deref());
    let raw_profile_json = d1_optional_text(raw_profile_json);
    let email_verified = i32::from(profile.email_verified);
    let args = [
        worker::d1::D1Type::Text(&profile.provider_id.0),
        worker::d1::D1Type::Text(&profile.subject.0),
        worker::d1::D1Type::Text(user_id),
        email,
        worker::d1::D1Type::Integer(email_verified),
        display_name,
        picture_url,
        raw_profile_json,
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now),
    ];

    db.prepare(
        "INSERT INTO zeroth_identities (
             provider_id, provider_subject, user_id, email, email_verified,
             display_name, picture_url, raw_profile_json, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(provider_id, provider_subject) DO UPDATE SET
             email = excluded.email,
             email_verified = excluded.email_verified,
             display_name = excluded.display_name,
             picture_url = excluded.picture_url,
             raw_profile_json = excluded.raw_profile_json,
             updated_at = excluded.updated_at
         WHERE zeroth_identities.user_id = excluded.user_id",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_authorization_code(
    db: &worker::d1::D1Database,
    code: &str,
    transaction: &AuthTransaction,
    user_id: &str,
    session_id: Option<&str>,
    auth_time: i32,
    now: i32,
) -> worker::Result<()> {
    let code_hash = hash_secret(code);
    let scope = transaction.scope.as_slice().join(" ");
    let session_id = d1_optional_text(session_id);
    let nonce = d1_optional_text(transaction.nonce.as_deref());
    let code_challenge = d1_optional_text(transaction.code_challenge.as_deref());
    let code_challenge_method = d1_optional_text(transaction.code_challenge_method.as_deref());
    put_authorization_code_values(
        db,
        &code_hash,
        &transaction.client_id.0,
        &transaction.redirect_uri,
        user_id,
        session_id,
        auth_time,
        nonce,
        code_challenge,
        code_challenge_method,
        &scope,
        now,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn put_authorization_code_for_request(
    db: &worker::d1::D1Database,
    code: &str,
    request: &AuthorizationRequest,
    user_id: &str,
    session_id: Option<&str>,
    auth_time: i32,
    now: i32,
) -> worker::Result<()> {
    let code_hash = hash_secret(code);
    let scope = request.scope.as_slice().join(" ");
    let session_id = d1_optional_text(session_id);
    let nonce = d1_optional_text(request.nonce.as_deref());
    let code_challenge = d1_optional_text(request.code_challenge.as_deref());
    let code_challenge_method = d1_optional_text(
        request
            .code_challenge_method
            .as_ref()
            .map(|method| method.as_str()),
    );
    put_authorization_code_values(
        db,
        &code_hash,
        &request.client_id.0,
        &request.redirect_uri,
        user_id,
        session_id,
        auth_time,
        nonce,
        code_challenge,
        code_challenge_method,
        &scope,
        now,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn put_authorization_code_values(
    db: &worker::d1::D1Database,
    code_hash: &str,
    client_id: &str,
    redirect_uri: &str,
    user_id: &str,
    session_id: worker::d1::D1Type<'_>,
    auth_time: i32,
    nonce: worker::d1::D1Type<'_>,
    code_challenge: worker::d1::D1Type<'_>,
    code_challenge_method: worker::d1::D1Type<'_>,
    scope: &str,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Text(code_hash),
        worker::d1::D1Type::Text(client_id),
        worker::d1::D1Type::Text(redirect_uri),
        worker::d1::D1Type::Text(user_id),
        session_id,
        worker::d1::D1Type::Integer(auth_time),
        nonce,
        code_challenge,
        code_challenge_method,
        worker::d1::D1Type::Text(scope),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + AUTH_CODE_TTL_SECONDS),
    ];

    db.prepare(
        "INSERT INTO zeroth_auth_codes (
             code_hash, client_id, redirect_uri, user_id, session_id, auth_time, nonce,
             code_challenge, code_challenge_method, scope, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_authorization_code(
    db: &worker::d1::D1Database,
    code: &str,
) -> worker::Result<Option<AuthCodeRow>> {
    let code_hash = hash_secret(code);
    let args = [worker::d1::D1Type::Text(&code_hash)];
    db.prepare(
        "SELECT code_hash, client_id, redirect_uri, user_id, session_id, auth_time, nonce,
                code_challenge, code_challenge_method, scope, created_at, expires_at, consumed_at
         FROM zeroth_auth_codes
         WHERE code_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<AuthCodeRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn consume_authorization_code(
    db: &worker::d1::D1Database,
    code_hash: &str,
    consumed_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(consumed_at),
        worker::d1::D1Type::Text(code_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_auth_codes
         SET consumed_at = ?
         WHERE code_hash = ? AND consumed_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn put_refresh_token(
    db: &worker::d1::D1Database,
    refresh_token: &str,
    code: &AuthCodeRow,
    now: i32,
) -> worker::Result<()> {
    let token_hash = hash_secret(refresh_token);
    put_refresh_token_row(db, &token_hash, &TokenIssue::from_auth_code(code), now).await
}

#[cfg(target_arch = "wasm32")]
async fn put_rotated_refresh_token(
    db: &worker::d1::D1Database,
    refresh_token: &str,
    row: &RefreshTokenRow,
    now: i32,
) -> worker::Result<()> {
    let token_hash = hash_secret(refresh_token);
    put_refresh_token_row(db, &token_hash, &TokenIssue::from_refresh_token(row), now).await
}

#[cfg(target_arch = "wasm32")]
async fn put_refresh_token_row(
    db: &worker::d1::D1Database,
    token_hash: &str,
    issue: &TokenIssue,
    now: i32,
) -> worker::Result<()> {
    let session_id = d1_optional_text(issue.session_id.as_deref());
    let auth_time = d1_optional_integer(issue.auth_time);
    let args = [
        worker::d1::D1Type::Text(token_hash),
        worker::d1::D1Type::Text(&issue.client_id),
        worker::d1::D1Type::Text(&issue.user_id),
        session_id,
        auth_time,
        worker::d1::D1Type::Text(&issue.scope),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + REFRESH_TOKEN_TTL_SECONDS),
    ];
    db.prepare(
        "INSERT INTO zeroth_refresh_tokens (
             token_hash, client_id, user_id, session_id, auth_time, scope, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_refresh_token(
    db: &worker::d1::D1Database,
    refresh_token: &str,
) -> worker::Result<Option<RefreshTokenRow>> {
    let token_hash = hash_secret(refresh_token);
    let args = [worker::d1::D1Type::Text(&token_hash)];
    db.prepare(
        "SELECT token_hash, client_id, user_id, session_id, auth_time, scope,
                created_at, expires_at, rotated_at, revoked_at
         FROM zeroth_refresh_tokens
         WHERE token_hash = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<RefreshTokenRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn rotate_refresh_token(
    db: &worker::d1::D1Database,
    token_hash: &str,
    rotated_at: i32,
) -> worker::Result<bool> {
    let args = [
        worker::d1::D1Type::Integer(rotated_at),
        worker::d1::D1Type::Text(token_hash),
    ];
    let result = db
        .prepare(
            "UPDATE zeroth_refresh_tokens
         SET rotated_at = ?
         WHERE token_hash = ? AND rotated_at IS NULL AND revoked_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
    d1_result_changed_one(result)
}

#[cfg(target_arch = "wasm32")]
async fn revoke_refresh_token(
    db: &worker::d1::D1Database,
    token_hash: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(token_hash),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
         SET revoked_at = ?
         WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_refresh_token_family(
    db: &worker::d1::D1Database,
    row: &RefreshTokenRow,
    revoked_at: i32,
) -> worker::Result<()> {
    if let Some(session_id) = row.session_id.as_deref() {
        let args = [
            worker::d1::D1Type::Integer(revoked_at),
            worker::d1::D1Type::Text(&row.client_id),
            worker::d1::D1Type::Text(&row.user_id),
            worker::d1::D1Type::Text(session_id),
        ];
        db.prepare(
            "UPDATE zeroth_refresh_tokens
             SET revoked_at = ?
             WHERE client_id = ? AND user_id = ? AND session_id = ? AND revoked_at IS NULL",
        )
        .bind_refs(&args)?
        .run()
        .await?;
        return Ok(());
    }

    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(&row.client_id),
        worker::d1::D1Type::Text(&row.user_id),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
         SET revoked_at = ?
         WHERE client_id = ? AND user_id = ? AND session_id IS NULL AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    user_id: &str,
    client_id: &str,
    now: i32,
    user_agent: Option<&str>,
    ip_hash: Option<&str>,
) -> worker::Result<()> {
    let user_agent = d1_optional_text(user_agent);
    let ip_hash = d1_optional_text(ip_hash);
    let args = [
        worker::d1::D1Type::Text(session_id),
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Text(client_id),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(now + SESSION_TTL_SECONDS),
        user_agent,
        ip_hash,
    ];
    db.prepare(
        "INSERT INTO zeroth_sessions (
             id, user_id, client_id, created_at, expires_at, user_agent, ip_hash
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get_session(
    db: &worker::d1::D1Database,
    session_id: &str,
) -> worker::Result<Option<SessionRow>> {
    let args = [worker::d1::D1Type::Text(session_id)];
    db.prepare(
        "SELECT id, user_id, client_id, created_at, expires_at, revoked_at, user_agent, ip_hash
         FROM zeroth_sessions
         WHERE id = ?
         LIMIT 1",
    )
    .bind_refs(&args)?
    .first::<SessionRow>(None)
    .await
}

#[cfg(target_arch = "wasm32")]
async fn list_active_sessions_for_user(
    db: &worker::d1::D1Database,
    user_id: &str,
    now: i32,
) -> worker::Result<Vec<SessionRow>> {
    let args = [
        worker::d1::D1Type::Text(user_id),
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(SESSION_LIST_LIMIT),
    ];
    db.prepare(
        "SELECT id, user_id, client_id, created_at, expires_at, revoked_at, user_agent, ip_hash
         FROM zeroth_sessions
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
         ORDER BY created_at DESC
         LIMIT ?",
    )
    .bind_refs(&args)?
    .all()
    .await?
    .results::<SessionRow>()
}

#[cfg(target_arch = "wasm32")]
async fn revoke_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(session_id),
    ];
    db.prepare(
        "UPDATE zeroth_sessions
         SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_user_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(session_id),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_sessions
         SET revoked_at = ?
         WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn revoke_refresh_token_family_for_session(
    db: &worker::d1::D1Database,
    session_id: &str,
    user_id: &str,
    revoked_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(revoked_at),
        worker::d1::D1Type::Text(session_id),
        worker::d1::D1Type::Text(user_id),
    ];
    db.prepare(
        "UPDATE zeroth_refresh_tokens
         SET revoked_at = ?
         WHERE session_id = ? AND user_id = ? AND revoked_at IS NULL",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn current_session_from_request(
    request: &Request,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
) -> worker::Result<Option<CurrentSession>> {
    let Some(session_id) = session_id_from_request(request, &config.cookie_name)? else {
        return Ok(None);
    };
    let Some(session) = get_session(db, &session_id).await? else {
        return Ok(None);
    };
    if !session_row_is_active(&session, now) {
        return Ok(None);
    }

    let Some(user) = get_user(db, &session.user_id).await? else {
        return Ok(None);
    };
    if user.disabled_at.is_some() {
        return Ok(None);
    }

    Ok(Some(CurrentSession { session, user }))
}

#[cfg(target_arch = "wasm32")]
async fn cleanup_expired_auth_transactions(
    db: &worker::d1::D1Database,
    now: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(now),
        worker::d1::D1Type::Integer(AUTH_TRANSACTION_CLEANUP_LIMIT),
    ];
    db.prepare(
        "DELETE FROM zeroth_auth_transactions
         WHERE provider_state IN (
             SELECT provider_state
             FROM zeroth_auth_transactions
             WHERE expires_at <= ?
             ORDER BY expires_at
             LIMIT ?
         )",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn put_auth_transaction(
    db: &worker::d1::D1Database,
    transaction: &AuthTransaction,
) -> worker::Result<()> {
    let scope = transaction.scope.as_slice().join(" ");
    let created_at = system_time_to_d1_integer(transaction.created_at)?;
    let expires_at = system_time_to_d1_integer(transaction.expires_at)?;
    let app_state = d1_optional_text(transaction.app_state.as_deref());
    let nonce = d1_optional_text(transaction.nonce.as_deref());
    let provider_nonce = d1_optional_text(transaction.provider_nonce.as_deref());
    let code_challenge = d1_optional_text(transaction.code_challenge.as_deref());
    let code_challenge_method = d1_optional_text(transaction.code_challenge_method.as_deref());
    let link_user_id = d1_optional_text(
        transaction
            .link_user_id
            .as_ref()
            .map(|user_id| user_id.0.as_str()),
    );
    let link_session_id = d1_optional_text(transaction.link_session_id.as_deref());
    let session_return_to = d1_optional_text(transaction.session_return_to.as_deref());
    let args = [
        worker::d1::D1Type::Text(&transaction.provider_state),
        worker::d1::D1Type::Text(&transaction.client_id.0),
        worker::d1::D1Type::Text(&transaction.provider_id.0),
        worker::d1::D1Type::Text(&transaction.redirect_uri),
        worker::d1::D1Type::Text(&transaction.provider_redirect_uri),
        app_state,
        nonce,
        provider_nonce,
        code_challenge,
        code_challenge_method,
        worker::d1::D1Type::Text(&scope),
        link_user_id,
        link_session_id,
        session_return_to,
        worker::d1::D1Type::Integer(created_at),
        worker::d1::D1Type::Integer(expires_at),
    ];

    db.prepare(
        "INSERT INTO zeroth_auth_transactions (
             provider_state, client_id, provider_id, redirect_uri, provider_redirect_uri,
             app_state, nonce, provider_nonce, code_challenge, code_challenge_method, scope, link_user_id,
             link_session_id, session_return_to, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_d1_schema(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    if let Err(error) = validate_admin_request(&request, &env, &db, &config, now).await {
        return client_management_error_json(&error);
    }

    let mut migrations_applied = Vec::new();
    let mut migrations_skipped = Vec::new();
    ensure_schema_migrations_table(&db).await?;
    for migration in zeroth_storage::migrations::ALL {
        if schema_migration_applied(&db, migration.version).await? {
            migrations_skipped.push(migration.name);
            continue;
        }
        for statement in migration.statements() {
            db.prepare(statement.to_owned()).run().await?;
        }
        record_schema_migration(&db, migration, now).await?;
        migrations_applied.push(migration.name);
    }
    ensure_compat_columns(&db).await?;
    record_audit_event(
        &db,
        &request,
        "schema.ensure",
        None,
        None,
        None,
        serde_json::json!({
            "applied": &migrations_applied,
            "skipped": &migrations_skipped
        }),
        now,
    )
    .await;

    json(&MigrationResponse {
        ok: true,
        binding: D1_BINDING,
        migrations_applied,
        migrations_skipped,
    })
}

#[cfg(target_arch = "wasm32")]
async fn d1_schema_status(request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    if let Err(error) =
        validate_admin_request(&request, &env, &db, &config, unix_timestamp_seconds()).await
    {
        return client_management_error_json(&error);
    }

    let tables = db_table_statuses(&db).await?;
    let migrations_table_present = tables
        .iter()
        .any(|table| table.name == zeroth_storage::SCHEMA_MIGRATIONS_TABLE && table.present);
    let applied_migration_versions = if migrations_table_present {
        applied_schema_migration_versions(&db).await?
    } else {
        Vec::new()
    };
    let migrations = zeroth_storage::migrations::ALL
        .iter()
        .map(|migration| DbMigrationStatus {
            version: migration.version,
            name: migration.name,
            applied: applied_migration_versions.contains(&migration.version),
        })
        .collect::<Vec<_>>();
    let compatibility_columns = db_compatibility_column_statuses(&db).await?;
    let clients_table_present = tables
        .iter()
        .any(|table| table.name == "zeroth_clients" && table.present);
    let client_count = if clients_table_present {
        count_registered_clients(&db).await?
    } else {
        0
    };
    let ok = db_schema_status_ok(&tables, &migrations, &compatibility_columns);

    let response = DbSchemaStatusResponse {
        ok,
        binding: D1_BINDING,
        tables,
        migrations,
        compatibility_columns,
        client_count,
    };
    let status = if response.ok { 200 } else { 503 };
    json_status(&response, status)
}

#[cfg(target_arch = "wasm32")]
async fn db_table_statuses(db: &worker::d1::D1Database) -> worker::Result<Vec<DbTableStatus>> {
    let mut tables = Vec::with_capacity(zeroth_storage::REQUIRED_TABLES.len());
    for table in zeroth_storage::REQUIRED_TABLES {
        tables.push(DbTableStatus {
            name: table,
            present: db_table_exists(db, table).await?,
        });
    }
    Ok(tables)
}

#[cfg(target_arch = "wasm32")]
async fn db_table_exists(db: &worker::d1::D1Database, table: &str) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Text(table)];
    let row = db
        .prepare(
            "SELECT name
             FROM sqlite_master
             WHERE type = 'table' AND name = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<TableColumnRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.name == table))
}

#[cfg(target_arch = "wasm32")]
async fn applied_schema_migration_versions(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<i32>> {
    let rows = db
        .prepare(
            "SELECT version
             FROM zeroth_schema_migrations
             ORDER BY version",
        )
        .all()
        .await?
        .results::<SchemaMigrationRow>()?;
    Ok(rows.into_iter().map(|row| row.version).collect())
}

#[cfg(target_arch = "wasm32")]
async fn db_compatibility_column_statuses(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<DbCompatibilityColumnStatus>> {
    let mut statuses = Vec::with_capacity(zeroth_storage::compatibility::ALL.len());
    for table in zeroth_storage::compatibility::TABLES {
        let columns = db
            .prepare(format!("PRAGMA table_info({table})"))
            .all()
            .await?
            .results::<TableColumnRow>()?;

        for compat in zeroth_storage::compatibility::ALL
            .iter()
            .copied()
            .filter(|compat| compat.table == *table)
        {
            statuses.push(DbCompatibilityColumnStatus {
                table: compat.table,
                name: compat.name,
                present: columns.iter().any(|column| column.name == compat.name),
            });
        }
    }
    Ok(statuses)
}

#[cfg(target_arch = "wasm32")]
async fn count_registered_clients(db: &worker::d1::D1Database) -> worker::Result<i32> {
    let row = db
        .prepare("SELECT COUNT(*) AS count FROM zeroth_clients")
        .first::<IdentityCountRow>(None)
        .await?;
    Ok(row.map(|row| row.count).unwrap_or(0))
}

fn db_schema_status_ok(
    tables: &[DbTableStatus],
    migrations: &[DbMigrationStatus],
    compatibility_columns: &[DbCompatibilityColumnStatus],
) -> bool {
    zeroth_storage::REQUIRED_TABLES.iter().all(|required| {
        tables
            .iter()
            .any(|table| table.name == *required && table.present)
    }) && zeroth_storage::migrations::ALL.iter().all(|required| {
        migrations.iter().any(|migration| {
            migration.version == required.version
                && migration.name == required.name
                && migration.applied
        })
    }) && zeroth_storage::compatibility::ALL.iter().all(|required| {
        compatibility_columns.iter().any(|column| {
            column.table == required.table && column.name == required.name && column.present
        })
    })
}

#[cfg(target_arch = "wasm32")]
async fn ensure_schema_migrations_table(db: &worker::d1::D1Database) -> worker::Result<()> {
    db.prepare(zeroth_storage::SCHEMA_MIGRATIONS_CREATE_SQL)
        .run()
        .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn schema_migration_applied(
    db: &worker::d1::D1Database,
    version: i32,
) -> worker::Result<bool> {
    let args = [worker::d1::D1Type::Integer(version)];
    let row = db
        .prepare(
            "SELECT version
             FROM zeroth_schema_migrations
             WHERE version = ?
             LIMIT 1",
        )
        .bind_refs(&args)?
        .first::<SchemaMigrationRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.version == version))
}

#[cfg(target_arch = "wasm32")]
async fn record_schema_migration(
    db: &worker::d1::D1Database,
    migration: &zeroth_storage::Migration,
    applied_at: i32,
) -> worker::Result<()> {
    let args = [
        worker::d1::D1Type::Integer(migration.version),
        worker::d1::D1Type::Text(migration.name),
        worker::d1::D1Type::Integer(applied_at),
    ];
    db.prepare(
        "INSERT OR IGNORE INTO zeroth_schema_migrations (version, name, applied_at)
         VALUES (?, ?, ?)",
    )
    .bind_refs(&args)?
    .run()
    .await?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn ensure_compat_columns(db: &worker::d1::D1Database) -> worker::Result<()> {
    for table in zeroth_storage::compatibility::TABLES {
        let pragma = format!("PRAGMA table_info({table})");
        let columns = db
            .prepare(pragma)
            .all()
            .await?
            .results::<TableColumnRow>()?;

        for compat in zeroth_storage::compatibility::ALL
            .iter()
            .copied()
            .filter(|compat| compat.table == *table)
        {
            if columns.iter().any(|column| column.name == compat.name) {
                continue;
            }
            db.prepare(compat.alter_table_sql()).run().await?;
        }
    }

    Ok(())
}

fn auth_transaction_from_request(
    request: &AuthorizationRequest,
    provider_id: &str,
    provider_state: String,
    provider_nonce: String,
    provider_redirect_uri: String,
    created_at: i32,
) -> AuthTransaction {
    AuthTransaction {
        provider_state,
        client_id: request.client_id.clone(),
        provider_id: ProviderId(provider_id.to_owned()),
        redirect_uri: request.redirect_uri.clone(),
        provider_redirect_uri,
        app_state: request.state.clone(),
        nonce: request.nonce.clone(),
        provider_nonce: Some(provider_nonce),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: request
            .code_challenge_method
            .as_ref()
            .map(|method| method.as_str().to_owned()),
        scope: request.scope.clone(),
        link_user_id: None,
        link_session_id: None,
        session_return_to: None,
        created_at: unix_seconds_to_system_time(created_at),
        expires_at: unix_seconds_to_system_time(created_at + AUTH_TRANSACTION_TTL_SECONDS),
    }
}

fn auth_transaction_from_session_login_request(
    client: &Client,
    provider_id: &str,
    provider_state: String,
    provider_nonce: String,
    provider_redirect_uri: String,
    return_to: String,
    app_state: Option<String>,
    created_at: i32,
) -> AuthTransaction {
    AuthTransaction {
        provider_state,
        client_id: client.id.clone(),
        provider_id: ProviderId(provider_id.to_owned()),
        redirect_uri: return_to.clone(),
        provider_redirect_uri,
        app_state,
        nonce: None,
        provider_nonce: Some(provider_nonce),
        code_challenge: None,
        code_challenge_method: None,
        scope: ScopeSet::new(["openid", "email", "profile"]),
        link_user_id: None,
        link_session_id: None,
        session_return_to: Some(return_to),
        created_at: unix_seconds_to_system_time(created_at),
        expires_at: unix_seconds_to_system_time(created_at + AUTH_TRANSACTION_TTL_SECONDS),
    }
}

fn auth_transaction_from_link_request(
    client: &Client,
    provider_id: &str,
    provider_state: String,
    provider_nonce: String,
    provider_redirect_uri: String,
    return_to: String,
    app_state: Option<String>,
    user_id: &str,
    session_id: &str,
    created_at: i32,
) -> AuthTransaction {
    AuthTransaction {
        provider_state,
        client_id: client.id.clone(),
        provider_id: ProviderId(provider_id.to_owned()),
        redirect_uri: return_to,
        provider_redirect_uri,
        app_state,
        nonce: None,
        provider_nonce: Some(provider_nonce),
        code_challenge: None,
        code_challenge_method: None,
        scope: ScopeSet::new(["openid", "email", "profile"]),
        link_user_id: Some(UserId(user_id.to_owned())),
        link_session_id: Some(session_id.to_owned()),
        session_return_to: None,
        created_at: unix_seconds_to_system_time(created_at),
        expires_at: unix_seconds_to_system_time(created_at + AUTH_TRANSACTION_TTL_SECONDS),
    }
}

fn auth_transaction_from_row(row: AuthTransactionRow) -> Result<StoredAuthTransaction, String> {
    Ok(StoredAuthTransaction {
        transaction: AuthTransaction {
            provider_state: row.provider_state,
            client_id: ClientId(row.client_id),
            provider_id: ProviderId(row.provider_id),
            redirect_uri: row.redirect_uri,
            provider_redirect_uri: row.provider_redirect_uri,
            app_state: row.app_state,
            nonce: row.nonce,
            provider_nonce: row.provider_nonce,
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            scope: ScopeSet::new(row.scope.split_whitespace()),
            link_user_id: row.link_user_id.map(UserId),
            link_session_id: row.link_session_id,
            session_return_to: row.session_return_to,
            created_at: unix_seconds_to_system_time(row.created_at),
            expires_at: unix_seconds_to_system_time(row.expires_at),
        },
        consumed_at: row.consumed_at,
    })
}

fn validate_stored_auth_transaction(
    record: &StoredAuthTransaction,
    now: i32,
) -> Result<(), ProviderCallbackError> {
    if record.consumed_at.is_some() {
        return Err(ProviderCallbackError::invalid_request(
            "provider callback state has already been consumed",
        ));
    }

    let expires_at = system_time_to_unix_seconds(record.transaction.expires_at)
        .map_err(ProviderCallbackError::invalid_request)?;
    if expires_at <= now {
        return Err(ProviderCallbackError::invalid_request(
            "provider callback state has expired",
        ));
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_client(
    transaction: &AuthTransaction,
    issuer: &str,
    code: &str,
) -> worker::Result<Response> {
    let redirect_url = client_redirect_url(transaction, issuer, code)
        .map_err(|error| worker::Error::RustError(error.description))?;
    Response::redirect(redirect_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_authorization_request_client(
    request: &AuthorizationRequest,
    issuer: &str,
    code: &str,
) -> worker::Result<Response> {
    let redirect_url = authorization_request_client_redirect_url(request, issuer, code)
        .map_err(|error| worker::Error::RustError(error.description))?;
    Response::redirect(redirect_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_authorization_request_error(
    request: &AuthorizationRequest,
    issuer: &str,
    error: &str,
    error_description: &str,
) -> worker::Result<Response> {
    let redirect_url =
        authorization_request_error_redirect_url(request, issuer, error, error_description)
            .map_err(worker::Error::RustError)?;
    Response::redirect(redirect_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_session_login_return(transaction: &AuthTransaction) -> worker::Result<Response> {
    let return_url =
        session_login_return_url(transaction).map_err(|error| worker::Error::RustError(error))?;
    Response::redirect(return_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_provider_callback_error(
    transaction: &AuthTransaction,
    issuer: &str,
    error: &ProviderCallbackError,
) -> worker::Result<Response> {
    let return_url = provider_callback_error_return_url(transaction, issuer, error)
        .map_err(|error| worker::Error::RustError(error))?;
    Response::redirect(return_url)
}

fn client_redirect_url(
    transaction: &AuthTransaction,
    issuer: &str,
    code: &str,
) -> Result<url::Url, TokenExchangeError> {
    let mut redirect_url = url::Url::parse(&transaction.redirect_uri).map_err(|error| {
        TokenExchangeError::invalid_request(format!("invalid redirect_uri: {error}"))
    })?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }
    Ok(redirect_url)
}

fn authorization_request_client_redirect_url(
    request: &AuthorizationRequest,
    issuer: &str,
    code: &str,
) -> Result<url::Url, TokenExchangeError> {
    let mut redirect_url = url::Url::parse(&request.redirect_uri).map_err(|error| {
        TokenExchangeError::invalid_request(format!("invalid redirect_uri: {error}"))
    })?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = &request.state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }
    Ok(redirect_url)
}

fn authorization_request_error_redirect_url(
    request: &AuthorizationRequest,
    issuer: &str,
    error: &str,
    error_description: &str,
) -> Result<url::Url, String> {
    let mut redirect_url = url::Url::parse(&request.redirect_uri)
        .map_err(|error| format!("invalid redirect_uri: {error}"))?;
    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.append_pair("error", error);
        pairs.append_pair("error_description", error_description);
        if let Some(state) = &request.state {
            pairs.append_pair("state", state);
        }
        pairs.append_pair("iss", issuer);
    }
    Ok(redirect_url)
}

fn authorization_request_error_redirect_url_for_client(
    request: &AuthorizationRequest,
    client: &Client,
    issuer: &str,
    error: &AuthorizationRequestError,
) -> Result<Option<url::Url>, String> {
    if !authorization_request_redirect_uri_registered_for_client(request, client) {
        return Ok(None);
    }
    authorization_request_error_redirect_url(request, issuer, error.code, &error.description)
        .map(Some)
}

fn session_login_return_url(transaction: &AuthTransaction) -> Result<url::Url, String> {
    let return_to = transaction
        .session_return_to
        .as_deref()
        .unwrap_or(&transaction.redirect_uri);
    let mut return_url =
        url::Url::parse(return_to).map_err(|error| format!("invalid return_to: {error}"))?;
    if let Some(state) = &transaction.app_state {
        return_url.query_pairs_mut().append_pair("state", state);
    }
    Ok(return_url)
}

fn provider_callback_error_return_url(
    transaction: &AuthTransaction,
    issuer: &str,
    error: &ProviderCallbackError,
) -> Result<url::Url, String> {
    let return_to = transaction
        .session_return_to
        .as_deref()
        .unwrap_or(&transaction.redirect_uri);
    let mut return_url =
        url::Url::parse(return_to).map_err(|error| format!("invalid return_to: {error}"))?;
    {
        let mut pairs = return_url.query_pairs_mut();
        pairs.append_pair("error", &error.code);
        pairs.append_pair("error_description", &error.description);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
        if transaction.session_return_to.is_none() {
            pairs.append_pair("iss", issuer);
        }
    }
    Ok(return_url)
}

fn client_return_to_from_url(
    url: &url::Url,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<String, String> {
    let return_to = query_param(url, "return_to")
        .or_else(|| query_param(url, "redirect_uri"))
        .or_else(|| client.redirect_uris.first().cloned())
        .ok_or_else(|| "missing return_to".to_owned())?;

    validate_client_return_to(&return_to, client, issuer_base_url)?;
    Ok(return_to)
}

fn identity_link_return_to_from_url(
    url: &url::Url,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<String, String> {
    client_return_to_from_url(url, client, issuer_base_url)
}

#[cfg(target_arch = "wasm32")]
async fn logout_redirect_target(
    url: &url::Url,
    current: Option<&CurrentSession>,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    env: &Env,
    now: i32,
) -> worker::Result<Result<Option<url::Url>, String>> {
    let Some(return_to) =
        query_param(url, "post_logout_redirect_uri").or_else(|| query_param(url, "return_to"))
    else {
        return Ok(Ok(None));
    };

    let client_id = if let Some(client_id) = current.and_then(|current| {
        current
            .session
            .client_id
            .as_ref()
            .map(std::string::ToString::to_string)
    }) {
        client_id
    } else if let Some(client_id) = query_param(url, "client_id") {
        client_id
    } else if let Some(id_token_hint) = query_param(url, "id_token_hint") {
        let material = signing_material_from_env(env)?;
        match verify_zeroth_id_token_hint(&id_token_hint, config, &material.verification_keys, now)
        {
            Ok(claims) => claims.aud,
            Err(error) => return Ok(Err(error)),
        }
    } else {
        return Ok(Err(
            "client_id, active session, or valid id_token_hint is required for logout redirects"
                .to_owned(),
        ));
    };

    let Some(client) = get_client(db, &client_id).await? else {
        return Ok(Err("logout client is not registered".to_owned()));
    };
    match validated_logout_redirect_url(url, &return_to, &client, Some(&config.public_base_url)) {
        Ok(target) => Ok(Ok(Some(target))),
        Err(error) => Ok(Err(error)),
    }
}

fn validated_logout_redirect_url(
    request_url: &url::Url,
    return_to: &str,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<url::Url, String> {
    validate_client_return_to(return_to, client, issuer_base_url)?;
    let mut target = url::Url::parse(return_to)
        .map_err(|error| format!("invalid logout redirect URI: {error}"))?;
    if let Some(state) = query_param(request_url, "state") {
        target.query_pairs_mut().append_pair("state", &state);
    }
    Ok(target)
}

fn validate_client_return_to(
    return_to: &str,
    client: &Client,
    issuer_base_url: Option<&str>,
) -> Result<(), String> {
    if client
        .redirect_uris
        .iter()
        .any(|redirect_uri| redirect_uri == return_to)
    {
        return Ok(());
    }

    let url = url::Url::parse(return_to).map_err(|error| {
        format!("return_to must be an absolute URL or registered redirect URI: {error}")
    })?;
    if matches!(url.scheme(), "http" | "https") {
        let origin = url.origin().ascii_serialization();
        if origin_allowed(&client.allowed_origins, &origin) {
            return Ok(());
        }
        if return_to_is_hosted_url(&url, issuer_base_url) {
            return Ok(());
        }
    }

    Err("return_to must match a registered redirect URI or allowed origin".to_owned())
}

fn return_to_is_hosted_url(url: &url::Url, issuer_base_url: Option<&str>) -> bool {
    let Some(issuer_base_url) = issuer_base_url else {
        return false;
    };
    let Ok(issuer_url) = url::Url::parse(issuer_base_url) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.origin() == issuer_url.origin()
        && matches!(url.path(), "/account" | "/admin" | "/admin/clients")
}

fn identity_link_return_url(
    transaction: &AuthTransaction,
    profile: &ProviderProfile,
) -> Result<url::Url, String> {
    let mut return_url = url::Url::parse(&transaction.redirect_uri)
        .map_err(|error| format!("invalid return_to: {error}"))?;
    {
        let mut pairs = return_url.query_pairs_mut();
        pairs.append_pair("identity_linked", "true");
        pairs.append_pair("provider", &profile.provider_id.0);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
    }
    Ok(return_url)
}

fn identity_link_error_url(
    transaction: &AuthTransaction,
    error: &IdentityLinkError,
) -> Result<url::Url, String> {
    let mut return_url = url::Url::parse(&transaction.redirect_uri)
        .map_err(|error| format!("invalid return_to: {error}"))?;
    {
        let mut pairs = return_url.query_pairs_mut();
        pairs.append_pair("error", &error.code);
        pairs.append_pair("error_description", &error.description);
        if let Some(state) = &transaction.app_state {
            pairs.append_pair("state", state);
        }
    }
    Ok(return_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_identity_link_return(
    transaction: &AuthTransaction,
    profile: &ProviderProfile,
) -> worker::Result<Response> {
    let return_url = identity_link_return_url(transaction, profile).map_err(worker_error)?;
    Response::redirect(return_url)
}

#[cfg(target_arch = "wasm32")]
fn redirect_to_identity_link_error(
    transaction: &AuthTransaction,
    error: &IdentityLinkError,
) -> worker::Result<Response> {
    let return_url = identity_link_error_url(transaction, error).map_err(worker_error)?;
    Response::redirect(return_url)
}

#[cfg(target_arch = "wasm32")]
async fn token_exchange_form_from_request(
    request: &mut Request,
) -> Result<TokenExchangeForm, TokenExchangeError> {
    let basic_auth = client_basic_auth_from_header(
        request
            .headers()
            .get("Authorization")
            .map_err(|error| {
                TokenExchangeError::invalid_request(format!(
                    "could not read Authorization header: {error}"
                ))
            })?
            .as_deref(),
    )?;
    let form = request.form_data().await.map_err(|error| {
        TokenExchangeError::invalid_request(format!("could not parse token request form: {error}"))
    })?;
    let (client_id, client_auth) = token_client_auth(
        optional_form_field(&form, "client_id"),
        optional_form_field(&form, "client_secret"),
        basic_auth,
    )?;

    Ok(TokenExchangeForm {
        grant_type: required_form_field(&form, "grant_type")?,
        client_id,
        client_auth,
        redirect_uri: optional_form_field(&form, "redirect_uri"),
        code: optional_form_field(&form, "code"),
        code_verifier: optional_form_field(&form, "code_verifier"),
        refresh_token: optional_form_field(&form, "refresh_token"),
        scope: optional_form_field(&form, "scope"),
        subject_token: optional_form_field(&form, "subject_token")
            .or_else(|| optional_form_field(&form, "identity_token"))
            .or_else(|| optional_form_field(&form, "access_token")),
        subject_token_type: optional_form_field(&form, "subject_token_type"),
        provider: optional_form_field(&form, "provider"),
        provider_client_id: optional_form_field(&form, "provider_client_id")
            .or_else(|| optional_form_field(&form, "apple_client_id")),
        nonce: optional_form_field(&form, "nonce"),
    })
}

#[cfg(target_arch = "wasm32")]
async fn token_revocation_form_from_request(
    request: &mut Request,
) -> Result<TokenRevocationForm, TokenExchangeError> {
    let basic_auth = client_basic_auth_from_header(
        request
            .headers()
            .get("Authorization")
            .map_err(|error| {
                TokenExchangeError::invalid_request(format!(
                    "could not read Authorization header: {error}"
                ))
            })?
            .as_deref(),
    )?;
    let form = request.form_data().await.map_err(|error| {
        TokenExchangeError::invalid_request(format!(
            "could not parse revocation request form: {error}"
        ))
    })?;
    let (client_id, client_auth) = token_client_auth(
        optional_form_field(&form, "client_id"),
        optional_form_field(&form, "client_secret"),
        basic_auth,
    )?;

    Ok(TokenRevocationForm {
        client_id,
        client_auth,
        token: required_form_field(&form, "token")?,
        token_type_hint: optional_form_field(&form, "token_type_hint"),
    })
}

#[cfg(target_arch = "wasm32")]
async fn token_introspection_form_from_request(
    request: &mut Request,
) -> Result<TokenIntrospectionForm, TokenExchangeError> {
    let basic_auth = client_basic_auth_from_header(
        request
            .headers()
            .get("Authorization")
            .map_err(|error| {
                TokenExchangeError::invalid_request(format!(
                    "could not read Authorization header: {error}"
                ))
            })?
            .as_deref(),
    )?;
    let form = request.form_data().await.map_err(|error| {
        TokenExchangeError::invalid_request(format!(
            "could not parse introspection request form: {error}"
        ))
    })?;
    let (client_id, client_auth) = token_client_auth(
        optional_form_field(&form, "client_id"),
        optional_form_field(&form, "client_secret"),
        basic_auth,
    )?;

    Ok(TokenIntrospectionForm {
        client_id,
        client_auth,
        token: required_form_field(&form, "token")?,
        token_type_hint: optional_form_field(&form, "token_type_hint"),
    })
}

#[cfg(target_arch = "wasm32")]
async fn profile_patch_from_request(
    request: &mut Request,
) -> Result<ProfilePatch, ProfilePatchError> {
    let content_type = request_header(request, "Content-Type").map_err(|error| {
        ProfilePatchError::invalid_request(format!("could not read Content-Type header: {error}"))
    })?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err(ProfilePatchError::invalid_request(
            "Content-Type must be application/json",
        ));
    }

    if let Some(content_length) = request_header(request, "Content-Length").map_err(|error| {
        ProfilePatchError::invalid_request(format!("could not read Content-Length header: {error}"))
    })? {
        let length = content_length
            .trim()
            .parse::<usize>()
            .map_err(|_| ProfilePatchError::invalid_request("Content-Length must be an integer"))?;
        if length > PROFILE_PATCH_BODY_LIMIT {
            return Err(ProfilePatchError::payload_too_large(
                "profile patch JSON body is too large",
            ));
        }
    }

    let body = request.bytes().await.map_err(|error| {
        ProfilePatchError::invalid_request(format!("could not read profile patch body: {error}"))
    })?;
    if body.len() > PROFILE_PATCH_BODY_LIMIT {
        return Err(ProfilePatchError::payload_too_large(
            "profile patch JSON body is too large",
        ));
    }
    let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        ProfilePatchError::invalid_request(format!("invalid profile patch JSON: {error}"))
    })?;
    profile_patch_from_value(value)
}

#[cfg(target_arch = "wasm32")]
async fn client_upsert_from_request(
    request: &mut Request,
) -> Result<ValidatedClientUpsert, ClientManagementError> {
    let content_type = request_header(request, "Content-Type").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Type header: {error}"
        ))
    })?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err(ClientManagementError::invalid_request(
            "Content-Type must be application/json",
        ));
    }

    if let Some(content_length) = request_header(request, "Content-Length").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Length header: {error}"
        ))
    })? {
        let length = content_length.trim().parse::<usize>().map_err(|_| {
            ClientManagementError::invalid_request("Content-Length must be an integer")
        })?;
        if length > CLIENT_MANAGEMENT_BODY_LIMIT {
            return Err(ClientManagementError::payload_too_large(
                "client management JSON body is too large",
            ));
        }
    }

    let body = request.bytes().await.map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read client management body: {error}"
        ))
    })?;
    if body.len() > CLIENT_MANAGEMENT_BODY_LIMIT {
        return Err(ClientManagementError::payload_too_large(
            "client management JSON body is too large",
        ));
    }
    let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|error| {
        ClientManagementError::invalid_request(format!("invalid client JSON: {error}"))
    })?;
    client_upsert_from_value(value)
}

#[cfg(target_arch = "wasm32")]
async fn admin_user_patch_from_request(
    request: &mut Request,
) -> Result<AdminUserPatchRequest, ClientManagementError> {
    let content_type = request_header(request, "Content-Type").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Type header: {error}"
        ))
    })?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err(ClientManagementError::invalid_request(
            "Content-Type must be application/json",
        ));
    }

    if let Some(content_length) = request_header(request, "Content-Length").map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read Content-Length header: {error}"
        ))
    })? {
        let length = content_length.trim().parse::<usize>().map_err(|_| {
            ClientManagementError::invalid_request("Content-Length must be an integer")
        })?;
        if length > USER_MANAGEMENT_BODY_LIMIT {
            return Err(ClientManagementError::payload_too_large(
                "user management JSON body is too large",
            ));
        }
    }

    let body = request.bytes().await.map_err(|error| {
        ClientManagementError::invalid_request(format!(
            "could not read user management body: {error}"
        ))
    })?;
    if body.len() > USER_MANAGEMENT_BODY_LIMIT {
        return Err(ClientManagementError::payload_too_large(
            "user management JSON body is too large",
        ));
    }
    serde_json::from_slice::<AdminUserPatchRequest>(&body).map_err(|error| {
        ClientManagementError::invalid_request(format!("invalid user JSON: {error}"))
    })
}

#[cfg(target_arch = "wasm32")]
fn required_form_field(form: &FormData, name: &str) -> Result<String, TokenExchangeError> {
    form.get_field(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenExchangeError::invalid_request(format!("missing {name}")))
}

#[cfg(target_arch = "wasm32")]
fn optional_form_field(form: &FormData, name: &str) -> Option<String> {
    form.get_field(name).filter(|value| !value.is_empty())
}

fn token_client_auth(
    form_client_id: Option<String>,
    form_client_secret: Option<String>,
    basic_auth: Option<ClientBasicAuth>,
) -> Result<(String, ClientAuth), TokenExchangeError> {
    match (basic_auth, form_client_secret) {
        (Some(_), Some(_)) => Err(TokenExchangeError::invalid_request(
            "client authentication must use only one method",
        )),
        (Some(basic_auth), None) => {
            if let Some(form_client_id) = form_client_id {
                if form_client_id != basic_auth.client_id {
                    return Err(TokenExchangeError::invalid_client(
                        "client_id did not match Basic authentication",
                    ));
                }
            }

            Ok((
                basic_auth.client_id,
                ClientAuth::SecretBasic(basic_auth.client_secret),
            ))
        }
        (None, Some(client_secret)) => {
            let client_id = form_client_id
                .ok_or_else(|| TokenExchangeError::invalid_request("missing client_id"))?;
            Ok((client_id, ClientAuth::SecretPost(client_secret)))
        }
        (None, None) => {
            let client_id = form_client_id
                .ok_or_else(|| TokenExchangeError::invalid_request("missing client_id"))?;
            Ok((client_id, ClientAuth::None))
        }
    }
}

fn client_basic_auth_from_header(
    authorization: Option<&str>,
) -> Result<Option<ClientBasicAuth>, TokenExchangeError> {
    let Some(authorization) = authorization else {
        return Ok(None);
    };
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let credentials = parts.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(TokenExchangeError::invalid_client(
            "unsupported client authentication scheme",
        ));
    }
    if credentials.is_empty() {
        return Err(TokenExchangeError::invalid_client(
            "Basic client authentication is missing credentials",
        ));
    }

    let decoded = STANDARD.decode(credentials).map_err(|error| {
        TokenExchangeError::invalid_client(format!("invalid Basic client authentication: {error}"))
    })?;
    let decoded = String::from_utf8(decoded).map_err(|error| {
        TokenExchangeError::invalid_client(format!(
            "Basic client authentication is not UTF-8: {error}"
        ))
    })?;
    let (client_id, client_secret) = decoded.split_once(':').ok_or_else(|| {
        TokenExchangeError::invalid_client(
            "Basic client authentication must contain client_id and client_secret",
        )
    })?;
    let client_id = decode_client_auth_value(client_id)?;
    let client_secret = decode_client_auth_value(client_secret)?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(TokenExchangeError::invalid_client(
            "Basic client authentication must include client_id and client_secret",
        ));
    }

    Ok(Some(ClientBasicAuth {
        client_id,
        client_secret,
    }))
}

fn decode_client_auth_value(value: &str) -> Result<String, TokenExchangeError> {
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .map_err(|error| {
            TokenExchangeError::invalid_client(format!(
                "client authentication value was not percent encoded correctly: {error}"
            ))
        })
}

fn validate_token_exchange_form(form: &TokenExchangeForm) -> Result<(), TokenExchangeError> {
    match form.grant_type.as_str() {
        "authorization_code" => {
            let fields = authorization_code_fields(form)?;
            if let Some(code_verifier) = fields.code_verifier {
                if code_verifier.len() < 43 || code_verifier.len() > 128 {
                    return Err(TokenExchangeError::invalid_request(
                        "code_verifier must be 43 to 128 characters",
                    ));
                }
            }
        }
        "refresh_token" => {
            refresh_token_field(form)?;
        }
        TOKEN_EXCHANGE_GRANT_TYPE => {
            native_provider_token_fields(form)?;
        }
        _ => {
            return Err(TokenExchangeError::unsupported_grant_type(
                "grant_type must be authorization_code, refresh_token, or token exchange",
            ))
        }
    }

    Ok(())
}

fn validate_token_client_auth(
    registered_client: &RegisteredClient,
    client_id: &str,
    client_auth: &ClientAuth,
) -> Result<(), TokenExchangeError> {
    if registered_client.client.id.0 != client_id {
        return Err(TokenExchangeError::invalid_client(
            "client_id does not match registered client",
        ));
    }

    if !registered_client.client.confidential {
        if matches!(client_auth, ClientAuth::None) {
            return Ok(());
        }

        return Err(TokenExchangeError::invalid_client(
            "public clients must not use client_secret authentication",
        ));
    }

    let Some(client_secret) = client_auth_secret(client_auth) else {
        return Err(TokenExchangeError::invalid_client(
            "confidential clients must authenticate with client_secret",
        ));
    };
    let Some(secret_hash) = registered_client.secret_hash.as_deref() else {
        return Err(TokenExchangeError::invalid_client(
            "confidential client is missing secret_hash",
        ));
    };
    if !client_secret_matches(secret_hash, client_secret) {
        return Err(TokenExchangeError::invalid_client(
            "client_secret did not match registered client",
        ));
    }

    Ok(())
}

fn validate_introspection_client_auth(
    registered_client: &RegisteredClient,
    client_id: &str,
    client_auth: &ClientAuth,
) -> Result<(), TokenExchangeError> {
    if !registered_client.client.confidential {
        return Err(TokenExchangeError::invalid_client(
            "token introspection requires confidential client authentication",
        ));
    }

    validate_token_client_auth(registered_client, client_id, client_auth)
}

fn validate_token_revocation_form(form: &TokenRevocationForm) -> Result<(), TokenExchangeError> {
    if form.token.is_empty() {
        return Err(TokenExchangeError::invalid_request("missing token"));
    }

    match form.token_type_hint.as_deref() {
        None | Some("refresh_token") | Some("access_token") => Ok(()),
        Some(_) => Err(TokenExchangeError::unsupported_token_type(
            "token_type_hint must be refresh_token or access_token",
        )),
    }
}

fn validate_token_introspection_form(
    form: &TokenIntrospectionForm,
) -> Result<(), TokenExchangeError> {
    if form.token.is_empty() {
        return Err(TokenExchangeError::invalid_request("missing token"));
    }

    match form.token_type_hint.as_deref() {
        None | Some("access_token") | Some("refresh_token") => Ok(()),
        Some(_) => Err(TokenExchangeError::unsupported_token_type(
            "token_type_hint must be access_token or refresh_token",
        )),
    }
}

fn should_attempt_refresh_token_revocation(token_type_hint: Option<&str>) -> bool {
    token_type_hint != Some("access_token")
}

fn client_auth_secret(auth: &ClientAuth) -> Option<&str> {
    match auth {
        ClientAuth::None => None,
        ClientAuth::SecretPost(secret) | ClientAuth::SecretBasic(secret) => Some(secret),
    }
}

fn client_secret_matches(secret_hash: &str, client_secret: &str) -> bool {
    let expected_hash = secret_hash
        .strip_prefix("sha256:")
        .unwrap_or(secret_hash)
        .trim();
    if expected_hash.len() != 64 || !expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }

    constant_time_eq(expected_hash, &hash_secret(client_secret))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff = left.len() ^ right.len();
    let len = left.len().max(right.len());
    for index in 0..len {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

fn authorization_code_fields(
    form: &TokenExchangeForm,
) -> Result<AuthorizationCodeFields<'_>, TokenExchangeError> {
    Ok(AuthorizationCodeFields {
        client_id: &form.client_id,
        redirect_uri: required_token_form_value(form.redirect_uri.as_deref(), "redirect_uri")?,
        code: required_token_form_value(form.code.as_deref(), "code")?,
        code_verifier: form.code_verifier.as_deref(),
    })
}

fn native_provider_token_fields(
    form: &TokenExchangeForm,
) -> Result<NativeProviderTokenFields<'_>, TokenExchangeError> {
    let provider_id = form.provider.as_deref().unwrap_or(well_known::APPLE);
    if !is_native_token_exchange_provider(provider_id) {
        return Err(TokenExchangeError::invalid_request(
            "token exchange provider must be apple, google, or spotify",
        ));
    }
    let subject_token_type = match (provider_id, form.subject_token_type.as_deref()) {
        (well_known::APPLE | well_known::GOOGLE, Some(ID_TOKEN_SUBJECT_TOKEN_TYPE) | None) => {
            ID_TOKEN_SUBJECT_TOKEN_TYPE
        }
        (well_known::APPLE | well_known::GOOGLE, Some(_)) => {
            return Err(TokenExchangeError::invalid_request(
                "subject_token_type must be urn:ietf:params:oauth:token-type:id_token",
            ))
        }
        (well_known::SPOTIFY, Some(ACCESS_TOKEN_SUBJECT_TOKEN_TYPE)) => {
            ACCESS_TOKEN_SUBJECT_TOKEN_TYPE
        }
        (well_known::SPOTIFY, _) => {
            return Err(TokenExchangeError::invalid_request(
                "subject_token_type must be urn:ietf:params:oauth:token-type:access_token",
            ))
        }
        _ => unreachable!("native provider was checked above"),
    };
    Ok(NativeProviderTokenFields {
        provider_id,
        scope: form.scope.as_deref(),
        subject_token: required_token_form_value(form.subject_token.as_deref(), "subject_token")?,
        subject_token_type,
        provider_client_id: form.provider_client_id.as_deref(),
        nonce: form.nonce.as_deref(),
    })
}

fn is_native_token_exchange_provider(provider_id: &str) -> bool {
    matches!(
        provider_id,
        well_known::APPLE | well_known::GOOGLE | well_known::SPOTIFY
    )
}

fn refresh_token_field(form: &TokenExchangeForm) -> Result<&str, TokenExchangeError> {
    required_token_form_value(form.refresh_token.as_deref(), "refresh_token")
}

fn required_token_form_value<'a>(
    value: Option<&'a str>,
    name: &str,
) -> Result<&'a str, TokenExchangeError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenExchangeError::invalid_request(format!("missing {name}")))
}

fn validate_refresh_token_exchange(
    row: &RefreshTokenRow,
    client_id: &str,
    now: i32,
) -> Result<(), TokenExchangeError> {
    if row.client_id != client_id {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token client_id does not match",
        ));
    }

    if row.revoked_at.is_some() {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token has been revoked",
        ));
    }

    if row.rotated_at.is_some() {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token has already been rotated",
        ));
    }

    if row.expires_at <= now {
        return Err(TokenExchangeError::invalid_grant(
            "refresh token has expired",
        ));
    }

    Ok(())
}

fn refresh_token_replay_detected(row: &RefreshTokenRow, client_id: &str) -> bool {
    row.client_id == client_id && row.rotated_at.is_some() && row.revoked_at.is_none()
}

fn validate_authorization_code_exchange(
    code: &AuthCodeRow,
    form: &AuthorizationCodeFields<'_>,
    now: i32,
) -> Result<(), TokenExchangeError> {
    if code.consumed_at.is_some() {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code has already been consumed",
        ));
    }

    if code.expires_at <= now {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code has expired",
        ));
    }

    if code.client_id != form.client_id {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code client_id does not match",
        ));
    }

    if code.redirect_uri != form.redirect_uri {
        return Err(TokenExchangeError::invalid_grant(
            "authorization code redirect_uri does not match",
        ));
    }

    match code.code_challenge_method.as_deref() {
        Some("S256") => {
            let Some(code_challenge) = &code.code_challenge else {
                return Err(TokenExchangeError::invalid_grant(
                    "authorization code is missing PKCE challenge",
                ));
            };
            let Some(code_verifier) = form.code_verifier else {
                return Err(TokenExchangeError::invalid_grant(
                    "code_verifier is required for this authorization code",
                ));
            };

            if pkce_s256_challenge(code_verifier) != *code_challenge {
                return Err(TokenExchangeError::invalid_grant(
                    "code_verifier did not match code_challenge",
                ));
            }
        }
        Some(_) => {
            return Err(TokenExchangeError::invalid_grant(
                "authorization code used unsupported PKCE method",
            ))
        }
        None => {
            if code.code_challenge.is_some() {
                return Err(TokenExchangeError::invalid_grant(
                    "authorization code used unsupported PKCE method",
                ));
            }
        }
    }

    Ok(())
}

fn token_response(
    config: &ZerothServerConfig,
    signing_key: &Es256SigningKey,
    issue: &TokenIssue,
    refresh_token: Option<String>,
    now: i32,
) -> Result<TokenResponse, String> {
    let access_claims = JwtClaims {
        iss: config.issuer().issuer.clone(),
        sub: issue.user_id.clone(),
        aud: issue.client_id.clone(),
        exp: now + ACCESS_TOKEN_TTL_SECONDS,
        iat: now,
        auth_time: None,
        sid: issue.session_id.clone(),
        nonce: None,
        scope: Some(issue.scope.clone()),
        client_id: Some(issue.client_id.clone()),
        token_use: "access".to_owned(),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
    };
    let id_claims = JwtClaims {
        iss: config.issuer().issuer,
        sub: issue.user_id.clone(),
        aud: issue.client_id.clone(),
        exp: now + ID_TOKEN_TTL_SECONDS,
        iat: now,
        auth_time: issue.auth_time,
        sid: issue.session_id.clone(),
        nonce: issue.nonce.clone(),
        scope: None,
        client_id: None,
        token_use: "id".to_owned(),
        email: issue.email.clone(),
        email_verified: issue.email_verified,
        name: issue.name.clone(),
        picture: issue.picture.clone(),
    };

    Ok(TokenResponse {
        access_token: sign_jwt(signing_key, &access_claims)?,
        id_token: sign_jwt(signing_key, &id_claims)?,
        refresh_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        scope: issue.scope.clone(),
    })
}

fn verify_zeroth_access_token(
    token: &str,
    config: &ZerothServerConfig,
    verification_keys: &[Es256VerificationKey],
    now: i32,
) -> Result<JwtClaims, String> {
    let claims = verify_zeroth_signed_jwt(token, config, verification_keys, now, "access token")?;
    validate_zeroth_access_token_claims(&claims)?;
    Ok(claims)
}

fn verify_zeroth_id_token_hint(
    token: &str,
    config: &ZerothServerConfig,
    verification_keys: &[Es256VerificationKey],
    now: i32,
) -> Result<JwtClaims, String> {
    let claims = verify_zeroth_signed_jwt(token, config, verification_keys, now, "id_token_hint")?;
    validate_zeroth_id_token_hint_claims(&claims)?;
    Ok(claims)
}

fn verify_zeroth_signed_jwt(
    token: &str,
    config: &ZerothServerConfig,
    verification_keys: &[Es256VerificationKey],
    now: i32,
    token_label: &str,
) -> Result<JwtClaims, String> {
    let segments = token.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(format!(
            "{token_label} must have three non-empty JWT segments"
        ));
    }

    let header = decode_zeroth_jwt_segment::<SignedJwtHeader>(segments[0])?;
    if header.alg != "ES256" {
        return Err(format!("unsupported {token_label} alg: {}", header.alg));
    }
    let Some(kid) = header.kid.as_deref() else {
        return Err(format!("{token_label} kid is missing"));
    };
    let Some(verification_key) = verification_keys.iter().find(|key| key.kid == kid) else {
        return Err(format!(
            "{token_label} kid did not match configured verification keys"
        ));
    };

    let signature_bytes = decode_zeroth_jwt_segment_bytes(segments[2])?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|error| format!("invalid ES256 {token_label} signature: {error}"))?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    verification_key
        .verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| format!("{token_label} signature did not verify"))?;

    let claims = decode_zeroth_jwt_segment::<JwtClaims>(segments[1])?;
    if claims.iss != config.issuer().issuer {
        return Err(format!("{token_label} issuer did not match Zeroth issuer"));
    }
    if claims.exp <= now {
        return Err(format!("{token_label} has expired"));
    }
    Ok(claims)
}

fn decode_zeroth_jwt_segment<T: serde::de::DeserializeOwned>(segment: &str) -> Result<T, String> {
    let bytes = decode_zeroth_jwt_segment_bytes(segment)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid Zeroth JWT JSON: {error}"))
}

fn decode_zeroth_jwt_segment_bytes(segment: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .map_err(|error| format!("invalid Zeroth JWT base64url segment: {error}"))
}

fn validate_zeroth_access_token_claims(claims: &JwtClaims) -> Result<(), String> {
    if claims.token_use != "access" {
        return Err("token is not an access token".to_owned());
    }
    if claims.sub.is_empty() {
        return Err("access token subject is empty".to_owned());
    }
    if claims.client_id.as_deref() != Some(&claims.aud) {
        return Err("access token client_id did not match audience".to_owned());
    }

    Ok(())
}

fn validate_zeroth_id_token_hint_claims(claims: &JwtClaims) -> Result<(), String> {
    if claims.token_use != "id" {
        return Err("id_token_hint is not an ID token".to_owned());
    }
    if claims.sub.is_empty() {
        return Err("id_token_hint subject is empty".to_owned());
    }
    if claims.aud.is_empty() {
        return Err("id_token_hint audience is empty".to_owned());
    }

    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn introspection_response_for_token(
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    verification_keys: &[Es256VerificationKey],
    form: &TokenIntrospectionForm,
    now: i32,
) -> worker::Result<TokenIntrospectionResponse> {
    if form.token_type_hint.as_deref() != Some("refresh_token") {
        if let Ok(claims) = verify_zeroth_access_token(&form.token, config, verification_keys, now)
        {
            return introspection_response_for_access_token_claims(db, &claims, now).await;
        }
    }

    if form.token_type_hint.as_deref() != Some("access_token") {
        if let Some(refresh_token) = get_refresh_token(db, &form.token).await? {
            return introspection_response_for_refresh_token_row(
                db,
                &refresh_token,
                &form.client_id,
                now,
            )
            .await;
        }
    }

    Ok(TokenIntrospectionResponse::inactive())
}

#[cfg(target_arch = "wasm32")]
async fn introspection_response_for_access_token_claims(
    db: &worker::d1::D1Database,
    claims: &JwtClaims,
    now: i32,
) -> worker::Result<TokenIntrospectionResponse> {
    let Some(user) = get_user(db, &claims.sub).await? else {
        return Ok(TokenIntrospectionResponse::inactive());
    };
    if user.disabled_at.is_some() {
        return Ok(TokenIntrospectionResponse::inactive());
    }
    if validate_access_token_session(db, claims, now)
        .await?
        .is_err()
    {
        return Ok(TokenIntrospectionResponse::inactive());
    }
    if active_client_allowed_origins(db, &claims.aud)
        .await?
        .is_err()
    {
        return Ok(TokenIntrospectionResponse::inactive());
    }

    Ok(TokenIntrospectionResponse::active_access_token(claims))
}

#[cfg(target_arch = "wasm32")]
async fn introspection_response_for_refresh_token_row(
    db: &worker::d1::D1Database,
    row: &RefreshTokenRow,
    client_id: &str,
    now: i32,
) -> worker::Result<TokenIntrospectionResponse> {
    if validate_refresh_token_exchange(row, client_id, now).is_err() {
        return Ok(TokenIntrospectionResponse::inactive());
    }
    let Some(user) = get_user(db, &row.user_id).await? else {
        return Ok(TokenIntrospectionResponse::inactive());
    };
    if user.disabled_at.is_some() {
        return Ok(TokenIntrospectionResponse::inactive());
    }

    Ok(TokenIntrospectionResponse::active_refresh_token(row))
}

fn profile_patch_from_value(value: serde_json::Value) -> Result<ProfilePatch, ProfilePatchError> {
    let Some(object) = value.as_object() else {
        return Err(ProfilePatchError::invalid_request(
            "profile patch JSON must be an object",
        ));
    };

    let mut patch = ProfilePatch {
        display_name: None,
        picture_url: None,
    };

    for (key, value) in object {
        match key.as_str() {
            "name" | "displayName" => {
                if patch.display_name.is_some() {
                    return Err(ProfilePatchError::invalid_request(
                        "profile patch included duplicate name fields",
                    ));
                }
                patch.display_name = Some(profile_patch_optional_string(
                    value,
                    "name",
                    PROFILE_NAME_MAX_CHARS,
                    ProfilePatchStringKind::DisplayName,
                )?);
            }
            "picture" | "pictureUrl" => {
                if patch.picture_url.is_some() {
                    return Err(ProfilePatchError::invalid_request(
                        "profile patch included duplicate picture fields",
                    ));
                }
                patch.picture_url = Some(profile_patch_optional_string(
                    value,
                    "picture",
                    PROFILE_PICTURE_MAX_BYTES,
                    ProfilePatchStringKind::PictureUrl,
                )?);
            }
            _ => {
                return Err(ProfilePatchError::invalid_request(format!(
                    "unsupported profile patch field: {key}"
                )));
            }
        }
    }

    if patch.display_name.is_none() && patch.picture_url.is_none() {
        return Err(ProfilePatchError::invalid_request(
            "profile patch must include name or picture",
        ));
    }

    Ok(patch)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ProfilePatchStringKind {
    DisplayName,
    PictureUrl,
}

fn profile_patch_optional_string(
    value: &serde_json::Value,
    field_name: &str,
    max: usize,
    kind: ProfilePatchStringKind,
) -> Result<Option<String>, ProfilePatchError> {
    if value.is_null() {
        return Ok(None);
    }
    let Some(raw) = value.as_str() else {
        return Err(ProfilePatchError::invalid_request(format!(
            "{field_name} must be a string or null"
        )));
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProfilePatchError::invalid_request(format!(
            "{field_name} must not be empty"
        )));
    }

    match kind {
        ProfilePatchStringKind::DisplayName => {
            if trimmed.chars().count() > max {
                return Err(ProfilePatchError::invalid_request(format!(
                    "{field_name} must be at most {max} characters"
                )));
            }
        }
        ProfilePatchStringKind::PictureUrl => {
            if trimmed.len() > max {
                return Err(ProfilePatchError::invalid_request(format!(
                    "{field_name} must be at most {max} bytes"
                )));
            }
            let url = url::Url::parse(trimmed).map_err(|_| {
                ProfilePatchError::invalid_request(format!("{field_name} must be an absolute URL"))
            })?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(ProfilePatchError::invalid_request(
                    "picture must use http or https",
                ));
            }
        }
    }

    Ok(Some(trimmed.to_owned()))
}

fn client_upsert_from_value(
    value: serde_json::Value,
) -> Result<ValidatedClientUpsert, ClientManagementError> {
    let request = serde_json::from_value::<ClientUpsertRequest>(value).map_err(|error| {
        ClientManagementError::invalid_request(format!("invalid client JSON: {error}"))
    })?;
    validate_client_upsert_request(request)
}

fn validate_client_upsert_request(
    request: ClientUpsertRequest,
) -> Result<ValidatedClientUpsert, ClientManagementError> {
    let id = validate_client_id(&request.id)?;
    let name = validate_client_name(&request.name)?;
    let redirect_uris = validate_redirect_uris(&request.redirect_uris)?;
    let allowed_origins = validate_allowed_origins(&request.allowed_origins)?;
    let allowed_email_domains = validate_allowed_email_domains(&request.allowed_email_domains)?;
    let secret_hash = validated_client_secret_hash(
        request.confidential,
        request.client_secret.as_deref(),
        request.secret_hash.as_deref(),
    )?;

    Ok(ValidatedClientUpsert {
        id,
        name,
        redirect_uris,
        allowed_origins,
        allowed_email_domains,
        confidential: request.confidential,
        secret_hash,
        disabled: request.disabled,
    })
}

fn validate_client_id(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request("missing client id"));
    }
    if value.chars().count() > CLIENT_ID_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "client id must be at most {CLIENT_ID_MAX_CHARS} characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ClientManagementError::invalid_request(
            "client id contains unsupported characters",
        ));
    }
    Ok(value.to_owned())
}

fn validate_admin_user_id(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request("missing user id"));
    }
    if value.chars().count() > USER_ID_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "user id must be at most {USER_ID_MAX_CHARS} characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ClientManagementError::invalid_request(
            "user id contains unsupported characters",
        ));
    }
    Ok(value.to_owned())
}

fn validate_audit_event_type(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request("missing event_type"));
    }
    if value.chars().count() > AUDIT_EVENT_TYPE_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "event_type must be at most {AUDIT_EVENT_TYPE_MAX_CHARS} characters"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ClientManagementError::invalid_request(
            "event_type contains unsupported characters",
        ));
    }
    Ok(value.to_owned())
}

fn audit_event_filter_from_url(url: &url::Url) -> Result<AuditEventFilter, ClientManagementError> {
    let event_type = query_param(url, "event_type")
        .map(|value| validate_audit_event_type(&value))
        .transpose()?;
    let user_id = query_param(url, "user_id")
        .map(|value| validate_admin_user_id(&value))
        .transpose()?;
    let client_id = query_param(url, "client_id")
        .map(|value| validate_client_id(&value))
        .transpose()?;
    let provider_id = query_param(url, "provider_id")
        .map(|value| {
            validate_identity_provider_id(&value)
                .map_err(ClientManagementError::invalid_request)?;
            Ok::<_, ClientManagementError>(value)
        })
        .transpose()?;

    Ok(AuditEventFilter {
        event_type,
        user_id,
        client_id,
        provider_id,
    })
}

fn validate_client_name(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request(
            "missing client name",
        ));
    }
    if value.chars().count() > CLIENT_NAME_MAX_CHARS {
        return Err(ClientManagementError::invalid_request(format!(
            "client name must be at most {CLIENT_NAME_MAX_CHARS} characters"
        )));
    }
    Ok(value.to_owned())
}

fn validate_redirect_uris(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.is_empty() {
        return Err(ClientManagementError::invalid_request(
            "client requires at least one redirect URI",
        ));
    }
    if raw.len() > CLIENT_URI_LIST_LIMIT {
        return Err(ClientManagementError::invalid_request(format!(
            "client can register at most {CLIENT_URI_LIST_LIMIT} redirect URIs"
        )));
    }

    let mut uris = Vec::with_capacity(raw.len());
    for raw_uri in raw {
        let uri = raw_uri.trim();
        if uri.is_empty() {
            return Err(ClientManagementError::invalid_request(
                "redirect URI must not be empty",
            ));
        }
        if uri.len() > CLIENT_URI_MAX_BYTES {
            return Err(ClientManagementError::invalid_request(format!(
                "redirect URI must be at most {CLIENT_URI_MAX_BYTES} bytes"
            )));
        }
        let parsed = url::Url::parse(uri).map_err(|error| {
            ClientManagementError::invalid_request(format!("invalid redirect URI: {error}"))
        })?;
        if parsed.scheme().is_empty() {
            return Err(ClientManagementError::invalid_request(
                "redirect URI must be absolute",
            ));
        }
        if parsed.fragment().is_some() {
            return Err(ClientManagementError::invalid_request(
                "redirect URI must not include a fragment",
            ));
        }
        push_unique(&mut uris, uri.to_owned());
    }
    Ok(uris)
}

fn validate_allowed_origins(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.len() > CLIENT_URI_LIST_LIMIT {
        return Err(ClientManagementError::invalid_request(format!(
            "client can register at most {CLIENT_URI_LIST_LIMIT} allowed origins"
        )));
    }

    let mut origins = Vec::with_capacity(raw.len());
    for raw_origin in raw {
        let origin = raw_origin.trim();
        if origin.is_empty() {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must not be empty",
            ));
        }
        if origin.len() > CLIENT_URI_MAX_BYTES {
            return Err(ClientManagementError::invalid_request(format!(
                "allowed origin must be at most {CLIENT_URI_MAX_BYTES} bytes"
            )));
        }
        let parsed = url::Url::parse(origin).map_err(|error| {
            ClientManagementError::invalid_request(format!("invalid allowed origin: {error}"))
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must use http or https",
            ));
        }
        if parsed.username() != "" || parsed.password().is_some() {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must not include credentials",
            ));
        }
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ClientManagementError::invalid_request(
                "allowed origin must not include a path, query, or fragment",
            ));
        }
        push_unique(&mut origins, parsed.origin().ascii_serialization());
    }
    Ok(origins)
}

fn validate_allowed_email_domains(raw: &[String]) -> Result<Vec<String>, ClientManagementError> {
    if raw.len() > CLIENT_URI_LIST_LIMIT {
        return Err(ClientManagementError::invalid_request(format!(
            "client can register at most {CLIENT_URI_LIST_LIMIT} allowed email domains"
        )));
    }

    let mut domains = Vec::with_capacity(raw.len());
    for raw_domain in raw {
        push_unique(&mut domains, normalize_allowed_email_domain(raw_domain)?);
    }
    Ok(domains)
}

fn normalize_allowed_email_domain(raw: &str) -> Result<String, ClientManagementError> {
    let value = raw.trim().strip_prefix('@').unwrap_or_else(|| raw.trim());
    if value.is_empty() {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must not be empty",
        ));
    }
    if value.len() > CLIENT_EMAIL_DOMAIN_MAX_BYTES {
        return Err(ClientManagementError::invalid_request(format!(
            "allowed email domain must be at most {CLIENT_EMAIL_DOMAIN_MAX_BYTES} bytes"
        )));
    }
    if !value.is_ascii() {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must use ASCII",
        ));
    }
    if !value.contains('.') {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must include a dot",
        ));
    }
    if value.starts_with('.') || value.ends_with('.') {
        return Err(ClientManagementError::invalid_request(
            "allowed email domain must not start or end with a dot",
        ));
    }
    for label in value.split('.') {
        if label.is_empty() {
            return Err(ClientManagementError::invalid_request(
                "allowed email domain must not contain empty labels",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ClientManagementError::invalid_request(
                "allowed email domain labels must not start or end with a hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ClientManagementError::invalid_request(
                "allowed email domain contains unsupported characters",
            ));
        }
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_client_email_domain_policy(
    client: &Client,
    profile: &ProviderProfile,
) -> Result<(), ProviderCallbackError> {
    if client.allowed_email_domains.is_empty() {
        return Ok(());
    }
    if !profile.email_verified {
        return Err(ProviderCallbackError::access_denied(
            "verified email is required for this client",
        ));
    }

    let email_domain = provider_profile_email_domain(profile)?;
    if client
        .allowed_email_domains
        .iter()
        .any(|allowed_domain| allowed_domain.eq_ignore_ascii_case(&email_domain))
    {
        return Ok(());
    }

    Err(ProviderCallbackError::access_denied(
        "email domain is not allowed for this client",
    ))
}

fn provider_profile_email_domain(
    profile: &ProviderProfile,
) -> Result<String, ProviderCallbackError> {
    let email = profile
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or_else(|| ProviderCallbackError::access_denied("email is required for this client"))?;
    let (_, domain) = email.rsplit_once('@').ok_or_else(|| {
        ProviderCallbackError::access_denied("email domain is required for this client")
    })?;
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(ProviderCallbackError::access_denied(
            "email domain is required for this client",
        ));
    }
    Ok(domain.to_ascii_lowercase())
}

fn native_token_scope(scope: Option<&str>) -> Result<String, TokenExchangeError> {
    let raw = scope.unwrap_or(DEFAULT_NATIVE_TOKEN_SCOPE);
    let mut scopes = Vec::new();
    for scope in raw.split_whitespace() {
        if scope.len() > 64
            || !scope.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(TokenExchangeError::invalid_request(
                "scope contains unsupported characters",
            ));
        }
        push_unique(&mut scopes, scope.to_owned());
    }
    if scopes.is_empty() {
        return Err(TokenExchangeError::invalid_request(
            "scope must not be empty",
        ));
    }
    if !scopes.iter().any(|scope| scope == "openid") {
        return Err(TokenExchangeError::invalid_request(
            "scope must include openid",
        ));
    }
    Ok(scopes.join(" "))
}

#[cfg(target_arch = "wasm32")]
fn native_provider_client_id(
    env: &Env,
    provider_id: &str,
    requested_client_id: Option<&str>,
) -> Result<String, TokenExchangeError> {
    let configured = native_provider_client_ids_from_env(env, provider_id);
    native_provider_client_id_from_list(provider_id, &configured, requested_client_id)
}

#[cfg(target_arch = "wasm32")]
fn native_provider_client_ids_from_env(env: &Env, provider_id: &str) -> Vec<String> {
    let (native_binding, fallback_binding) = match provider_id {
        well_known::APPLE => ("APPLE_NATIVE_CLIENT_IDS", "APPLE_BUNDLE_ID"),
        well_known::GOOGLE => ("GOOGLE_NATIVE_CLIENT_IDS", "GOOGLE_CLIENT_ID"),
        well_known::SPOTIFY => ("SPOTIFY_NATIVE_CLIENT_IDS", "SPOTIFY_CLIENT_ID"),
        _ => return Vec::new(),
    };
    binding_value_from_env(env, native_binding)
        .filter(|value| config_value_configured(Some(value)))
        .or_else(|| provider_client_id_from_env(env, fallback_binding))
        .map(|value| split_token_list(&value))
        .unwrap_or_default()
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn native_apple_provider_client_id_from_list(
    configured: &[String],
    requested_client_id: Option<&str>,
) -> Result<String, TokenExchangeError> {
    native_provider_client_id_from_list(well_known::APPLE, configured, requested_client_id)
}

fn native_provider_client_id_from_list(
    provider_id: &str,
    configured: &[String],
    requested_client_id: Option<&str>,
) -> Result<String, TokenExchangeError> {
    if configured.is_empty() {
        return Err(TokenExchangeError::invalid_request(format!(
            "{} is not configured",
            native_provider_client_ids_binding(provider_id)
        )));
    }
    if let Some(requested_client_id) = requested_client_id {
        if token_list_slice_contains(configured, requested_client_id, false) {
            return Ok(requested_client_id.to_owned());
        }
        return Err(TokenExchangeError::invalid_request(
            "provider_client_id is not allowed",
        ));
    }
    if configured.len() == 1 {
        return Ok(configured[0].clone());
    }
    Err(TokenExchangeError::invalid_request(format!(
        "provider_client_id is required when multiple {} native client IDs are configured",
        provider_label(provider_id)
    )))
}

fn native_provider_client_ids_binding(provider_id: &str) -> &'static str {
    match provider_id {
        well_known::APPLE => "APPLE_NATIVE_CLIENT_IDS",
        well_known::GOOGLE => "GOOGLE_NATIVE_CLIENT_IDS",
        well_known::SPOTIFY => "SPOTIFY_NATIVE_CLIENT_IDS",
        _ => "PROVIDER_NATIVE_CLIENT_IDS",
    }
}

fn provider_label(provider_id: &str) -> &'static str {
    match provider_id {
        well_known::APPLE => "Apple",
        well_known::GOOGLE => "Google",
        well_known::SPOTIFY => "Spotify",
        _ => "provider",
    }
}

fn split_token_list(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    for token in value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        push_unique(&mut values, token.to_owned());
    }
    values
}

fn token_list_slice_contains(
    values: &[String],
    needle: &str,
    ascii_case_insensitive: bool,
) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    values.iter().any(|value| {
        if ascii_case_insensitive {
            value.eq_ignore_ascii_case(needle)
        } else {
            value == needle
        }
    })
}

fn native_oidc_profile_from_verified_token(
    provider_id: &str,
    verified: VerifiedProviderIdToken,
) -> ResolvedProviderProfile {
    let claims = verified.claims;
    ResolvedProviderProfile {
        profile: ProviderProfile {
            provider_id: ProviderId(provider_id.to_owned()),
            subject: Subject(claims.sub),
            email: claims.email,
            email_verified: boolish_claim(claims.email_verified.as_ref()).unwrap_or(false),
            display_name: claims.name,
            picture_url: claims.picture,
        },
        raw_profile_json: Some(verified.raw_claims_json),
    }
}

fn validated_client_secret_hash(
    confidential: bool,
    client_secret: Option<&str>,
    secret_hash: Option<&str>,
) -> Result<Option<String>, ClientManagementError> {
    if client_secret.is_some() && secret_hash.is_some() {
        return Err(ClientManagementError::invalid_request(
            "clientSecret and secretHash are mutually exclusive",
        ));
    }

    if !confidential {
        if client_secret.is_some() || secret_hash.is_some() {
            return Err(ClientManagementError::invalid_request(
                "public clients must not include clientSecret or secretHash",
            ));
        }
        return Ok(None);
    }

    if let Some(client_secret) = client_secret {
        let client_secret = client_secret.trim();
        if client_secret.len() < 16 {
            return Err(ClientManagementError::invalid_request(
                "clientSecret must be at least 16 bytes",
            ));
        }
        if client_secret.len() > 4096 {
            return Err(ClientManagementError::invalid_request(
                "clientSecret must be at most 4096 bytes",
            ));
        }
        return Ok(Some(format!("sha256:{}", hash_secret(client_secret))));
    }

    secret_hash
        .map(|value| normalize_sha256_secret_hash(value, "secretHash"))
        .transpose()
}

fn normalize_sha256_secret_hash(
    value: &str,
    field_name: &str,
) -> Result<String, ClientManagementError> {
    let hash = value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| value.trim());
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ClientManagementError::invalid_request(format!(
            "{field_name} must be a sha256 hex digest"
        )));
    }
    Ok(format!("sha256:{}", hash.to_ascii_lowercase()))
}

fn admin_token_matches_config(presented_token: &str, configured_hash: &str) -> bool {
    let Ok(expected_hash) = normalize_admin_token_hash(configured_hash) else {
        return false;
    };
    constant_time_eq(&expected_hash, &hash_secret(presented_token.trim()))
}

fn normalize_admin_token_hash(value: &str) -> Result<String, String> {
    let hash = value
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| value.trim());
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ADMIN_TOKEN_SHA256 must be a sha256 hex digest".to_owned());
    }
    Ok(hash.to_ascii_lowercase())
}

fn client_response_from_row(row: ClientRow) -> Result<ClientResponse, String> {
    Ok(ClientResponse {
        id: row.id,
        name: row.name,
        redirect_uris: parse_string_array_json(&row.redirect_uris_json, "redirect_uris_json")?,
        allowed_origins: parse_string_array_json(
            &row.allowed_origins_json,
            "allowed_origins_json",
        )?,
        allowed_email_domains: parse_string_array_json(
            &row.allowed_email_domains_json,
            "allowed_email_domains_json",
        )?,
        confidential: row.confidential != 0,
        disabled: row.disabled_at.is_some(),
        has_secret: row
            .secret_hash
            .as_deref()
            .is_some_and(|secret_hash| !secret_hash.trim().is_empty()),
    })
}

fn admin_user_response_from_row(row: AdminUserRow) -> AdminUserResponse {
    AdminUserResponse {
        id: row.id,
        email: row.primary_email,
        display_name: row.display_name,
        picture_url: row.picture_url,
        created_at: row.created_at,
        updated_at: row.updated_at,
        disabled: row.disabled_at.is_some(),
        admin: row.admin_membership_active != 0,
        identity_count: row.identity_count,
        active_session_count: row.active_session_count,
    }
}

fn audit_event_response_from_row(row: AuditEventRow) -> AuditEventResponse {
    let details = serde_json::from_str(&row.details_json)
        .unwrap_or_else(|_| serde_json::json!({ "invalidDetailsJson": true }));
    AuditEventResponse {
        id: row.id,
        event_type: row.event_type,
        user_id: row.user_id,
        client_id: row.client_id,
        provider_id: row.provider_id,
        created_at: row.created_at,
        ip_hash: row.ip_hash,
        user_agent: row.user_agent,
        details,
    }
}

fn audit_event_admin_ui_from_row(row: AuditEventRow) -> EventAdminUi {
    EventAdminUi {
        event_id: row.id,
        event_type: row.event_type,
        user_id: row.user_id,
        client_id: row.client_id,
        provider_id: row.provider_id,
        created_at: Some(row.created_at.to_string()),
        details: Some(row.details_json),
    }
}

fn audit_details_json(details: serde_json::Value) -> Result<String, String> {
    let json = serde_json::to_string(&details)
        .map_err(|error| format!("could not serialize audit details: {error}"))?;
    if json.len() <= AUDIT_EVENT_DETAILS_MAX_BYTES {
        return Ok(json);
    }

    Ok(serde_json::json!({
        "truncated": true,
        "originalBytes": json.len()
    })
    .to_string())
}

fn user_admin_ui_from_row(row: AdminUserRow) -> UserAdminUi {
    UserAdminUi {
        user_id: row.id,
        email: row.primary_email,
        display_name: row.display_name,
        disabled: row.disabled_at.is_some(),
        admin: row.admin_membership_active != 0,
        identity_count: row.identity_count,
        active_session_count: row.active_session_count,
        created_at: Some(row.created_at.to_string()),
        updated_at: Some(row.updated_at.to_string()),
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn user_with_profile_patch(user: &UserRow, patch: &ProfilePatch) -> UserRow {
    let mut user = user.clone();
    if let Some(display_name) = &patch.display_name {
        user.display_name = display_name.clone();
    }
    if let Some(picture_url) = &patch.picture_url {
        user.picture_url = picture_url.clone();
    }
    user
}

fn content_type_is_json(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}

fn userinfo_response(user: &UserRow, scope: Option<&str>) -> UserInfoResponse {
    let has_email = scope_contains(scope, "email");
    let has_profile = scope_contains(scope, "profile");
    UserInfoResponse {
        sub: user.id.clone(),
        email: has_email.then(|| user.primary_email.clone()).flatten(),
        name: has_profile.then(|| user.display_name.clone()).flatten(),
        picture: has_profile.then(|| user.picture_url.clone()).flatten(),
    }
}

fn session_response(current: Option<(&SessionRow, &UserRow)>) -> SessionResponse {
    match current {
        Some((session, user)) => SessionResponse {
            authenticated: true,
            session: Some(session_info_response(session)),
            user: Some(userinfo_response(user, Some("email profile"))),
        },
        None => SessionResponse {
            authenticated: false,
            session: None,
            user: None,
        },
    }
}

fn sessions_response(sessions: &[SessionRow], current_session_id: &str) -> SessionsResponse {
    SessionsResponse {
        sessions: sessions
            .iter()
            .map(|session| SessionListItemResponse {
                id: session.id.clone(),
                client_id: session.client_id.clone(),
                created_at: session.created_at,
                expires_at: session.expires_at,
                current: session.id == current_session_id,
            })
            .collect(),
    }
}

fn identities_response(identities: &[IdentityRow]) -> IdentitiesResponse {
    IdentitiesResponse {
        identities: identities
            .iter()
            .map(|identity| IdentityResponse {
                provider_id: identity.provider_id.clone(),
                provider_subject: identity.provider_subject.clone(),
                email: identity.email.clone(),
                email_verified: identity.email_verified != 0,
                display_name: identity.display_name.clone(),
                picture_url: identity.picture_url.clone(),
                created_at: identity.created_at,
                updated_at: identity.updated_at,
            })
            .collect(),
    }
}

#[cfg(target_arch = "wasm32")]
async fn passkey_json_from_request<T: serde::de::DeserializeOwned>(
    request: &mut Request,
) -> Result<T, String> {
    let content_type = request
        .headers()
        .get("Content-Type")
        .map_err(|error| format!("could not read Content-Type header: {error}"))?;
    if !content_type_is_json(content_type.as_deref()) {
        return Err("Content-Type must be application/json".to_owned());
    }
    let body = request
        .bytes()
        .await
        .map_err(|error| format!("could not read passkey body: {error}"))?;
    if body.len() > PASSKEY_BODY_LIMIT {
        return Err("passkey JSON body is too large".to_owned());
    }
    serde_json::from_slice::<T>(&body).map_err(|error| format!("invalid passkey JSON: {error}"))
}

#[cfg(target_arch = "wasm32")]
fn passkey_registration_subject(
    current: Option<&CurrentSession>,
    body: &PasskeyRegisterOptionsRequest,
) -> Result<(Option<String>, String, Option<String>), String> {
    if let Some(current) = current {
        let email = current
            .user
            .primary_email
            .as_deref()
            .or(body.email.as_deref())
            .ok_or_else(|| "current user has no email; provide email".to_owned())
            .and_then(validate_passkey_email)?;
        let display_name = body
            .display_name
            .as_deref()
            .or(current.user.display_name.as_deref())
            .map(validate_passkey_display_name)
            .transpose()?;
        return Ok((Some(current.user.id.clone()), email, display_name));
    }

    let email = body
        .email
        .as_deref()
        .ok_or_else(|| "email is required to register the first passkey".to_owned())
        .and_then(validate_passkey_email)?;
    let display_name = body
        .display_name
        .as_deref()
        .map(validate_passkey_display_name)
        .transpose()?;
    Ok((None, email, display_name))
}

#[cfg(target_arch = "wasm32")]
fn passkey_client_id_from_request(env: &Env, client_id: Option<&str>) -> worker::Result<String> {
    client_id
        .map(str::trim)
        .filter(|client_id| !client_id.is_empty())
        .map(str::to_owned)
        .or_else(|| env_string(env, "DEFAULT_LOGIN_CLIENT_ID"))
        .filter(|client_id| !client_id.is_empty())
        .ok_or_else(|| {
            worker_error(
                "missing client_id and DEFAULT_LOGIN_CLIENT_ID is not configured".to_owned(),
            )
        })
}

#[cfg(target_arch = "wasm32")]
fn passkey_return_to(
    request_url: &url::Url,
    return_to: Option<&str>,
    client: &Client,
    config: &ZerothServerConfig,
) -> worker::Result<String> {
    let value = return_to
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}/admin", config.issuer().issuer));
    let value = if value.starts_with('/') {
        let mut target = request_url.clone();
        target.set_path(&value);
        target.set_query(None);
        target.set_fragment(None);
        target.to_string()
    } else {
        value
    };
    validate_client_return_to(&value, client, Some(&config.public_base_url))
        .map_err(|error| worker_error(format!("invalid passkey return_to: {error}")))?;
    Ok(value)
}

fn validate_passkey_email(value: &str) -> Result<String, String> {
    let email = value.trim().to_ascii_lowercase();
    if email.is_empty() {
        return Err("email must not be empty".to_owned());
    }
    if email.len() > PASSKEY_EMAIL_MAX_BYTES {
        return Err("email is too long".to_owned());
    }
    if email.bytes().any(|byte| byte.is_ascii_whitespace()) || !email.contains('@') {
        return Err("email is not valid".to_owned());
    }
    Ok(email)
}

fn validate_passkey_display_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("displayName must not be empty".to_owned());
    }
    if value.chars().count() > PROFILE_NAME_MAX_CHARS {
        return Err(format!(
            "displayName must be at most {PROFILE_NAME_MAX_CHARS} characters"
        ));
    }
    Ok(value.to_owned())
}

fn validate_passkey_label(value: Option<&str>) -> Result<Option<String>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > PASSKEY_LABEL_MAX_CHARS {
        return Err(format!(
            "label must be at most {PASSKEY_LABEL_MAX_CHARS} characters"
        ));
    }
    Ok(Some(value.to_owned()))
}

fn passkey_creation_options(
    config: &ZerothServerConfig,
    challenge: &str,
    user_id: &str,
    email: &str,
    display_name: &str,
    exclude_credentials: Vec<PasskeyCredentialDescriptor>,
) -> Result<PasskeyPublicKeyCredentialCreationOptions, String> {
    Ok(PasskeyPublicKeyCredentialCreationOptions {
        challenge: passkey_challenge_for_browser(challenge),
        rp: PasskeyRpEntity {
            id: passkey_rp_id(config)?,
            name: passkey_rp_name(config),
        },
        user: PasskeyUserEntity {
            id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
            name: email.to_owned(),
            display_name: display_name.to_owned(),
        },
        pub_key_cred_params: vec![PasskeyPubKeyCredParam {
            credential_type: "public-key",
            alg: -7,
        }],
        timeout: 300_000,
        authenticator_selection: PasskeyAuthenticatorSelection {
            resident_key: "required",
            require_resident_key: true,
            user_verification: "required",
        },
        attestation: "none",
        exclude_credentials,
    })
}

fn passkey_request_options(
    config: &ZerothServerConfig,
    challenge: &str,
    allow_credentials: Vec<PasskeyCredentialDescriptor>,
) -> Result<PasskeyPublicKeyCredentialRequestOptions, String> {
    Ok(PasskeyPublicKeyCredentialRequestOptions {
        challenge: passkey_challenge_for_browser(challenge),
        rp_id: passkey_rp_id(config)?,
        timeout: 300_000,
        user_verification: "required",
        allow_credentials,
    })
}

fn passkey_challenge_for_browser(challenge: &str) -> String {
    URL_SAFE_NO_PAD.encode(challenge.as_bytes())
}

fn passkey_challenge_from_browser(value: &str) -> Result<String, String> {
    let bytes = decode_base64url(value)?;
    String::from_utf8(bytes).map_err(|error| format!("challenge was not UTF-8: {error}"))
}

fn passkey_challenge_hash_from_client_data(client_data_json: &str) -> Result<String, String> {
    let client_data = decode_passkey_client_data(client_data_json)?;
    let challenge = passkey_challenge_from_browser(&client_data.challenge)?;
    Ok(hash_secret(&challenge))
}

fn passkey_challenge_matches_client_data(challenge_hash: &str, client_data_json: &str) -> bool {
    passkey_challenge_hash_from_client_data(client_data_json)
        .is_ok_and(|actual| actual == challenge_hash)
}

fn passkey_rp_id(config: &ZerothServerConfig) -> Result<String, String> {
    let url = url::Url::parse(&config.public_base_url)
        .map_err(|error| format!("PUBLIC_BASE_URL is invalid: {error}"))?;
    url.host_str()
        .map(str::to_owned)
        .ok_or_else(|| "PUBLIC_BASE_URL must include a host".to_owned())
}

fn passkey_rp_name(config: &ZerothServerConfig) -> String {
    url::Url::parse(&config.public_base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "Zeroth".to_owned())
}

fn passkey_expected_origin(config: &ZerothServerConfig) -> Result<String, String> {
    let url = url::Url::parse(&config.public_base_url)
        .map_err(|error| format!("PUBLIC_BASE_URL is invalid: {error}"))?;
    Ok(url.origin().ascii_serialization())
}

fn validate_passkey_client_data(
    config: &ZerothServerConfig,
    client_data_json: &str,
    expected_type: &str,
) -> Result<WebAuthnClientData, String> {
    let client_data = decode_passkey_client_data(client_data_json)?;
    if client_data.ceremony_type != expected_type {
        return Err(format!("passkey client data type must be {expected_type}"));
    }
    let expected_origin = passkey_expected_origin(config)?;
    if client_data.origin != expected_origin {
        return Err("passkey origin did not match Zeroth issuer".to_owned());
    }
    if client_data.cross_origin.unwrap_or(false) {
        return Err("cross-origin passkey ceremonies are not accepted".to_owned());
    }
    Ok(client_data)
}

fn decode_passkey_client_data(client_data_json: &str) -> Result<WebAuthnClientData, String> {
    let bytes = decode_base64url(client_data_json)?;
    serde_json::from_slice::<WebAuthnClientData>(&bytes)
        .map_err(|error| format!("invalid passkey clientDataJSON: {error}"))
}

fn validate_passkey_registration_response(
    config: &ZerothServerConfig,
    body: &PasskeyRegisterVerifyRequest,
) -> Result<ValidatedPasskeyRegistration, String> {
    let raw_id = passkey_raw_id(&body.raw_id)?;
    if passkey_raw_id(&body.id)? != raw_id {
        return Err("passkey id and rawId did not match".to_owned());
    }
    validate_passkey_client_data(config, &body.response.client_data_json, "webauthn.create")?;
    let attestation_object = decode_base64url(&body.response.attestation_object)?;
    let auth_data = parse_passkey_attestation_object(&attestation_object)?;
    validate_passkey_authenticator_data(config, &auth_data, true)?;
    let credential_id = auth_data
        .credential_id
        .ok_or_else(|| "passkey registration did not include credential data".to_owned())
        .map(|credential_id| URL_SAFE_NO_PAD.encode(credential_id))?;
    if credential_id != raw_id {
        return Err("passkey authenticator credential id did not match rawId".to_owned());
    }
    let public_key = auth_data
        .public_key
        .ok_or_else(|| "passkey registration did not include a public key".to_owned())?;
    Ok(ValidatedPasskeyRegistration {
        credential_id,
        public_key_x: URL_SAFE_NO_PAD.encode(public_key.x),
        public_key_y: URL_SAFE_NO_PAD.encode(public_key.y),
        sign_count: auth_data.sign_count,
    })
}

fn validate_passkey_authentication_response(
    config: &ZerothServerConfig,
    body: &PasskeyAuthenticateVerifyRequest,
    credential: &PasskeyCredentialRow,
    challenge: &PasskeyChallengeRow,
) -> Result<(), String> {
    let raw_id = passkey_raw_id(&body.raw_id)?;
    if passkey_raw_id(&body.id)? != raw_id || raw_id != credential.credential_id {
        return Err("passkey credential id did not match".to_owned());
    }
    let client_data =
        validate_passkey_client_data(config, &body.response.client_data_json, "webauthn.get")?;
    let challenge_value = passkey_challenge_from_browser(&client_data.challenge)?;
    if hash_secret(&challenge_value) != challenge.challenge_hash {
        return Err("passkey challenge did not match".to_owned());
    }
    let authenticator_data_bytes = decode_base64url(&body.response.authenticator_data)?;
    let auth_data = parse_passkey_authenticator_data(&authenticator_data_bytes)?;
    validate_passkey_authenticator_data(config, &auth_data, false)?;
    validate_passkey_sign_count(credential.sign_count, auth_data.sign_count)?;
    let client_data_bytes = decode_base64url(&body.response.client_data_json)?;
    let mut signed_data = authenticator_data_bytes;
    signed_data.extend_from_slice(&Sha256::digest(&client_data_bytes));
    let signature = decode_base64url(&body.response.signature)?;
    verify_passkey_es256_signature(credential, &signed_data, &signature)
}

fn validate_passkey_authenticator_data(
    config: &ZerothServerConfig,
    auth_data: &ParsedAuthenticatorData,
    require_attested_credential: bool,
) -> Result<(), String> {
    let rp_id = passkey_rp_id(config)?;
    let expected_hash = Sha256::digest(rp_id.as_bytes()).to_vec();
    if auth_data.rp_id_hash != expected_hash {
        return Err("passkey relying-party id hash did not match".to_owned());
    }
    if auth_data.flags & 0x01 == 0 {
        return Err("passkey user-present flag was not set".to_owned());
    }
    if auth_data.flags & 0x04 == 0 {
        return Err("passkey user-verified flag was not set".to_owned());
    }
    if require_attested_credential && auth_data.flags & 0x40 == 0 {
        return Err("passkey attested-credential flag was not set".to_owned());
    }
    Ok(())
}

fn validate_passkey_sign_count(stored: i32, incoming: i32) -> Result<(), String> {
    if stored > 0 && incoming > 0 && incoming <= stored {
        return Err("passkey sign counter did not increase".to_owned());
    }
    Ok(())
}

fn verify_passkey_es256_signature(
    credential: &PasskeyCredentialRow,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let x = decode_base64url(&credential.public_key_x)?;
    let y = decode_base64url(&credential.public_key_y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("stored passkey public key is not P-256".to_owned());
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|error| format!("invalid passkey public key: {error}"))?;
    let signature = Signature::from_der(signature)
        .map_err(|error| format!("invalid passkey signature: {error}"))?;
    verifying_key
        .verify(signed_data, &signature)
        .map_err(|_| "passkey signature did not verify".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn passkey_authenticator_sign_count(authenticator_data: &str) -> worker::Result<i32> {
    let authenticator_data = decode_base64url(authenticator_data).map_err(worker_error)?;
    parse_passkey_authenticator_data(&authenticator_data)
        .map(|data| data.sign_count)
        .map_err(worker_error)
}

fn passkey_raw_id(value: &str) -> Result<String, String> {
    decode_base64url(value).map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|error| format!("invalid base64url value: {error}"))
}

fn parse_passkey_attestation_object(bytes: &[u8]) -> Result<ParsedAuthenticatorData, String> {
    let value = CborReader::new(bytes).read_single()?;
    let CborValue::Map(entries) = value else {
        return Err("passkey attestationObject must be a CBOR map".to_owned());
    };
    let auth_data = cbor_map_text_bytes(&entries, "authData")
        .ok_or_else(|| "passkey attestationObject is missing authData".to_owned())?;
    parse_passkey_authenticator_data(auth_data)
}

fn parse_passkey_authenticator_data(bytes: &[u8]) -> Result<ParsedAuthenticatorData, String> {
    if bytes.len() < 37 {
        return Err("passkey authenticatorData is too short".to_owned());
    }
    let rp_id_hash = bytes[0..32].to_vec();
    let flags = bytes[32];
    let sign_count = i32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    let mut credential_id = None;
    let mut public_key = None;

    if flags & 0x40 != 0 {
        if bytes.len() < 55 {
            return Err("passkey attested credential data is too short".to_owned());
        }
        let credential_id_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
        let credential_start = 55;
        let credential_end = credential_start + credential_id_len;
        if bytes.len() <= credential_end {
            return Err("passkey credential public key is missing".to_owned());
        }
        credential_id = Some(bytes[credential_start..credential_end].to_vec());
        public_key = Some(parse_passkey_cose_public_key(&bytes[credential_end..])?);
    }

    Ok(ParsedAuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        public_key,
    })
}

fn parse_passkey_cose_public_key(bytes: &[u8]) -> Result<PasskeyCredentialPublicKey, String> {
    let value = CborReader::new(bytes).read_single()?;
    let CborValue::Map(entries) = value else {
        return Err("passkey public key must be a COSE_Key map".to_owned());
    };
    if cbor_map_int_i64(&entries, 1) != Some(2) {
        return Err("passkey public key must be EC2".to_owned());
    }
    if cbor_map_int_i64(&entries, 3) != Some(-7) {
        return Err("passkey public key must use ES256".to_owned());
    }
    if cbor_map_int_i64(&entries, -1) != Some(1) {
        return Err("passkey public key must use P-256".to_owned());
    }
    let x = cbor_map_int_bytes(&entries, -2)
        .ok_or_else(|| "passkey public key is missing x coordinate".to_owned())?
        .to_vec();
    let y = cbor_map_int_bytes(&entries, -3)
        .ok_or_else(|| "passkey public key is missing y coordinate".to_owned())?
        .to_vec();
    if x.len() != 32 || y.len() != 32 {
        return Err("passkey public key coordinates must be 32 bytes".to_owned());
    }
    Ok(PasskeyCredentialPublicKey { x, y })
}

fn cbor_map_text_bytes<'a>(entries: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a [u8]> {
    entries
        .iter()
        .find_map(|(entry_key, value)| match (entry_key, value) {
            (CborValue::Text(entry_key), CborValue::Bytes(value)) if entry_key == key => {
                Some(value.as_slice())
            }
            _ => None,
        })
}

fn cbor_map_int_i64(entries: &[(CborValue, CborValue)], key: i64) -> Option<i64> {
    entries.iter().find_map(|(entry_key, value)| {
        if cbor_int(entry_key)? != key {
            return None;
        }
        cbor_int(value)
    })
}

fn cbor_map_int_bytes<'a>(entries: &'a [(CborValue, CborValue)], key: i64) -> Option<&'a [u8]> {
    entries.iter().find_map(|(entry_key, value)| {
        if cbor_int(entry_key)? != key {
            return None;
        }
        match value {
            CborValue::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    })
}

fn cbor_int(value: &CborValue) -> Option<i64> {
    match value {
        CborValue::Unsigned(value) => i64::try_from(*value).ok(),
        CborValue::Negative(value) => Some(*value),
        _ => None,
    }
}

struct CborReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_single(mut self) -> Result<CborValue, String> {
        let value = self.read_value()?;
        if self.offset != self.bytes.len() {
            return Err("CBOR value had trailing bytes".to_owned());
        }
        Ok(value)
    }

    fn read_value(&mut self) -> Result<CborValue, String> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(CborValue::Unsigned(self.read_len(additional)?)),
            1 => {
                let value = self.read_len(additional)?;
                let value = i64::try_from(value)
                    .map_err(|_| "CBOR negative integer is too large".to_owned())?;
                Ok(CborValue::Negative(-1 - value))
            }
            2 => {
                let len = self.read_len_usize(additional)?;
                Ok(CborValue::Bytes(self.read_exact(len)?.to_vec()))
            }
            3 => {
                let len = self.read_len_usize(additional)?;
                let bytes = self.read_exact(len)?;
                let text = std::str::from_utf8(bytes)
                    .map_err(|error| format!("CBOR text was not UTF-8: {error}"))?;
                Ok(CborValue::Text(text.to_owned()))
            }
            4 => {
                let len = self.read_len_usize(additional)?;
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    values.push(self.read_value()?);
                }
                Ok(CborValue::Array(values))
            }
            5 => {
                let len = self.read_len_usize(additional)?;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.read_value()?;
                    let value = self.read_value()?;
                    entries.push((key, value));
                }
                Ok(CborValue::Map(entries))
            }
            7 => match additional {
                20 => Ok(CborValue::Bool(false)),
                21 => Ok(CborValue::Bool(true)),
                22 => Ok(CborValue::Null),
                _ => Err("unsupported CBOR simple value".to_owned()),
            },
            _ => Err("unsupported CBOR major type".to_owned()),
        }
    }

    fn read_len_usize(&mut self, additional: u8) -> Result<usize, String> {
        let len = self.read_len(additional)?;
        usize::try_from(len).map_err(|_| "CBOR length is too large".to_owned())
    }

    fn read_len(&mut self, additional: u8) -> Result<u64, String> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.read_u8()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.read_array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.read_array()?))),
            27 => Ok(u64::from_be_bytes(self.read_array()?)),
            _ => Err("indefinite or reserved CBOR length is not supported".to_owned()),
        }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let Some(byte) = self.bytes.get(self.offset).copied() else {
            return Err("unexpected end of CBOR data".to_owned());
        };
        self.offset += 1;
        Ok(byte)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.read_exact(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "CBOR length overflow".to_owned())?;
        if end > self.bytes.len() {
            return Err("unexpected end of CBOR data".to_owned());
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
}

fn validate_access_token_response(claims: &JwtClaims, user: &UserRow) -> ValidateResponse {
    ValidateResponse {
        valid: true,
        kind: "access_token",
        sub: claims.sub.clone(),
        client_id: Some(claims.aud.clone()),
        scope: claims.scope.clone(),
        expires_at: Some(claims.exp),
        session_id: claims.sid.clone(),
        session: None,
        user: userinfo_response(user, claims.scope.as_deref()),
    }
}

fn validate_session_response(session: &SessionRow, user: &UserRow) -> ValidateResponse {
    ValidateResponse {
        valid: true,
        kind: "session",
        sub: user.id.clone(),
        client_id: session.client_id.clone(),
        scope: None,
        expires_at: Some(session.expires_at),
        session_id: Some(session.id.clone()),
        session: Some(session_info_response(session)),
        user: userinfo_response(user, Some("email profile")),
    }
}

#[cfg(target_arch = "wasm32")]
async fn validate_access_token_session(
    db: &worker::d1::D1Database,
    claims: &JwtClaims,
    now: i32,
) -> worker::Result<Result<(), String>> {
    let Some(session_id) = claims.sid.as_deref() else {
        return Ok(Ok(()));
    };
    let session = get_session(db, session_id).await?;
    Ok(validate_access_token_session_claims(
        claims,
        session.as_ref(),
        now,
    ))
}

fn validate_access_token_session_claims(
    claims: &JwtClaims,
    session: Option<&SessionRow>,
    now: i32,
) -> Result<(), String> {
    let Some(session_id) = claims.sid.as_deref() else {
        return Ok(());
    };
    let Some(session) = session else {
        return Err("access token session was not found".to_owned());
    };
    if session.id != session_id {
        return Err("access token session id did not match session row".to_owned());
    }
    if session.user_id != claims.sub {
        return Err("access token session user did not match subject".to_owned());
    }
    if session.client_id.as_deref() != Some(&claims.aud) {
        return Err("access token session client did not match audience".to_owned());
    }
    if !session_row_is_active(session, now) {
        return Err("access token session is no longer active".to_owned());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn validate_session_cors_origin(
    db: &worker::d1::D1Database,
    origin: Option<&str>,
    session: &SessionRow,
) -> worker::Result<Result<(), String>> {
    let Some(client_id) = session.client_id.as_deref() else {
        return validate_any_client_cors_origin(db, origin).await;
    };
    match active_client_allowed_origins(db, client_id).await? {
        Ok(allowed_origins) => Ok(validate_cors_origin(origin, &allowed_origins)),
        Err(error) => Ok(Err(error)),
    }
}

#[cfg(target_arch = "wasm32")]
async fn validate_any_client_cors_origin(
    db: &worker::d1::D1Database,
    origin: Option<&str>,
) -> worker::Result<Result<(), String>> {
    let Some(origin) = origin else {
        return Ok(Ok(()));
    };
    if origin_allowed_by_any_client(db, origin).await? {
        Ok(Ok(()))
    } else {
        Ok(Err(cors_disallowed_origin(origin)))
    }
}

fn validate_cors_origin(origin: Option<&str>, allowed_origins: &[String]) -> Result<(), String> {
    let Some(origin) = origin else {
        return Ok(());
    };
    if origin_allowed(allowed_origins, origin) {
        Ok(())
    } else {
        Err(cors_disallowed_origin(origin))
    }
}

fn cors_disallowed_origin(origin: &str) -> String {
    format!("Origin is not allowed for this client: {origin}")
}

fn origin_allowed(allowed_origins: &[String], origin: &str) -> bool {
    allowed_origins
        .iter()
        .any(|allowed_origin| allowed_origin == origin)
}

fn origin_allowed_in_client_origin_rows(
    rows: &[ClientOriginsRow],
    origin: &str,
) -> Result<bool, String> {
    for row in rows {
        if !row.allowed_origins_json.contains(origin) {
            continue;
        }
        let allowed_origins =
            parse_string_array_json(&row.allowed_origins_json, "allowed_origins_json")?;
        if origin_allowed(&allowed_origins, origin) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn active_client_allowed_origins_from_client(
    client: Option<Client>,
) -> Result<Vec<String>, String> {
    client
        .map(|client| client.allowed_origins)
        .ok_or_else(|| "client is not registered or is disabled".to_owned())
}

fn cors_path(path: &str) -> bool {
    matches!(
        path,
        "/oauth/token"
            | "/oauth/revoke"
            | "/oauth/introspect"
            | "/userinfo"
            | "/session"
            | "/sessions"
            | "/profile"
            | "/identities/link"
            | "/identities"
            | "/validate"
            | "/logout"
    )
}

fn cors_method_allowed(path: &str, method: &str) -> bool {
    match path {
        "/oauth/token" | "/oauth/revoke" | "/oauth/introspect" => method == "POST",
        "/userinfo" | "/session" | "/validate" => method == "GET",
        "/profile" => method == "GET" || method == "PATCH",
        "/identities/link" => method == "GET",
        "/identities" => method == "GET" || method == "DELETE",
        "/sessions" => method == "GET" || method == "DELETE",
        "/logout" => method == "GET" || method == "POST",
        _ => false,
    }
}

fn session_info_response(session: &SessionRow) -> SessionInfoResponse {
    SessionInfoResponse {
        id: session.id.clone(),
        client_id: session.client_id.clone(),
        created_at: session.created_at,
        expires_at: session.expires_at,
    }
}

fn session_row_is_active(session: &SessionRow, now: i32) -> bool {
    session.revoked_at.is_none() && session.expires_at > now
}

fn authorization_request_may_reuse_session(
    request: &AuthorizationRequest,
    session: &SessionRow,
    now: i32,
) -> bool {
    request.prompt.allows_session_reuse()
        && authorization_request_session_is_fresh(request, session, now)
}

fn authorization_request_session_is_fresh(
    request: &AuthorizationRequest,
    session: &SessionRow,
    now: i32,
) -> bool {
    request
        .max_age
        .map(|max_age| now.saturating_sub(session.created_at) <= max_age)
        .unwrap_or(true)
}

fn session_cookie(name: &str, value: &str, max_age_seconds: i32, domain: Option<&str>) -> String {
    let domain = cookie_domain_attribute(domain);
    format!(
        "{name}={value}; Path=/; Max-Age={max_age_seconds};{domain} HttpOnly; Secure; SameSite=Lax"
    )
}

fn clear_session_cookie(name: &str, domain: Option<&str>) -> String {
    let domain = cookie_domain_attribute(domain);
    format!("{name}=; Path=/; Max-Age=0;{domain} HttpOnly; Secure; SameSite=Lax")
}

fn transaction_cookie(name: &str, value: &str, max_age_seconds: i32) -> String {
    format!("{name}={value}; Path=/oauth2/callback; Max-Age={max_age_seconds}; HttpOnly; Secure; SameSite=None")
}

fn clear_transaction_cookie(name: &str) -> String {
    format!("{name}=; Path=/oauth2/callback; Max-Age=0; HttpOnly; Secure; SameSite=None")
}

fn cookie_domain_attribute(domain: Option<&str>) -> String {
    let Some(domain) = domain.and_then(valid_cookie_domain) else {
        return String::new();
    };
    format!(" Domain={domain};")
}

fn valid_cookie_domain(domain: &str) -> Option<&str> {
    let domain = domain.trim();
    if domain.is_empty() {
        return None;
    }
    if domain
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        Some(domain)
    } else {
        None
    }
}

fn cookie_value(cookie_header: Option<&str>, name: &str) -> Option<String> {
    cookie_header?.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name && !value.is_empty()).then(|| value.to_owned())
    })
}

fn provider_callback_state_matches_transaction_cookie(
    callback_state: &str,
    cookie_state: Option<&str>,
) -> Result<(), ProviderCallbackError> {
    if cookie_state == Some(callback_state) {
        return Ok(());
    }
    Err(ProviderCallbackError::invalid_request(
        "provider callback state did not match browser transaction",
    ))
}

fn scope_contains(scope: Option<&str>, expected: &str) -> bool {
    scope
        .map(|scope| {
            scope
                .split_whitespace()
                .any(|candidate| candidate == expected)
        })
        .unwrap_or(false)
}

impl TokenIssue {
    fn from_auth_code(code: &AuthCodeRow) -> Self {
        Self {
            client_id: code.client_id.clone(),
            user_id: code.user_id.clone(),
            session_id: code.session_id.clone(),
            scope: code.scope.clone(),
            auth_time: Some(code.auth_time.unwrap_or(code.created_at)),
            nonce: code.nonce.clone(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        }
    }

    fn from_native_provider(client_id: &str, user_id: &str, scope: &str, auth_time: i32) -> Self {
        Self {
            client_id: client_id.to_owned(),
            user_id: user_id.to_owned(),
            session_id: None,
            scope: scope.to_owned(),
            auth_time: Some(auth_time),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        }
    }

    fn from_refresh_token(row: &RefreshTokenRow) -> Self {
        Self {
            client_id: row.client_id.clone(),
            user_id: row.user_id.clone(),
            session_id: row.session_id.clone(),
            scope: row.scope.clone(),
            auth_time: row.auth_time,
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        }
    }

    fn with_user_claims(mut self, user: &UserTokenClaimsRow) -> Self {
        if scope_contains(Some(&self.scope), "email") {
            self.email = user.primary_email.clone();
            self.email_verified = user
                .primary_email
                .as_ref()
                .map(|_| user.email_verified != 0);
        }
        if scope_contains(Some(&self.scope), "profile") {
            self.name = user.display_name.clone();
            self.picture = user.picture_url.clone();
        }
        self
    }
}

fn sign_jwt<T: Serialize>(signing_key: &Es256SigningKey, claims: &T) -> Result<String, String> {
    let header = JwtHeader {
        alg: "ES256",
        kid: signing_key.kid.clone(),
        typ: "JWT",
    };
    let signing_input = format!(
        "{}.{}",
        jwt_json_segment(&header)?,
        jwt_json_segment(claims)?
    );
    let signature: Signature = signing_key.signing_key.sign(signing_input.as_bytes());

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn apple_client_secret_from_config(
    config: &AppleClientSecretConfig,
    issued_at: i64,
) -> Result<(String, i64), String> {
    let signing_key = SigningKey::from_pkcs8_pem(&config.private_key_pem)
        .map_err(|error| format!("invalid Apple private key PEM: {error}"))?;
    let expires_at = issued_at + config.ttl_seconds;
    let token = apple_client_secret_from_signing_key(&signing_key, config, issued_at, expires_at)?;
    Ok((token, expires_at))
}

fn apple_client_secret_from_signing_key(
    signing_key: &SigningKey,
    config: &AppleClientSecretConfig,
    issued_at: i64,
    expires_at: i64,
) -> Result<String, String> {
    let header = AppleClientSecretHeader {
        alg: "ES256",
        kid: config.key_id.clone(),
    };
    let claims = AppleClientSecretClaims {
        iss: config.team_id.clone(),
        iat: issued_at,
        exp: expires_at,
        aud: "https://appleid.apple.com",
        sub: config.client_id.clone(),
    };
    let signing_input = format!(
        "{}.{}",
        jwt_json_segment(&header)?,
        jwt_json_segment(&claims)?
    );
    let signature: Signature = signing_key.sign(signing_input.as_bytes());

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn jwt_json_segment<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|json| URL_SAFE_NO_PAD.encode(json))
        .map_err(|error| format!("could not serialize JWT segment: {error}"))
}

fn jwks_response(
    signing_key: &Es256SigningKey,
    previous_public_jwks_json: Option<&str>,
) -> Result<JwksResponse, String> {
    let active_key = es256_public_jwk(signing_key)?;
    let mut seen_kids = vec![active_key.kid.clone()];
    let mut keys = vec![active_key];

    if let Some(previous_public_jwks_json) = previous_public_jwks_json {
        for key in parse_previous_public_jwks(previous_public_jwks_json)? {
            if seen_kids.iter().any(|kid| kid == &key.kid) {
                continue;
            }
            seen_kids.push(key.kid.clone());
            keys.push(key);
        }
    }

    Ok(JwksResponse { keys })
}

fn es256_public_jwk(signing_key: &Es256SigningKey) -> Result<JwkKey, String> {
    let verifying_key = signing_key.signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| "ES256 public key is missing x coordinate".to_owned())?;
    let y = point
        .y()
        .ok_or_else(|| "ES256 public key is missing y coordinate".to_owned())?;

    Ok(JwkKey {
        kty: "EC".to_owned(),
        key_use: "sig".to_owned(),
        kid: signing_key.kid.clone(),
        alg: "ES256".to_owned(),
        crv: "P-256".to_owned(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
    })
}

fn parse_previous_public_jwks(value: &str) -> Result<Vec<JwkKey>, String> {
    let jwks = serde_json::from_str::<JwksResponse>(value)
        .map_err(|error| format!("invalid JWT_PREVIOUS_PUBLIC_JWKS_JSON JWKS JSON: {error}"))?;
    for key in &jwks.keys {
        validate_previous_public_jwk(key)?;
    }
    Ok(jwks.keys)
}

fn validate_previous_public_jwk(key: &JwkKey) -> Result<(), String> {
    validate_es256_public_jwk(key, "JWT_PREVIOUS_PUBLIC_JWKS_JSON")
}

fn validate_es256_public_jwk(key: &JwkKey, source: &str) -> Result<(), String> {
    if key.kty != "EC" {
        return Err(format!("{source} only supports EC keys"));
    }
    if key.key_use != "sig" {
        return Err(format!("{source} keys must have use=sig"));
    }
    if key.alg != "ES256" {
        return Err(format!("{source} keys must have alg=ES256"));
    }
    if key.crv != "P-256" {
        return Err(format!("{source} keys must have crv=P-256"));
    }
    if key.kid.trim().is_empty() {
        return Err(format!("{source} keys must include kid"));
    }
    decode_public_jwk_coordinate(&key.x, "x", source)?;
    decode_public_jwk_coordinate(&key.y, "y", source)?;
    Ok(())
}

fn decode_public_jwk_coordinate(
    value: &str,
    field_name: &str,
    source: &str,
) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|error| format!("{source} key {field_name} must be base64url: {error}"))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!("{source} key {field_name} must decode to 32 bytes"))
            }
        })
}

fn es256_verification_keys_from_jwks(
    jwks: &JwksResponse,
) -> Result<Vec<Es256VerificationKey>, String> {
    let mut keys = Vec::with_capacity(jwks.keys.len());
    for key in &jwks.keys {
        keys.push(es256_verification_key_from_jwk(key)?);
    }
    Ok(keys)
}

fn es256_verification_key_from_jwk(key: &JwkKey) -> Result<Es256VerificationKey, String> {
    validate_es256_public_jwk(key, "ES256 public JWK")?;
    let x = decode_public_jwk_coordinate(&key.x, "x", "ES256 public JWK")?;
    let y = decode_public_jwk_coordinate(&key.y, "y", "ES256 public JWK")?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|error| format!("invalid ES256 public key {}: {error}", key.kid))?;
    Ok(Es256VerificationKey {
        kid: key.kid.clone(),
        verifying_key,
    })
}

#[cfg(target_arch = "wasm32")]
fn signing_key_from_env(env: &Env) -> worker::Result<Es256SigningKey> {
    Ok(signing_material_from_env(env)?.signing_key)
}

#[cfg(target_arch = "wasm32")]
fn signing_material_from_env(env: &Env) -> worker::Result<CachedSigningMaterial> {
    let kid =
        binding_value_from_env(env, "JWT_KEY_ID").unwrap_or_else(|| "zeroth-es256-1".to_owned());
    let private_key = binding_value_from_env(env, "JWT_ES256_PRIVATE_KEY")
        .ok_or_else(|| worker::Error::RustError("missing JWT_ES256_PRIVATE_KEY".to_owned()))?;
    let previous_public_jwks = binding_value_from_env(env, "JWT_PREVIOUS_PUBLIC_JWKS_JSON")
        .filter(|value| !value.trim().is_empty());

    SIGNING_MATERIAL_CACHE.with(|cache| {
        if let Some(material) = cache.borrow().as_ref() {
            if material.kid == kid
                && material.private_key == private_key
                && material.previous_public_jwks == previous_public_jwks
            {
                return Ok(material.clone());
            }
        }

        let signing_key =
            es256_signing_key_from_config(kid.clone(), &private_key).map_err(worker_error)?;
        let jwks =
            jwks_response(&signing_key, previous_public_jwks.as_deref()).map_err(worker_error)?;
        let verification_keys = es256_verification_keys_from_jwks(&jwks).map_err(worker_error)?;
        let material = CachedSigningMaterial {
            kid,
            private_key,
            previous_public_jwks,
            signing_key,
            verification_keys,
            jwks,
        };
        *cache.borrow_mut() = Some(material.clone());
        Ok(material)
    })
}

fn es256_signing_key_from_config(
    kid: impl Into<String>,
    private_key: &str,
) -> Result<Es256SigningKey, String> {
    let scalar = es256_private_scalar_from_config(private_key)?;
    let signing_key = SigningKey::from_slice(&scalar)
        .map_err(|error| format!("invalid ES256 private key: {error}"))?;
    Ok(Es256SigningKey {
        kid: kid.into(),
        signing_key,
    })
}

fn es256_private_scalar_from_config(private_key: &str) -> Result<Vec<u8>, String> {
    let trimmed = private_key.trim();
    if trimmed.starts_with('{') {
        let value = serde_json::from_str::<serde_json::Value>(trimmed)
            .map_err(|error| format!("invalid ES256 JWK JSON: {error}"))?;
        let d = value
            .get("d")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "ES256 JWK private key is missing d".to_owned())?;
        return decode_base64(d, "ES256 JWK d");
    }

    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex_to_bytes(trimmed);
    }

    decode_base64(trimmed, "ES256 private key")
}

fn decode_base64(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .map_err(|error| format!("{field_name} must be base64url, base64, or hex: {error}"))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!("{field_name} must decode to 32 bytes"))
            }
        })
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|error| format!("invalid hex ES256 private key: {error}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn discovery_response(config: &ZerothServerConfig) -> DiscoveryResponse {
    let issuer = config.issuer();
    let revocation_endpoint = format!("{}/oauth/revoke", issuer.issuer);
    let introspection_endpoint = format!("{}/oauth/introspect", issuer.issuer);
    let end_session_endpoint = format!("{}/logout", issuer.issuer);
    DiscoveryResponse {
        issuer: issuer.issuer,
        authorization_endpoint: issuer.authorization_endpoint,
        token_endpoint: issuer.token_endpoint,
        revocation_endpoint,
        introspection_endpoint,
        end_session_endpoint,
        userinfo_endpoint: issuer.userinfo_endpoint,
        jwks_uri: issuer.jwks_uri,
        response_types_supported: vec!["code"],
        response_modes_supported: vec!["query"],
        prompt_values_supported: vec!["none", "login", "consent", "select_account"],
        grant_types_supported: vec![
            "authorization_code",
            "refresh_token",
            TOKEN_EXCHANGE_GRANT_TYPE,
        ],
        scopes_supported: vec!["openid", "profile", "email", "offline_access"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec![
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        revocation_endpoint_auth_methods_supported: vec![
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        introspection_endpoint_auth_methods_supported: vec![
            "client_secret_post",
            "client_secret_basic",
        ],
        id_token_signing_alg_values_supported: vec!["ES256"],
        subject_types_supported: vec!["public"],
        claims_supported: vec![
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "sid",
            "nonce",
            "email",
            "email_verified",
            "name",
            "picture",
        ],
        authorization_response_iss_parameter_supported: true,
    }
}

fn registered_client_from_row(row: ClientRow) -> Result<Option<RegisteredClient>, String> {
    let secret_hash = row.secret_hash.clone();
    Ok(client_from_row(row)?.map(|client| RegisteredClient {
        client,
        secret_hash,
    }))
}

fn client_from_row(row: ClientRow) -> Result<Option<Client>, String> {
    if row.disabled_at.is_some() {
        return Ok(None);
    }

    Ok(Some(Client {
        id: ClientId(row.id),
        name: row.name,
        redirect_uris: parse_string_array_json(&row.redirect_uris_json, "redirect_uris_json")?,
        allowed_origins: parse_string_array_json(
            &row.allowed_origins_json,
            "allowed_origins_json",
        )?,
        allowed_email_domains: parse_string_array_json(
            &row.allowed_email_domains_json,
            "allowed_email_domains_json",
        )?,
        confidential: row.confidential != 0,
    }))
}

fn parse_string_array_json(value: &str, field_name: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(value)
        .map_err(|error| format!("client {field_name} must be a JSON string array: {error}"))
}

#[cfg(target_arch = "wasm32")]
fn server_config(env: &Env, request_url: &url::Url) -> ZerothServerConfig {
    ZerothServerConfig {
        public_base_url: env_string(env, "PUBLIC_BASE_URL")
            .unwrap_or_else(|| request_url.origin().ascii_serialization()),
        cookie_name: env_string(env, "SESSION_COOKIE_NAME")
            .unwrap_or_else(|| ZerothServerConfig::default().cookie_name),
        cookie_domain: env_string(env, "SESSION_COOKIE_DOMAIN")
            .and_then(|value| valid_cookie_domain(&value).map(str::to_owned)),
        transaction_cookie_name: env_string(env, "TX_COOKIE_NAME")
            .unwrap_or_else(|| ZerothServerConfig::default().transaction_cookie_name),
    }
}

fn provider_id_from_url(url: &url::Url) -> Result<String, AuthorizationRequestError> {
    optional_provider_id_from_url(url)?
        .ok_or_else(|| AuthorizationRequestError::invalid_request("missing provider"))
}

fn optional_provider_id_from_url(
    url: &url::Url,
) -> Result<Option<String>, AuthorizationRequestError> {
    let Some(provider_id) = query_param(url, "provider") else {
        return Ok(None);
    };
    if !is_supported_provider_id(&provider_id) {
        return Err(AuthorizationRequestError::invalid_request(format!(
            "unsupported provider: {provider_id}"
        )));
    }
    Ok(Some(provider_id))
}

fn is_supported_provider_id(provider_id: &str) -> bool {
    matches!(
        provider_id,
        well_known::APPLE | well_known::GOOGLE | well_known::SPOTIFY
    )
}

fn provider_authorize_nonce(transaction: &AuthTransaction) -> Option<&str> {
    if !provider_uses_oidc_nonce(&transaction.provider_id.0) {
        return None;
    }
    transaction
        .provider_nonce
        .as_deref()
        .or(transaction.nonce.as_deref())
}

fn provider_uses_oidc_nonce(provider_id: &str) -> bool {
    matches!(provider_id, well_known::APPLE | well_known::GOOGLE)
}

fn authorization_login_request_present(url: &url::Url) -> bool {
    query_param(url, "response_type").is_some()
}

#[cfg(target_arch = "wasm32")]
fn session_login_client_id_from_url(
    env: &Env,
    url: &url::Url,
) -> Result<String, AuthorizationRequestError> {
    query_param(url, "client_id")
        .filter(|client_id| !client_id.is_empty())
        .or_else(|| env_string(env, "DEFAULT_LOGIN_CLIENT_ID"))
        .filter(|client_id| !client_id.is_empty())
        .ok_or_else(|| {
            AuthorizationRequestError::invalid_request(
                "missing client_id and DEFAULT_LOGIN_CLIENT_ID is not configured",
            )
        })
}

#[cfg(target_arch = "wasm32")]
fn provider_from_env(env: &Env, provider_id: &str) -> worker::Result<OAuthProvider> {
    match provider_id {
        well_known::APPLE => provider_client_id_from_env(env, "APPLE_CLIENT_ID")
            .map(OAuthProvider::apple)
            .ok_or_else(|| missing_provider_config("APPLE_CLIENT_ID")),
        well_known::GOOGLE => provider_client_id_from_env(env, "GOOGLE_CLIENT_ID")
            .map(OAuthProvider::google)
            .ok_or_else(|| missing_provider_config("GOOGLE_CLIENT_ID")),
        well_known::SPOTIFY => provider_client_id_from_env(env, "SPOTIFY_CLIENT_ID")
            .map(OAuthProvider::spotify)
            .ok_or_else(|| missing_provider_config("SPOTIFY_CLIENT_ID")),
        _ => Err(worker::Error::RustError(format!(
            "unknown provider: {provider_id}"
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
fn provider_client_secret_from_env(env: &Env, provider_id: &str) -> worker::Result<Option<String>> {
    if provider_id == well_known::APPLE {
        return apple_client_secret_from_env(env);
    }

    let binding = match provider_id {
        well_known::GOOGLE => "GOOGLE_CLIENT_SECRET",
        well_known::SPOTIFY => "SPOTIFY_CLIENT_SECRET",
        _ => {
            return Err(worker::Error::RustError(format!(
                "unknown provider: {provider_id}"
            )))
        }
    };

    secret_string(env, binding)
        .or_else(|| env_string(env, binding))
        .map(Some)
        .ok_or_else(|| missing_provider_config(binding))
}

#[cfg(target_arch = "wasm32")]
fn apple_client_secret_from_env(env: &Env) -> worker::Result<Option<String>> {
    if let Some(client_secret) =
        secret_string(env, "APPLE_CLIENT_SECRET").or_else(|| env_string(env, "APPLE_CLIENT_SECRET"))
    {
        return Ok(Some(client_secret));
    }

    let config = match apple_client_secret_config_from_env(env)? {
        Some(config) => config,
        None => {
            return Err(missing_provider_config(
                "APPLE_CLIENT_SECRET or APPLE_TEAM_ID/APPLE_KEY_ID/APPLE_PRIVATE_KEY",
            ))
        }
    };
    let now = i64::from(unix_timestamp_seconds());

    APPLE_CLIENT_SECRET_CACHE.with(|cache| {
        if let Some(cached) = cache.borrow().as_ref() {
            if cached.config == config
                && cached.expires_at - APPLE_CLIENT_SECRET_CACHE_REFRESH_SECONDS > now
            {
                return Ok(Some(cached.token.clone()));
            }
        }

        let (token, expires_at) =
            apple_client_secret_from_config(&config, now).map_err(worker_error)?;
        *cache.borrow_mut() = Some(CachedAppleClientSecret {
            config,
            token: token.clone(),
            expires_at,
        });
        Ok(Some(token))
    })
}

#[cfg(target_arch = "wasm32")]
fn apple_client_secret_config_from_env(
    env: &Env,
) -> worker::Result<Option<AppleClientSecretConfig>> {
    let Some(team_id) =
        secret_string(env, "APPLE_TEAM_ID").or_else(|| env_string(env, "APPLE_TEAM_ID"))
    else {
        return Ok(None);
    };
    let Some(key_id) =
        secret_string(env, "APPLE_KEY_ID").or_else(|| env_string(env, "APPLE_KEY_ID"))
    else {
        return Ok(None);
    };
    let Some(client_id) = provider_client_id_from_env(env, "APPLE_CLIENT_ID") else {
        return Ok(None);
    };
    let Some(private_key) = secret_string(env, "APPLE_PRIVATE_KEY")
        .or_else(|| secret_string(env, "APPLE_PRIVATE_KEY_PEM"))
        .or_else(|| env_string(env, "APPLE_PRIVATE_KEY"))
        .or_else(|| env_string(env, "APPLE_PRIVATE_KEY_PEM"))
    else {
        return Ok(None);
    };
    let ttl_seconds = apple_client_secret_ttl_seconds(
        env_string(env, "APPLE_CLIENT_SECRET_TTL_SECONDS").as_deref(),
    )
    .map_err(worker_error)?;

    Ok(Some(AppleClientSecretConfig {
        team_id,
        key_id,
        client_id,
        private_key_pem: normalize_private_key_pem_secret(&private_key),
        ttl_seconds,
    }))
}

fn apple_client_secret_ttl_seconds(value: Option<&str>) -> Result<i64, String> {
    let Some(value) = value else {
        return Ok(APPLE_CLIENT_SECRET_DEFAULT_TTL_SECONDS);
    };
    let ttl = value
        .trim()
        .parse::<i64>()
        .map_err(|error| format!("APPLE_CLIENT_SECRET_TTL_SECONDS must be an integer: {error}"))?;
    if !(60..=APPLE_CLIENT_SECRET_MAX_TTL_SECONDS).contains(&ttl) {
        return Err(format!(
            "APPLE_CLIENT_SECRET_TTL_SECONDS must be between 60 and {APPLE_CLIENT_SECRET_MAX_TTL_SECONDS}"
        ));
    }
    Ok(ttl)
}

fn normalize_private_key_pem_secret(value: &str) -> String {
    value.trim().replace("\\n", "\n")
}

#[cfg(target_arch = "wasm32")]
fn provider_client_id_from_env(env: &Env, name: &str) -> Option<String> {
    binding_value_from_env(env, name).filter(|value| config_value_configured(Some(value)))
}

#[cfg(target_arch = "wasm32")]
fn missing_provider_config(name: &str) -> worker::Error {
    worker::Error::RustError(format!("missing provider configuration: {name}"))
}

#[cfg(target_arch = "wasm32")]
fn binding_value_from_env(env: &Env, name: &str) -> Option<String> {
    secret_string(env, name).or_else(|| env_string(env, name))
}

#[cfg(target_arch = "wasm32")]
fn env_string(env: &Env, name: &str) -> Option<String> {
    env.var(name).map(|value| value.to_string()).ok()
}

#[cfg(target_arch = "wasm32")]
fn secret_string(env: &Env, name: &str) -> Option<String> {
    env.secret(name).map(|value| value.to_string()).ok()
}

#[cfg(target_arch = "wasm32")]
fn request_origin(request: &Request) -> worker::Result<Option<String>> {
    request_header(request, "Origin")
}

#[cfg(target_arch = "wasm32")]
fn request_origin_for_config(
    request: &Request,
    config: &ZerothServerConfig,
) -> worker::Result<Option<String>> {
    let origin = request_origin(request)?;
    Ok(origin.filter(|origin| !origin_matches_public_base_url(origin, &config.public_base_url)))
}

#[cfg(target_arch = "wasm32")]
fn audit_request_context(request: &Request) -> worker::Result<AuditRequestContext> {
    Ok(AuditRequestContext {
        ip_hash: request_header(request, "CF-Connecting-IP")?.map(|ip| hash_secret(&ip)),
        user_agent: request_header(request, "User-Agent")?,
    })
}

fn origin_matches_public_base_url(origin: &str, public_base_url: &str) -> bool {
    let Ok(base_url) = url::Url::parse(public_base_url) else {
        return false;
    };
    base_url.origin().ascii_serialization() == origin
}

#[cfg(target_arch = "wasm32")]
fn session_id_from_request(request: &Request, cookie_name: &str) -> worker::Result<Option<String>> {
    let cookie = request_header(request, "Cookie")?;
    Ok(cookie_value(cookie.as_deref(), cookie_name))
}

#[cfg(target_arch = "wasm32")]
fn transaction_state_from_request(
    request: &Request,
    cookie_name: &str,
) -> worker::Result<Option<String>> {
    let cookie = request_header(request, "Cookie")?;
    Ok(cookie_value(cookie.as_deref(), cookie_name))
}

#[cfg(target_arch = "wasm32")]
fn request_header(request: &Request, name: &str) -> worker::Result<Option<String>> {
    request
        .headers()
        .get(name)
        .map_err(|error| worker::Error::RustError(format!("could not read {name} header: {error}")))
}

#[cfg(target_arch = "wasm32")]
fn with_set_cookie(response: Response, cookie: &str) -> worker::Result<Response> {
    response.headers().append("Set-Cookie", cookie)?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn with_cors_actual_headers(response: Response, origin: Option<&str>) -> worker::Result<Response> {
    if let Some(origin) = origin {
        set_cors_origin_headers(&response, origin)?;
    }
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn with_cors_preflight_headers(response: Response, origin: &str) -> worker::Result<Response> {
    set_cors_origin_headers(&response, origin)?;
    response
        .headers()
        .set("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)?;
    response
        .headers()
        .set("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)?;
    response
        .headers()
        .set("Access-Control-Max-Age", CORS_MAX_AGE_SECONDS)?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn set_cors_origin_headers(response: &Response, origin: &str) -> worker::Result<()> {
    response
        .headers()
        .set("Access-Control-Allow-Origin", origin)?;
    response
        .headers()
        .set("Access-Control-Allow-Credentials", "true")?;
    response.headers().set("Vary", "Origin")?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn bearer_token_from_request(request: &Request) -> Result<String, String> {
    let authorization = request
        .headers()
        .get("Authorization")
        .map_err(|error| format!("could not read Authorization header: {error}"))?
        .ok_or_else(|| "missing bearer token".to_owned())?;
    bearer_token_from_authorization_header(Some(&authorization))?
        .ok_or_else(|| "missing bearer token".to_owned())
}

#[cfg(target_arch = "wasm32")]
async fn validate_admin_request(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
) -> Result<(), ClientManagementError> {
    authorize_admin_request(request, env, db, config, now)
        .await
        .map(|_| ())
}

#[cfg(target_arch = "wasm32")]
async fn authorize_admin_request(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    now: i32,
) -> Result<AdminAuthorization, ClientManagementError> {
    if validate_admin_bearer_request(request, env).is_ok() {
        return Ok(AdminAuthorization::BootstrapToken);
    }

    let Some(current) = current_session_from_request(request, db, config, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!(
                "could not validate admin session: {error}"
            ))
        })?
    else {
        return Err(ClientManagementError::unauthorized(
            "admin bearer token or allowed Zeroth session is required",
        ));
    };
    let Some(admin_user) = get_admin_user_row(db, &current.user.id, now)
        .await
        .map_err(|error| {
            ClientManagementError::server_error(format!("could not load admin user: {error}"))
        })?
    else {
        return Err(ClientManagementError::unauthorized(
            "admin session user was not found",
        ));
    };

    if admin_user_allowed(env, &admin_user)
        || user_has_active_admin_membership(db, &admin_user.id)
            .await
            .map_err(|error| {
                ClientManagementError::server_error(format!(
                    "could not load admin membership: {error}"
                ))
            })?
    {
        Ok(AdminAuthorization::Session {
            user_id: current.user.id,
        })
    } else {
        Err(ClientManagementError::unauthorized(
            "admin session user is not allowlisted",
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn validate_admin_bearer_request(
    request: &Request,
    env: &Env,
) -> Result<(), ClientManagementError> {
    let token = bearer_token_from_request(request).map_err(ClientManagementError::unauthorized)?;
    let configured_hash = admin_token_hash_from_env(env)?;
    if admin_token_matches_config(&token, &configured_hash) {
        Ok(())
    } else {
        Err(ClientManagementError::unauthorized(
            "admin token did not match",
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn admin_user_allowed(env: &Env, user: &AdminUserRow) -> bool {
    let verified_email = if user.email_verified != 0 {
        user.primary_email.as_deref()
    } else {
        None
    };
    admin_identity_allowed(
        &user.id,
        verified_email,
        binding_value_from_env(env, "ADMIN_USER_IDS").as_deref(),
        binding_value_from_env(env, "ADMIN_EMAILS").as_deref(),
    )
}

fn admin_identity_allowed(
    user_id: &str,
    verified_email: Option<&str>,
    allowed_user_ids: Option<&str>,
    allowed_emails: Option<&str>,
) -> bool {
    token_list_contains(allowed_user_ids, user_id, false)
        || verified_email.is_some_and(|email| token_list_contains(allowed_emails, email, true))
}

fn admin_authorization_granted_by(authorization: &AdminAuthorization) -> String {
    match authorization {
        AdminAuthorization::BootstrapToken => "bootstrap_token".to_owned(),
        AdminAuthorization::Session { user_id } => format!("user:{user_id}"),
    }
}

fn token_list_contains(values: Option<&str>, needle: &str, ascii_case_insensitive: bool) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    values
        .unwrap_or_default()
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|value| !value.trim().is_empty())
        .any(|value| {
            let value = value.trim();
            if ascii_case_insensitive {
                value.eq_ignore_ascii_case(needle)
            } else {
                value == needle
            }
        })
}

#[cfg(target_arch = "wasm32")]
fn admin_token_hash_from_env(env: &Env) -> Result<String, ClientManagementError> {
    if let Some(hash) =
        secret_string(env, "ADMIN_TOKEN_SHA256").or_else(|| env_string(env, "ADMIN_TOKEN_SHA256"))
    {
        return normalize_admin_token_hash(&hash).map_err(ClientManagementError::server_error);
    }

    if let Some(token) =
        secret_string(env, "ADMIN_TOKEN").or_else(|| env_string(env, "ADMIN_TOKEN"))
    {
        let token = token.trim();
        if token.is_empty() {
            return Err(ClientManagementError::server_error(
                "ADMIN_TOKEN must not be empty",
            ));
        }
        return Ok(hash_secret(token));
    }

    Err(ClientManagementError::server_error(
        "ADMIN_TOKEN or ADMIN_TOKEN_SHA256 is not configured",
    ))
}

fn bearer_token_from_authorization_header(
    authorization: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(authorization) = authorization else {
        return Ok(None);
    };
    let mut parts = authorization.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default();
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err("missing bearer token".to_owned());
    }
    Ok(Some(token.to_owned()))
}

#[cfg(target_arch = "wasm32")]
fn auth_error_json(error: &AuthorizationRequestError, status: u16) -> worker::Result<Response> {
    oauth_error_json(error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn provider_callback_error_json(
    error: &ProviderCallbackError,
    status: u16,
) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn provider_token_exchange_error_json(
    error: &ProviderTokenExchangeError,
    status: u16,
) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn provider_profile_error_json(
    error: &ProviderProfileError,
    status: u16,
) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn token_exchange_error_json(error: &TokenExchangeError, status: u16) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, status)
}

#[cfg(target_arch = "wasm32")]
fn client_management_error_json(error: &ClientManagementError) -> worker::Result<Response> {
    oauth_error_json(&error.code, &error.description, error.status)
}

#[cfg(target_arch = "wasm32")]
fn oauth_error_json(
    error: impl Into<String>,
    error_description: impl Into<String>,
    status: u16,
) -> worker::Result<Response> {
    json_status(
        &OAuthErrorResponse {
            error: error.into(),
            error_description: error_description.into(),
        },
        status,
    )
}

fn query_param(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn identity_reference_from_url(url: &url::Url) -> Result<IdentityReference, String> {
    let provider_id =
        query_param(url, "provider_id").ok_or_else(|| "missing provider_id".to_owned())?;
    let provider_subject = query_param(url, "provider_subject")
        .ok_or_else(|| "missing provider_subject".to_owned())?;

    validate_identity_provider_id(&provider_id)?;
    validate_identity_provider_subject(&provider_subject)?;

    Ok(IdentityReference {
        provider_id,
        provider_subject,
    })
}

fn validate_identity_provider_id(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("missing provider_id".to_owned());
    }
    if value.len() > 64 {
        return Err("provider_id is too long".to_owned());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("provider_id contains unsupported characters".to_owned());
    }
    Ok(())
}

fn validate_identity_provider_subject(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("missing provider_subject".to_owned());
    }
    if value.len() > 512 {
        return Err("provider_subject is too long".to_owned());
    }
    Ok(())
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    bytes_to_hex(&digest)
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn provider_token_request_body(request: &TokenExchangeRequest) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in &request.params {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

fn provider_token_response_to_set(
    response: ProviderTokenResponse,
) -> Result<ProviderTokenSet, ProviderTokenExchangeError> {
    if let Some(error) = response.error {
        return Err(ProviderTokenExchangeError {
            code: error,
            description: response
                .error_description
                .unwrap_or_else(|| "provider token exchange failed".to_owned()),
        });
    }

    if response.access_token.is_none() && response.id_token.is_none() {
        return Err(ProviderTokenExchangeError::invalid_response(
            "provider token response did not include an access_token or id_token",
        ));
    }

    Ok(ProviderTokenSet {
        access_token: response.access_token,
        id_token: response.id_token,
        refresh_token: response.refresh_token,
        expires_in: response.expires_in,
    })
}

#[cfg(target_arch = "wasm32")]
async fn resolve_provider_profile(
    provider: &OAuthProvider,
    token_set: &ProviderTokenSet,
    transaction: &AuthTransaction,
    callback: &ProviderCallback,
) -> Result<ResolvedProviderProfile, ProviderProfileError> {
    match provider.id().0.as_str() {
        well_known::SPOTIFY => fetch_spotify_profile(provider, token_set).await,
        well_known::APPLE | well_known::GOOGLE => {
            resolve_oidc_provider_profile(provider, token_set, transaction, callback).await
        }
        provider_id => Err(ProviderProfileError::invalid_response(format!(
            "unsupported provider profile source: {provider_id}"
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_oidc_provider_profile(
    provider: &OAuthProvider,
    token_set: &ProviderTokenSet,
    transaction: &AuthTransaction,
    callback: &ProviderCallback,
) -> Result<ResolvedProviderProfile, ProviderProfileError> {
    let id_token = token_set
        .id_token
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("missing provider id_token"))?;
    let now = unix_timestamp_seconds();
    let jwks = cached_provider_jwks(&provider.id().0, now).await?;
    let verified = verify_provider_id_token_with_web_crypto(
        id_token,
        &jwks,
        ProviderIdTokenValidation {
            provider_id: &provider.id().0,
            client_id: &provider.config().client_id,
            nonce: provider_authorize_nonce(transaction),
            now,
        },
    )
    .await?;
    let claims = verified.claims;
    let apple_user = if provider.id().0 == well_known::APPLE {
        callback
            .apple_user_json
            .as_deref()
            .map(apple_callback_user_from_json)
            .transpose()?
    } else {
        None
    };
    let display_name = claims.name.or_else(|| {
        apple_user
            .as_ref()
            .and_then(apple_callback_user_display_name)
    });
    let raw_profile_json = merge_oidc_raw_profile_json(
        &verified.raw_claims_json,
        apple_user
            .as_ref()
            .and_then(|_| callback.apple_user_json.as_deref()),
    );
    let source = ProviderProfileSource::OidcClaims {
        sub: claims.sub,
        email: claims.email,
        email_verified: boolish_claim(claims.email_verified.as_ref()).unwrap_or(false),
        name: display_name,
        picture: claims.picture,
    };
    let profile = provider
        .normalize_profile(source)
        .map_err(|error| ProviderProfileError {
            code: error.code,
            description: error.description,
        })?;

    Ok(ResolvedProviderProfile {
        profile,
        raw_profile_json,
    })
}

fn apple_callback_user_from_json(value: &str) -> Result<AppleCallbackUser, ProviderProfileError> {
    serde_json::from_str(value).map_err(|error| {
        ProviderProfileError::invalid_response(format!("invalid Apple callback user JSON: {error}"))
    })
}

fn apple_callback_user_display_name(user: &AppleCallbackUser) -> Option<String> {
    let name = user.name.as_ref()?;
    let first = name.first_name.as_deref().map(str::trim).unwrap_or("");
    let last = name.last_name.as_deref().map(str::trim).unwrap_or("");
    let display_name = match (first.is_empty(), last.is_empty()) {
        (false, false) => format!("{first} {last}"),
        (false, true) => first.to_owned(),
        (true, false) => last.to_owned(),
        (true, true) => String::new(),
    };
    (!display_name.is_empty()).then_some(display_name)
}

fn merge_oidc_raw_profile_json(claims_json: &str, apple_user_json: Option<&str>) -> Option<String> {
    let Some(apple_user_json) = apple_user_json else {
        return Some(claims_json.to_owned());
    };
    let claims = serde_json::from_str::<serde_json::Value>(claims_json).ok()?;
    let apple_user = serde_json::from_str::<serde_json::Value>(apple_user_json).ok()?;
    serde_json::to_string(&serde_json::json!({
        "id_token_claims": claims,
        "apple_user": apple_user,
    }))
    .ok()
}

#[cfg(target_arch = "wasm32")]
async fn cached_provider_jwks(
    provider_id: &str,
    now: i32,
) -> Result<ProviderJwksResponse, ProviderProfileError> {
    if let Some(jwks) = PROVIDER_JWKS_CACHE.with(|cache| cache.borrow_mut().get(provider_id, now)) {
        return Ok(jwks);
    }

    let jwks = fetch_provider_jwks(provider_id).await?;
    PROVIDER_JWKS_CACHE.with(|cache| cache.borrow_mut().put(provider_id, jwks.clone(), now));
    Ok(jwks)
}

#[cfg(target_arch = "wasm32")]
async fn fetch_provider_jwks(
    provider_id: &str,
) -> Result<ProviderJwksResponse, ProviderProfileError> {
    let endpoint = provider_jwks_endpoint(provider_id)?;
    let headers = Headers::new();
    headers
        .set("Accept", "application/json")
        .map_err(ProviderProfileError::worker)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let outbound = Request::new_with_init(endpoint, &init).map_err(ProviderProfileError::worker)?;
    let mut response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(ProviderProfileError::worker)?;
    let status = response.status_code();
    let jwks = response
        .json::<ProviderJwksResponse>()
        .await
        .map_err(ProviderProfileError::worker)?;
    if !(200..300).contains(&status) {
        return Err(ProviderProfileError::invalid_response(format!(
            "provider JWKS endpoint returned HTTP {status}"
        )));
    }

    Ok(jwks)
}

fn provider_jwks_endpoint(provider_id: &str) -> Result<&'static str, ProviderProfileError> {
    match provider_id {
        well_known::APPLE => Ok("https://appleid.apple.com/auth/keys"),
        well_known::GOOGLE => Ok("https://www.googleapis.com/oauth2/v3/certs"),
        _ => Err(ProviderProfileError::invalid_response(format!(
            "provider does not expose OIDC JWKS: {provider_id}"
        ))),
    }
}

#[cfg(target_arch = "wasm32")]
async fn verify_provider_id_token_with_web_crypto(
    id_token: &str,
    jwks: &ProviderJwksResponse,
    validation: ProviderIdTokenValidation<'_>,
) -> Result<VerifiedProviderIdToken, ProviderProfileError> {
    let segments = jwt_segments(id_token)?;
    let header = decode_jwt_segment::<ProviderJwtHeader>(segments[0])?;
    if header.alg != "RS256" {
        return Err(ProviderProfileError::invalid_response(format!(
            "unsupported provider id_token alg: {}",
            header.alg
        )));
    }

    let jwk = provider_jwk_for_header(jwks, &header)?;
    verify_rs256_signature_with_web_crypto(
        jwk,
        &format!("{}.{}", segments[0], segments[1]),
        segments[2],
    )
    .await?;

    verified_provider_id_token_from_segments(&segments, validation)
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn verify_provider_id_token(
    id_token: &str,
    jwks: &ProviderJwksResponse,
    validation: ProviderIdTokenValidation<'_>,
) -> Result<VerifiedProviderIdToken, ProviderProfileError> {
    let segments = jwt_segments(id_token)?;
    let header = decode_jwt_segment::<ProviderJwtHeader>(segments[0])?;
    if header.alg != "RS256" {
        return Err(ProviderProfileError::invalid_response(format!(
            "unsupported provider id_token alg: {}",
            header.alg
        )));
    }

    let key = provider_rsa_key_for_header(jwks, &header)?;
    verify_rs256_signature(
        &key,
        &format!("{}.{}", segments[0], segments[1]),
        segments[2],
    )?;

    verified_provider_id_token_from_segments(&segments, validation)
}

fn verified_provider_id_token_from_segments(
    segments: &[&str],
    validation: ProviderIdTokenValidation<'_>,
) -> Result<VerifiedProviderIdToken, ProviderProfileError> {
    let raw_claims_json =
        String::from_utf8(decode_jwt_segment_bytes(segments[1])?).map_err(|error| {
            ProviderProfileError::invalid_response(format!(
                "id_token claims are not UTF-8: {error}"
            ))
        })?;
    let claims =
        serde_json::from_str::<ProviderIdTokenClaims>(&raw_claims_json).map_err(|error| {
            ProviderProfileError::invalid_response(format!("invalid id_token claims: {error}"))
        })?;
    validate_provider_id_token_claims(&claims, validation)?;

    Ok(VerifiedProviderIdToken {
        claims,
        raw_claims_json,
    })
}

fn jwt_segments(jwt: &str) -> Result<Vec<&str>, ProviderProfileError> {
    let segments = jwt.split('.').collect::<Vec<_>>();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(ProviderProfileError::invalid_response(
            "id_token must have three non-empty JWT segments",
        ));
    }
    Ok(segments)
}

fn decode_jwt_segment<T: serde::de::DeserializeOwned>(
    segment: &str,
) -> Result<T, ProviderProfileError> {
    let bytes = decode_jwt_segment_bytes(segment)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ProviderProfileError::invalid_response(format!("invalid JWT JSON: {error}"))
    })
}

fn decode_jwt_segment_bytes(segment: &str) -> Result<Vec<u8>, ProviderProfileError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .map_err(|error| {
            ProviderProfileError::invalid_response(format!(
                "invalid JWT base64url segment: {error}"
            ))
        })
}

fn provider_jwk_for_header<'a>(
    jwks: &'a ProviderJwksResponse,
    header: &ProviderJwtHeader,
) -> Result<&'a ProviderJwk, ProviderProfileError> {
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("id_token header is missing kid"))?;
    jwks.keys
        .iter()
        .find(|key| {
            key.kid.as_deref() == Some(kid)
                && key.kty == "RSA"
                && key.key_use.as_deref().unwrap_or("sig") == "sig"
                && key.alg.as_deref().unwrap_or("RS256") == "RS256"
        })
        .ok_or_else(|| {
            ProviderProfileError::invalid_response("matching provider JWKS key was not found")
        })
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn provider_rsa_key_for_header(
    jwks: &ProviderJwksResponse,
    header: &ProviderJwtHeader,
) -> Result<RsaPublicKey, ProviderProfileError> {
    let jwk = provider_jwk_for_header(jwks, header)?;
    let n = decode_jwk_rsa_part(jwk.n.as_deref(), "n")?;
    let e = decode_jwk_rsa_part(jwk.e.as_deref(), "e")?;

    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e)).map_err(|error| {
        ProviderProfileError::invalid_response(format!("invalid provider RSA JWK: {error}"))
    })
}

#[cfg(target_arch = "wasm32")]
async fn verify_rs256_signature_with_web_crypto(
    jwk: &ProviderJwk,
    signing_input: &str,
    signature_segment: &str,
) -> Result<(), ProviderProfileError> {
    let signature = decode_jwt_segment_bytes(signature_segment)?;
    let subtle = worker_global_crypto_subtle()?;
    let algorithm = rsa_pkcs1_sha256_algorithm()?;
    let key_data = provider_jwk_key_data(jwk)?;
    let key_usages = single_js_string_array("verify");

    let key_value = JsFuture::from(
        subtle
            .import_key_with_object("jwk", &key_data, &algorithm, false, &key_usages)
            .map_err(|error| js_profile_error("could not import provider RSA JWK", error))?,
    )
    .await
    .map_err(|error| js_profile_error("provider RSA JWK import failed", error))?;
    let key = key_value
        .dyn_into::<worker::web_sys::CryptoKey>()
        .map_err(|error| js_profile_error("provider RSA JWK did not produce a CryptoKey", error))?;

    let verified = JsFuture::from(
        subtle
            .verify_with_object_and_u8_array_and_u8_array(
                &algorithm,
                &key,
                &signature,
                signing_input.as_bytes(),
            )
            .map_err(|error| js_profile_error("could not verify provider id_token", error))?,
    )
    .await
    .map_err(|error| js_profile_error("provider id_token verification failed", error))?;

    if verified.as_bool() == Some(true) {
        Ok(())
    } else {
        Err(ProviderProfileError::invalid_response(
            "provider id_token signature did not verify",
        ))
    }
}

#[cfg(target_arch = "wasm32")]
fn worker_global_crypto_subtle() -> Result<worker::web_sys::SubtleCrypto, ProviderProfileError> {
    let global: worker::web_sys::WorkerGlobalScope = worker::js_sys::global().unchecked_into();
    let crypto = global
        .crypto()
        .map_err(|error| js_profile_error("could not access Worker crypto", error))?;
    Ok(crypto.subtle())
}

#[cfg(target_arch = "wasm32")]
fn rsa_pkcs1_sha256_algorithm() -> Result<worker::js_sys::Object, ProviderProfileError> {
    let algorithm = worker::js_sys::Object::new();
    set_js_string_property(&algorithm, "name", "RSASSA-PKCS1-v1_5")?;
    set_js_string_property(&algorithm, "hash", "SHA-256")?;
    Ok(algorithm)
}

#[cfg(target_arch = "wasm32")]
fn provider_jwk_key_data(
    jwk: &ProviderJwk,
) -> Result<worker::js_sys::Object, ProviderProfileError> {
    let n = jwk
        .n
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("provider RSA JWK is missing n"))?;
    let e = jwk
        .e
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("provider RSA JWK is missing e"))?;

    let key_data = worker::js_sys::Object::new();
    set_js_string_property(&key_data, "kty", "RSA")?;
    set_js_string_property(&key_data, "n", n)?;
    set_js_string_property(&key_data, "e", e)?;
    set_js_string_property(&key_data, "alg", "RS256")?;
    set_js_string_property(&key_data, "use", "sig")?;
    set_js_value_property(&key_data, "ext", &JsValue::from_bool(true))?;
    set_js_value_property(&key_data, "key_ops", &single_js_string_array("verify"))?;
    Ok(key_data)
}

#[cfg(target_arch = "wasm32")]
fn single_js_string_array(value: &str) -> JsValue {
    let array = worker::js_sys::Array::new();
    array.push(&JsValue::from_str(value));
    array.into()
}

#[cfg(target_arch = "wasm32")]
fn set_js_string_property(
    target: &worker::js_sys::Object,
    name: &str,
    value: &str,
) -> Result<(), ProviderProfileError> {
    set_js_value_property(target, name, &JsValue::from_str(value))
}

#[cfg(target_arch = "wasm32")]
fn set_js_value_property(
    target: &worker::js_sys::Object,
    name: &str,
    value: &JsValue,
) -> Result<(), ProviderProfileError> {
    let ok = worker::js_sys::Reflect::set(target, &JsValue::from_str(name), value)
        .map_err(|error| js_profile_error("could not set WebCrypto parameter", error))?;
    if ok {
        Ok(())
    } else {
        Err(ProviderProfileError::invalid_response(format!(
            "could not set WebCrypto parameter: {name}"
        )))
    }
}

#[cfg(target_arch = "wasm32")]
fn js_profile_error(context: &str, error: JsValue) -> ProviderProfileError {
    let detail = error
        .dyn_ref::<worker::js_sys::Error>()
        .map(|error| error.message().into())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "JavaScript error".to_owned());
    ProviderProfileError::invalid_response(format!("{context}: {detail}"))
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn decode_jwk_rsa_part(value: Option<&str>, name: &str) -> Result<Vec<u8>, ProviderProfileError> {
    let value = value.ok_or_else(|| {
        ProviderProfileError::invalid_response(format!("provider RSA JWK is missing {name}"))
    })?;
    decode_jwt_segment_bytes(value)
}

#[cfg(any(test, not(target_arch = "wasm32")))]
fn verify_rs256_signature(
    key: &RsaPublicKey,
    signing_input: &str,
    signature_segment: &str,
) -> Result<(), ProviderProfileError> {
    let signature_bytes = decode_jwt_segment_bytes(signature_segment)?;
    let signature =
        RsaPkcs1v15Signature::try_from(signature_bytes.as_slice()).map_err(|error| {
            ProviderProfileError::invalid_response(format!("invalid RS256 signature: {error}"))
        })?;
    let verifying_key = RsaPkcs1v15VerifyingKey::<Sha256>::new(key.clone());
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| {
            ProviderProfileError::invalid_response("provider id_token signature did not verify")
        })
}

fn validate_provider_id_token_claims(
    claims: &ProviderIdTokenClaims,
    validation: ProviderIdTokenValidation<'_>,
) -> Result<(), ProviderProfileError> {
    if !provider_issuer_matches(validation.provider_id, &claims.iss) {
        return Err(ProviderProfileError::invalid_response(format!(
            "id_token issuer did not match provider: {}",
            claims.iss
        )));
    }

    if !claims.aud.contains(validation.client_id) {
        return Err(ProviderProfileError::invalid_response(
            "id_token audience did not include provider client_id",
        ));
    }

    if claims.exp <= i64::from(validation.now) {
        return Err(ProviderProfileError::invalid_response(
            "id_token has expired",
        ));
    }

    if let Some(expected_nonce) = validation.nonce {
        if claims.nonce.as_deref() != Some(expected_nonce) {
            return Err(ProviderProfileError::invalid_response(
                "id_token nonce did not match authorization request",
            ));
        }
    }

    if claims.sub.is_empty() {
        return Err(ProviderProfileError::invalid_response(
            "id_token subject is empty",
        ));
    }

    Ok(())
}

fn provider_issuer_matches(provider_id: &str, issuer: &str) -> bool {
    match provider_id {
        well_known::APPLE => issuer == "https://appleid.apple.com",
        well_known::GOOGLE => {
            issuer == "https://accounts.google.com" || issuer == "accounts.google.com"
        }
        _ => false,
    }
}

impl AudienceClaim {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Self::One(value) => value == audience,
            Self::Many(values) => values.iter().any(|value| value == audience),
        }
    }
}

fn boolish_claim(value: Option<&serde_json::Value>) -> Option<bool> {
    match value {
        Some(serde_json::Value::Bool(value)) => Some(*value),
        Some(serde_json::Value::String(value)) if value == "true" => Some(true),
        Some(serde_json::Value::String(value)) if value == "false" => Some(false),
        Some(serde_json::Value::Number(value)) => value.as_i64().map(|value| value != 0),
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_spotify_profile(
    provider: &OAuthProvider,
    token_set: &ProviderTokenSet,
) -> Result<ResolvedProviderProfile, ProviderProfileError> {
    let endpoint = provider
        .config()
        .profile_endpoint
        .as_deref()
        .ok_or_else(|| {
            ProviderProfileError::invalid_response("missing Spotify profile endpoint")
        })?;
    let access_token = token_set
        .access_token
        .as_deref()
        .ok_or_else(|| ProviderProfileError::invalid_response("missing Spotify access token"))?;

    let headers = Headers::new();
    headers
        .set("Authorization", &format!("Bearer {access_token}"))
        .map_err(ProviderProfileError::worker)?;
    headers
        .set("Accept", "application/json")
        .map_err(ProviderProfileError::worker)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let outbound = Request::new_with_init(endpoint, &init).map_err(ProviderProfileError::worker)?;
    let mut response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(ProviderProfileError::worker)?;
    let status = response.status_code();
    let spotify_profile = response
        .json::<SpotifyApiProfile>()
        .await
        .map_err(ProviderProfileError::worker)?;
    if !(200..300).contains(&status) {
        return Err(ProviderProfileError::invalid_response(format!(
            "Spotify profile endpoint returned HTTP {status}"
        )));
    }

    let raw_profile_json = serde_json::to_string(&spotify_profile).ok();
    let source = spotify_profile_source(spotify_profile)?;
    let profile = provider
        .normalize_profile(source)
        .map_err(|error| ProviderProfileError {
            code: error.code,
            description: error.description,
        })?;

    Ok(ResolvedProviderProfile {
        profile,
        raw_profile_json,
    })
}

fn spotify_profile_source(
    profile: SpotifyApiProfile,
) -> Result<ProviderProfileSource, ProviderProfileError> {
    if profile.id.is_empty() {
        return Err(ProviderProfileError::invalid_response(
            "Spotify profile did not include an id",
        ));
    }

    Ok(ProviderProfileSource::SpotifyProfile {
        id: profile.id,
        email: profile.email,
        display_name: profile.display_name,
        image_url: spotify_profile_image_url(&profile.images),
    })
}

fn spotify_profile_image_url(images: &[SpotifyApiImage]) -> Option<String> {
    images.iter().find_map(|image| image.url.clone())
}

#[cfg(target_arch = "wasm32")]
async fn exchange_provider_code(
    request: TokenExchangeRequest,
) -> Result<ProviderTokenSet, ProviderTokenExchangeError> {
    if matches!(request.token_auth, TokenAuth::None) {
        return Err(ProviderTokenExchangeError::invalid_request(
            "unsupported provider token auth mode",
        ));
    }

    let body = provider_token_request_body(&request);
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(ProviderTokenExchangeError::worker)?;
    headers
        .set("Accept", "application/json")
        .map_err(ProviderTokenExchangeError::worker)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&body)));

    let outbound = Request::new_with_init(&request.endpoint, &init)
        .map_err(ProviderTokenExchangeError::worker)?;
    let mut response = Fetch::Request(outbound)
        .send()
        .await
        .map_err(ProviderTokenExchangeError::worker)?;
    let status = response.status_code();
    let token_response = response
        .json::<ProviderTokenResponse>()
        .await
        .map_err(ProviderTokenExchangeError::worker)?;

    let token_set = provider_token_response_to_set(token_response)?;
    if !(200..300).contains(&status) {
        return Err(ProviderTokenExchangeError::invalid_response(format!(
            "provider token endpoint returned HTTP {status}"
        )));
    }
    Ok(token_set)
}

#[cfg(target_arch = "wasm32")]
fn d1_optional_text(value: Option<&str>) -> worker::d1::D1Type<'_> {
    match value {
        Some(value) => worker::d1::D1Type::Text(value),
        None => worker::d1::D1Type::Null,
    }
}

#[cfg(target_arch = "wasm32")]
fn d1_optional_integer(value: Option<i32>) -> worker::d1::D1Type<'static> {
    match value {
        Some(value) => worker::d1::D1Type::Integer(value),
        None => worker::d1::D1Type::Null,
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
fn d1_changes_exactly_one(changes: Option<usize>) -> bool {
    changes == Some(1)
}

#[cfg(target_arch = "wasm32")]
fn d1_result_changed_one(result: worker::d1::D1Result) -> worker::Result<bool> {
    let meta = result
        .meta()?
        .ok_or_else(|| worker_error("D1 result metadata was not populated".to_owned()))?;
    Ok(d1_changes_exactly_one(meta.changes))
}

#[cfg(target_arch = "wasm32")]
fn unix_timestamp_seconds() -> i32 {
    (worker::js_sys::Date::now() / 1000.0) as i32
}

fn unix_seconds_to_system_time(seconds: i32) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds as u64)
}

fn system_time_to_unix_seconds(time: SystemTime) -> Result<i32, String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "time is before unix epoch".to_owned())?
        .as_secs();
    i32::try_from(seconds).map_err(|_| "time exceeds D1 integer range".to_owned())
}

#[cfg(target_arch = "wasm32")]
fn system_time_to_d1_integer(time: SystemTime) -> worker::Result<i32> {
    system_time_to_unix_seconds(time).map_err(worker_error)
}

impl ProviderCallbackError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn access_denied(description: impl Into<String>) -> Self {
        Self {
            code: "access_denied".to_owned(),
            description: description.into(),
        }
    }
}

impl ProviderTokenExchangeError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn invalid_response(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_response".to_owned(),
            description: description.into(),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn worker(error: worker::Error) -> Self {
        Self {
            code: "provider_exchange_failed".to_owned(),
            description: error.to_string(),
        }
    }
}

impl ProviderProfileError {
    fn invalid_response(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_response".to_owned(),
            description: description.into(),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn worker(error: worker::Error) -> Self {
        Self {
            code: "provider_profile_failed".to_owned(),
            description: error.to_string(),
        }
    }
}

impl IdentityLinkError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn conflict(description: impl Into<String>) -> Self {
        Self {
            code: "identity_link_conflict".to_owned(),
            description: description.into(),
        }
    }
}

impl ProfilePatchError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: 400,
        }
    }

    fn payload_too_large(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            status: 413,
        }
    }
}

impl ClientManagementError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
            status: 400,
        }
    }

    fn unauthorized(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_token".to_owned(),
            description: description.into(),
            status: 401,
        }
    }

    fn not_found(description: impl Into<String>) -> Self {
        Self {
            code: "not_found".to_owned(),
            description: description.into(),
            status: 404,
        }
    }

    fn payload_too_large(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
            status: 413,
        }
    }

    fn server_error(description: impl Into<String>) -> Self {
        Self {
            code: "server_error".to_owned(),
            description: description.into(),
            status: 503,
        }
    }
}

impl TokenExchangeError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request".to_owned(),
            description: description.into(),
        }
    }

    fn invalid_client(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_client".to_owned(),
            description: description.into(),
        }
    }

    fn invalid_grant(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_grant".to_owned(),
            description: description.into(),
        }
    }

    fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self {
            code: "unsupported_grant_type".to_owned(),
            description: description.into(),
        }
    }

    fn unsupported_token_type(description: impl Into<String>) -> Self {
        Self {
            code: "unsupported_token_type".to_owned(),
            description: description.into(),
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn worker_error(error: String) -> worker::Error {
    worker::Error::RustError(error)
}

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
#[worker::wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues, catch)]
    fn get_random_values(buf: &mut [u8]) -> Result<(), worker::wasm_bindgen::JsValue>;
}

#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
#[worker::wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "crypto"], js_name = getRandomValues, catch)]
    fn get_random_values(
        buf: &worker::js_sys::Uint8Array,
    ) -> Result<(), worker::wasm_bindgen::JsValue>;
}

#[cfg(target_arch = "wasm32")]
const MAX_RANDOM_BYTES: usize = 65_536;

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
fn fill_random(bytes: &mut [u8]) -> worker::Result<()> {
    for chunk in bytes.chunks_mut(MAX_RANDOM_BYTES) {
        get_random_values(chunk)
            .map_err(|_| worker::Error::RustError("WebCrypto getRandomValues failed".to_owned()))?;
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
fn fill_random(bytes: &mut [u8]) -> worker::Result<()> {
    let buffer_len = usize::min(bytes.len(), MAX_RANDOM_BYTES);
    let buffer_len = u32::try_from(buffer_len)
        .map_err(|_| worker::Error::RustError("random buffer is too large".to_owned()))?;
    let buffer = worker::js_sys::Uint8Array::new_with_length(buffer_len);

    for chunk in bytes.chunks_mut(buffer_len as usize) {
        let chunk_len = u32::try_from(chunk.len())
            .map_err(|_| worker::Error::RustError("random chunk is too large".to_owned()))?;
        let sub_buffer = if chunk_len == buffer_len {
            buffer.clone()
        } else {
            buffer.subarray(0, chunk_len)
        };

        get_random_values(&sub_buffer)
            .map_err(|_| worker::Error::RustError("WebCrypto getRandomValues failed".to_owned()))?;
        sub_buffer.copy_to(chunk);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn random_token() -> worker::Result<String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;

    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

#[cfg(target_arch = "wasm32")]
fn json<T: Serialize>(value: &T) -> worker::Result<Response> {
    Response::from_json(value)
}

#[cfg(target_arch = "wasm32")]
fn json_status<T: Serialize>(value: &T, status: u16) -> worker::Result<Response> {
    Response::from_json(value).map(|response| response.with_status(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::{
        pkcs1v15::SigningKey as RsaPkcs1v15SigningKey,
        rand_core::OsRng,
        signature::{RandomizedSigner, SignatureEncoding},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use zeroth_oidc::PkceChallengeMethod;

    #[test]
    fn discovery_uses_base_url() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };

        let discovery = discovery_response(&config);
        assert_eq!(discovery.issuer, "https://id.example.com");
        assert_eq!(
            discovery.authorization_endpoint,
            "https://id.example.com/authorize"
        );
        assert_eq!(
            discovery.revocation_endpoint,
            "https://id.example.com/oauth/revoke"
        );
        assert_eq!(
            discovery.introspection_endpoint,
            "https://id.example.com/oauth/introspect"
        );
        assert_eq!(
            discovery.end_session_endpoint,
            "https://id.example.com/logout"
        );
        assert!(discovery
            .grant_types_supported
            .contains(&"authorization_code"));
        assert!(discovery
            .revocation_endpoint_auth_methods_supported
            .contains(&"client_secret_basic"));
        assert!(discovery
            .introspection_endpoint_auth_methods_supported
            .contains(&"client_secret_basic"));
        assert!(!discovery
            .introspection_endpoint_auth_methods_supported
            .contains(&"none"));
        assert!(discovery.response_modes_supported.contains(&"query"));
        assert!(discovery.prompt_values_supported.contains(&"none"));
        assert!(discovery.prompt_values_supported.contains(&"login"));
        assert!(discovery
            .id_token_signing_alg_values_supported
            .contains(&"ES256"));
        assert!(discovery.claims_supported.contains(&"email"));
        assert!(discovery.claims_supported.contains(&"email_verified"));
        assert!(discovery.claims_supported.contains(&"name"));
        assert!(discovery.claims_supported.contains(&"picture"));
        assert!(discovery.claims_supported.contains(&"sid"));
        assert!(discovery.authorization_response_iss_parameter_supported);
    }

    #[test]
    fn readiness_requires_https_issuer_signing_and_all_providers() {
        let issuer = ReadinessCheck {
            configured: true,
            notes: Vec::new(),
        };
        let signing = ReadinessCheck {
            configured: true,
            notes: Vec::new(),
        };
        let providers = vec![
            ProviderReadiness {
                id: "apple",
                label: "Apple",
                kind: "oidc",
                configured: true,
                notes: Vec::new(),
            },
            ProviderReadiness {
                id: "google",
                label: "Google",
                kind: "oidc",
                configured: true,
                notes: Vec::new(),
            },
            ProviderReadiness {
                id: "spotify",
                label: "Spotify",
                kind: "oauth2",
                configured: true,
                notes: Vec::new(),
            },
        ];

        assert!(readiness_is_ready(&issuer, &signing, &providers));

        let mut missing_provider = providers.clone();
        missing_provider[2].configured = false;
        assert!(!readiness_is_ready(&issuer, &signing, &missing_provider));

        let missing_signing = ReadinessCheck {
            configured: false,
            notes: vec!["missing_jwt_es256_private_key"],
        };
        assert!(!readiness_is_ready(&issuer, &missing_signing, &providers));
    }

    #[test]
    fn issuer_readiness_requires_https_url_with_host() {
        let ready = issuer_readiness(&ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        });
        assert!(ready.configured);
        assert!(ready.notes.is_empty());

        let http = issuer_readiness(&ZerothServerConfig {
            public_base_url: "http://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        });
        assert!(!http.configured);
        assert_eq!(http.notes, vec!["issuer_not_https"]);

        let invalid = issuer_readiness(&ZerothServerConfig {
            public_base_url: "not a url".to_owned(),
            ..ZerothServerConfig::default()
        });
        assert!(!invalid.configured);
        assert_eq!(invalid.notes, vec!["invalid_issuer_url"]);
    }

    #[test]
    fn apple_app_site_association_readiness_requires_object_json() {
        let ready = apple_app_site_association_readiness_from_payload(Some(
            r#"{"webcredentials":{"apps":["TEAM.ai.wavey.app"]}}"#,
        ));
        assert!(ready.configured);
        assert!(ready.notes.is_empty());

        let missing = apple_app_site_association_readiness_from_payload(None);
        assert!(!missing.configured);
        assert_eq!(
            missing.notes,
            vec!["missing_apple_app_site_association_json"]
        );

        let array = apple_app_site_association_readiness_from_payload(Some("[]"));
        assert!(!array.configured);
        assert_eq!(array.notes, vec!["apple_app_site_association_not_object"]);
    }

    #[test]
    fn passkey_challenge_round_trips_through_browser_encoding() {
        let challenge = "0123456789abcdef";
        let encoded = passkey_challenge_for_browser(challenge);

        assert_eq!(passkey_challenge_from_browser(&encoded).unwrap(), challenge);
        assert!(passkey_challenge_matches_client_data(
            &hash_secret(challenge),
            &test_passkey_client_data("webauthn.get", challenge, "https://id.example.com")
        ));
    }

    #[test]
    fn passkey_registration_response_extracts_es256_credential() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let credential_id = b"credential-1";
        let x = [3u8; 32];
        let y = [7u8; 32];
        let auth_data = test_passkey_authenticator_data(
            "id.example.com",
            0x45,
            9,
            credential_id,
            &test_passkey_cose_key(&x, &y),
        );
        let body = PasskeyRegisterVerifyRequest {
            id: URL_SAFE_NO_PAD.encode(credential_id),
            raw_id: URL_SAFE_NO_PAD.encode(credential_id),
            response: PasskeyRegisterCredentialResponse {
                client_data_json: test_passkey_client_data(
                    "webauthn.create",
                    "challenge-1",
                    "https://id.example.com",
                ),
                attestation_object: URL_SAFE_NO_PAD
                    .encode(test_passkey_attestation_object(&auth_data)),
                transports: Vec::new(),
            },
        };

        let validated = validate_passkey_registration_response(&config, &body).unwrap();

        assert_eq!(
            validated.credential_id,
            URL_SAFE_NO_PAD.encode(credential_id)
        );
        assert_eq!(validated.public_key_x, URL_SAFE_NO_PAD.encode(x));
        assert_eq!(validated.public_key_y, URL_SAFE_NO_PAD.encode(y));
        assert_eq!(validated.sign_count, 9);
    }

    #[test]
    fn passkey_es256_signature_verifies_signed_authenticator_payload() {
        let signing_key = SigningKey::from_slice(&[11u8; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        let credential = PasskeyCredentialRow {
            credential_id: "cred_1".to_owned(),
            user_id: "usr_1".to_owned(),
            label: None,
            public_key_x: URL_SAFE_NO_PAD.encode(x),
            public_key_y: URL_SAFE_NO_PAD.encode(y),
            sign_count: 0,
            created_at: 1,
            updated_at: 1,
            last_used_at: None,
            disabled_at: None,
        };
        let signed_data = b"authenticator-data-and-client-data-hash";
        let signature: Signature = signing_key.sign(signed_data);
        let der = signature.to_der();

        verify_passkey_es256_signature(&credential, signed_data, der.as_bytes()).unwrap();

        let error =
            verify_passkey_es256_signature(&credential, b"tampered", der.as_bytes()).unwrap_err();
        assert_eq!(error, "passkey signature did not verify");
    }

    #[test]
    fn config_value_configured_rejects_empty_and_scaffold_placeholders() {
        assert!(config_value_configured(Some(
            "real-google-client-id.apps.googleusercontent.com"
        )));
        assert!(config_value_configured(Some("ai.wavey.signin")));

        for value in [
            None,
            Some(""),
            Some("   "),
            Some("replace-with-google-oauth-client-id"),
            Some("replace-with-sign-in-with-apple-service-id"),
            Some("<Sign in with Apple service id>"),
            Some("changeme"),
            Some("change-me"),
            Some("todo"),
        ] {
            assert!(
                !config_value_configured(value),
                "value should not be configured: {value:?}"
            );
        }
    }

    #[test]
    fn config_value_note_distinguishes_missing_and_placeholder_values() {
        assert_eq!(
            config_value_note(None, "missing_client_id", "placeholder_client_id"),
            Some("missing_client_id")
        );
        assert_eq!(
            config_value_note(
                Some("replace-with-google-oauth-client-id"),
                "missing_client_id",
                "placeholder_client_id"
            ),
            Some("placeholder_client_id")
        );
        assert_eq!(
            config_value_note(
                Some("real-google-client-id.apps.googleusercontent.com"),
                "missing_client_id",
                "placeholder_client_id"
            ),
            None
        );
    }

    #[test]
    fn discovery_serializes_oidc_snake_case_fields() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };

        let value = serde_json::to_value(discovery_response(&config)).unwrap();

        assert!(value.get("authorization_endpoint").is_some());
        assert!(value.get("revocation_endpoint").is_some());
        assert!(value.get("introspection_endpoint").is_some());
        assert!(value.get("end_session_endpoint").is_some());
        assert!(value
            .get("revocation_endpoint_auth_methods_supported")
            .is_some());
        assert!(value
            .get("introspection_endpoint_auth_methods_supported")
            .is_some());
        assert!(value.get("response_modes_supported").is_some());
        assert!(value.get("prompt_values_supported").is_some());
        assert!(value.get("id_token_signing_alg_values_supported").is_some());
        assert!(value.get("claims_supported").is_some());
        assert!(value
            .get("authorization_response_iss_parameter_supported")
            .is_some());
        assert!(value.get("authorizationEndpoint").is_none());
    }

    #[test]
    fn migration_response_reports_applied_and_skipped_migrations() {
        let value = serde_json::to_value(MigrationResponse {
            ok: true,
            binding: D1_BINDING,
            migrations_applied: vec!["init"],
            migrations_skipped: vec!["future"],
        })
        .unwrap();

        assert_eq!(value["ok"], true);
        assert_eq!(value["binding"], D1_BINDING);
        assert_eq!(value["migrationsApplied"][0], "init");
        assert_eq!(value["migrationsSkipped"][0], "future");
        assert!(value.get("migrations_applied").is_none());
    }

    #[test]
    fn db_schema_status_response_serializes_camel_case() {
        let value = serde_json::to_value(DbSchemaStatusResponse {
            ok: true,
            binding: D1_BINDING,
            tables: vec![DbTableStatus {
                name: "zeroth_clients",
                present: true,
            }],
            migrations: vec![DbMigrationStatus {
                version: 1,
                name: "init",
                applied: true,
            }],
            compatibility_columns: vec![DbCompatibilityColumnStatus {
                table: "zeroth_auth_codes",
                name: "auth_time",
                present: true,
            }],
            client_count: 5,
        })
        .unwrap();

        assert_eq!(value["ok"], true);
        assert_eq!(value["binding"], D1_BINDING);
        assert_eq!(value["tables"][0]["name"], "zeroth_clients");
        assert_eq!(value["tables"][0]["present"], true);
        assert_eq!(value["migrations"][0]["applied"], true);
        assert_eq!(
            value["compatibilityColumns"][0]["table"],
            "zeroth_auth_codes"
        );
        assert_eq!(value["clientCount"], 5);
        assert!(value.get("compatibility_columns").is_none());
        assert!(value.get("client_count").is_none());
    }

    #[test]
    fn db_schema_status_ok_requires_every_schema_piece() {
        let tables = zeroth_storage::REQUIRED_TABLES
            .iter()
            .map(|table| DbTableStatus {
                name: table,
                present: true,
            })
            .collect::<Vec<_>>();
        let migrations = zeroth_storage::migrations::ALL
            .iter()
            .map(|migration| DbMigrationStatus {
                version: migration.version,
                name: migration.name,
                applied: true,
            })
            .collect::<Vec<_>>();
        let compatibility_columns = zeroth_storage::compatibility::ALL
            .iter()
            .map(|column| DbCompatibilityColumnStatus {
                table: column.table,
                name: column.name,
                present: true,
            })
            .collect::<Vec<_>>();

        assert!(db_schema_status_ok(
            &tables,
            &migrations,
            &compatibility_columns
        ));

        let mut missing_table = tables.clone();
        missing_table[0].present = false;
        assert!(!db_schema_status_ok(
            &missing_table,
            &migrations,
            &compatibility_columns
        ));
        let partial_tables = tables[1..].to_vec();
        assert!(!db_schema_status_ok(
            &partial_tables,
            &migrations,
            &compatibility_columns
        ));

        let mut pending_migration = migrations.clone();
        pending_migration[0].applied = false;
        assert!(!db_schema_status_ok(
            &tables,
            &pending_migration,
            &compatibility_columns
        ));
        assert!(!db_schema_status_ok(&tables, &[], &compatibility_columns));

        let mut missing_column = compatibility_columns.clone();
        missing_column[0].present = false;
        assert!(!db_schema_status_ok(&tables, &migrations, &missing_column));
        let partial_columns = compatibility_columns[1..].to_vec();
        assert!(!db_schema_status_ok(&tables, &migrations, &partial_columns));
    }

    #[test]
    fn client_row_parses_registered_redirects() {
        let client = client_from_row(ClientRow {
            id: "ios".to_owned(),
            name: "Wavey iOS".to_owned(),
            secret_hash: None,
            redirect_uris_json: r#"["wavey://auth/callback"]"#.to_owned(),
            allowed_origins_json: "[]".to_owned(),
            allowed_email_domains_json: "[]".to_owned(),
            confidential: 0,
            disabled_at: None,
        })
        .unwrap()
        .unwrap();

        assert_eq!(client.id, ClientId("ios".to_owned()));
        assert_eq!(client.redirect_uris, vec!["wavey://auth/callback"]);
        assert!(!client.confidential);
    }

    #[test]
    fn disabled_client_rows_are_hidden() {
        let client = client_from_row(ClientRow {
            id: "web".to_owned(),
            name: "Wavey Web".to_owned(),
            secret_hash: Some(format!("sha256:{}", hash_secret("web-secret"))),
            redirect_uris_json: r#"["https://app.example.com/callback"]"#.to_owned(),
            allowed_origins_json: "[]".to_owned(),
            allowed_email_domains_json: "[]".to_owned(),
            confidential: 1,
            disabled_at: Some(1_780_000_000),
        })
        .unwrap();

        assert_eq!(client, None);
    }

    #[test]
    fn active_client_allowed_origins_requires_active_client() {
        let client = registered_confidential_client("web-secret").client;

        let allowed_origins = active_client_allowed_origins_from_client(Some(client)).unwrap();

        assert_eq!(allowed_origins, vec!["https://app.example.com"]);
        assert_eq!(
            active_client_allowed_origins_from_client(None).unwrap_err(),
            "client is not registered or is disabled"
        );
    }

    #[test]
    fn client_upsert_accepts_native_and_web_redirects() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "ai.wavey.ios",
            "name": "Wavey iOS",
            "redirectUris": [
                "wavey://auth/callback",
                "https://app.example.com/auth/callback",
                "wavey://auth/callback"
            ],
            "allowedOrigins": ["https://app.example.com/"],
            "confidential": false
        }))
        .unwrap();

        assert_eq!(upsert.id, "ai.wavey.ios");
        assert_eq!(
            upsert.redirect_uris,
            vec![
                "wavey://auth/callback".to_owned(),
                "https://app.example.com/auth/callback".to_owned()
            ]
        );
        assert_eq!(
            upsert.allowed_origins,
            vec!["https://app.example.com".to_owned()]
        );
        assert_eq!(upsert.allowed_email_domains, Vec::<String>::new());
        assert!(!upsert.confidential);
        assert_eq!(upsert.secret_hash, None);
    }

    #[test]
    fn client_upsert_accepts_normalized_allowed_email_domains() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "wavey-admin",
            "name": "Wavey Admin",
            "redirectUris": ["https://id.example.com/admin"],
            "allowedEmailDomains": [" @Wavey.ai ", "wavey.ai", "example.com"],
            "confidential": false
        }))
        .unwrap();

        assert_eq!(
            upsert.allowed_email_domains,
            vec!["wavey.ai".to_owned(), "example.com".to_owned()]
        );
    }

    #[test]
    fn confidential_client_upsert_hashes_client_secret() {
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "wavey-web",
            "name": "Wavey Web",
            "redirectUris": ["https://app.example.com/auth/callback"],
            "allowedOrigins": ["https://app.example.com"],
            "confidential": true,
            "clientSecret": "super-secret-client-value"
        }))
        .unwrap();

        assert_eq!(
            upsert.secret_hash,
            Some(format!(
                "sha256:{}",
                hash_secret("super-secret-client-value")
            ))
        );
    }

    #[test]
    fn confidential_client_upsert_accepts_normalized_secret_hash() {
        let hash = hash_secret("super-secret-client-value").to_uppercase();
        let upsert = client_upsert_from_value(serde_json::json!({
            "id": "wavey-web",
            "name": "Wavey Web",
            "redirect_uris": ["https://app.example.com/auth/callback"],
            "allowed_origins": ["https://app.example.com"],
            "confidential": true,
            "secret_hash": format!("sha256:{hash}")
        }))
        .unwrap();

        assert_eq!(
            upsert.secret_hash,
            Some(format!("sha256:{}", hash.to_ascii_lowercase()))
        );
    }

    #[test]
    fn public_client_upsert_rejects_secret_material() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "ios",
            "name": "Wavey iOS",
            "redirectUris": ["wavey://auth/callback"],
            "confidential": false,
            "clientSecret": "super-secret-client-value"
        }))
        .unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "public clients must not include clientSecret or secretHash"
        );
    }

    #[test]
    fn client_upsert_rejects_origin_paths() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "web",
            "name": "Wavey Web",
            "redirectUris": ["https://app.example.com/auth/callback"],
            "allowedOrigins": ["https://app.example.com/path"],
            "confidential": false
        }))
        .unwrap_err();

        assert_eq!(
            error.description,
            "allowed origin must not include a path, query, or fragment"
        );
    }

    #[test]
    fn client_upsert_rejects_invalid_allowed_email_domains() {
        let error = client_upsert_from_value(serde_json::json!({
            "id": "wavey-admin",
            "name": "Wavey Admin",
            "redirectUris": ["https://id.example.com/admin"],
            "allowedEmailDomains": ["wavey"],
            "confidential": false
        }))
        .unwrap_err();

        assert_eq!(error.description, "allowed email domain must include a dot");
    }

    #[test]
    fn client_email_domain_policy_requires_verified_allowed_domain() {
        let client = Client {
            id: ClientId("admin".to_owned()),
            name: "Admin".to_owned(),
            redirect_uris: vec!["https://id.example.com/admin".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec!["wavey.ai".to_owned()],
            confidential: false,
        };
        let mut profile = ProviderProfile {
            provider_id: ProviderId(well_known::GOOGLE.to_owned()),
            subject: zeroth_core::Subject("google-sub".to_owned()),
            email: Some("Admin@Wavey.ai".to_owned()),
            email_verified: true,
            display_name: None,
            picture_url: None,
        };

        validate_client_email_domain_policy(&client, &profile).unwrap();

        profile.email_verified = false;
        let error = validate_client_email_domain_policy(&client, &profile).unwrap_err();
        assert_eq!(error.code, "access_denied");
        assert_eq!(
            error.description,
            "verified email is required for this client"
        );

        profile.email_verified = true;
        profile.email = Some("admin@example.com".to_owned());
        let error = validate_client_email_domain_policy(&client, &profile).unwrap_err();
        assert_eq!(
            error.description,
            "email domain is not allowed for this client"
        );
    }

    #[test]
    fn provider_identity_attachment_validation_rejects_missing_or_conflicting_identity() {
        validate_provider_identity_attached_to_user(Some("usr_123"), "usr_123").unwrap();

        let error = validate_provider_identity_attached_to_user(None, "usr_123").unwrap_err();
        assert_eq!(error, "provider identity could not be linked to the user");

        let error =
            validate_provider_identity_attached_to_user(Some("usr_other"), "usr_123").unwrap_err();
        assert_eq!(error, "provider identity is already linked to another user");
    }

    #[test]
    fn client_response_marks_disabled_and_secret_state() {
        let response = client_response_from_row(ClientRow {
            id: "web".to_owned(),
            name: "Wavey Web".to_owned(),
            secret_hash: Some(format!("sha256:{}", hash_secret("web-secret"))),
            redirect_uris_json: r#"["https://app.example.com/callback"]"#.to_owned(),
            allowed_origins_json: r#"["https://app.example.com"]"#.to_owned(),
            allowed_email_domains_json: r#"["example.com"]"#.to_owned(),
            confidential: 1,
            disabled_at: Some(1_780_000_000),
        })
        .unwrap();

        assert_eq!(response.id, "web");
        assert_eq!(
            response.redirect_uris,
            vec!["https://app.example.com/callback".to_owned()]
        );
        assert_eq!(
            response.allowed_origins,
            vec!["https://app.example.com".to_owned()]
        );
        assert!(response.confidential);
        assert!(response.disabled);
        assert!(response.has_secret);
    }

    #[test]
    fn admin_user_response_marks_disabled_and_counts() {
        let response = admin_user_response_from_row(AdminUserRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: None,
            created_at: 1_780_000_000,
            updated_at: 1_780_000_100,
            disabled_at: Some(1_780_000_200),
            email_verified: 1,
            admin_membership_active: 1,
            identity_count: 2,
            active_session_count: 3,
        });

        assert_eq!(response.id, "usr_123");
        assert_eq!(response.email.as_deref(), Some("user@example.com"));
        assert!(response.disabled);
        assert!(response.admin);
        assert_eq!(response.identity_count, 2);
        assert_eq!(response.active_session_count, 3);
    }

    #[test]
    fn admin_user_id_validation_rejects_unsupported_input() {
        assert_eq!(validate_admin_user_id(" usr_123 ").unwrap(), "usr_123");
        let error = validate_admin_user_id("usr/123").unwrap_err();
        assert_eq!(error.description, "user id contains unsupported characters");
    }

    #[test]
    fn admin_identity_allowlist_accepts_user_ids_and_verified_emails() {
        assert!(admin_identity_allowed(
            "usr_admin",
            None,
            Some("usr_other, usr_admin"),
            None,
        ));
        assert!(admin_identity_allowed(
            "usr_123",
            Some("Admin@Wavey.ai"),
            None,
            Some("ops@example.com admin@wavey.ai"),
        ));
        assert!(!admin_identity_allowed(
            "usr_123",
            Some("user@example.com"),
            Some("usr_other"),
            Some("admin@wavey.ai"),
        ));
        assert!(!admin_identity_allowed(
            "usr_123",
            None,
            None,
            Some("admin@wavey.ai"),
        ));
    }

    #[test]
    fn admin_authorization_granted_by_records_source() {
        assert_eq!(
            admin_authorization_granted_by(&AdminAuthorization::BootstrapToken),
            "bootstrap_token"
        );
        assert_eq!(
            admin_authorization_granted_by(&AdminAuthorization::Session {
                user_id: "usr_admin".to_owned()
            }),
            "user:usr_admin"
        );
    }

    #[test]
    fn audit_event_response_parses_details_json() {
        let response = audit_event_response_from_row(AuditEventRow {
            id: "evt_123".to_owned(),
            event_type: "session.login".to_owned(),
            user_id: Some("usr_123".to_owned()),
            client_id: Some("web".to_owned()),
            provider_id: Some("google".to_owned()),
            created_at: 1_780_000_000,
            ip_hash: Some("ip-hash".to_owned()),
            user_agent: Some("agent".to_owned()),
            details_json: r#"{"mode":"hosted"}"#.to_owned(),
        });

        assert_eq!(response.event_type, "session.login");
        assert_eq!(response.details["mode"], "hosted");
        assert_eq!(response.user_id.as_deref(), Some("usr_123"));
    }

    #[test]
    fn audit_details_json_truncates_large_payloads() {
        let details = serde_json::json!({ "value": "x".repeat(AUDIT_EVENT_DETAILS_MAX_BYTES) });
        let json = audit_details_json(details).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["truncated"], true);
        assert!(value["originalBytes"].as_u64().unwrap() > AUDIT_EVENT_DETAILS_MAX_BYTES as u64);
    }

    #[test]
    fn audit_event_filter_validates_query_values() {
        let url = url::Url::parse(
            "https://id.example.com/events?event_type=session.login&user_id=usr_123&client_id=web&provider_id=google",
        )
        .unwrap();
        let filter = audit_event_filter_from_url(&url).unwrap();

        assert_eq!(filter.event_type.as_deref(), Some("session.login"));
        assert_eq!(filter.user_id.as_deref(), Some("usr_123"));
        assert_eq!(filter.client_id.as_deref(), Some("web"));
        assert_eq!(filter.provider_id.as_deref(), Some("google"));

        let url =
            url::Url::parse("https://id.example.com/events?event_type=session/login").unwrap();
        let error = audit_event_filter_from_url(&url).unwrap_err();
        assert_eq!(
            error.description,
            "event_type contains unsupported characters"
        );
    }

    #[test]
    fn client_admin_ui_from_row_includes_disabled_secret_state() {
        let client = client_admin_ui_from_row(ClientRow {
            id: "web".to_owned(),
            name: "Wavey Web".to_owned(),
            secret_hash: Some(format!("sha256:{}", hash_secret("web-secret"))),
            redirect_uris_json: r#"["https://app.example.com/callback"]"#.to_owned(),
            allowed_origins_json: r#"["https://app.example.com"]"#.to_owned(),
            allowed_email_domains_json: r#"["example.com"]"#.to_owned(),
            confidential: 1,
            disabled_at: Some(1_780_000_000),
        })
        .unwrap();

        assert_eq!(client.client_id, "web");
        assert!(client.confidential);
        assert!(client.disabled);
        assert!(client.has_secret);
    }

    #[test]
    fn admin_token_matches_sha256_config() {
        let hash = hash_secret("admin-token");

        assert!(admin_token_matches_config(
            "admin-token",
            &format!("sha256:{hash}")
        ));
        assert!(admin_token_matches_config("admin-token", &hash));
        assert!(!admin_token_matches_config("wrong-token", &hash));
    }

    #[test]
    fn provider_query_can_be_absent_for_hosted_picker() {
        let url = url::Url::parse("https://id.example.com/authorize").unwrap();
        assert_eq!(optional_provider_id_from_url(&url).unwrap(), None);
        let error = provider_id_from_url(&url).unwrap_err();
        assert_eq!(error.description, "missing provider");

        let url = url::Url::parse("https://id.example.com/authorize?provider=github").unwrap();
        let error = optional_provider_id_from_url(&url).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn transaction_preserves_downstream_state_and_redirect() {
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: Some("downstream-pkce".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        };

        let transaction = auth_transaction_from_request(
            &request,
            well_known::APPLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            1_780_000_000,
        );

        assert_eq!(transaction.provider_state, "provider-state");
        assert_eq!(transaction.nonce, Some("nonce-1".to_owned()));
        assert_eq!(
            transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(transaction.app_state, Some("app-state".to_owned()));
        assert_eq!(transaction.redirect_uri, "wavey://auth/callback");
        assert_eq!(
            transaction.provider_redirect_uri,
            "https://id.example.com/oauth2/callback"
        );
        assert_eq!(transaction.code_challenge_method, Some("S256".to_owned()));
        assert_eq!(transaction.link_user_id, None);
        assert_eq!(transaction.link_session_id, None);
        assert_eq!(transaction.session_return_to, None);
    }

    #[test]
    fn link_transaction_records_user_session_and_return() {
        let client = Client {
            id: ClientId("web".to_owned()),
            name: "Wavey Web".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let transaction = auth_transaction_from_link_request(
            &client,
            well_known::SPOTIFY,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/settings".to_owned(),
            Some("app-state".to_owned()),
            "usr_123",
            "sess_123",
            1_780_000_000,
        );

        assert_eq!(transaction.client_id, ClientId("web".to_owned()));
        assert_eq!(
            transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(transaction.redirect_uri, "https://app.example.com/settings");
        assert_eq!(transaction.app_state, Some("app-state".to_owned()));
        assert_eq!(transaction.link_user_id, Some(UserId("usr_123".to_owned())));
        assert_eq!(transaction.link_session_id, Some("sess_123".to_owned()));
        assert_eq!(transaction.session_return_to, None);
        assert!(transaction.scope.contains("openid"));
    }

    #[test]
    fn session_login_transaction_records_return() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard".to_owned(),
            Some("app-state".to_owned()),
            1_780_000_000,
        );

        assert_eq!(transaction.client_id, ClientId("browser".to_owned()));
        assert_eq!(
            transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(
            transaction.redirect_uri,
            "https://app.example.com/dashboard"
        );
        assert_eq!(
            transaction.session_return_to,
            Some("https://app.example.com/dashboard".to_owned())
        );
        assert_eq!(transaction.link_user_id, None);
        assert_eq!(transaction.link_session_id, None);
        assert!(transaction.scope.contains("profile"));
    }

    #[test]
    fn provider_authorize_nonce_prefers_provider_nonce_for_oidc() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let google_transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard".to_owned(),
            None,
            1_780_000_000,
        );
        let spotify_transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::SPOTIFY,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard".to_owned(),
            None,
            1_780_000_000,
        );

        assert_eq!(
            provider_authorize_nonce(&google_transaction),
            Some("provider-nonce")
        );
        assert_eq!(provider_authorize_nonce(&spotify_transaction), None);
    }

    #[test]
    fn identity_link_return_to_is_client_bounded() {
        let client = Client {
            id: ClientId("web".to_owned()),
            name: "Wavey Web".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fapp.example.com%2Fsettings",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, None).unwrap(),
            "https://app.example.com/settings"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=wavey%3A%2F%2Fauth%2Fcallback",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, None).unwrap(),
            "wavey://auth/callback"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fevil.example%2Fsettings",
        )
        .unwrap();
        let error = identity_link_return_to_from_url(&url, &client, None).unwrap_err();
        assert_eq!(
            error,
            "return_to must match a registered redirect URI or allowed origin"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Faccount",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
                .unwrap(),
            "https://id.example.com/account"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Fadmin",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
                .unwrap(),
            "https://id.example.com/admin"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Fadmin%2Fclients",
        )
        .unwrap();
        assert_eq!(
            identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
                .unwrap(),
            "https://id.example.com/admin/clients"
        );

        let url = url::Url::parse(
            "https://id.example.com/identities/link?return_to=https%3A%2F%2Fid.example.com%2Fadmin%2Fevil",
        )
        .unwrap();
        let error = identity_link_return_to_from_url(&url, &client, Some("https://id.example.com"))
            .unwrap_err();
        assert_eq!(
            error,
            "return_to must match a registered redirect URI or allowed origin"
        );
    }

    #[test]
    fn logout_redirect_url_is_client_bounded_and_preserves_state() {
        let client = Client {
            id: ClientId("web".to_owned()),
            name: "Wavey Web".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };

        let url = url::Url::parse(
            "https://id.example.com/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fsigned-out&state=done",
        )
        .unwrap();
        assert_eq!(
            validated_logout_redirect_url(
                &url,
                "https://app.example.com/signed-out",
                &client,
                None
            )
            .unwrap()
            .as_str(),
            "https://app.example.com/signed-out?state=done"
        );

        let url = url::Url::parse(
            "https://id.example.com/logout?post_logout_redirect_uri=wavey%3A%2F%2Fauth%2Fcallback&state=done",
        )
        .unwrap();
        assert_eq!(
            validated_logout_redirect_url(&url, "wavey://auth/callback", &client, None)
                .unwrap()
                .as_str(),
            "wavey://auth/callback?state=done"
        );

        let error =
            validated_logout_redirect_url(&url, "https://evil.example/signed-out", &client, None)
                .unwrap_err();
        assert_eq!(
            error,
            "return_to must match a registered redirect URI or allowed origin"
        );
    }

    #[test]
    fn identity_link_return_url_preserves_state_and_provider() {
        let transaction = auth_transaction_from_link_request(
            &Client {
                id: ClientId("web".to_owned()),
                name: "Wavey Web".to_owned(),
                redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
                allowed_origins: vec!["https://app.example.com".to_owned()],
                allowed_email_domains: vec![],
                confidential: false,
            },
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/settings?tab=login".to_owned(),
            Some("app-state".to_owned()),
            "usr_123",
            "sess_123",
            1_780_000_000,
        );
        let profile = ProviderProfile {
            provider_id: ProviderId(well_known::GOOGLE.to_owned()),
            subject: zeroth_core::Subject("google-sub".to_owned()),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            display_name: None,
            picture_url: None,
        };

        let return_url = identity_link_return_url(&transaction, &profile).unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            return_url.as_str().split('?').next().unwrap(),
            "https://app.example.com/settings"
        );
        assert!(query_pairs.contains(&("tab".to_owned(), "login".to_owned())));
        assert!(query_pairs.contains(&("identity_linked".to_owned(), "true".to_owned())));
        assert!(query_pairs.contains(&("provider".to_owned(), "google".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
    }

    #[test]
    fn session_login_return_url_preserves_return_and_optional_state() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard?existing=1".to_owned(),
            Some("app-state".to_owned()),
            1_780_000_000,
        );

        let return_url = session_login_return_url(&transaction).unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            return_url.as_str().split('?').next().unwrap(),
            "https://app.example.com/dashboard"
        );
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
    }

    #[test]
    fn provider_callback_error_return_url_uses_oidc_redirect() {
        let transaction = AuthTransaction {
            provider_state: "provider-state".to_owned(),
            client_id: ClientId("ios".to_owned()),
            provider_id: ProviderId(well_known::APPLE.to_owned()),
            redirect_uri: "wavey://auth/callback?existing=1".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: Some("app-state".to_owned()),
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: unix_seconds_to_system_time(1_780_000_000),
            expires_at: unix_seconds_to_system_time(1_780_000_600),
        };
        let error = ProviderCallbackError {
            code: "access_denied".to_owned(),
            description: "User cancelled".to_owned(),
        };

        let return_url =
            provider_callback_error_return_url(&transaction, "https://id.example.com", &error)
                .unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(return_url.scheme(), "wavey");
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("error".to_owned(), "access_denied".to_owned())));
        assert!(
            query_pairs.contains(&("error_description".to_owned(), "User cancelled".to_owned()))
        );
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(query_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));
        assert!(!query_pairs.iter().any(|(key, _)| key == "code"));
    }

    #[test]
    fn provider_callback_error_return_url_uses_session_return_to() {
        let client = Client {
            id: ClientId("browser".to_owned()),
            name: "Browser SSO".to_owned(),
            redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
            allowed_origins: vec!["https://app.example.com".to_owned()],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let transaction = auth_transaction_from_session_login_request(
            &client,
            well_known::GOOGLE,
            "provider-state".to_owned(),
            "provider-nonce".to_owned(),
            "https://id.example.com/oauth2/callback".to_owned(),
            "https://app.example.com/dashboard?existing=1".to_owned(),
            Some("app-state".to_owned()),
            1_780_000_000,
        );
        let error = ProviderCallbackError {
            code: "access_denied".to_owned(),
            description: "User cancelled".to_owned(),
        };

        let return_url =
            provider_callback_error_return_url(&transaction, "https://id.example.com", &error)
                .unwrap();
        let query_pairs = return_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            return_url.as_str().split('?').next().unwrap(),
            "https://app.example.com/dashboard"
        );
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("error".to_owned(), "access_denied".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(!query_pairs.iter().any(|(key, _)| key == "iss"));
    }

    #[test]
    fn client_redirect_url_includes_auth_code_and_app_state() {
        let transaction = AuthTransaction {
            provider_state: "provider-state".to_owned(),
            client_id: ClientId("ios".to_owned()),
            provider_id: ProviderId(well_known::SPOTIFY.to_owned()),
            redirect_uri: "wavey://auth/callback?existing=1".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: Some("app-state".to_owned()),
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: unix_seconds_to_system_time(1_780_000_000),
            expires_at: unix_seconds_to_system_time(1_780_000_600),
        };

        let redirect_url =
            client_redirect_url(&transaction, "https://id.example.com", "zeroth-code").unwrap();
        let query_pairs = redirect_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(redirect_url.scheme(), "wavey");
        assert!(query_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(query_pairs.contains(&("code".to_owned(), "zeroth-code".to_owned())));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(query_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));
    }

    #[test]
    fn prompt_none_redirect_urls_include_code_or_login_required() {
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback?existing=1".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            prompt: AuthorizationPrompt::None,
            max_age: None,
            code_challenge: Some("downstream-pkce".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        };

        let success_url =
            authorization_request_client_redirect_url(&request, "https://id.example.com", "code-1")
                .unwrap();
        let success_pairs = success_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(success_url.scheme(), "wavey");
        assert!(success_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(success_pairs.contains(&("code".to_owned(), "code-1".to_owned())));
        assert!(success_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(success_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));

        let error_url = authorization_request_error_redirect_url(
            &request,
            "https://id.example.com",
            "login_required",
            "active browser session was not found",
        )
        .unwrap();
        let error_pairs = error_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(error_url.scheme(), "wavey");
        assert!(error_pairs.contains(&("existing".to_owned(), "1".to_owned())));
        assert!(error_pairs.contains(&("error".to_owned(), "login_required".to_owned())));
        assert!(error_pairs.contains(&(
            "error_description".to_owned(),
            "active browser session was not found".to_owned()
        )));
        assert!(error_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(error_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));
        assert!(!error_pairs.iter().any(|(key, _)| key == "code"));
    }

    #[test]
    fn authorization_request_errors_redirect_only_for_registered_redirect_uri() {
        let client = Client {
            id: ClientId("ios".to_owned()),
            name: "Wavey iOS".to_owned(),
            redirect_uris: vec!["wavey://auth/callback".to_owned()],
            allowed_origins: vec![],
            allowed_email_domains: vec![],
            confidential: false,
        };
        let request = AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: None,
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
        };
        let error = validate_authorization_request_for_client(&request, &client).unwrap_err();

        let redirect_url = authorization_request_error_redirect_url_for_client(
            &request,
            &client,
            "https://id.example.com",
            &error,
        )
        .unwrap()
        .unwrap();
        let query_pairs = redirect_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(redirect_url.scheme(), "wavey");
        assert!(query_pairs.contains(&("error".to_owned(), "invalid_request".to_owned())));
        assert!(query_pairs.contains(&(
            "error_description".to_owned(),
            "public clients must use PKCE".to_owned()
        )));
        assert!(query_pairs.contains(&("state".to_owned(), "app-state".to_owned())));
        assert!(query_pairs.contains(&("iss".to_owned(), "https://id.example.com".to_owned())));

        let unregistered_redirect_request = AuthorizationRequest {
            redirect_uri: "wavey://evil/callback".to_owned(),
            ..request
        };
        let error =
            validate_authorization_request_for_client(&unregistered_redirect_request, &client)
                .unwrap_err();

        assert!(authorization_request_error_redirect_url_for_client(
            &unregistered_redirect_request,
            &client,
            "https://id.example.com",
            &error,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn hash_secret_returns_sha256_hex() {
        assert_eq!(
            hash_secret("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn pkce_s256_challenge_matches_rfc7636_example() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        assert_eq!(
            pkce_s256_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn token_exchange_form_rejects_wrong_grant_type() {
        let mut form = valid_token_exchange_form();
        form.grant_type = "client_credentials".to_owned();

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "unsupported_grant_type");
    }

    #[test]
    fn token_exchange_form_rejects_short_code_verifier() {
        let mut form = valid_token_exchange_form();
        form.code_verifier = Some("short".to_owned());

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "code_verifier must be 43 to 128 characters"
        );
    }

    #[test]
    fn token_exchange_form_accepts_refresh_token_grant() {
        let form = TokenExchangeForm {
            grant_type: "refresh_token".to_owned(),
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            redirect_uri: None,
            code: None,
            code_verifier: None,
            refresh_token: Some("refresh-token".to_owned()),
            scope: None,
            subject_token: None,
            subject_token_type: None,
            provider: None,
            provider_client_id: None,
            nonce: None,
        };

        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn token_exchange_form_accepts_native_apple_id_token_grant() {
        let form = valid_native_apple_token_exchange_form();

        let fields = native_provider_token_fields(&form).unwrap();

        assert_eq!(fields.provider_id, well_known::APPLE);
        assert_eq!(fields.subject_token, "apple.id.token");
        assert_eq!(fields.provider_client_id, Some("ai.wavey.id"));
        assert_eq!(fields.subject_token_type, ID_TOKEN_SUBJECT_TOKEN_TYPE);
        assert_eq!(
            native_token_scope(fields.scope).unwrap(),
            DEFAULT_NATIVE_TOKEN_SCOPE
        );
        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn token_exchange_form_accepts_native_google_id_token_grant() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some(well_known::GOOGLE.to_owned());
        form.subject_token = Some("google.id.token".to_owned());
        form.provider_client_id = Some("google-ios-client".to_owned());

        let fields = native_provider_token_fields(&form).unwrap();

        assert_eq!(fields.provider_id, well_known::GOOGLE);
        assert_eq!(fields.subject_token, "google.id.token");
        assert_eq!(fields.provider_client_id, Some("google-ios-client"));
        assert_eq!(fields.subject_token_type, ID_TOKEN_SUBJECT_TOKEN_TYPE);
        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn token_exchange_form_accepts_native_spotify_access_token_grant() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some(well_known::SPOTIFY.to_owned());
        form.subject_token = Some("spotify.access.token".to_owned());
        form.subject_token_type = Some(ACCESS_TOKEN_SUBJECT_TOKEN_TYPE.to_owned());
        form.provider_client_id = Some("spotify-ios-client".to_owned());

        let fields = native_provider_token_fields(&form).unwrap();

        assert_eq!(fields.provider_id, well_known::SPOTIFY);
        assert_eq!(fields.subject_token, "spotify.access.token");
        assert_eq!(fields.provider_client_id, Some("spotify-ios-client"));
        assert_eq!(fields.subject_token_type, ACCESS_TOKEN_SUBJECT_TOKEN_TYPE);
        validate_token_exchange_form(&form).unwrap();
    }

    #[test]
    fn native_provider_token_grant_rejects_unsupported_provider() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some("github".to_owned());

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "token exchange provider must be apple, google, or spotify"
        );
    }

    #[test]
    fn native_spotify_token_grant_requires_access_token_type() {
        let mut form = valid_native_apple_token_exchange_form();
        form.provider = Some(well_known::SPOTIFY.to_owned());

        let error = validate_token_exchange_form(&form).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "subject_token_type must be urn:ietf:params:oauth:token-type:access_token"
        );
    }

    #[test]
    fn native_apple_client_id_selects_single_configured_audience() {
        let configured = vec!["ai.wavey.id".to_owned()];

        assert_eq!(
            native_apple_provider_client_id_from_list(&configured, None).unwrap(),
            "ai.wavey.id"
        );
        assert_eq!(
            native_apple_provider_client_id_from_list(&configured, Some("ai.wavey.id")).unwrap(),
            "ai.wavey.id"
        );
    }

    #[test]
    fn native_apple_client_id_requires_allowed_requested_audience() {
        let configured = vec!["ai.wavey.id".to_owned(), "ai.bitneedle.app".to_owned()];

        let missing = native_apple_provider_client_id_from_list(&configured, None).unwrap_err();
        assert_eq!(
            missing.description,
            "provider_client_id is required when multiple Apple native client IDs are configured"
        );

        let denied =
            native_apple_provider_client_id_from_list(&configured, Some("evil.app")).unwrap_err();
        assert_eq!(denied.description, "provider_client_id is not allowed");
    }

    #[test]
    fn native_google_client_id_selects_allowed_audience() {
        let configured = vec!["google-ios-client".to_owned()];

        assert_eq!(
            native_provider_client_id_from_list(well_known::GOOGLE, &configured, None).unwrap(),
            "google-ios-client"
        );
        assert_eq!(
            native_provider_client_id_from_list(
                well_known::GOOGLE,
                &configured,
                Some("google-ios-client")
            )
            .unwrap(),
            "google-ios-client"
        );
    }

    #[test]
    fn native_spotify_client_id_requires_configured_audience() {
        let error =
            native_provider_client_id_from_list(well_known::SPOTIFY, &[], None).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "SPOTIFY_NATIVE_CLIENT_IDS is not configured"
        );
    }

    #[test]
    fn native_token_scope_defaults_to_openid_profile_email() {
        assert_eq!(
            native_token_scope(None).unwrap(),
            DEFAULT_NATIVE_TOKEN_SCOPE.to_owned()
        );

        let error = native_token_scope(Some("email profile")).unwrap_err();
        assert_eq!(error.description, "scope must include openid");
    }

    #[test]
    fn token_client_auth_accepts_client_secret_post() {
        let (client_id, auth) =
            token_client_auth(Some("web".to_owned()), Some("web-secret".to_owned()), None).unwrap();

        assert_eq!(client_id, "web");
        assert_eq!(auth, ClientAuth::SecretPost("web-secret".to_owned()));
    }

    #[test]
    fn token_client_auth_accepts_basic_auth() {
        let credentials = STANDARD.encode("web:web-secret");
        let basic = client_basic_auth_from_header(Some(&format!("Basic {credentials}")))
            .unwrap()
            .unwrap();
        let (client_id, auth) =
            token_client_auth(Some("web".to_owned()), None, Some(basic)).unwrap();

        assert_eq!(client_id, "web");
        assert_eq!(auth, ClientAuth::SecretBasic("web-secret".to_owned()));
    }

    #[test]
    fn token_client_auth_rejects_mixed_auth_methods() {
        let basic = ClientBasicAuth {
            client_id: "web".to_owned(),
            client_secret: "basic-secret".to_owned(),
        };

        let error = token_client_auth(
            Some("web".to_owned()),
            Some("post-secret".to_owned()),
            Some(basic),
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "client authentication must use only one method"
        );
    }

    #[test]
    fn confidential_client_auth_accepts_matching_secret_hash() {
        let client = registered_confidential_client("web-secret");
        let mut form = valid_token_exchange_form();
        form.client_id = "web".to_owned();
        form.client_auth = ClientAuth::SecretPost("web-secret".to_owned());

        validate_token_client_auth(&client, &form.client_id, &form.client_auth).unwrap();
    }

    #[test]
    fn confidential_client_auth_rejects_missing_secret() {
        let client = registered_confidential_client("web-secret");
        let mut form = valid_token_exchange_form();
        form.client_id = "web".to_owned();
        form.client_auth = ClientAuth::None;

        let error =
            validate_token_client_auth(&client, &form.client_id, &form.client_auth).unwrap_err();

        assert_eq!(error.code, "invalid_client");
        assert_eq!(
            error.description,
            "confidential clients must authenticate with client_secret"
        );
    }

    #[test]
    fn public_client_auth_rejects_client_secret() {
        let client = registered_public_client();
        let mut form = valid_token_exchange_form();
        form.client_auth = ClientAuth::SecretPost("ios-secret".to_owned());

        let error =
            validate_token_client_auth(&client, &form.client_id, &form.client_auth).unwrap_err();

        assert_eq!(error.code, "invalid_client");
        assert_eq!(
            error.description,
            "public clients must not use client_secret authentication"
        );
    }

    #[test]
    fn authorization_code_exchange_accepts_matching_pkce() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = valid_auth_code_row(pkce_s256_challenge(verifier));
        let mut form = valid_token_exchange_form();
        form.code_verifier = Some(verifier.to_owned());
        let fields = authorization_code_fields(&form).unwrap();

        validate_authorization_code_exchange(&code, &fields, 1_780_000_100).unwrap();
    }

    #[test]
    fn authorization_code_exchange_accepts_confidential_code_without_pkce() {
        let mut code = valid_auth_code_row(String::new());
        code.client_id = "web".to_owned();
        code.redirect_uri = "https://app.example.com/auth/callback".to_owned();
        code.code_challenge = None;
        code.code_challenge_method = None;
        let form = TokenExchangeForm {
            grant_type: "authorization_code".to_owned(),
            client_id: "web".to_owned(),
            client_auth: ClientAuth::SecretBasic("web-secret".to_owned()),
            redirect_uri: Some("https://app.example.com/auth/callback".to_owned()),
            code: Some("zeroth-code".to_owned()),
            code_verifier: None,
            refresh_token: None,
            scope: None,
            subject_token: None,
            subject_token_type: None,
            provider: None,
            provider_client_id: None,
            nonce: None,
        };
        let fields = authorization_code_fields(&form).unwrap();

        validate_authorization_code_exchange(&code, &fields, 1_780_000_100).unwrap();
    }

    #[test]
    fn authorization_code_exchange_rejects_bad_pkce() {
        let code = valid_auth_code_row(pkce_s256_challenge(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        ));
        let mut form = valid_token_exchange_form();
        form.code_verifier = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned());
        let fields = authorization_code_fields(&form).unwrap();

        let error =
            validate_authorization_code_exchange(&code, &fields, 1_780_000_100).unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(
            error.description,
            "code_verifier did not match code_challenge"
        );
    }

    #[test]
    fn refresh_token_exchange_rejects_rotated_token() {
        let mut row = valid_refresh_token_row();
        row.rotated_at = Some(1_780_000_100);

        let error = validate_refresh_token_exchange(&row, "ios", 1_780_000_200).unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(error.description, "refresh token has already been rotated");
        assert!(refresh_token_replay_detected(&row, "ios"));
    }

    #[test]
    fn refresh_token_exchange_rejects_wrong_client() {
        let row = valid_refresh_token_row();

        let error = validate_refresh_token_exchange(&row, "web", 1_780_000_200).unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(error.description, "refresh token client_id does not match");
        assert!(!refresh_token_replay_detected(&row, "web"));
    }

    #[test]
    fn refresh_token_replay_detection_ignores_revoked_or_unrotated_tokens() {
        let mut row = valid_refresh_token_row();
        assert!(!refresh_token_replay_detected(&row, "ios"));

        row.rotated_at = Some(1_780_000_100);
        row.revoked_at = Some(1_780_000_150);
        assert!(!refresh_token_replay_detected(&row, "ios"));
    }

    #[test]
    fn d1_change_detection_requires_exactly_one_change() {
        assert!(d1_changes_exactly_one(Some(1)));
        assert!(!d1_changes_exactly_one(Some(0)));
        assert!(!d1_changes_exactly_one(Some(2)));
        assert!(!d1_changes_exactly_one(None));
    }

    #[test]
    fn token_issue_preserves_session_id_for_refresh_token_family() {
        let code = valid_auth_code_row("challenge".to_owned());
        let issue = TokenIssue::from_auth_code(&code);
        assert_eq!(issue.session_id, Some("sess_123".to_owned()));

        let row = valid_refresh_token_row();
        let issue = TokenIssue::from_refresh_token(&row);
        assert_eq!(issue.session_id, Some("sess_123".to_owned()));

        let mut legacy_row = row;
        legacy_row.session_id = None;
        let issue = TokenIssue::from_refresh_token(&legacy_row);
        assert_eq!(issue.session_id, None);
    }

    #[test]
    fn token_issue_preserves_original_auth_time_for_silent_sso() {
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.created_at = 1_780_000_500;
        code.auth_time = Some(1_780_000_000);

        let issue = TokenIssue::from_auth_code(&code);

        assert_eq!(issue.auth_time, Some(1_780_000_000));

        let mut legacy_code = code;
        legacy_code.auth_time = None;
        let issue = TokenIssue::from_auth_code(&legacy_code);
        assert_eq!(issue.auth_time, Some(1_780_000_500));
    }

    #[test]
    fn token_issue_preserves_refresh_token_auth_time() {
        let mut row = valid_refresh_token_row();
        row.created_at = 1_780_000_600;
        row.auth_time = Some(1_780_000_000);

        let issue = TokenIssue::from_refresh_token(&row);

        assert_eq!(issue.auth_time, Some(1_780_000_000));
    }

    #[test]
    fn token_revocation_form_accepts_refresh_token_hint() {
        let form = TokenRevocationForm {
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            token: "refresh-token".to_owned(),
            token_type_hint: Some("refresh_token".to_owned()),
        };

        validate_token_revocation_form(&form).unwrap();
        assert!(should_attempt_refresh_token_revocation(
            form.token_type_hint.as_deref()
        ));
    }

    #[test]
    fn token_revocation_form_accepts_access_token_noop_hint() {
        let form = TokenRevocationForm {
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            token: "access-token".to_owned(),
            token_type_hint: Some("access_token".to_owned()),
        };

        validate_token_revocation_form(&form).unwrap();
        assert!(!should_attempt_refresh_token_revocation(
            form.token_type_hint.as_deref()
        ));
    }

    #[test]
    fn token_revocation_form_rejects_unknown_hint() {
        let form = TokenRevocationForm {
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            token: "refresh-token".to_owned(),
            token_type_hint: Some("id_token".to_owned()),
        };

        let error = validate_token_revocation_form(&form).unwrap_err();

        assert_eq!(error.code, "unsupported_token_type");
        assert_eq!(
            error.description,
            "token_type_hint must be refresh_token or access_token"
        );
    }

    #[test]
    fn token_introspection_form_accepts_access_and_refresh_hints() {
        let access_form = TokenIntrospectionForm {
            client_id: "web".to_owned(),
            client_auth: ClientAuth::SecretPost("web-secret".to_owned()),
            token: "access-token".to_owned(),
            token_type_hint: Some("access_token".to_owned()),
        };
        let refresh_form = TokenIntrospectionForm {
            token_type_hint: Some("refresh_token".to_owned()),
            ..access_form.clone()
        };

        validate_token_introspection_form(&access_form).unwrap();
        validate_token_introspection_form(&refresh_form).unwrap();
    }

    #[test]
    fn token_introspection_form_rejects_unknown_hint() {
        let form = TokenIntrospectionForm {
            client_id: "web".to_owned(),
            client_auth: ClientAuth::SecretPost("web-secret".to_owned()),
            token: "access-token".to_owned(),
            token_type_hint: Some("id_token".to_owned()),
        };

        let error = validate_token_introspection_form(&form).unwrap_err();

        assert_eq!(error.code, "unsupported_token_type");
        assert_eq!(
            error.description,
            "token_type_hint must be access_token or refresh_token"
        );
    }

    #[test]
    fn token_introspection_requires_confidential_client() {
        let client = registered_public_client();

        let error =
            validate_introspection_client_auth(&client, "ios", &ClientAuth::None).unwrap_err();

        assert_eq!(error.code, "invalid_client");
        assert_eq!(
            error.description,
            "token introspection requires confidential client authentication"
        );
    }

    #[test]
    fn token_introspection_response_serializes_inactive_minimally() {
        let value = serde_json::to_value(TokenIntrospectionResponse::inactive()).unwrap();

        assert_eq!(value["active"], false);
        assert_eq!(value.as_object().unwrap().len(), 1);
    }

    #[test]
    fn token_introspection_response_serializes_active_access_token() {
        let claims = JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "web".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: Some("sess_123".to_owned()),
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("web".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        };

        let value =
            serde_json::to_value(TokenIntrospectionResponse::active_access_token(&claims)).unwrap();

        assert_eq!(value["active"], true);
        assert_eq!(value["scope"], "openid email");
        assert_eq!(value["client_id"], "web");
        assert_eq!(value["token_type"], "Bearer");
        assert_eq!(value["token_use"], "access_token");
        assert_eq!(value["sub"], "usr_123");
        assert_eq!(value["aud"], "web");
        assert_eq!(value["iss"], "https://id.example.com");
        assert_eq!(value["iat"], 1_780_000_000);
        assert_eq!(value["exp"], 1_780_003_600);
        assert_eq!(value["sid"], "sess_123");
        assert!(value.get("clientId").is_none());
    }

    #[test]
    fn token_introspection_response_serializes_active_refresh_token() {
        let row = valid_refresh_token_row();

        let value =
            serde_json::to_value(TokenIntrospectionResponse::active_refresh_token(&row)).unwrap();

        assert_eq!(value["active"], true);
        assert_eq!(value["scope"], "openid profile email offline_access");
        assert_eq!(value["client_id"], "ios");
        assert_eq!(value["token_use"], "refresh_token");
        assert_eq!(value["sub"], "usr_123");
        assert_eq!(value["aud"], "ios");
        assert_eq!(value["iat"], 1_780_000_000);
        assert_eq!(value["exp"], 1_780_086_400);
        assert_eq!(value["sid"], "sess_123");
        assert!(value.get("token_type").is_none());
        assert!(value.get("iss").is_none());
    }

    #[test]
    fn jwks_response_publishes_es256_public_key() {
        let signing_key = test_signing_key();

        let jwks = jwks_response(&signing_key, None).unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty.as_str(), "EC");
        assert_eq!(jwks.keys[0].key_use.as_str(), "sig");
        assert_eq!(jwks.keys[0].kid.as_str(), "test-key");
        assert_eq!(jwks.keys[0].alg.as_str(), "ES256");
        assert_eq!(jwks.keys[0].crv.as_str(), "P-256");
        assert!(!jwks.keys[0].x.is_empty());
        assert!(!jwks.keys[0].y.is_empty());
    }

    #[test]
    fn jwks_response_includes_previous_public_keys_for_rotation() {
        let active_signing_key = test_signing_key();
        let previous_signing_key = es256_signing_key_from_config(
            "previous-key",
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let previous_jwks = jwks_response(&previous_signing_key, None).unwrap();
        let previous_json = serde_json::to_string(&previous_jwks).unwrap();

        let jwks = jwks_response(&active_signing_key, Some(&previous_json)).unwrap();

        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid.as_str(), "test-key");
        assert_eq!(jwks.keys[1].kid.as_str(), "previous-key");
    }

    #[test]
    fn jwks_response_deduplicates_previous_active_kid() {
        let signing_key = test_signing_key();
        let previous_jwks = jwks_response(&signing_key, None).unwrap();
        let previous_json = serde_json::to_string(&previous_jwks).unwrap();

        let jwks = jwks_response(&signing_key, Some(&previous_json)).unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid.as_str(), "test-key");
    }

    #[test]
    fn jwks_response_rejects_private_previous_jwk() {
        let signing_key = test_signing_key();
        let previous_jwks = serde_json::json!({
            "keys": [{
                "kty": "EC",
                "use": "sig",
                "kid": "previous-key",
                "alg": "ES256",
                "crv": "P-256",
                "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "d": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }]
        });

        let error = jwks_response(&signing_key, Some(&previous_jwks.to_string())).unwrap_err();

        assert!(error.contains("invalid JWT_PREVIOUS_PUBLIC_JWKS_JSON JWKS JSON"));
    }

    #[test]
    fn sign_jwt_produces_es256_jwt() {
        let signing_key = test_signing_key();
        let claims = JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "ios".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: None,
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("ios".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        };

        let jwt = sign_jwt(&signing_key, &claims).unwrap();
        let segments = jwt.split('.').collect::<Vec<_>>();
        let header = decode_jwt_json_segment::<serde_json::Value>(segments[0]);
        let payload = decode_jwt_json_segment::<serde_json::Value>(segments[1]);

        assert_eq!(segments.len(), 3);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "test-key");
        assert_eq!(payload["iss"], "https://id.example.com");
        assert_eq!(payload["sub"], "usr_123");
        assert_eq!(payload["token_use"], "access");
        assert_eq!(URL_SAFE_NO_PAD.decode(segments[2]).unwrap().len(), 64);
    }

    #[test]
    fn apple_client_secret_signs_expected_claims() {
        let signing_key = test_signing_key();
        let config = AppleClientSecretConfig {
            team_id: "TEAM12345".to_owned(),
            key_id: "KEY12345".to_owned(),
            client_id: "ai.wavey.service".to_owned(),
            private_key_pem: String::new(),
            ttl_seconds: 3_600,
        };

        let jwt = apple_client_secret_from_signing_key(
            &signing_key.signing_key,
            &config,
            1_780_000_000,
            1_780_003_600,
        )
        .unwrap();
        let segments = jwt.split('.').collect::<Vec<_>>();
        let header = decode_jwt_json_segment::<serde_json::Value>(segments[0]);
        let payload = decode_jwt_json_segment::<serde_json::Value>(segments[1]);

        assert_eq!(segments.len(), 3);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY12345");
        assert!(header.get("typ").is_none());
        assert_eq!(payload["iss"], "TEAM12345");
        assert_eq!(payload["sub"], "ai.wavey.service");
        assert_eq!(payload["aud"], "https://appleid.apple.com");
        assert_eq!(payload["iat"], 1_780_000_000);
        assert_eq!(payload["exp"], 1_780_003_600);
        assert_eq!(URL_SAFE_NO_PAD.decode(segments[2]).unwrap().len(), 64);
    }

    #[test]
    fn apple_client_secret_from_config_accepts_pkcs8_pem() {
        let signing_key = test_signing_key();
        let private_key_pem = signing_key
            .signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let config = AppleClientSecretConfig {
            team_id: "TEAM12345".to_owned(),
            key_id: "KEY12345".to_owned(),
            client_id: "ai.wavey.service".to_owned(),
            private_key_pem,
            ttl_seconds: 600,
        };

        let (jwt, expires_at) = apple_client_secret_from_config(&config, 1_780_000_000).unwrap();

        assert_eq!(expires_at, 1_780_000_600);
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn apple_client_secret_ttl_seconds_is_bounded() {
        assert_eq!(apple_client_secret_ttl_seconds(None).unwrap(), 15_552_000);
        assert_eq!(apple_client_secret_ttl_seconds(Some("600")).unwrap(), 600);

        let error = apple_client_secret_ttl_seconds(Some("31536000")).unwrap_err();

        assert_eq!(
            error,
            "APPLE_CLIENT_SECRET_TTL_SECONDS must be between 60 and 15552000"
        );
    }

    #[test]
    fn apple_private_key_secret_normalizes_escaped_newlines() {
        assert_eq!(
            normalize_private_key_pem_secret("-----BEGIN\\nKEY\\n-----END-----"),
            "-----BEGIN\nKEY\n-----END-----"
        );
    }

    #[test]
    fn token_response_mints_access_id_and_refresh_tokens() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.scope = "openid profile email offline_access".to_owned();
        let user_claims = valid_user_token_claims_row();
        let issue = TokenIssue::from_auth_code(&code).with_user_claims(&user_claims);

        let response = token_response(
            &config,
            &signing_key,
            &issue,
            Some("refresh-token".to_owned()),
            1_780_000_000,
        )
        .unwrap();
        let access_claims = decode_jwt_claims(&response.access_token);
        let id_claims = decode_jwt_claims(&response.id_token);

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, ACCESS_TOKEN_TTL_SECONDS);
        assert_eq!(response.refresh_token, Some("refresh-token".to_owned()));
        assert_eq!(response.scope, "openid profile email offline_access");
        assert_eq!(access_claims["token_use"], "access");
        assert_eq!(
            access_claims["scope"],
            "openid profile email offline_access"
        );
        assert_eq!(access_claims["client_id"], "ios");
        assert_eq!(access_claims["sid"], "sess_123");
        assert!(access_claims.get("email").is_none());
        assert!(access_claims.get("name").is_none());
        assert_eq!(id_claims["token_use"], "id");
        assert_eq!(id_claims["nonce"], "nonce-1");
        assert_eq!(id_claims["auth_time"], 1_780_000_000);
        assert_eq!(id_claims["sid"], "sess_123");
        assert_eq!(id_claims["email"], "user@example.com");
        assert_eq!(id_claims["email_verified"], true);
        assert_eq!(id_claims["name"], "Example User");
        assert_eq!(id_claims["picture"], "https://example.com/avatar.png");
    }

    #[test]
    fn token_response_omits_id_claims_outside_requested_scopes() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.scope = "openid".to_owned();
        let user_claims = valid_user_token_claims_row();
        let issue = TokenIssue::from_auth_code(&code).with_user_claims(&user_claims);

        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_000).unwrap();
        let id_claims = decode_jwt_claims(&response.id_token);

        assert_eq!(id_claims["token_use"], "id");
        assert!(id_claims.get("email").is_none());
        assert!(id_claims.get("email_verified").is_none());
        assert!(id_claims.get("name").is_none());
        assert!(id_claims.get("picture").is_none());
    }

    #[test]
    fn verify_zeroth_access_token_accepts_current_es256_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let issue = TokenIssue {
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email".to_owned(),
            auth_time: Some(1_780_000_000),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        };
        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_100).unwrap();
        let verification_keys = test_verification_keys(&signing_key);

        let claims = verify_zeroth_access_token(
            &response.access_token,
            &config,
            &verification_keys,
            1_780_000_200,
        )
        .unwrap();

        assert_eq!(claims.sub, "usr_123");
        assert_eq!(claims.token_use, "access");
        assert_eq!(claims.scope, Some("openid profile email".to_owned()));
    }

    #[test]
    fn verify_zeroth_access_token_accepts_previous_es256_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let active_signing_key = test_signing_key();
        let previous_signing_key = es256_signing_key_from_config(
            "previous-key",
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let previous_jwks = jwks_response(&previous_signing_key, None).unwrap();
        let previous_json = serde_json::to_string(&previous_jwks).unwrap();
        let jwks = jwks_response(&active_signing_key, Some(&previous_json)).unwrap();
        let verification_keys = es256_verification_keys_from_jwks(&jwks).unwrap();
        let issue = TokenIssue {
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email".to_owned(),
            auth_time: Some(1_780_000_000),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        };
        let response =
            token_response(&config, &previous_signing_key, &issue, None, 1_780_000_100).unwrap();

        let claims = verify_zeroth_access_token(
            &response.access_token,
            &config,
            &verification_keys,
            1_780_000_200,
        )
        .unwrap();

        assert_eq!(claims.sub, "usr_123");
        assert_eq!(claims.token_use, "access");
    }

    #[test]
    fn verify_zeroth_access_token_rejects_id_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let issue = TokenIssue {
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email".to_owned(),
            auth_time: Some(1_780_000_000),
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        };
        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_100).unwrap();
        let verification_keys = test_verification_keys(&signing_key);

        let error = verify_zeroth_access_token(
            &response.id_token,
            &config,
            &verification_keys,
            1_780_000_200,
        )
        .unwrap_err();

        assert_eq!(error, "token is not an access token");
    }

    #[test]
    fn verify_zeroth_id_token_hint_accepts_id_token_and_rejects_access_token() {
        let config = ZerothServerConfig {
            public_base_url: "https://id.example.com".to_owned(),
            ..ZerothServerConfig::default()
        };
        let signing_key = test_signing_key();
        let mut code = valid_auth_code_row("challenge".to_owned());
        code.scope = "openid profile email".to_owned();
        let issue =
            TokenIssue::from_auth_code(&code).with_user_claims(&valid_user_token_claims_row());
        let response = token_response(&config, &signing_key, &issue, None, 1_780_000_100).unwrap();
        let verification_keys = test_verification_keys(&signing_key);

        let claims = verify_zeroth_id_token_hint(
            &response.id_token,
            &config,
            &verification_keys,
            1_780_000_200,
        )
        .unwrap();
        assert_eq!(claims.token_use, "id");
        assert_eq!(claims.aud, "ios");
        assert_eq!(claims.sub, "usr_123");

        let error = verify_zeroth_id_token_hint(
            &response.access_token,
            &config,
            &verification_keys,
            1_780_000_200,
        )
        .unwrap_err();
        assert_eq!(error, "id_token_hint is not an ID token");
    }

    #[test]
    fn bearer_token_from_authorization_header_accepts_bearer_token() {
        let token = bearer_token_from_authorization_header(Some("Bearer access-token")).unwrap();

        assert_eq!(token, Some("access-token".to_owned()));
    }

    #[test]
    fn bearer_token_from_authorization_header_allows_missing_header() {
        let token = bearer_token_from_authorization_header(None).unwrap();

        assert_eq!(token, None);
    }

    #[test]
    fn bearer_token_from_authorization_header_rejects_malformed_header() {
        let error = bearer_token_from_authorization_header(Some("Basic abc")).unwrap_err();

        assert_eq!(error, "missing bearer token");
    }

    #[test]
    fn validate_response_for_access_token_respects_scopes() {
        let user = valid_user_row();
        let claims = JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "ios".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: Some("sess_123".to_owned()),
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("ios".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        };

        let value = serde_json::to_value(validate_access_token_response(&claims, &user)).unwrap();

        assert_eq!(value["valid"], true);
        assert_eq!(value["kind"], "access_token");
        assert_eq!(value["clientId"], "ios");
        assert_eq!(value["expiresAt"], 1_780_003_600);
        assert_eq!(value["sessionId"], "sess_123");
        assert_eq!(value["user"]["email"], "user@example.com");
        assert!(value["user"].get("name").is_none());
        assert!(value.get("session").is_none());
    }

    #[test]
    fn access_token_session_claim_validation_allows_sessionless_tokens() {
        let mut claims = valid_access_token_claims();
        claims.sid = None;

        validate_access_token_session_claims(&claims, None, 1_780_000_100).unwrap();
    }

    #[test]
    fn access_token_session_claim_validation_requires_active_matching_session() {
        let claims = valid_access_token_claims();
        let session = valid_session_row();

        validate_access_token_session_claims(&claims, Some(&session), 1_780_000_100).unwrap();

        let error = validate_access_token_session_claims(&claims, None, 1_780_000_100).unwrap_err();
        assert_eq!(error, "access token session was not found");

        let mut mismatched_user = valid_session_row();
        mismatched_user.user_id = "usr_other".to_owned();
        let error =
            validate_access_token_session_claims(&claims, Some(&mismatched_user), 1_780_000_100)
                .unwrap_err();
        assert_eq!(error, "access token session user did not match subject");

        let mut mismatched_client = valid_session_row();
        mismatched_client.client_id = Some("web".to_owned());
        let error =
            validate_access_token_session_claims(&claims, Some(&mismatched_client), 1_780_000_100)
                .unwrap_err();
        assert_eq!(error, "access token session client did not match audience");

        let mut revoked = valid_session_row();
        revoked.revoked_at = Some(1_780_000_050);
        let error = validate_access_token_session_claims(&claims, Some(&revoked), 1_780_000_100)
            .unwrap_err();
        assert_eq!(error, "access token session is no longer active");
    }

    #[test]
    fn validate_response_for_session_includes_session_and_profile() {
        let session = valid_session_row();
        let user = valid_user_row();

        let value = serde_json::to_value(validate_session_response(&session, &user)).unwrap();

        assert_eq!(value["valid"], true);
        assert_eq!(value["kind"], "session");
        assert_eq!(value["clientId"], "ios");
        assert_eq!(value["expiresAt"], session.expires_at);
        assert_eq!(value["session"]["id"], "sess_123");
        assert_eq!(value["user"]["name"], "Example User");
    }

    #[test]
    fn userinfo_response_respects_access_token_scopes() {
        let user = UserRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/avatar.png".to_owned()),
            disabled_at: None,
        };

        let response = userinfo_response(&user, Some("openid email"));

        assert_eq!(response.sub, "usr_123");
        assert_eq!(response.email, Some("user@example.com".to_owned()));
        assert_eq!(response.name, None);
        assert_eq!(response.picture, None);
    }

    #[test]
    fn session_cookie_is_secure_http_only_and_lax() {
        let cookie = session_cookie("zeroth_session", "sess_123", SESSION_TTL_SECONDS, None);

        assert!(cookie.starts_with("zeroth_session=sess_123; Path=/;"));
        assert!(cookie.contains("Max-Age=2592000"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Domain="));
    }

    #[test]
    fn session_cookie_can_target_parent_domain() {
        let cookie = session_cookie(
            "zeroth_session",
            "sess_123",
            SESSION_TTL_SECONDS,
            Some(".wavey.ai"),
        );

        assert!(cookie.contains("Domain=.wavey.ai"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn clear_session_cookie_expires_browser_cookie() {
        let cookie = clear_session_cookie("zeroth_session", None);

        assert_eq!(
            cookie,
            "zeroth_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn clear_session_cookie_uses_parent_domain_when_configured() {
        let cookie = clear_session_cookie("zeroth_session", Some(".wavey.ai"));

        assert_eq!(
            cookie,
            "zeroth_session=; Path=/; Max-Age=0; Domain=.wavey.ai; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn cookie_domain_attribute_rejects_header_delimiters() {
        assert_eq!(
            cookie_domain_attribute(Some(".wavey.ai")),
            " Domain=.wavey.ai;"
        );
        assert_eq!(cookie_domain_attribute(Some("bad.example; Secure")), "");
        assert_eq!(cookie_domain_attribute(Some("bad.example\r\nX: y")), "");
    }

    #[test]
    fn transaction_cookie_is_callback_scoped_and_cross_site_post_safe() {
        let cookie =
            transaction_cookie("zeroth_tx", "provider-state", AUTH_TRANSACTION_TTL_SECONDS);

        assert!(cookie.starts_with("zeroth_tx=provider-state; Path=/oauth2/callback;"));
        assert!(cookie.contains("Max-Age=600"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=None"));
    }

    #[test]
    fn clear_transaction_cookie_expires_callback_cookie() {
        let cookie = clear_transaction_cookie("zeroth_tx");

        assert_eq!(
            cookie,
            "zeroth_tx=; Path=/oauth2/callback; Max-Age=0; HttpOnly; Secure; SameSite=None"
        );
    }

    #[test]
    fn cookie_value_extracts_named_cookie() {
        let cookie = cookie_value(
            Some("theme=dark; zeroth_session=sess_123; other=value"),
            "zeroth_session",
        );

        assert_eq!(cookie, Some("sess_123".to_owned()));
    }

    #[test]
    fn provider_callback_state_requires_matching_transaction_cookie() {
        provider_callback_state_matches_transaction_cookie("state-1", Some("state-1")).unwrap();

        let error = provider_callback_state_matches_transaction_cookie("state-1", Some("state-2"))
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "provider callback state did not match browser transaction"
        );

        let error =
            provider_callback_state_matches_transaction_cookie("state-1", None).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn session_row_is_inactive_when_revoked_or_expired() {
        let mut session = valid_session_row();

        assert!(session_row_is_active(&session, 1_780_000_100));

        session.revoked_at = Some(1_780_000_200);
        assert!(!session_row_is_active(&session, 1_780_000_300));

        session.revoked_at = None;
        session.expires_at = 1_780_000_300;
        assert!(!session_row_is_active(&session, 1_780_000_300));
    }

    #[test]
    fn authorization_request_session_reuse_respects_prompt_login_and_max_age() {
        let session = valid_session_row();
        let mut request = valid_authorization_request();

        assert!(authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));

        request.max_age = Some(120);
        assert!(authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_120
        ));
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_121
        ));

        request.max_age = Some(0);
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_001
        ));

        request.max_age = None;
        request.prompt = AuthorizationPrompt::Login;
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));

        request.prompt = AuthorizationPrompt::SelectAccount;
        assert!(!authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));

        request.prompt = AuthorizationPrompt::Consent;
        assert!(authorization_request_may_reuse_session(
            &request,
            &session,
            1_780_000_100
        ));
    }

    #[test]
    fn session_response_includes_authenticated_user_profile() {
        let session = valid_session_row();
        let user = valid_user_row();

        let value = serde_json::to_value(session_response(Some((&session, &user)))).unwrap();

        assert_eq!(value["authenticated"], true);
        assert_eq!(value["session"]["id"], "sess_123");
        assert_eq!(value["session"]["clientId"], "ios");
        assert_eq!(value["user"]["sub"], "usr_123");
        assert_eq!(value["user"]["email"], "user@example.com");
        assert_eq!(value["user"]["name"], "Example User");
    }

    #[test]
    fn session_response_omits_session_and_user_when_anonymous() {
        let value = serde_json::to_value(session_response(None)).unwrap();

        assert_eq!(value["authenticated"], false);
        assert!(value.get("session").is_none());
        assert!(value.get("user").is_none());
    }

    #[test]
    fn profile_patch_accepts_aliases_and_null_clears_picture() {
        let patch = profile_patch_from_value(serde_json::json!({
            "displayName": "  New Name  ",
            "picture": null
        }))
        .unwrap();

        assert_eq!(
            patch,
            ProfilePatch {
                display_name: Some(Some("New Name".to_owned())),
                picture_url: Some(None),
            }
        );
    }

    #[test]
    fn profile_patch_rejects_unknown_and_invalid_fields() {
        let error = profile_patch_from_value(serde_json::json!({ "email": "new@example.com" }))
            .unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error
            .description
            .contains("unsupported profile patch field"));

        let error = profile_patch_from_value(serde_json::json!({ "picture": "ftp://x.test/a" }))
            .unwrap_err();
        assert_eq!(error.description, "picture must use http or https");
    }

    #[test]
    fn user_with_profile_patch_applies_local_profile_changes() {
        let user = valid_user_row();
        let patch = ProfilePatch {
            display_name: Some(Some("Local Name".to_owned())),
            picture_url: Some(None),
        };

        let updated = user_with_profile_patch(&user, &patch);

        assert_eq!(updated.primary_email, user.primary_email);
        assert_eq!(updated.display_name.as_deref(), Some("Local Name"));
        assert_eq!(updated.picture_url, None);
    }

    #[test]
    fn identity_reference_from_url_requires_provider_identity() {
        let url = url::Url::parse(
            "https://id.example.com/identities?provider_id=google&provider_subject=sub_123",
        )
        .unwrap();

        assert_eq!(
            identity_reference_from_url(&url).unwrap(),
            IdentityReference {
                provider_id: "google".to_owned(),
                provider_subject: "sub_123".to_owned(),
            }
        );

        let url = url::Url::parse(
            "https://id.example.com/identities?provider_id=google.com&provider_subject=sub_123",
        )
        .unwrap();
        let error = identity_reference_from_url(&url).unwrap_err();
        assert_eq!(error, "provider_id contains unsupported characters");
    }

    #[test]
    fn sessions_response_marks_current_session() {
        let current = valid_session_row();
        let mut other = valid_session_row();
        other.id = "sess_other".to_owned();
        other.client_id = Some("web".to_owned());
        other.created_at = 1_780_000_050;

        let value = serde_json::to_value(sessions_response(&[other, current], "sess_123")).unwrap();

        assert_eq!(value["sessions"][0]["id"], "sess_other");
        assert_eq!(value["sessions"][0]["clientId"], "web");
        assert_eq!(value["sessions"][0]["current"], false);
        assert_eq!(value["sessions"][1]["id"], "sess_123");
        assert_eq!(value["sessions"][1]["current"], true);
    }

    #[test]
    fn identities_response_serializes_linked_provider_identities() {
        let value = serde_json::to_value(identities_response(&[valid_identity_row()])).unwrap();

        assert_eq!(value["identities"][0]["providerId"], "google");
        assert_eq!(value["identities"][0]["providerSubject"], "google-sub-123");
        assert_eq!(value["identities"][0]["email"], "user@example.com");
        assert_eq!(value["identities"][0]["emailVerified"], true);
        assert_eq!(value["identities"][0]["displayName"], "Example User");
        assert_eq!(
            value["identities"][0]["pictureUrl"],
            "https://example.com/user.jpg"
        );
        assert_eq!(value["identities"][0]["createdAt"], 1_780_000_000);
        assert_eq!(value["identities"][0]["updatedAt"], 1_780_000_100);
    }

    #[test]
    fn cors_policy_allows_expected_paths_and_methods() {
        assert!(cors_path("/oauth/token"));
        assert!(cors_path("/oauth/revoke"));
        assert!(cors_path("/oauth/introspect"));
        assert!(cors_path("/userinfo"));
        assert!(cors_path("/session"));
        assert!(cors_path("/sessions"));
        assert!(cors_path("/profile"));
        assert!(cors_path("/identities"));
        assert!(cors_path("/validate"));
        assert!(cors_path("/logout"));
        assert!(!cors_path("/authorize"));

        assert!(cors_method_allowed("/oauth/token", "POST"));
        assert!(cors_method_allowed("/oauth/revoke", "POST"));
        assert!(cors_method_allowed("/oauth/introspect", "POST"));
        assert!(!cors_method_allowed("/oauth/token", "GET"));
        assert!(!cors_method_allowed("/oauth/revoke", "GET"));
        assert!(!cors_method_allowed("/oauth/introspect", "GET"));
        assert!(cors_method_allowed("/userinfo", "GET"));
        assert!(cors_method_allowed("/profile", "GET"));
        assert!(cors_method_allowed("/profile", "PATCH"));
        assert!(!cors_method_allowed("/profile", "DELETE"));
        assert!(cors_method_allowed("/sessions", "GET"));
        assert!(cors_method_allowed("/sessions", "DELETE"));
        assert!(!cors_method_allowed("/sessions", "POST"));
        assert!(cors_method_allowed("/identities", "GET"));
        assert!(cors_method_allowed("/identities", "DELETE"));
        assert!(!cors_method_allowed("/identities", "POST"));
        assert!(cors_method_allowed("/validate", "GET"));
        assert!(cors_method_allowed("/logout", "GET"));
        assert!(cors_method_allowed("/logout", "POST"));
        assert!(!cors_method_allowed("/logout", "PUT"));
    }

    #[test]
    fn validate_cors_origin_allows_native_requests_without_origin() {
        validate_cors_origin(None, &[]).unwrap();
    }

    #[test]
    fn validate_cors_origin_requires_exact_registered_origin() {
        let allowed_origins = vec!["https://app.example.com".to_owned()];

        validate_cors_origin(Some("https://app.example.com"), &allowed_origins).unwrap();
        let error =
            validate_cors_origin(Some("https://evil.example.com"), &allowed_origins).unwrap_err();

        assert_eq!(
            error,
            "Origin is not allowed for this client: https://evil.example.com"
        );
    }

    #[test]
    fn origin_allowed_in_client_origin_rows_reads_registered_origins() {
        let rows = vec![
            ClientOriginsRow {
                allowed_origins_json: "[]".to_owned(),
            },
            ClientOriginsRow {
                allowed_origins_json: r#"["https://app.example.com"]"#.to_owned(),
            },
        ];

        assert!(origin_allowed_in_client_origin_rows(&rows, "https://app.example.com").unwrap());
        assert!(!origin_allowed_in_client_origin_rows(&rows, "https://other.example.com").unwrap());
    }

    #[test]
    fn provider_jwks_cache_reuses_replaces_and_expires_entries() {
        let mut cache = ProviderJwksCache::default();

        assert_eq!(cache.get(well_known::GOOGLE, 100), None);

        cache.put(well_known::GOOGLE, provider_jwks_with_kid("google-1"), 100);
        cache.put(well_known::APPLE, provider_jwks_with_kid("apple-1"), 110);

        assert_eq!(
            cached_provider_kid(cache.get(well_known::GOOGLE, 120)),
            Some("google-1".to_owned())
        );
        assert_eq!(
            cached_provider_kid(cache.get(well_known::APPLE, 120)),
            Some("apple-1".to_owned())
        );
        assert_eq!(cache.entries.len(), 2);

        cache.put(well_known::GOOGLE, provider_jwks_with_kid("google-2"), 130);

        assert_eq!(
            cached_provider_kid(cache.get(well_known::GOOGLE, 131)),
            Some("google-2".to_owned())
        );
        assert_eq!(cache.entries.len(), 2);

        assert_eq!(
            cache.get(well_known::APPLE, 110 + PROVIDER_JWKS_CACHE_TTL_SECONDS),
            None
        );
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn provider_id_token_verification_accepts_google_rs256_jwt() {
        let now = 1_780_000_000_i32;
        let (id_token, jwks) = signed_provider_id_token(
            well_known::GOOGLE,
            "google-client",
            "nonce-1",
            provider_id_token_claims(
                "https://accounts.google.com",
                "google-client",
                Some("nonce-1"),
                i64::from(now) + 600,
            ),
        );

        let verified = verify_provider_id_token(
            &id_token,
            &jwks,
            ProviderIdTokenValidation {
                provider_id: well_known::GOOGLE,
                client_id: "google-client",
                nonce: Some("nonce-1"),
                now,
            },
        )
        .unwrap();

        assert_eq!(verified.claims.sub, "provider-sub");
        assert_eq!(verified.claims.email, Some("user@example.com".to_owned()));
        assert!(verified.raw_claims_json.contains("user@example.com"));
    }

    #[test]
    fn provider_id_token_claim_validation_rejects_wrong_audience() {
        let claims = provider_id_token_claims(
            "https://appleid.apple.com",
            "apple-service-id",
            Some("nonce-1"),
            1_780_000_600,
        );

        let error = validate_provider_id_token_claims(
            &claims,
            ProviderIdTokenValidation {
                provider_id: well_known::APPLE,
                client_id: "different-client",
                nonce: Some("nonce-1"),
                now: 1_780_000_000,
            },
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_response");
        assert_eq!(
            error.description,
            "id_token audience did not include provider client_id"
        );
    }

    #[test]
    fn provider_id_token_claim_validation_rejects_wrong_nonce() {
        let claims = provider_id_token_claims(
            "https://accounts.google.com",
            "google-client",
            Some("nonce-1"),
            1_780_000_600,
        );

        let error = validate_provider_id_token_claims(
            &claims,
            ProviderIdTokenValidation {
                provider_id: well_known::GOOGLE,
                client_id: "google-client",
                nonce: Some("nonce-2"),
                now: 1_780_000_000,
            },
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_response");
        assert_eq!(
            error.description,
            "id_token nonce did not match authorization request"
        );
    }

    #[test]
    fn oidc_email_verified_claim_accepts_provider_string_bool() {
        assert_eq!(
            boolish_claim(Some(&serde_json::Value::String("true".to_owned()))),
            Some(true)
        );
        assert_eq!(
            boolish_claim(Some(&serde_json::Value::String("false".to_owned()))),
            Some(false)
        );
    }

    #[test]
    fn callback_values_accept_code_and_state() {
        let callback = provider_callback_from_values(
            Some("provider-code".to_owned()),
            Some("provider-state".to_owned()),
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(callback.state, "provider-state");
        assert_eq!(callback.code, Some("provider-code".to_owned()));
        assert_eq!(callback.provider_error, None);
        assert_eq!(callback.apple_user_json, None);
    }

    #[test]
    fn callback_values_preserve_apple_user_json() {
        let callback = provider_callback_from_values(
            Some("provider-code".to_owned()),
            Some("provider-state".to_owned()),
            None,
            None,
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#.to_owned()),
        )
        .unwrap();

        assert_eq!(
            callback.apple_user_json.as_deref(),
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#)
        );
    }

    #[test]
    fn callback_values_preserve_provider_errors_with_state() {
        let callback = provider_callback_from_values(
            None,
            Some("provider-state".to_owned()),
            Some("access_denied".to_owned()),
            Some("User cancelled".to_owned()),
            Some(r#"{"name":{"firstName":"Ada"}}"#.to_owned()),
        )
        .unwrap();
        let error = callback.provider_error.unwrap();

        assert_eq!(callback.state, "provider-state");
        assert_eq!(callback.code, None);
        assert_eq!(error.code, "access_denied");
        assert_eq!(error.description, "User cancelled");
    }

    #[test]
    fn callback_values_reject_provider_errors_without_state() {
        let error = provider_callback_from_values(
            None,
            None,
            Some("access_denied".to_owned()),
            Some("User cancelled".to_owned()),
            None,
        )
        .unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.description, "missing state");
    }

    #[test]
    fn apple_callback_user_display_name_joins_name_parts() {
        let user = apple_callback_user_from_json(
            r#"{"name":{"firstName":"  Ada ","lastName":" Lovelace "},"email":"ada@example.com"}"#,
        )
        .unwrap();

        assert_eq!(
            apple_callback_user_display_name(&user),
            Some("Ada Lovelace".to_owned())
        );
    }

    #[test]
    fn apple_callback_user_display_name_accepts_single_name_part() {
        let user = apple_callback_user_from_json(r#"{"name":{"firstName":"Ada"}}"#).unwrap();
        assert_eq!(
            apple_callback_user_display_name(&user),
            Some("Ada".to_owned())
        );

        let user = apple_callback_user_from_json(r#"{"name":{"lastName":"Lovelace"}}"#).unwrap();
        assert_eq!(
            apple_callback_user_display_name(&user),
            Some("Lovelace".to_owned())
        );
    }

    #[test]
    fn oidc_raw_profile_json_preserves_apple_callback_user() {
        let raw = merge_oidc_raw_profile_json(
            r#"{"sub":"apple-sub","email":"ada@example.com"}"#,
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(value["id_token_claims"]["sub"], "apple-sub");
        assert_eq!(value["apple_user"]["name"]["firstName"], "Ada");
    }

    #[test]
    fn transaction_row_hydrates_stored_transaction() {
        let record = auth_transaction_from_row(AuthTransactionRow {
            provider_state: "provider-state".to_owned(),
            client_id: "ios".to_owned(),
            provider_id: well_known::GOOGLE.to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid email".to_owned(),
            link_user_id: Some("usr_123".to_owned()),
            link_session_id: Some("sess_123".to_owned()),
            session_return_to: Some("https://app.example.com/dashboard".to_owned()),
            created_at: 1_780_000_000,
            expires_at: 1_780_000_600,
            consumed_at: None,
        })
        .unwrap();

        assert_eq!(record.transaction.client_id, ClientId("ios".to_owned()));
        assert_eq!(
            record.transaction.provider_id,
            ProviderId(well_known::GOOGLE.to_owned())
        );
        assert!(record.transaction.scope.contains("email"));
        assert_eq!(
            record.transaction.provider_nonce,
            Some("provider-nonce".to_owned())
        );
        assert_eq!(
            record.transaction.link_user_id,
            Some(UserId("usr_123".to_owned()))
        );
        assert_eq!(
            record.transaction.link_session_id,
            Some("sess_123".to_owned())
        );
        assert_eq!(
            record.transaction.session_return_to,
            Some("https://app.example.com/dashboard".to_owned())
        );
        assert_eq!(record.consumed_at, None);
    }

    #[test]
    fn expired_transactions_are_rejected() {
        let record = auth_transaction_from_row(AuthTransactionRow {
            provider_state: "provider-state".to_owned(),
            client_id: "ios".to_owned(),
            provider_id: well_known::GOOGLE.to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: None,
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid".to_owned(),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: 1_780_000_000,
            expires_at: 1_780_000_100,
            consumed_at: None,
        })
        .unwrap();

        let error = validate_stored_auth_transaction(&record, 1_780_000_100).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.description, "provider callback state has expired");
    }

    #[test]
    fn consumed_transactions_are_rejected() {
        let record = auth_transaction_from_row(AuthTransactionRow {
            provider_state: "provider-state".to_owned(),
            client_id: "ios".to_owned(),
            provider_id: well_known::GOOGLE.to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            provider_redirect_uri: "https://id.example.com/oauth2/callback".to_owned(),
            app_state: None,
            nonce: None,
            provider_nonce: Some("provider-nonce".to_owned()),
            code_challenge: Some("challenge".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid".to_owned(),
            link_user_id: None,
            link_session_id: None,
            session_return_to: None,
            created_at: 1_780_000_000,
            expires_at: 1_780_000_600,
            consumed_at: Some(1_780_000_050),
        })
        .unwrap();

        let error = validate_stored_auth_transaction(&record, 1_780_000_100).unwrap_err();

        assert_eq!(error.code, "invalid_request");
        assert_eq!(
            error.description,
            "provider callback state has already been consumed"
        );
    }

    #[test]
    fn provider_token_request_body_is_form_encoded() {
        let request = TokenExchangeRequest {
            endpoint: "https://oauth2.googleapis.com/token".to_owned(),
            params: vec![
                ("grant_type".to_owned(), "authorization_code".to_owned()),
                ("client_id".to_owned(), "client id".to_owned()),
                ("code".to_owned(), "code+value".to_owned()),
                (
                    "redirect_uri".to_owned(),
                    "https://id.example.com/oauth2/callback".to_owned(),
                ),
                ("client_secret".to_owned(), "secret/value".to_owned()),
            ],
            token_auth: TokenAuth::ClientSecretPost,
        };

        let body = provider_token_request_body(&request);

        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("client_id=client+id"));
        assert!(body.contains("code=code%2Bvalue"));
        assert!(body.contains("client_secret=secret%2Fvalue"));
    }

    #[test]
    fn provider_token_response_maps_to_token_set() {
        let token_set = provider_token_response_to_set(ProviderTokenResponse {
            access_token: Some("access".to_owned()),
            id_token: Some("id".to_owned()),
            refresh_token: Some("refresh".to_owned()),
            expires_in: Some(3600),
            error: None,
            error_description: None,
        })
        .unwrap();

        assert_eq!(token_set.access_token, Some("access".to_owned()));
        assert_eq!(token_set.id_token, Some("id".to_owned()));
        assert_eq!(token_set.refresh_token, Some("refresh".to_owned()));
        assert_eq!(token_set.expires_in, Some(3600));
    }

    #[test]
    fn provider_token_response_surfaces_provider_errors() {
        let error = provider_token_response_to_set(ProviderTokenResponse {
            access_token: None,
            id_token: None,
            refresh_token: None,
            expires_in: None,
            error: Some("invalid_grant".to_owned()),
            error_description: Some("Code was already used".to_owned()),
        })
        .unwrap_err();

        assert_eq!(error.code, "invalid_grant");
        assert_eq!(error.description, "Code was already used");
    }

    #[test]
    fn spotify_profile_source_uses_first_image() {
        let source = spotify_profile_source(SpotifyApiProfile {
            id: "spotify-user".to_owned(),
            email: Some("listener@example.com".to_owned()),
            display_name: Some("Listener".to_owned()),
            images: vec![
                SpotifyApiImage {
                    url: Some("https://i.scdn.co/image/1".to_owned()),
                },
                SpotifyApiImage {
                    url: Some("https://i.scdn.co/image/2".to_owned()),
                },
            ],
        })
        .unwrap();

        assert_eq!(
            source,
            ProviderProfileSource::SpotifyProfile {
                id: "spotify-user".to_owned(),
                email: Some("listener@example.com".to_owned()),
                display_name: Some("Listener".to_owned()),
                image_url: Some("https://i.scdn.co/image/1".to_owned()),
            }
        );
    }

    #[test]
    fn spotify_profile_source_requires_id() {
        let error = spotify_profile_source(SpotifyApiProfile {
            id: String::new(),
            email: None,
            display_name: None,
            images: vec![],
        })
        .unwrap_err();

        assert_eq!(error.code, "invalid_response");
        assert_eq!(error.description, "Spotify profile did not include an id");
    }

    fn valid_token_exchange_form() -> TokenExchangeForm {
        TokenExchangeForm {
            grant_type: "authorization_code".to_owned(),
            client_id: "ios".to_owned(),
            client_auth: ClientAuth::None,
            redirect_uri: Some("wavey://auth/callback".to_owned()),
            code: Some("zeroth-code".to_owned()),
            code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned()),
            refresh_token: None,
            scope: None,
            subject_token: None,
            subject_token_type: None,
            provider: None,
            provider_client_id: None,
            nonce: None,
        }
    }

    fn valid_native_apple_token_exchange_form() -> TokenExchangeForm {
        TokenExchangeForm {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE.to_owned(),
            client_id: "wavey-ios".to_owned(),
            client_auth: ClientAuth::None,
            redirect_uri: None,
            code: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            subject_token: Some("apple.id.token".to_owned()),
            subject_token_type: Some(ID_TOKEN_SUBJECT_TOKEN_TYPE.to_owned()),
            provider: Some(well_known::APPLE.to_owned()),
            provider_client_id: Some("ai.wavey.id".to_owned()),
            nonce: None,
        }
    }

    fn valid_authorization_request() -> AuthorizationRequest {
        AuthorizationRequest {
            client_id: ClientId("ios".to_owned()),
            redirect_uri: "wavey://auth/callback".to_owned(),
            scope: zeroth_core::ScopeSet::new(["openid", "email"]),
            state: Some("app-state".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            prompt: AuthorizationPrompt::Default,
            max_age: None,
            code_challenge: Some("downstream-pkce".to_owned()),
            code_challenge_method: Some(PkceChallengeMethod::S256),
        }
    }

    fn registered_public_client() -> RegisteredClient {
        RegisteredClient {
            client: Client {
                id: ClientId("ios".to_owned()),
                name: "Wavey iOS".to_owned(),
                redirect_uris: vec!["wavey://auth/callback".to_owned()],
                allowed_origins: vec![],
                allowed_email_domains: vec![],
                confidential: false,
            },
            secret_hash: None,
        }
    }

    fn registered_confidential_client(secret: &str) -> RegisteredClient {
        RegisteredClient {
            client: Client {
                id: ClientId("web".to_owned()),
                name: "Wavey Web".to_owned(),
                redirect_uris: vec!["https://app.example.com/auth/callback".to_owned()],
                allowed_origins: vec!["https://app.example.com".to_owned()],
                allowed_email_domains: vec![],
                confidential: true,
            },
            secret_hash: Some(format!("sha256:{}", hash_secret(secret))),
        }
    }

    fn valid_auth_code_row(code_challenge: String) -> AuthCodeRow {
        AuthCodeRow {
            code_hash: hash_secret("zeroth-code"),
            client_id: "ios".to_owned(),
            redirect_uri: "wavey://auth/callback".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            nonce: Some("nonce-1".to_owned()),
            code_challenge: Some(code_challenge),
            code_challenge_method: Some("S256".to_owned()),
            scope: "openid email".to_owned(),
            auth_time: Some(1_780_000_000),
            created_at: 1_780_000_000,
            expires_at: 1_780_000_600,
            consumed_at: None,
        }
    }

    fn valid_refresh_token_row() -> RefreshTokenRow {
        RefreshTokenRow {
            token_hash: hash_secret("refresh-token"),
            client_id: "ios".to_owned(),
            user_id: "usr_123".to_owned(),
            session_id: Some("sess_123".to_owned()),
            scope: "openid profile email offline_access".to_owned(),
            auth_time: Some(1_780_000_000),
            created_at: 1_780_000_000,
            expires_at: 1_780_086_400,
            rotated_at: None,
            revoked_at: None,
        }
    }

    fn valid_session_row() -> SessionRow {
        SessionRow {
            id: "sess_123".to_owned(),
            user_id: "usr_123".to_owned(),
            client_id: Some("ios".to_owned()),
            created_at: 1_780_000_000,
            expires_at: 1_780_086_400,
            revoked_at: None,
            user_agent: Some("Zeroth Test".to_owned()),
            ip_hash: Some(hash_secret("127.0.0.1")),
        }
    }

    fn valid_identity_row() -> IdentityRow {
        IdentityRow {
            provider_id: "google".to_owned(),
            provider_subject: "google-sub-123".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: 1,
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/user.jpg".to_owned()),
            created_at: 1_780_000_000,
            updated_at: 1_780_000_100,
        }
    }

    fn valid_user_row() -> UserRow {
        UserRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/avatar.png".to_owned()),
            disabled_at: None,
        }
    }

    fn valid_user_token_claims_row() -> UserTokenClaimsRow {
        UserTokenClaimsRow {
            id: "usr_123".to_owned(),
            primary_email: Some("user@example.com".to_owned()),
            display_name: Some("Example User".to_owned()),
            picture_url: Some("https://example.com/avatar.png".to_owned()),
            disabled_at: None,
            email_verified: 1,
        }
    }

    fn valid_access_token_claims() -> JwtClaims {
        JwtClaims {
            iss: "https://id.example.com".to_owned(),
            sub: "usr_123".to_owned(),
            aud: "ios".to_owned(),
            exp: 1_780_003_600,
            iat: 1_780_000_000,
            auth_time: None,
            sid: Some("sess_123".to_owned()),
            nonce: None,
            scope: Some("openid email".to_owned()),
            client_id: Some("ios".to_owned()),
            token_use: "access".to_owned(),
            email: None,
            email_verified: None,
            name: None,
            picture: None,
        }
    }

    fn test_signing_key() -> Es256SigningKey {
        es256_signing_key_from_config(
            "test-key",
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap()
    }

    fn test_verification_keys(signing_key: &Es256SigningKey) -> Vec<Es256VerificationKey> {
        let jwks = jwks_response(signing_key, None).unwrap();
        es256_verification_keys_from_jwks(&jwks).unwrap()
    }

    fn decode_jwt_claims(jwt: &str) -> serde_json::Value {
        let payload = jwt.split('.').nth(1).unwrap();
        decode_jwt_json_segment(payload)
    }

    fn decode_jwt_json_segment<T: serde::de::DeserializeOwned>(segment: &str) -> T {
        let json = URL_SAFE_NO_PAD.decode(segment).unwrap();
        serde_json::from_slice(&json).unwrap()
    }

    fn provider_id_token_claims(
        issuer: &str,
        audience: &str,
        nonce: Option<&str>,
        expires_at: i64,
    ) -> ProviderIdTokenClaims {
        ProviderIdTokenClaims {
            iss: issuer.to_owned(),
            sub: "provider-sub".to_owned(),
            aud: AudienceClaim::One(audience.to_owned()),
            exp: expires_at,
            iat: Some(expires_at - 600),
            nonce: nonce.map(str::to_owned),
            email: Some("user@example.com".to_owned()),
            email_verified: Some(serde_json::Value::String("true".to_owned())),
            name: Some("Example User".to_owned()),
            picture: Some("https://example.com/avatar.png".to_owned()),
        }
    }

    fn signed_provider_id_token(
        provider_id: &str,
        client_id: &str,
        nonce: &str,
        claims: ProviderIdTokenClaims,
    ) -> (String, ProviderJwksResponse) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let key_id = format!("{provider_id}-{client_id}-{nonce}");
        let header = ProviderJwtHeader {
            alg: "RS256".to_owned(),
            kid: Some(key_id.clone()),
        };
        let signing_input = format!(
            "{}.{}",
            jwt_json_segment(&header).unwrap(),
            jwt_json_segment(&claims).unwrap()
        );
        let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
        let id_token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let jwks = ProviderJwksResponse {
            keys: vec![ProviderJwk {
                kty: "RSA".to_owned(),
                key_use: Some("sig".to_owned()),
                kid: Some(key_id),
                alg: Some("RS256".to_owned()),
                n: Some(URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be())),
                e: Some(URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be())),
            }],
        };

        (id_token, jwks)
    }

    fn provider_jwks_with_kid(kid: &str) -> ProviderJwksResponse {
        ProviderJwksResponse {
            keys: vec![ProviderJwk {
                kty: "RSA".to_owned(),
                key_use: Some("sig".to_owned()),
                kid: Some(kid.to_owned()),
                alg: Some("RS256".to_owned()),
                n: Some("n".to_owned()),
                e: Some("e".to_owned()),
            }],
        }
    }

    fn test_passkey_client_data(ceremony_type: &str, challenge: &str, origin: &str) -> String {
        URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "type": ceremony_type,
                "challenge": passkey_challenge_for_browser(challenge),
                "origin": origin,
                "crossOrigin": false
            })
            .to_string()
            .as_bytes(),
        )
    }

    fn test_passkey_authenticator_data(
        rp_id: &str,
        flags: u8,
        sign_count: i32,
        credential_id: &[u8],
        cose_key: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(cose_key);
        data
    }

    fn test_passkey_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0xa3);
        cbor_text(&mut out, "fmt");
        cbor_text(&mut out, "none");
        cbor_text(&mut out, "authData");
        cbor_bytes(&mut out, auth_data);
        cbor_text(&mut out, "attStmt");
        out.push(0xa0);
        out
    }

    fn test_passkey_cose_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0xa5);
        out.push(0x01);
        out.push(0x02);
        out.push(0x03);
        out.push(0x26);
        out.push(0x20);
        out.push(0x01);
        out.push(0x21);
        cbor_bytes(&mut out, x);
        out.push(0x22);
        cbor_bytes(&mut out, y);
        out
    }

    fn cbor_text(out: &mut Vec<u8>, value: &str) {
        cbor_len(out, 0x60, value.len());
        out.extend_from_slice(value.as_bytes());
    }

    fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
        cbor_len(out, 0x40, value.len());
        out.extend_from_slice(value);
    }

    fn cbor_len(out: &mut Vec<u8>, major: u8, len: usize) {
        if len < 24 {
            out.push(major | (len as u8));
        } else if len <= u8::MAX as usize {
            out.push(major | 24);
            out.push(len as u8);
        } else {
            out.push(major | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }

    fn cached_provider_kid(jwks: Option<ProviderJwksResponse>) -> Option<String> {
        jwks.and_then(|jwks| jwks.keys.into_iter().next()?.kid)
    }
}
