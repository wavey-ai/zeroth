//! Portable service-principal policy and ES256 verification.
//!
//! Verification does not consume an assertion. The issuer must atomically claim
//! `(client.id, jti)` through the assertion's expiry, recheck the client revision,
//! and capture issuance before returning a token. No user session is involved.

use std::collections::HashSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use p256::ecdsa::signature::Verifier as _;

pub const MAX_SERVICE_KEYS: usize = 8;
pub const MAX_SERVICE_AUDIENCES: usize = 10;
pub const MAX_SERVICE_SCOPES: usize = 32;
pub const MAX_SERVICE_TOKEN_TTL_SECONDS: u32 = 600;
pub const MAX_SERVICE_ASSERTION_TTL_SECONDS: u32 = 300;
pub const MAX_SERVICE_JWKS_BYTES: usize = 16 * 1024;
pub const MAX_SERVICE_JWT_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 1024;
const MAX_CLAIMS_BYTES: usize = 4096;
const MAX_SCOPE_BYTES: usize = 2048;
const MAX_CLOCK_SKEW_SECONDS: u32 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceTokenError {
    pub code: &'static str,
    pub description: &'static str,
}

impl std::fmt::Display for ServiceTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.description)
    }
}

impl std::error::Error for ServiceTokenError {}

fn error(code: &'static str, description: &'static str) -> ServiceTokenError {
    ServiceTokenError { code, description }
}

fn invalid() -> ServiceTokenError {
    error("invalid_token", "invalid service credential")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceJwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub alg: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl ServiceJwk {
    fn verifying_key(&self) -> Result<VerifyingKey, ServiceTokenError> {
        if self.kty != "EC" || self.key_use != "sig" || self.alg != "ES256" || self.crv != "P-256" {
            return Err(invalid());
        }
        let x = URL_SAFE_NO_PAD.decode(&self.x).map_err(|_| invalid())?;
        let y = URL_SAFE_NO_PAD.decode(&self.y).map_err(|_| invalid())?;
        if x.len() != 32 || y.len() != 32 {
            return Err(invalid());
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| invalid())
    }
}

/// Strict public-only registration format. Unknown members, including private
/// JWK parameters, fail deserialization instead of being silently discarded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceJwks {
    pub keys: Vec<ServiceJwk>,
}

impl ServiceJwks {
    pub fn from_json(json: &str) -> Result<Self, ServiceTokenError> {
        if json.len() > MAX_SERVICE_JWKS_BYTES {
            return Err(error("invalid_client_metadata", "public JWKS is too large"));
        }
        let jwks: Self = serde_json::from_str(json)
            .map_err(|_| error("invalid_client_metadata", "invalid public JWKS"))?;
        jwks.validate()?;
        Ok(jwks)
    }

    pub fn validate(&self) -> Result<(), ServiceTokenError> {
        if self.keys.is_empty() || self.keys.len() > MAX_SERVICE_KEYS {
            return Err(error("invalid_client_metadata", "invalid public key count"));
        }
        let mut kids = HashSet::new();
        for key in &self.keys {
            if !opaque_id(&key.kid)
                || !kids.insert(&key.kid)
                || key.x.len() != 43
                || key.y.len() != 43
            {
                return Err(error("invalid_client_metadata", "invalid public key"));
            }
            for coordinate in [&key.x, &key.y] {
                let bytes = URL_SAFE_NO_PAD.decode(coordinate).map_err(|_| {
                    error("invalid_client_metadata", "invalid public key coordinate")
                })?;
                if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != *coordinate {
                    return Err(error(
                        "invalid_client_metadata",
                        "invalid public key coordinate",
                    ));
                }
            }
            key.verifying_key()
                .map_err(|_| error("invalid_client_metadata", "invalid ES256 public key"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceClient {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub disabled: bool,
    pub revision: i64,
    pub allowed_audiences: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub public_jwks: ServiceJwks,
    pub token_ttl_seconds: u32,
}

impl ServiceClient {
    pub fn validate(&self) -> Result<(), ServiceTokenError> {
        if !service_id(&self.id)
            || !opaque_id(&self.tenant_id)
            || self.name.trim().is_empty()
            || self.name.chars().count() > 128
            || self.name.chars().any(char::is_control)
            || self.revision < 1
            || !(60..=MAX_SERVICE_TOKEN_TTL_SECONDS).contains(&self.token_ttl_seconds)
            || self.allowed_audiences.is_empty()
            || self.allowed_audiences.len() > MAX_SERVICE_AUDIENCES
            || self.allowed_scopes.is_empty()
            || self.allowed_scopes.len() > MAX_SERVICE_SCOPES
        {
            return Err(error(
                "invalid_client_metadata",
                "invalid service client policy",
            ));
        }
        let mut audiences = HashSet::new();
        for audience in &self.allowed_audiences {
            if !audience_ok(audience) || !audiences.insert(audience) {
                return Err(error("invalid_client_metadata", "invalid audience policy"));
            }
        }
        let mut scopes = HashSet::new();
        for scope in &self.allowed_scopes {
            if !scope_ok(scope) || !scopes.insert(scope) {
                return Err(error(
                    "invalid_client_metadata",
                    "invalid service scope policy",
                ));
            }
        }
        self.public_jwks.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceClientAssertionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    pub jti: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAssertionValidation {
    pub token_endpoint: String,
    pub now: i64,
    pub max_lifetime_seconds: u32,
    pub clock_skew_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub tenant_id: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub token_use: String,
    pub principal_type: String,
    pub client_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAccessTokenValidation {
    pub issuer: String,
    pub audience: String,
    pub tenant_id: String,
    pub required_scopes: Vec<String>,
    pub now: i64,
    pub max_lifetime_seconds: u32,
    pub clock_skew_seconds: u32,
}

/// The caller must durably claim the verified jti before issuing a token. This
/// pure function does not establish replay protection or current client state.
pub fn verify_service_client_assertion(
    token: &str,
    client: &ServiceClient,
    validation: &ServiceAssertionValidation,
) -> Result<ServiceClientAssertionClaims, ServiceTokenError> {
    client.validate()?;
    if client.disabled || !https_endpoint(&validation.token_endpoint) {
        return Err(error(
            "invalid_client",
            "service client authentication failed",
        ));
    }
    let result = (|| {
        let claims: ServiceClientAssertionClaims = verify_signed(token, &client.public_jwks)?;
        validate_times(
            claims.iat,
            claims.exp,
            claims.nbf,
            validation.now,
            validation.max_lifetime_seconds,
            MAX_SERVICE_ASSERTION_TTL_SECONDS,
            validation.clock_skew_seconds,
        )?;
        if claims.iss != client.id
            || claims.sub != client.id
            || claims.aud != validation.token_endpoint
            || !opaque_id(&claims.jti)
        {
            return Err(invalid());
        }
        Ok(claims)
    })();
    result.map_err(|_| error("invalid_client", "service client authentication failed"))
}

/// Validate an explicit audience and requested scopes against registered grants.
/// Returns a deterministic space-separated scope string; no implicit grants.
pub fn validate_service_token_request(
    client: &ServiceClient,
    audience: &str,
    scope: &str,
) -> Result<String, ServiceTokenError> {
    client.validate()?;
    if client.disabled {
        return Err(error("invalid_client", "service client is disabled"));
    }
    if !client
        .allowed_audiences
        .iter()
        .any(|allowed| allowed == audience)
    {
        return Err(error(
            "invalid_target",
            "audience is not granted to this client",
        ));
    }
    let mut scopes = parse_scopes(scope)?;
    if scopes.iter().any(|s| !client.allowed_scopes.contains(s)) {
        return Err(error(
            "invalid_scope",
            "scope is not granted to this client",
        ));
    }
    scopes.sort_unstable();
    Ok(scopes.join(" "))
}

pub fn build_service_access_token_claims(
    client: &ServiceClient,
    issuer: &str,
    audience: &str,
    scope: &str,
    now: i64,
    jti: &str,
) -> Result<ServiceAccessTokenClaims, ServiceTokenError> {
    let scope = validate_service_token_request(client, audience, scope)?;
    if !https_endpoint(issuer) || now < 0 || !opaque_id(jti) {
        return Err(invalid());
    }
    let exp = now
        .checked_add(i64::from(client.token_ttl_seconds))
        .ok_or_else(invalid)?;
    let claims = ServiceAccessTokenClaims {
        iss: issuer.to_owned(),
        sub: client.id.clone(),
        aud: audience.to_owned(),
        client_id: client.id.clone(),
        tenant_id: client.tenant_id.clone(),
        scope,
        iat: now,
        exp,
        jti: jti.to_owned(),
        token_use: "access".to_owned(),
        principal_type: "service".to_owned(),
        client_revision: client.revision,
    };
    if serde_json::to_vec(&claims).map_err(|_| invalid())?.len() > MAX_CLAIMS_BYTES {
        return Err(invalid());
    }
    Ok(claims)
}

/// Offline verification checks a pinned issuer key set and explicit resource
/// policy. Current client revision/disabled state require an online lookup.
pub fn verify_service_access_token(
    token: &str,
    issuer_jwks: &ServiceJwks,
    validation: &ServiceAccessTokenValidation,
) -> Result<ServiceAccessTokenClaims, ServiceTokenError> {
    let claims: ServiceAccessTokenClaims = verify_signed(token, issuer_jwks)?;
    validate_times(
        claims.iat,
        claims.exp,
        None,
        validation.now,
        validation.max_lifetime_seconds,
        MAX_SERVICE_TOKEN_TTL_SECONDS,
        validation.clock_skew_seconds,
    )?;
    if !https_endpoint(&validation.issuer)
        || !audience_ok(&validation.audience)
        || !opaque_id(&validation.tenant_id)
        || claims.iss != validation.issuer
        || claims.aud != validation.audience
        || claims.tenant_id != validation.tenant_id
        || claims.token_use != "access"
        || claims.principal_type != "service"
        || !service_id(&claims.client_id)
        || claims.sub != claims.client_id
        || claims.client_revision < 1
        || !opaque_id(&claims.jti)
        || validation.required_scopes.len() > MAX_SERVICE_SCOPES
    {
        return Err(invalid());
    }
    let scopes = parse_scopes(&claims.scope)?;
    for required in &validation.required_scopes {
        if !scope_ok(required) || !scopes.iter().any(|scope| scope == required) {
            return Err(error(
                "insufficient_scope",
                "required service scope is missing",
            ));
        }
    }
    Ok(claims)
}

/// Rust agents generate jti with a CSPRNG and sign a fresh assertion per request.
/// The private key remains with the agent; it is never serialized or registered.
pub fn build_service_client_assertion_claims(
    client_id: &str,
    token_endpoint: &str,
    now: i64,
    ttl_seconds: u32,
    jti: &str,
) -> Result<ServiceClientAssertionClaims, ServiceTokenError> {
    if !service_id(client_id)
        || !https_endpoint(token_endpoint)
        || !opaque_id(jti)
        || now < 0
        || ttl_seconds == 0
        || ttl_seconds > MAX_SERVICE_ASSERTION_TTL_SECONDS
    {
        return Err(invalid());
    }
    Ok(ServiceClientAssertionClaims {
        iss: client_id.to_owned(),
        sub: client_id.to_owned(),
        aud: token_endpoint.to_owned(),
        iat: now,
        exp: now
            .checked_add(i64::from(ttl_seconds))
            .ok_or_else(invalid)?,
        nbf: None,
        jti: jti.to_owned(),
    })
}

pub fn sign_service_client_assertion(
    signing_key: &SigningKey,
    kid: &str,
    claims: &ServiceClientAssertionClaims,
) -> Result<String, ServiceTokenError> {
    if !opaque_id(kid) || claims.iss != claims.sub {
        return Err(invalid());
    }
    let header = serde_json::json!({"alg":"ES256","kid":kid,"typ":"JWT"});
    let input = format!("{}.{}", encode_json(&header)?, encode_json(claims)?);
    let signature: Signature = signing_key.sign(input.as_bytes());
    let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    if token.len() > MAX_SERVICE_JWT_BYTES {
        return Err(invalid());
    }
    Ok(token)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

fn verify_signed<T: DeserializeOwned>(
    token: &str,
    jwks: &ServiceJwks,
) -> Result<T, ServiceTokenError> {
    if token.len() > MAX_SERVICE_JWT_BYTES {
        return Err(invalid());
    }
    let mut segments = token.split('.');
    let header = segments.next().ok_or_else(invalid)?;
    let payload = segments.next().ok_or_else(invalid)?;
    let signature = segments.next().ok_or_else(invalid)?;
    if segments.next().is_some() {
        return Err(invalid());
    }
    let header: Header = decode_json(header, MAX_HEADER_BYTES)?;
    if header.alg != "ES256"
        || !opaque_id(&header.kid)
        || header
            .typ
            .as_deref()
            .is_some_and(|typ| !matches!(typ, "JWT" | "at+jwt"))
    {
        return Err(invalid());
    }
    // Decode and bound all parts before curve work or deserializing claim types.
    let payload = decode_segment(payload, MAX_CLAIMS_BYTES)?;
    let signature = decode_segment(signature, 64)?;
    let signature = Signature::try_from(signature.as_slice()).map_err(|_| invalid())?;
    jwks.validate()?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or_else(invalid)?;
    let verifying_key = key.verifying_key().map_err(|_| invalid())?;
    let input = token.rsplit_once('.').ok_or_else(invalid)?.0;
    verifying_key
        .verify(input.as_bytes(), &signature)
        .map_err(|_| invalid())?;
    serde_json::from_slice(&payload).map_err(|_| invalid())
}

fn decode_segment(segment: &str, max: usize) -> Result<Vec<u8>, ServiceTokenError> {
    if segment.is_empty() || segment.len() > max.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| invalid())?;
    if bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != segment {
        return Err(invalid());
    }
    Ok(bytes)
}

fn decode_json<T: DeserializeOwned>(segment: &str, max: usize) -> Result<T, ServiceTokenError> {
    serde_json::from_slice(&decode_segment(segment, max)?).map_err(|_| invalid())
}

fn encode_json(value: &impl Serialize) -> Result<String, ServiceTokenError> {
    let json = serde_json::to_vec(value).map_err(|_| invalid())?;
    if json.len() > MAX_CLAIMS_BYTES {
        return Err(invalid());
    }
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn validate_times(
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    now: i64,
    max_lifetime: u32,
    hard_max: u32,
    skew: u32,
) -> Result<(), ServiceTokenError> {
    if now < 0 || iat < 0 || exp <= iat || max_lifetime == 0 || max_lifetime > hard_max
        || skew > MAX_CLOCK_SKEW_SECONDS || exp.checked_sub(iat).is_none_or(|ttl| ttl > i64::from(max_lifetime))
        || iat > now.saturating_add(i64::from(skew))
        // Expiry is never extended: the durable replay claim may expire at exp.
        || exp <= now || nbf.is_some_and(|nbf| nbf < iat || nbf >= exp || nbf > now.saturating_add(i64::from(skew)))
    {
        return Err(invalid());
    }
    Ok(())
}

fn parse_scopes(scope: &str) -> Result<Vec<String>, ServiceTokenError> {
    if scope.is_empty() || scope.len() > MAX_SCOPE_BYTES {
        return Err(error(
            "invalid_scope",
            "explicit service scopes are required",
        ));
    }
    let scopes: Vec<_> = scope.split(' ').map(str::to_owned).collect();
    let mut seen = HashSet::new();
    if scopes.len() > MAX_SERVICE_SCOPES
        || scopes
            .iter()
            .any(|scope| !scope_ok(scope) || !seen.insert(scope))
    {
        return Err(error("invalid_scope", "invalid service scopes"));
    }
    Ok(scopes)
}

fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

fn service_id(value: &str) -> bool {
    value.starts_with("svc_") && value.len() > 4 && opaque_id(value)
}

fn audience_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|b| b.is_ascii_graphic() && b != b'*')
}

fn scope_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b':' | b'.' | b'_' | b'-' | b'/')
        })
        && !matches!(
            value,
            "openid"
                | "profile"
                | "email"
                | "offline_access"
                | "address"
                | "phone"
                | "groups"
                | "roles"
                | "admin"
        )
}

fn https_endpoint(value: &str) -> bool {
    if value.len() > 2048 {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
}

#[cfg(test)]
mod tests;
