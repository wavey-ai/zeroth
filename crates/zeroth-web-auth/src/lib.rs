#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

pub const AUTH_STATE_COOKIE: &str = "yl_auth_state";
pub const SESSION_COOKIE: &str = "yl_auth_session";
pub const ANON_COOKIE: &str = "zeroth";
pub const DEFAULT_ISSUER: &str = "https://id.yl.vin";
pub const DEFAULT_CLIENT_ID: &str = "yl-web";
pub const AUTH_STATE_TTL_SECONDS: u64 = 60 * 10;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub issuer: Url,
    pub client_id: String,
    pub state_ttl_seconds: u64,
    pub session_cookie_name: String,
    pub state_cookie_name: String,
    pub anonymous_cookie_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthState {
    pub state: String,
    pub return_to: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCookieNames {
    pub session_cookie: String,
    pub state_cookie: String,
    pub anonymous_cookie: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieOptions {
    pub path: String,
    pub domain: Option<String>,
    pub max_age: Option<i64>,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub secure: bool,
}

impl Default for CookieOptions {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            domain: None,
            max_age: None,
            http_only: true,
            same_site: None,
            secure: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieSpec {
    pub name: String,
    pub value: String,
    pub options: CookieOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    InvalidToken,
    InvalidSignature,
    InvalidJson,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthError::InvalidToken => "invalid token",
            AuthError::InvalidSignature => "invalid signature",
            AuthError::InvalidJson => "invalid json",
        })
    }
}

impl std::error::Error for AuthError {}

pub fn auth_cookie_names() -> AuthCookieNames {
    AuthCookieNames {
        session_cookie: SESSION_COOKIE.to_string(),
        state_cookie: AUTH_STATE_COOKIE.to_string(),
        anonymous_cookie: ANON_COOKIE.to_string(),
    }
}

pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Generates a token using the operating system's cryptographic random source.
///
/// # Panics
/// Panics if secure randomness is unavailable. Authentication must fail rather
/// than issue predictable tokens or PKCE verifiers.
pub fn random_token(byte_length: usize) -> String {
    random_token_with_rng(byte_length, getrandom::getrandom)
}

fn random_token_with_rng(
    byte_length: usize,
    fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>,
) -> String {
    let mut bytes = vec![0u8; byte_length];
    fill(&mut bytes).expect("secure randomness is unavailable");
    base64url_encode(&bytes)
}

pub fn generate_pkce() -> (String, String) {
    let verifier = random_token(48);
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

pub fn pkce_challenge(code_verifier: &str) -> String {
    base64url_encode(Sha256::digest(code_verifier.as_bytes()).as_slice())
}

pub fn sanitize_return_to(origin: &Url, value: Option<&str>, fallback: &str) -> String {
    value
        .filter(|input| !input.is_empty())
        .and_then(|input| same_origin_return_path(origin, input))
        .or_else(|| same_origin_return_path(origin, fallback))
        .unwrap_or_else(|| "/".to_owned())
}

fn same_origin_return_path(origin: &Url, candidate: &str) -> Option<String> {
    let url = origin.join(candidate).ok()?;
    if url.origin() != origin.origin() || url.path().starts_with("//") {
        // A same-origin absolute URL may still have a //host path. Returning
        // that path as a Location or re-joining it would redirect off origin.
        return None;
    }
    Some(format!(
        "{}{}{}",
        url.path(),
        url.query().map(|q| format!("?{q}")).unwrap_or_default(),
        url.fragment().map(|f| format!("#{f}")).unwrap_or_default()
    ))
}

pub fn absolute_return_to(origin: &Url, value: Option<&str>, fallback: &str) -> Url {
    let sanitized = sanitize_return_to(origin, value, fallback);
    origin.join(&sanitized).unwrap_or_else(|_| origin.clone())
}

pub fn seal_auth_state(state: &AuthState, secret: &[u8]) -> Result<String, AuthError> {
    let body = base64url_encode(
        serde_json::to_string(state)
            .map_err(|_| AuthError::InvalidJson)?
            .as_bytes(),
    );
    let signature = hmac_sha256(secret, &body);
    Ok(format!("{body}.{signature}"))
}

pub fn unseal_auth_state(value: &str, secret: &[u8]) -> Result<AuthState, AuthError> {
    let (body, signature) = value.rsplit_once('.').ok_or(AuthError::InvalidToken)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AuthError::InvalidSignature)?;
    let mut mac = HmacSha256::new_from_slice(secret).expect("invalid HMAC key length");
    mac.update(body.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| AuthError::InvalidSignature)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| AuthError::InvalidToken)?;
    serde_json::from_slice(&decoded).map_err(|_| AuthError::InvalidJson)
}

pub fn serialize_cookie(spec: CookieSpec) -> String {
    let mut parts = vec![format!(
        "{}={}",
        spec.name,
        urlencoding::encode(&spec.value)
    )];
    parts.push(format!("Path={}", spec.options.path));
    if let Some(domain) = spec.options.domain.as_deref() {
        let domain = domain.trim_start_matches('.');
        if !domain.is_empty() {
            parts.push(format!("Domain={domain}"));
        }
    }
    if let Some(max_age) = spec.options.max_age {
        parts.push(format!("Max-Age={}", max_age.max(0)));
    }
    if spec.options.http_only {
        parts.push("HttpOnly".to_string());
    }
    if let Some(same_site) = spec.options.same_site.as_deref() {
        parts.push(format!("SameSite={same_site}"));
    }
    if spec.options.secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

pub fn expire_cookie(name: &str, options: CookieOptions) -> String {
    serialize_cookie(CookieSpec {
        name: name.to_string(),
        value: String::new(),
        options: CookieOptions {
            max_age: Some(0),
            http_only: options.http_only,
            same_site: options.same_site.or_else(|| Some("None".to_string())),
            secure: options.secure,
            domain: options.domain,
            path: if options.path.is_empty() {
                "/".to_string()
            } else {
                options.path
            },
        },
    })
}

pub fn parse_cookie_header(header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for segment in header.split(';') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let Some((name, raw_value)) = segment.split_once('=') else {
            continue;
        };
        let value = urlencoding::decode(raw_value)
            .map(|decoded| decoded.into_owned())
            .unwrap_or_else(|_| raw_value.to_string());
        cookies.insert(name.trim().to_string(), value);
    }
    cookies
}

pub fn append_query(url: &Url, pairs: &[(&str, &str)]) -> Url {
    let mut url = url.clone();
    {
        let mut qp = url.query_pairs_mut();
        for (key, value) in pairs {
            if !value.is_empty() {
                qp.append_pair(key, value);
            }
        }
    }
    url
}

pub fn cookie_domain_for_host(hostname: &str) -> Option<String> {
    let host = hostname.to_lowercase();
    if host == "yl.vin" || host.ends_with(".yl.vin") {
        Some(".yl.vin".to_string())
    } else {
        None
    }
}

fn base64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hmac_sha256(secret: &[u8], value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("invalid HMAC key length");
    mac.update(value.as_bytes());
    let digest = mac.finalize().into_bytes();
    base64url_encode(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> &'static [u8] {
        b"test-secret"
    }

    #[test]
    fn cookies_match_js_fixture() {
        let state_cookie = serialize_cookie(CookieSpec {
            name: "yl_auth_state".to_string(),
            value: "VALUE".to_string(),
            options: CookieOptions {
                path: "/".to_string(),
                domain: None,
                max_age: Some(600),
                http_only: true,
                same_site: Some("None".to_string()),
                secure: true,
            },
        });
        assert_eq!(
            state_cookie,
            "yl_auth_state=VALUE; Path=/; Max-Age=600; HttpOnly; SameSite=None; Secure"
        );

        let session_cookie = serialize_cookie(CookieSpec {
            name: "yl_auth_session".to_string(),
            value: "session".to_string(),
            options: CookieOptions {
                path: "/".to_string(),
                domain: Some(".yl.vin".to_string()),
                max_age: Some(604800),
                http_only: true,
                same_site: Some("None".to_string()),
                secure: true,
            },
        });
        assert_eq!(
            session_cookie,
            "yl_auth_session=session; Path=/; Domain=yl.vin; Max-Age=604800; HttpOnly; SameSite=None; Secure"
        );
    }

    #[test]
    fn seal_and_unseal_match_js_fixture() {
        let payload = AuthState {
            state: "abc123".to_string(),
            return_to: "/play?x=1".to_string(),
            expires_at: 1_700_000_000,
        };
        let token = seal_auth_state(&payload, secret()).unwrap();
        assert_eq!(
            token,
            "eyJzdGF0ZSI6ImFiYzEyMyIsInJldHVyblRvIjoiL3BsYXk_eD0xIiwiZXhwaXJlc0F0IjoxNzAwMDAwMDAwfQ.e-wrRRHp12VFARhR_GIG0rq5qXuFn6L9kJQBnsNuM5U"
        );
        assert_eq!(unseal_auth_state(&token, secret()).unwrap(), payload);
    }

    #[test]
    #[should_panic(expected = "secure randomness is unavailable")]
    fn unavailable_randomness_never_produces_a_token() {
        random_token_with_rng(48, |_| Err(getrandom::Error::UNSUPPORTED));
    }

    #[test]
    fn auth_state_rejects_forged_or_malformed_signatures() {
        let state = AuthState {
            state: "state".into(),
            return_to: "/private".into(),
            expires_at: 1_700_000_000,
        };
        let token = seal_auth_state(&state, secret()).unwrap();
        let (body, _) = token.rsplit_once('.').unwrap();
        for signature in [
            URL_SAFE_NO_PAD.encode([0; 32]),
            URL_SAFE_NO_PAD.encode([0; 31]),
            "!malformed".into(),
        ] {
            assert_eq!(
                unseal_auth_state(&format!("{body}.{signature}"), secret()),
                Err(AuthError::InvalidSignature)
            );
        }
        assert_eq!(
            unseal_auth_state(&token, b"wrong-secret"),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn return_to_helpers_match_js_fixture() {
        let origin = Url::parse("https://yl.vin").unwrap();
        assert_eq!(
            sanitize_return_to(&origin, Some("https://yl.vin/play?x=1#y"), "/"),
            "/play?x=1#y"
        );
        assert_eq!(
            sanitize_return_to(&origin, Some("https://evil.example/x"), "/fallback"),
            "/fallback"
        );
        assert_eq!(
            absolute_return_to(&origin, Some("/play"), "/").to_string(),
            "https://yl.vin/play"
        );
        let appended = append_query(
            &Url::parse("https://yl.vin/path?a=1").unwrap(),
            &[("b", "2"), ("c", "")],
        );
        assert_eq!(appended.to_string(), "https://yl.vin/path?a=1&b=2");
    }

    #[test]
    fn same_origin_urls_cannot_be_reinterpreted_as_external_redirects() {
        let origin = Url::parse("https://app.example").unwrap();
        for candidate in [
            "https://app.example//evil.example/path",
            "https://app.example///evil.example/path",
            "https://app.example/\\evil.example/path",
        ] {
            assert_eq!(
                sanitize_return_to(&origin, Some(candidate), "/safe"),
                "/safe",
                "{candidate}"
            );
            let target = absolute_return_to(&origin, Some(candidate), "/safe");
            assert_eq!(target.origin(), origin.origin(), "{candidate}");
            assert_eq!(target.path(), "/safe");
        }
        assert_eq!(sanitize_return_to(&origin, None, "//evil.example"), "/");
        assert_eq!(
            absolute_return_to(&origin, Some("https://evil.example"), "//evil.example").origin(),
            origin.origin()
        );
    }
}
