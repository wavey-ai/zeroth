//! Read-only Google Workspace roster adapter. Transport and credential lookup
//! are independent from storage/lifecycle application, for Worker/native hosts.
//! No directory mutation is performed before a complete validated result exists.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
};

pub(super) const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub(super) const DIRECTORY_ENDPOINT: &str = "https://admin.googleapis.com/admin/directory/v1/users";
pub(super) const READ_SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_PRINCIPALS: usize = 10_000;
const MAX_PAGES: usize = 100;
const MAX_CONFIRMATIONS: usize = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DirectoryError(pub &'static str);
impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for DirectoryError {}

#[derive(Clone, Debug)]
pub(super) struct DirectoryConfig {
    pub customer_id: String,
    pub delegated_admin_email: String,
    pub service_account_secret_binding: String,
}

impl DirectoryConfig {
    pub fn validate(&self) -> Result<(), DirectoryError> {
        validate_customer_id(&self.customer_id)?;
        validate_email(&self.delegated_admin_email)?;
        validate_binding(&self.service_account_secret_binding)?;
        Ok(())
    }
}

pub(super) fn validate_customer_id(value: &str) -> Result<(), DirectoryError> {
    if !value.starts_with('C')
        || !(3..=64).contains(&value.len())
        || !value.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        Err(DirectoryError("invalid_customer_id"))
    } else {
        Ok(())
    }
}
pub(super) fn validate_binding(value: &str) -> Result<(), DirectoryError> {
    let middle = value
        .strip_prefix("TENANT_")
        .and_then(|s| s.strip_suffix("_GOOGLE_DIRECTORY_SERVICE_ACCOUNT"));
    if value.len() > 128
        || middle.is_none_or(|s| s.is_empty())
        || !value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        Err(DirectoryError("invalid_service_account_binding"))
    } else {
        Ok(())
    }
}

// Never Debug/Serialize this type: it contains a private key.
pub(super) struct ServiceAccountKey {
    pub private_key_id: String,
    pub client_email: String,
    pub private_key: String,
}

impl ServiceAccountKey {
    pub fn parse(secret: &str) -> Result<Self, DirectoryError> {
        #[derive(Deserialize)]
        struct KeyFile {
            r#type: String,
            private_key_id: String,
            client_email: String,
            private_key: String,
            #[serde(default)]
            token_uri: Option<String>,
        }
        if secret.len() > 32 * 1024 {
            return Err(DirectoryError("invalid_service_account_key"));
        }
        let key: KeyFile = serde_json::from_str(secret)
            .map_err(|_| DirectoryError("invalid_service_account_key"))?;
        if key.r#type != "service_account"
            || key
                .token_uri
                .as_deref()
                .is_some_and(|s| s != TOKEN_ENDPOINT)
            || key.private_key_id.is_empty()
            || key.private_key_id.len() > 128
            || !key
                .private_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || !key.client_email.ends_with(".gserviceaccount.com")
            || !key.private_key.starts_with("-----BEGIN PRIVATE KEY-----")
            || key.private_key.len() > 16 * 1024
        {
            return Err(DirectoryError("invalid_service_account_key"));
        }
        validate_email(&key.client_email)
            .map_err(|_| DirectoryError("invalid_service_account_key"))?;
        Ok(Self {
            private_key_id: key.private_key_id,
            client_email: key.client_email,
            private_key: key.private_key,
        })
    }
}

pub(super) trait CredentialProvider {
    fn load(
        &self,
        binding: &str,
    ) -> impl Future<Output = Result<ServiceAccountKey, DirectoryError>>;
}

pub(super) struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}
pub(super) trait DirectoryTransport {
    fn request(
        &self,
        url: &str,
        form: Option<&str>,
        bearer: Option<&str>,
    ) -> impl Future<Output = Result<HttpReply, DirectoryError>>;
    fn sign(
        &self,
        key: &ServiceAccountKey,
        input: &str,
    ) -> impl Future<Output = Result<Vec<u8>, DirectoryError>>;
}

#[derive(Clone, Debug)]
pub(super) struct DirectoryPrincipal {
    pub id: String,
    pub primary_email: String,
    pub active: bool,
    pub deleted: bool,
}

pub(super) struct VerifiedSnapshot {
    principals: Vec<DirectoryPrincipal>,
}
impl VerifiedSnapshot {
    pub fn into_principals(self) -> Vec<DirectoryPrincipal> {
        self.principals
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleUser {
    id: String,
    #[serde(default)]
    primary_email: Option<String>,
    #[serde(default)]
    customer_id: Option<String>,
    #[serde(default)]
    suspended: bool,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    is_admin: Option<bool>,
    #[serde(default)]
    deletion_time: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GooglePage {
    #[serde(default)]
    users: Vec<GoogleUser>,
    #[serde(default)]
    next_page_token: Option<String>,
}

pub(super) fn validate_email(value: &str) -> Result<(), DirectoryError> {
    let valid = value.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && !domain.is_empty()
            && !domain.contains('@')
            && domain.contains('.')
            && local.len() <= 64
            && value
                .bytes()
                .all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>' | b'"' | b'\\'))
    });
    if value.len() > 254 || !valid {
        Err(DirectoryError("invalid_delegated_admin_email"))
    } else {
        Ok(())
    }
}
fn validate_id(value: &str) -> Result<(), DirectoryError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        Err(DirectoryError("invalid_directory_user_id"))
    } else {
        Ok(())
    }
}

fn parse_body<T: serde::de::DeserializeOwned>(
    body: &[u8],
    code: &'static str,
) -> Result<T, DirectoryError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(DirectoryError("google_response_too_large"));
    }
    serde_json::from_slice(body).map_err(|_| DirectoryError(code))
}

pub(super) fn assertion_input(
    key: &ServiceAccountKey,
    config: &DirectoryConfig,
    now: i64,
) -> Result<String, DirectoryError> {
    config.validate()?;
    if now < 0 || now > i64::MAX - 3600 {
        return Err(DirectoryError("invalid_clock"));
    }
    let header = serde_json::to_vec(
        &serde_json::json!({"alg":"RS256","typ":"JWT","kid":key.private_key_id}),
    )
    .map_err(|_| DirectoryError("assertion_encoding_failed"))?;
    let claims = serde_json::to_vec(
        &serde_json::json!({"iss":key.client_email,"sub":config.delegated_admin_email,
        "aud":TOKEN_ENDPOINT,"scope":READ_SCOPE,"iat":now,"exp":now+3600}),
    )
    .map_err(|_| DirectoryError("assertion_encoding_failed"))?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    ))
}

async fn access_token<T: DirectoryTransport, C: CredentialProvider>(
    transport: &T,
    credentials: &C,
    config: &DirectoryConfig,
    now: i64,
) -> Result<String, DirectoryError> {
    let key = credentials
        .load(&config.service_account_secret_binding)
        .await?;
    let input = assertion_input(&key, config, now)?;
    let signature = transport.sign(&key, &input).await?;
    let assertion = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        .append_pair("assertion", &assertion)
        .finish();
    let response = transport.request(TOKEN_ENDPOINT, Some(&body), None).await?;
    if response.status != 200 {
        return Err(DirectoryError("service_account_token_failed"));
    }
    #[derive(Deserialize)]
    struct Token {
        access_token: String,
        token_type: String,
        expires_in: i64,
    }
    let token: Token = parse_body(&response.body, "invalid_token_response")?;
    if !token.token_type.eq_ignore_ascii_case("Bearer")
        || !(60..=3600).contains(&token.expires_in)
        || token.access_token.is_empty()
        || token.access_token.len() > 16 * 1024
        || !token.access_token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(DirectoryError("invalid_token_response"));
    }
    Ok(token.access_token)
}

fn user_url(key: &str) -> String {
    let mut url = url::Url::parse(DIRECTORY_ENDPOINT).expect("fixed Google endpoint");
    url.path_segments_mut()
        .expect("fixed URL supports path segments")
        .push(key);
    url.query_pairs_mut()
        .append_pair("projection", "full")
        .append_pair("viewType", "admin_view")
        .append_pair(
            "fields",
            "id,primaryEmail,customerId,suspended,archived,isAdmin,deletionTime",
        );
    url.into()
}

fn principal(
    user: GoogleUser,
    customer: &str,
    deleted: bool,
) -> Result<DirectoryPrincipal, DirectoryError> {
    validate_id(&user.id)?;
    if user.customer_id.as_deref().is_some_and(|id| id != customer)
        || (!deleted && user.customer_id.as_deref() != Some(customer))
    {
        return Err(DirectoryError("directory_customer_mismatch"));
    }
    let email = user.primary_email.unwrap_or_default();
    if !email.is_empty() {
        validate_email(&email).map_err(|_| DirectoryError("invalid_directory_user"))?;
    }
    if !deleted && email.is_empty() {
        return Err(DirectoryError("incomplete_directory_user"));
    }
    // Google's official generated client models these flags as bools with
    // false defaults. Empty optional timestamps are not deletion evidence.
    let removed = deleted
        || user
            .deletion_time
            .as_deref()
            .is_some_and(|value| !value.is_empty());
    Ok(DirectoryPrincipal {
        id: user.id,
        primary_email: email,
        active: !removed && !user.suspended && !user.archived,
        deleted: removed,
    })
}

async fn scan<T: DirectoryTransport>(
    transport: &T,
    config: &DirectoryConfig,
    token: &str,
    deleted: bool,
) -> Result<BTreeMap<String, DirectoryPrincipal>, DirectoryError> {
    let mut result = BTreeMap::new();
    let mut page_token: Option<String> = None;
    let mut seen = BTreeSet::new();
    for _ in 0..MAX_PAGES {
        let mut url = url::Url::parse(DIRECTORY_ENDPOINT).expect("fixed Google endpoint");
        url.query_pairs_mut()
            .append_pair("customer", &config.customer_id)
            .append_pair("maxResults", "500")
            .append_pair("projection", "full")
            .append_pair("viewType", "admin_view")
            .append_pair("showDeleted", if deleted { "true" } else { "false" })
            .append_pair(
                "fields",
                "users(id,primaryEmail,customerId,suspended,archived,deletionTime),nextPageToken",
            );
        if let Some(page) = &page_token {
            url.query_pairs_mut().append_pair("pageToken", page);
        }
        let reply = transport.request(url.as_str(), None, Some(token)).await?;
        if reply.status != 200 {
            return Err(DirectoryError("directory_list_failed"));
        }
        let page: GooglePage = parse_body(&reply.body, "invalid_directory_page")?;
        if page.users.len() > 500 {
            return Err(DirectoryError("directory_page_too_large"));
        }
        for user in page.users {
            let user = principal(user, &config.customer_id, deleted)?;
            if result.insert(user.id.clone(), user).is_some() {
                return Err(DirectoryError("duplicate_directory_user"));
            }
            if result.len() > MAX_PRINCIPALS {
                return Err(DirectoryError("directory_limit_exceeded"));
            }
        }
        match page.next_page_token {
            None => return Ok(result),
            Some(next)
                if next.is_empty()
                    || next.len() > 4096
                    || !next.bytes().all(|b| b.is_ascii_graphic())
                    || !seen.insert(next.clone()) =>
            {
                return Err(DirectoryError("invalid_directory_pagination"));
            }
            Some(next) => page_token = Some(next),
        }
    }
    Err(DirectoryError("directory_limit_exceeded"))
}

async fn verify_admin<T: DirectoryTransport>(
    transport: &T,
    config: &DirectoryConfig,
    token: &str,
) -> Result<String, DirectoryError> {
    let admin = transport
        .request(&user_url(&config.delegated_admin_email), None, Some(token))
        .await?;
    if admin.status != 200 {
        return Err(DirectoryError("admin_preflight_failed"));
    }
    let admin: GoogleUser = parse_body(&admin.body, "admin_preflight_failed")?;
    if admin.customer_id.as_deref() != Some(config.customer_id.as_str()) {
        return Err(DirectoryError("directory_customer_mismatch"));
    }
    if admin.is_admin != Some(true)
        || admin.suspended
        || admin.archived
        || admin
            .deletion_time
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        return Err(DirectoryError("super_admin_required"));
    }
    validate_id(&admin.id)?;
    Ok(admin.id)
}

/// Read-only proof phase. Google does not document snapshot isolation across
/// pages; missing previously known IDs receive individual lookups after both
/// scans. Any error returns no snapshot and must cause no lifecycle mutation.
pub(super) async fn collect<T: DirectoryTransport, C: CredentialProvider>(
    transport: &T,
    credentials: &C,
    config: &DirectoryConfig,
    known_ids: &[String],
    now: i64,
) -> Result<VerifiedSnapshot, DirectoryError> {
    config.validate()?;
    let token = access_token(transport, credentials, config, now).await?;
    let admin_id = verify_admin(transport, config, &token).await?;
    let mut users = scan(transport, config, &token, false).await?;
    if users.is_empty() || !users.get(&admin_id).is_some_and(|user| user.active) {
        return Err(DirectoryError("empty_or_incomplete_directory"));
    }
    let deleted = scan(transport, config, &token, true).await?;
    for (id, user) in deleted {
        if users.insert(id, user).is_some() {
            return Err(DirectoryError("directory_changed_during_scan"));
        }
    }
    let mut confirmations = 0;
    for id in known_ids {
        validate_id(id)?;
        if users.contains_key(id) {
            continue;
        }
        confirmations += 1;
        if confirmations > MAX_CONFIRMATIONS {
            return Err(DirectoryError("directory_confirmation_limit"));
        }
        let reply = transport.request(&user_url(id), None, Some(&token)).await?;
        let user = match reply.status {
            404 => DirectoryPrincipal {
                id: id.clone(),
                primary_email: String::new(),
                active: false,
                deleted: true,
            },
            200 => {
                let user: GoogleUser = parse_body(&reply.body, "invalid_directory_user")?;
                if user.id != *id {
                    return Err(DirectoryError("directory_identity_mismatch"));
                }
                principal(user, &config.customer_id, false)?
            }
            _ => return Err(DirectoryError("directory_confirmation_failed")),
        };
        users.insert(id.clone(), user);
    }
    if users.len() > MAX_PRINCIPALS {
        return Err(DirectoryError("directory_limit_exceeded"));
    }
    // A role loss during pagination must not make formerly visible users look
    // deleted. Check the same directory administrator again before accepting
    // any absence proof; errors leave the entire result unapplied.
    if verify_admin(transport, config, &token).await? != admin_id {
        return Err(DirectoryError("directory_changed_during_scan"));
    }
    Ok(VerifiedSnapshot {
        principals: users.into_values().collect(),
    })
}

pub(super) fn pkcs8_der(key: &ServiceAccountKey) -> Result<Vec<u8>, DirectoryError> {
    let text = key
        .private_key
        .strip_prefix("-----BEGIN PRIVATE KEY-----")
        .and_then(|s| s.trim().strip_suffix("-----END PRIVATE KEY-----"))
        .ok_or(DirectoryError("invalid_service_account_key"))?;
    let encoded: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(encoded)
        .map_err(|_| DirectoryError("invalid_service_account_key"))
}

pub(super) fn validate_request_url(value: &str, post: bool) -> Result<(), DirectoryError> {
    let url = url::Url::parse(value).map_err(|_| DirectoryError("invalid_google_endpoint"))?;
    let valid = if post {
        value == TOKEN_ENDPOINT
    } else {
        url.host_str() == Some("admin.googleapis.com")
            && (url.path() == "/admin/directory/v1/users"
                || url.path().starts_with("/admin/directory/v1/users/"))
    };
    if !valid
        || url.scheme() != "https"
        || url.port().is_some_and(|port| port != 443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(DirectoryError("invalid_google_endpoint"));
    }
    Ok(())
}

#[cfg(all(not(target_arch = "wasm32"), feature = "google-directory-native"))]
pub(super) struct NativeHttpTransport {
    client: reqwest::Client,
}
#[cfg(all(not(target_arch = "wasm32"), feature = "google-directory-native"))]
impl NativeHttpTransport {
    pub fn new() -> Result<Self, DirectoryError> {
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|_| DirectoryError("native_transport_configuration"))?,
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn native_sign(key: &ServiceAccountKey, input: &str) -> Result<Vec<u8>, DirectoryError> {
    use rsa::{
        pkcs8::DecodePrivateKey,
        signature::{RandomizedSigner, SignatureEncoding},
        traits::PublicKeyParts,
    };
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(&key.private_key)
        .map_err(|_| DirectoryError("invalid_service_account_key"))?;
    if private.n().bits() < 2048 {
        return Err(DirectoryError("weak_service_account_key"));
    }
    let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
    Ok(signing
        .sign_with_rng(&mut rsa::rand_core::OsRng, input.as_bytes())
        .to_vec())
}

#[cfg(all(not(target_arch = "wasm32"), feature = "google-directory-native"))]
impl DirectoryTransport for NativeHttpTransport {
    async fn request(
        &self,
        url: &str,
        form: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<HttpReply, DirectoryError> {
        validate_request_url(url, form.is_some())?;
        let mut request = if let Some(form) = form {
            self.client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form.to_owned())
        } else {
            self.client.get(url)
        };
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| DirectoryError("google_transport_failed"))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(DirectoryError("google_redirect_rejected"));
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
        {
            return Err(DirectoryError("google_response_too_large"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| DirectoryError("google_transport_failed"))?
        {
            if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                return Err(DirectoryError("google_response_too_large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(HttpReply {
            status,
            body: bytes,
        })
    }
    async fn sign(&self, key: &ServiceAccountKey, input: &str) -> Result<Vec<u8>, DirectoryError> {
        native_sign(key, input)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) struct EnvironmentCredentials;
#[cfg(not(target_arch = "wasm32"))]
impl CredentialProvider for EnvironmentCredentials {
    async fn load(&self, binding: &str) -> Result<ServiceAccountKey, DirectoryError> {
        validate_binding(binding)?;
        let value =
            std::env::var(binding).map_err(|_| DirectoryError("service_account_not_configured"))?;
        ServiceAccountKey::parse(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };

    fn config() -> DirectoryConfig {
        DirectoryConfig {
            customer_id: "C012345".into(),
            delegated_admin_email: "admin@acme.example".into(),
            service_account_secret_binding: "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT".into(),
        }
    }
    fn key() -> ServiceAccountKey {
        ServiceAccountKey {
            private_key_id: "fixture-key".into(),
            client_email: "directory@fixture.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN PRIVATE KEY-----\nZml4dHVyZQ==\n-----END PRIVATE KEY-----"
                .into(),
        }
    }
    fn user(id: &str) -> serde_json::Value {
        serde_json::json!({"id":id,"customerId":"C012345","primaryEmail":format!("user{id}@acme.example"),"suspended":false,"archived":false})
    }
    fn admin() -> serde_json::Value {
        let mut user = user("1");
        user["isAdmin"] = true.into();
        user
    }
    fn reply(value: serde_json::Value) -> HttpReply {
        HttpReply {
            status: 200,
            body: serde_json::to_vec(&value).unwrap(),
        }
    }
    fn token() -> HttpReply {
        reply(
            serde_json::json!({"access_token":"fixture-access-token","token_type":"Bearer","expires_in":3600}),
        )
    }
    struct Credentials(Cell<usize>);
    impl CredentialProvider for Credentials {
        async fn load(&self, _: &str) -> Result<ServiceAccountKey, DirectoryError> {
            self.0.set(self.0.get() + 1);
            Ok(key())
        }
    }
    struct Fake {
        responses: RefCell<VecDeque<HttpReply>>,
        requests: RefCell<Vec<(String, bool, bool)>>,
    }
    impl Fake {
        fn new(responses: Vec<HttpReply>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }
    impl DirectoryTransport for Fake {
        async fn request(
            &self,
            url: &str,
            form: Option<&str>,
            bearer: Option<&str>,
        ) -> Result<HttpReply, DirectoryError> {
            validate_request_url(url, form.is_some())?;
            self.requests
                .borrow_mut()
                .push((url.into(), form.is_some(), bearer.is_some()));
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or(DirectoryError("unexpected_test_request"))
        }
        async fn sign(&self, _: &ServiceAccountKey, _: &str) -> Result<Vec<u8>, DirectoryError> {
            Ok(vec![1, 2, 3])
        }
    }
    fn run<T>(future: impl Future<Output = T>) -> T {
        future.now_or_never().expect("mock transport never waits")
    }
    fn error(fake: &Fake, known: &[String]) -> DirectoryError {
        match run(collect(
            fake,
            &Credentials(Cell::new(0)),
            &config(),
            known,
            100,
        )) {
            Ok(_) => panic!("unsafe snapshot accepted"),
            Err(error) => error,
        }
    }

    #[test]
    fn complete_pagination_and_missing_id_confirmation_produce_only_verified_states() {
        let mut suspended = user("3");
        suspended["suspended"] = true.into();
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")],"nextPageToken":"next"})),
            reply(serde_json::json!({"users":[user("2"),suspended]})),
            reply(serde_json::json!({"users":[{"id":"4","primaryEmail":"deleted@acme.example"}]})),
            HttpReply {
                status: 404,
                body: vec![],
            },
            reply(user("6")),
            reply(admin()),
        ]);
        let snapshot = run(collect(
            &fake,
            &Credentials(Cell::new(0)),
            &config(),
            &["5".into(), "6".into()],
            100,
        ))
        .unwrap()
        .into_principals();
        assert_eq!(snapshot.len(), 6);
        for id in ["1", "2", "6"] {
            assert!(snapshot.iter().find(|u| u.id == id).unwrap().active);
        }
        for id in ["3", "4", "5"] {
            assert!(!snapshot.iter().find(|u| u.id == id).unwrap().active);
        }
        assert!(snapshot.iter().find(|u| u.id == "4").unwrap().deleted);
        let requests = fake.requests.borrow();
        assert_eq!(requests.len(), 8);
        assert!(requests[2].0.contains("customer=C012345"));
        assert!(requests[2].0.contains("viewType=admin_view"));
        assert!(!requests[2].0.contains("domain="));
        assert!(requests[3].0.contains("pageToken=next"));
        assert!(requests[4].0.contains("showDeleted=true"));
        assert!(requests[5].0.contains("/users/5?"));
    }

    #[test]
    fn errors_on_later_pages_or_absence_confirmation_return_no_partial_snapshot() {
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")],"nextPageToken":"next"})),
            HttpReply {
                status: 503,
                body: vec![],
            },
        ]);
        assert_eq!(error(&fake, &[]), DirectoryError("directory_list_failed"));
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")]})),
            reply(serde_json::json!({"users":[]})),
            HttpReply {
                status: 403,
                body: vec![],
            },
        ]);
        assert_eq!(
            error(&fake, &["missing".into()]),
            DirectoryError("directory_confirmation_failed")
        );
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")]})),
            reply(serde_json::json!({})),
            reply(user("another_id")),
        ]);
        assert_eq!(
            error(&fake, &["missing".into()]),
            DirectoryError("directory_identity_mismatch")
        );
    }

    #[test]
    fn verifies_full_customer_and_super_admin_visibility_before_scanning() {
        let mut wrong = admin();
        wrong["customerId"] = "CWRONG".into();
        let fake = Fake::new(vec![token(), reply(wrong)]);
        assert_eq!(
            error(&fake, &[]),
            DirectoryError("directory_customer_mismatch")
        );
        let mut limited = admin();
        limited["isAdmin"] = false.into();
        let fake = Fake::new(vec![token(), reply(limited)]);
        assert_eq!(error(&fake, &[]), DirectoryError("super_admin_required"));
        for users in [serde_json::json!([]), serde_json::json!([user("2")])] {
            let fake = Fake::new(vec![
                token(),
                reply(admin()),
                reply(serde_json::json!({"users":users})),
            ]);
            assert_eq!(
                error(&fake, &[]),
                DirectoryError("empty_or_incomplete_directory")
            );
        }
    }

    #[test]
    fn privilege_loss_during_scan_cannot_turn_hidden_users_into_deletions() {
        for last in [
            {
                let mut limited = admin();
                limited["isAdmin"] = false.into();
                reply(limited)
            },
            HttpReply {
                status: 403,
                body: Vec::new(),
            },
        ] {
            let fake = Fake::new(vec![
                token(),
                reply(admin()),
                reply(serde_json::json!({"users":[user("1")]})),
                reply(serde_json::json!({})),
                HttpReply {
                    status: 404,
                    body: Vec::new(),
                },
                last,
            ]);
            assert!(matches!(
                error(&fake, &["missing".into()]),
                DirectoryError("super_admin_required" | "admin_preflight_failed")
            ));
        }
    }

    #[test]
    fn omitted_default_flags_and_empty_timestamp_follow_google_resource_semantics() {
        let mut admin = admin();
        admin.as_object_mut().unwrap().remove("archived");
        let user = serde_json::json!({"id":"1","customerId":"C012345","primaryEmail":"admin@acme.example","deletionTime":""});
        let fake = Fake::new(vec![
            token(),
            reply(admin.clone()),
            reply(serde_json::json!({"users":[user]})),
            reply(serde_json::json!({})),
            reply(admin),
        ]);
        let users = run(collect(
            &fake,
            &Credentials(Cell::new(0)),
            &config(),
            &[],
            100,
        ))
        .unwrap()
        .into_principals();
        assert!(users[0].active);
        assert!(!users[0].deleted);
        let invalid = serde_json::json!({"id":"1","suspended":"false"});
        assert!(serde_json::from_value::<GoogleUser>(invalid).is_err());
    }

    #[test]
    fn rejects_duplicate_users_repeated_tokens_and_mixed_customer_pages() {
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")],"nextPageToken":"repeat"})),
            reply(serde_json::json!({"users":[user("2")],"nextPageToken":"repeat"})),
        ]);
        assert_eq!(
            error(&fake, &[]),
            DirectoryError("invalid_directory_pagination")
        );
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1"),user("1")]})),
        ]);
        assert_eq!(
            error(&fake, &[]),
            DirectoryError("duplicate_directory_user")
        );
        let mut wrong = user("2");
        wrong["customerId"] = "CWRONG".into();
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1"),wrong]})),
        ]);
        assert_eq!(
            error(&fake, &[]),
            DirectoryError("directory_customer_mismatch")
        );
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")]})),
            reply(serde_json::json!({"users":[{"id":"1"}]})),
        ]);
        assert_eq!(
            error(&fake, &[]),
            DirectoryError("directory_changed_during_scan")
        );
    }

    #[test]
    fn signed_assertions_have_fixed_google_audience_scope_and_delegated_subject() {
        let input = assertion_input(&key(), &config(), 123).unwrap();
        let (header, claims) = input.split_once('.').unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(claims["aud"], TOKEN_ENDPOINT);
        assert_eq!(claims["scope"], READ_SCOPE);
        assert_eq!(claims["sub"], "admin@acme.example");
        assert_eq!(claims["iat"], 123);
        assert_eq!(claims["exp"], 3723);
        let credentials = Credentials(Cell::new(0));
        let fake = Fake::new(vec![
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")]})),
            reply(serde_json::json!({})),
            reply(admin()),
            token(),
            reply(admin()),
            reply(serde_json::json!({"users":[user("1")]})),
            reply(serde_json::json!({})),
            reply(admin()),
        ]);
        for now in [100, 4000] {
            run(collect(&fake, &credentials, &config(), &[], now)).unwrap();
        }
        assert_eq!(credentials.0.get(), 2);
        assert_eq!(
            fake.requests
                .borrow()
                .iter()
                .filter(|(_, post, _)| *post)
                .count(),
            2
        );
    }

    #[test]
    fn endpoints_credentials_and_response_sizes_are_bounded_and_never_redirectable() {
        for url in [
            "http://admin.googleapis.com/admin/directory/v1/users",
            "https://admin.googleapis.com.evil/admin/directory/v1/users",
            "https://user:secret@admin.googleapis.com/admin/directory/v1/users",
            "https://admin.googleapis.com/admin/directory/v1/groups",
        ] {
            assert!(validate_request_url(url, false).is_err());
        }
        for binding in [
            "JWT_ES256_PRIVATE_KEY",
            "TENANT__GOOGLE_DIRECTORY_SERVICE_ACCOUNT",
            "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT=secret",
        ] {
            assert!(validate_binding(binding).is_err());
        }
        assert!(validate_customer_id("my_customer").is_err());
        let value = serde_json::json!({"type":"service_account","private_key_id":"fixture-key","client_email":"directory@fixture.iam.gserviceaccount.com","private_key":key().private_key,"token_uri":"https://evil.example/token"});
        assert!(ServiceAccountKey::parse(&value.to_string()).is_err());
        assert!(
            ServiceAccountKey::parse(r#"{"type":"authorized_user","access_token":"static"}"#)
                .is_err()
        );
        assert_eq!(
            parse_body::<serde_json::Value>(&vec![b' '; MAX_RESPONSE_BYTES + 1], "parse_failed")
                .unwrap_err(),
            DirectoryError("google_response_too_large")
        );
    }

    #[test]
    fn native_rs256_signing_uses_pkcs8_and_verifies_with_standard_rsa() {
        use rsa::{
            pkcs8::{EncodePrivateKey, LineEnding},
            signature::Verifier,
        };
        let private = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let public = rsa::RsaPublicKey::from(&private);
        let mut key = key();
        key.private_key = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let input = assertion_input(&key, &config(), 123).unwrap();
        let signature = native_sign(&key, &input).unwrap();
        let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap();
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public)
            .verify(input.as_bytes(), &signature)
            .unwrap();
        assert!(!pkcs8_der(&key).unwrap().is_empty());
    }
}
