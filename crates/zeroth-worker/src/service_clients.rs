//! Machine identities have their own registry, assertion replay ledger and token records.
use super::*;
#[cfg(any(test, target_arch = "wasm32"))]
use zeroth_machine::build_service_access_token_claims;
use zeroth_machine::{
    verify_service_access_token, ServiceAccessTokenValidation, ServiceClient, ServiceJwks,
};
#[cfg(target_arch = "wasm32")]
use zeroth_machine::{
    verify_service_client_assertion, ServiceAssertionValidation, ServiceTokenResponse,
};

const MAX_BODY: usize = 64 * 1024;
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const COLUMNS: &str = "id,tenant_id,name,audiences_json,scopes_json,public_jwks_json,disabled,revision,token_ttl_seconds,created_at,updated_at";
const UPSERT_SQL: &str = "INSERT INTO zeroth_service_clients
 (id,tenant_id,name,audiences_json,scopes_json,public_jwks_json,disabled,revision,token_ttl_seconds,created_at,updated_at)
 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)
 ON CONFLICT(id) DO UPDATE SET name=excluded.name,audiences_json=excluded.audiences_json,
 scopes_json=excluded.scopes_json,public_jwks_json=excluded.public_jwks_json,disabled=excluded.disabled,
 revision=excluded.revision,token_ttl_seconds=excluded.token_ttl_seconds,updated_at=excluded.updated_at";
const POLICY_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
 SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM zeroth_tenants WHERE id=?3 AND disabled=0)
 AND ((?4=0 AND NOT EXISTS(SELECT 1 FROM zeroth_service_clients WHERE id=?2)
 AND NOT EXISTS(SELECT 1 FROM zeroth_clients WHERE id=?2)) OR
 (?4=1 AND EXISTS(SELECT 1 FROM zeroth_service_clients WHERE id=?2 AND tenant_id=?3
 AND revision=?5 AND name IS ?6 AND audiences_json IS ?7 AND scopes_json IS ?8
 AND public_jwks_json IS ?9 AND disabled IS ?10 AND token_ttl_seconds IS ?11
 AND created_at IS ?12 AND updated_at IS ?13))) THEN 1 ELSE 0 END";
const USE_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
 SELECT ?1,CASE WHEN ?11>?12 AND ?11>CAST(strftime('%s','now') AS INTEGER)
 AND ?13>CAST(strftime('%s','now') AS INTEGER) AND EXISTS(SELECT 1 FROM zeroth_service_clients c
 JOIN zeroth_tenants t ON t.id=c.tenant_id WHERE c.id=?2 AND c.tenant_id=?3
 AND c.disabled=0 AND t.disabled=0 AND c.revision=?4 AND c.name IS ?5
 AND c.audiences_json IS ?6 AND c.scopes_json IS ?7 AND c.public_jwks_json IS ?8
 AND c.token_ttl_seconds IS ?9 AND c.updated_at IS ?10) THEN 1 ELSE 0 END";
const CLAIM_ASSERTION_SQL: &str = "INSERT INTO zeroth_service_assertions(client_id,jti_hash,expires_at,created_at) VALUES (?1,?2,?3,?4)";
const INSERT_TOKEN_SQL: &str = "INSERT INTO zeroth_service_tokens(token_hash,client_id,tenant_id,client_revision,expires_at,created_at) VALUES (?1,?2,?3,?4,?5,?6)";
const TOKEN_ACTIVE_SQL: &str = "SELECT COUNT(*) AS value FROM zeroth_service_tokens s
 JOIN zeroth_service_clients c ON c.id=s.client_id JOIN zeroth_tenants t ON t.id=c.tenant_id
 WHERE s.token_hash=?1 AND s.client_id=?2 AND s.tenant_id=?3 AND s.client_revision=?4
 AND c.tenant_id=s.tenant_id AND c.revision=s.client_revision AND c.disabled=0 AND t.disabled=0
 AND s.expires_at>?5 AND s.expires_at>CAST(strftime('%s','now') AS INTEGER)";
const TOKEN_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
 SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM zeroth_service_tokens WHERE token_hash=?2
 AND client_id=?3 AND tenant_id=?4 AND client_revision=?5 AND expires_at>?6
 AND expires_at>CAST(strftime('%s','now') AS INTEGER)) THEN 1 ELSE 0 END";

#[derive(Clone, Debug, Deserialize)]
struct ServiceRow {
    id: String,
    tenant_id: String,
    name: String,
    audiences_json: String,
    scopes_json: String,
    public_jwks_json: String,
    disabled: i32,
    revision: i32,
    token_ttl_seconds: i32,
    created_at: i32,
    updated_at: i32,
}
impl ServiceRow {
    fn client(&self) -> Result<ServiceClient, String> {
        let client = ServiceClient {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            name: self.name.clone(),
            disabled: self.disabled != 0,
            revision: i64::from(self.revision),
            allowed_audiences: serde_json::from_str(&self.audiences_json)
                .map_err(|_| "invalid service audiences")?,
            allowed_scopes: serde_json::from_str(&self.scopes_json)
                .map_err(|_| "invalid service scopes")?,
            public_jwks: ServiceJwks::from_json(&self.public_jwks_json)
                .map_err(|_| "invalid public service keys")?,
            token_ttl_seconds: u32::try_from(self.token_ttl_seconds)
                .map_err(|_| "invalid service lifetime")?,
        };
        client.validate().map_err(|_| "invalid service policy")?;
        Ok(client)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServiceUpsert {
    id: String,
    tenant_id: String,
    name: String,
    audiences: Vec<String>,
    scopes: Vec<String>,
    public_jwks: serde_json::Value,
    disabled: bool,
    token_ttl_seconds: i32,
    expected_revision: Option<i32>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceResponse {
    id: String,
    tenant_id: String,
    name: String,
    audiences: Vec<String>,
    scopes: Vec<String>,
    public_jwks: serde_json::Value,
    disabled: bool,
    revision: i32,
    token_ttl_seconds: i32,
    created_at: i32,
    updated_at: i32,
}
fn response(row: ServiceRow) -> Result<ServiceResponse, String> {
    let client = row.client()?;
    Ok(ServiceResponse {
        id: row.id,
        tenant_id: row.tenant_id,
        name: row.name,
        audiences: client.allowed_audiences,
        scopes: client.allowed_scopes,
        public_jwks: serde_json::from_str(&row.public_jwks_json)
            .map_err(|_| "invalid service keys")?,
        disabled: row.disabled != 0,
        revision: row.revision,
        token_ttl_seconds: row.token_ttl_seconds,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}
fn validate_upsert(
    input: ServiceUpsert,
    previous: Option<&ServiceRow>,
    now: i32,
) -> Result<ServiceRow, String> {
    if input.name.trim().is_empty()
        || input.name.chars().count() > 128
        || input.name.chars().any(char::is_control)
    {
        return Err("name must contain 1 to 128 characters".into());
    }
    if !(60..=600).contains(&input.token_ttl_seconds) {
        return Err("tokenTtlSeconds must be 60 to 600".into());
    }
    let revision = match previous {
        Some(old)
            if old.tenant_id == input.tenant_id
                && input.expected_revision == Some(old.revision) =>
        {
            old.revision
                .checked_add(1)
                .filter(|n| *n < i32::MAX)
                .ok_or("service revision exhausted")?
        }
        Some(old) if old.tenant_id != input.tenant_id => {
            return Err("service tenant ownership is immutable".into())
        }
        Some(_) => return Err("expectedRevision must match the current service revision".into()),
        None if input.expected_revision.is_some() => {
            return Err("service does not exist at expectedRevision".into())
        }
        None => 1,
    };
    let row = ServiceRow {
        id: input.id,
        tenant_id: input.tenant_id,
        name: input.name.trim().into(),
        audiences_json: serde_json::to_string(&input.audiences).map_err(|_| "invalid audiences")?,
        scopes_json: serde_json::to_string(&input.scopes).map_err(|_| "invalid scopes")?,
        public_jwks_json: serde_json::to_string(&input.public_jwks).map_err(|_| "invalid keys")?,
        disabled: i32::from(input.disabled),
        revision,
        token_ttl_seconds: input.token_ttl_seconds,
        created_at: previous.map_or(now, |old| old.created_at),
        updated_at: now,
    };
    row.client()?;
    Ok(row)
}

fn parse_form(body: &str) -> Result<BTreeMap<String, String>, String> {
    if body.len() > MAX_BODY {
        return Err("service request is too large".into());
    }
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(body).map_err(|_| "invalid form encoding")?;
    let mut result = BTreeMap::new();
    for (name, value) in pairs {
        if result.insert(name, value).is_some() {
            return Err("duplicate form parameter".into());
        }
    }
    Ok(result)
}
fn service_request(form: &BTreeMap<String, String>) -> bool {
    form.get("grant_type")
        .is_some_and(|v| v == "client_credentials")
        || form.contains_key("client_assertion")
        || form.contains_key("client_assertion_type")
}
fn validate_transport(url: &url::Url) -> Result<(), &'static str> {
    audit_stream::validate_endpoint(url)
        .map_err(|_| "service authentication requires HTTPS outside loopback")
}

fn validate_request(form: &BTreeMap<String, String>, introspection: bool) -> Result<(), String> {
    let allowed = if introspection {
        &[
            "client_id",
            "client_assertion",
            "client_assertion_type",
            "token",
            "token_type_hint",
        ][..]
    } else {
        &[
            "client_id",
            "client_assertion",
            "client_assertion_type",
            "grant_type",
            "audience",
            "resource",
            "scope",
        ][..]
    };
    if form.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unsupported service request parameter".into());
    }
    if !form.get("client_id").is_some_and(|v| v.starts_with("svc_"))
        || form.get("client_assertion_type").map(String::as_str) != Some(ASSERTION_TYPE)
        || form.get("client_assertion").is_none_or(|v| v.is_empty())
    {
        return Err("private_key_jwt service authentication is required".into());
    }
    if introspection {
        if form.get("token").is_none_or(|v| v.is_empty())
            || form
                .get("token_type_hint")
                .is_some_and(|v| v != "access_token")
        {
            return Err("an access token is required".into());
        }
    } else if form.get("grant_type").map(String::as_str) != Some("client_credentials")
        || (form.contains_key("audience") && form.contains_key("resource"))
        || form
            .get("resource")
            .or_else(|| form.get("audience"))
            .is_none_or(|v| v.is_empty())
        || form.get("scope").is_none_or(|v| v.is_empty())
    {
        return Err("client_credentials, audience and scope are required".into());
    }
    Ok(())
}
fn approved_grant(
    client: &ServiceClient,
    form: &BTreeMap<String, String>,
) -> Result<(String, String), String> {
    let audience = form
        .get("resource")
        .or_else(|| form.get("audience"))
        .ok_or("missing resource")?;
    if !client.allowed_audiences.contains(audience) {
        return Err("audience is not allowed".into());
    }
    let raw = form.get("scope").ok_or("missing scope")?;
    let scopes = raw.split(' ').collect::<Vec<_>>();
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|s| s.is_empty() || !client.allowed_scopes.iter().any(|v| v == s))
    {
        return Err("scope is not allowed".into());
    }
    let mut ordered = scopes.clone();
    ordered.sort_unstable();
    ordered.dedup();
    if ordered.len() != scopes.len() {
        return Err("duplicate scope".into());
    }
    Ok((audience.clone(), ordered.join(" ")))
}

#[cfg(target_arch = "wasm32")]
async fn bounded_body(request: &mut Request) -> worker::Result<Vec<u8>> {
    use futures_util::StreamExt;
    let mut stream = request.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err(worker_error("request too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
#[cfg(target_arch = "wasm32")]
async fn row(db: &worker::d1::D1Database, id: &str) -> worker::Result<Option<ServiceRow>> {
    db.prepare(format!(
        "SELECT {COLUMNS} FROM zeroth_service_clients WHERE id=?"
    ))
    .bind_refs(&[worker::d1::D1Type::Text(id)])?
    .first(None)
    .await
}
#[cfg(target_arch = "wasm32")]
async fn rows(
    db: &worker::d1::D1Database,
    tenant: Option<&str>,
) -> worker::Result<Vec<ServiceRow>> {
    let sql=format!("SELECT {COLUMNS} FROM zeroth_service_clients WHERE (?1 IS NULL OR tenant_id=?1) ORDER BY tenant_id,id LIMIT 1001");
    let result = db
        .prepare(sql)
        .bind_refs(&[d1_optional_text(tenant)])?
        .all()
        .await?
        .results::<ServiceRow>()?;
    if result.len() > 1000 {
        return Err(worker_error(
            "service client list exceeds 1000; choose a tenant filter".into(),
        ));
    }
    Ok(result)
}
#[cfg(target_arch = "wasm32")]
fn policy_guard(
    db: &worker::d1::D1Database,
    event_id: &str,
    id: &str,
    tenant: &str,
    old: Option<&ServiceRow>,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    use worker::d1::D1Type as V;
    db.prepare(POLICY_GUARD_SQL).bind_refs(&[
        V::Text(event_id),
        V::Text(id),
        V::Text(tenant),
        V::Integer(i32::from(old.is_some())),
        d1_optional_integer(old.map(|r| r.revision)),
        d1_optional_text(old.map(|r| r.name.as_str())),
        d1_optional_text(old.map(|r| r.audiences_json.as_str())),
        d1_optional_text(old.map(|r| r.scopes_json.as_str())),
        d1_optional_text(old.map(|r| r.public_jwks_json.as_str())),
        d1_optional_integer(old.map(|r| r.disabled)),
        d1_optional_integer(old.map(|r| r.token_ttl_seconds)),
        d1_optional_integer(old.map(|r| r.created_at)),
        d1_optional_integer(old.map(|r| r.updated_at)),
    ])
}
#[cfg(target_arch = "wasm32")]
fn use_guard(
    db: &worker::d1::D1Database,
    event_id: &str,
    row: &ServiceRow,
    expiry: i32,
    now: i32,
    token_expiry: i32,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    use worker::d1::D1Type as V;
    db.prepare(USE_GUARD_SQL).bind_refs(&[
        V::Text(event_id),
        V::Text(&row.id),
        V::Text(&row.tenant_id),
        V::Integer(row.revision),
        V::Text(&row.name),
        V::Text(&row.audiences_json),
        V::Text(&row.scopes_json),
        V::Text(&row.public_jwks_json),
        V::Integer(row.token_ttl_seconds),
        V::Integer(row.updated_at),
        V::Integer(expiry),
        V::Integer(now),
        V::Integer(token_expiry),
    ])
}
#[cfg(target_arch = "wasm32")]
async fn event(
    request: &Request,
    actor: zeroth_audit::AuditActor,
    name: &str,
    service: &ServiceRow,
    now: i32,
    existing: bool,
) -> worker::Result<(zeroth_audit::AuditEvent, Option<String>)> {
    let mut event = audit_capture::event(
        format!("evt_{}", random_token()?),
        name,
        actor,
        None,
        existing.then_some(service.id.as_str()),
        None,
        &serde_json::json!({"disabled":service.disabled!=0}),
        now,
    )
    .map_err(worker_error)?;
    event.organization_id = Some(service.tenant_id.clone());
    event.targets = vec![
        zeroth_audit::AuditTarget::new("service_client", &service.id)
            .map_err(|e| worker_error(e.to_string()))?,
    ];
    event.correlation_id = request_header(request, "X-Zeroth-Request-ID")?;
    event.validate().map_err(|e| worker_error(e.to_string()))?;
    Ok((event, None))
}
#[cfg(target_arch = "wasm32")]
fn failure(code: &str, message: &str, status: u16) -> worker::Result<Response> {
    oauth_error_json(code, message, status)
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn manage(mut request: Request, env: Env) -> worker::Result<Response> {
    use worker::d1::D1Type as V;
    let url = request.url()?;
    if let Err(message) = validate_transport(&url) {
        return failure("invalid_request", message, 400);
    }
    let config = server_config(&env, &url);
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let authorization = if request.method() == Method::Get {
        authorize_admin_request(&request, &env, &db, &config, now).await
    } else {
        authorize_admin_write_request(
            &mut request,
            &env,
            &db,
            &config,
            now,
            CSRF_ROUTE_FAMILY_ADMIN,
            false,
            "service_client_admin",
        )
        .await
    };
    let authorization = match authorization {
        Ok(value) => value,
        Err(error) => return client_management_error_json(&error),
    };
    match request.method() {
        Method::Get => {
            let params = url.query_pairs().collect::<Vec<_>>();
            if params.len() > 1 || params.iter().any(|(k, v)| k != "tenant_id" || v.is_empty()) {
                return failure(
                    "invalid_request",
                    "only one nonempty tenant_id filter is supported",
                    400,
                );
            }
            let tenant = params.first().map(|(_, v)| v.as_ref());
            let clients = rows(&db, tenant)
                .await?
                .into_iter()
                .map(response)
                .collect::<Result<Vec<_>, _>>()
                .map_err(worker_error)?;
            json(&serde_json::json!({"serviceClients":clients}))
        }
        Method::Post => {
            if url.query().is_some() {
                return failure(
                    "invalid_request",
                    "service updates do not accept query parameters",
                    400,
                );
            }
            if !content_type_is_json(request_header(&request, "Content-Type")?.as_deref()) {
                return failure("invalid_request", "application/json is required", 400);
            }
            let bytes = match bounded_body(&mut request).await {
                Ok(v) => v,
                Err(_) => return failure("invalid_request", "request exceeds 64 KiB", 413),
            };
            let input: ServiceUpsert = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => return failure("invalid_request", "invalid service client JSON", 400),
            };
            let previous = row(&db, &input.id).await?;
            let revision_matches = previous
                .as_ref()
                .map_or(input.expected_revision.is_none(), |old| {
                    input.expected_revision == Some(old.revision)
                });
            if !revision_matches {
                return failure(
                    "conflict",
                    "expectedRevision must match the current service revision",
                    409,
                );
            }
            let next = match validate_upsert(input, previous.as_ref(), now) {
                Ok(v) => v,
                Err(message) => return failure("invalid_request", &message, 400),
            };
            let actor = audit_capture::admin_actor(&authorization).map_err(worker_error)?;
            let kind = if previous.is_none() {
                "service_client.create"
            } else if next.disabled != 0 {
                "service_client.disable"
            } else {
                "service_client.update"
            };
            let event = event(&request, actor, kind, &next, now, previous.is_some()).await?;
            let guard = &event.0.event_id;
            let write = db.prepare(UPSERT_SQL).bind_refs(&[
                V::Text(&next.id),
                V::Text(&next.tenant_id),
                V::Text(&next.name),
                V::Text(&next.audiences_json),
                V::Text(&next.scopes_json),
                V::Text(&next.public_jwks_json),
                V::Integer(next.disabled),
                V::Integer(next.revision),
                V::Integer(next.token_ttl_seconds),
                V::Integer(now),
            ])?;
            if commit_credential_transition(
                &db,
                vec![
                    policy_guard(&db, guard, &next.id, &next.tenant_id, previous.as_ref())?,
                    write,
                    audit_capture::clear_guard(&db, guard)?,
                ],
                &event,
            )
            .await
            .is_err()
            {
                return failure(
                    "conflict",
                    "service policy or tenant changed; refresh before retrying",
                    409,
                );
            }
            json(
                &response(
                    row(&db, &next.id)
                        .await?
                        .ok_or_else(|| worker_error("service update unavailable".into()))?,
                )
                .map_err(worker_error)?,
            )
        }
        _ => failure("method_not_allowed", "method not allowed", 405),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn list_ui(
    db: &worker::d1::D1Database,
) -> worker::Result<Vec<zeroth_ui::ServiceClientAdminUi>> {
    rows(db, None)
        .await?
        .into_iter()
        .map(|row| {
            let client = row.client().map_err(worker_error)?;
            Ok(zeroth_ui::ServiceClientAdminUi {
                id: row.id,
                tenant_id: row.tenant_id,
                name: row.name,
                audiences: client.allowed_audiences,
                scopes: client.allowed_scopes,
                public_jwks_json: row.public_jwks_json,
                disabled: row.disabled != 0,
                revision: i64::from(row.revision),
                token_ttl_seconds: row.token_ttl_seconds,
                created_at: Some(row.created_at.to_string()),
                updated_at: Some(row.updated_at.to_string()),
            })
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn maybe_handle(
    request: &Request,
    env: &Env,
    introspection: bool,
) -> worker::Result<Option<Response>> {
    let content_type = request_header(request, "Content-Type")?;
    if !content_type_is_form_urlencoded(content_type.as_deref()) {
        return Ok(None);
    }
    let mut copy = request.clone()?;
    let bytes = match bounded_body(&mut copy).await {
        Ok(v) => v,
        Err(_) => return failure("invalid_request", "request exceeds 64 KiB", 413).map(Some),
    };
    let text = match String::from_utf8(bytes) {
        Ok(v) => v,
        Err(_) => return failure("invalid_request", "form must be UTF-8", 400).map(Some),
    };
    let form = match parse_form(&text) {
        Ok(v) => v,
        Err(message) => return failure("invalid_request", &message, 400).map(Some),
    };
    if !service_request(&form) {
        return Ok(None);
    }
    handle(request, env, form, introspection).await.map(Some)
}

#[cfg(target_arch = "wasm32")]
async fn handle(
    request: &Request,
    env: &Env,
    form: BTreeMap<String, String>,
    introspection: bool,
) -> worker::Result<Response> {
    use worker::d1::D1Type as V;
    if let Err(message) = validate_transport(&request.url()?) {
        return failure("invalid_request", message, 400);
    }
    if request_header(request, "Origin")?.is_some()
        || request_header(request, "Authorization")?.is_some()
    {
        return failure(
            "invalid_request",
            "service authentication requires a server request with only private_key_jwt",
            400,
        );
    }
    if let Err(message) = validate_request(&form, introspection) {
        return failure("invalid_request", &message, 400);
    }
    let id = &form["client_id"];
    let db = env.d1(D1_BINDING)?;
    let url = request.url()?;
    let config = server_config(env, &url);
    let now = unix_timestamp_seconds();
    let key = rate_limit_key_from_env(env).map_err(worker_error)?;
    let ip = rate_limit_request_ip(request)?.unwrap_or_else(|| "missing".into());
    let subjects = [
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_OAUTH_TOKEN_IP,
                window_seconds: OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS,
                max_attempts: OAUTH_TOKEN_RATE_LIMIT_MAX_ATTEMPTS,
            },
            &ip,
        ),
        rate_limit_subject(
            RateLimitPolicy {
                scope: RATE_LIMIT_SCOPE_OAUTH_TOKEN_CLIENT,
                window_seconds: OAUTH_TOKEN_RATE_LIMIT_WINDOW_SECONDS,
                max_attempts: OAUTH_TOKEN_RATE_LIMIT_MAX_ATTEMPTS,
            },
            id,
        ),
    ];
    if let Some(blocked) = rate_limit_increment_subjects(&db, &key, now, &subjects).await? {
        return rate_limit_oauth_error_json(blocked.retry_after_seconds, None);
    }
    let Some(row) = row(&db, id).await? else {
        return failure("invalid_client", "service authentication failed", 401);
    };
    let client = match row.client() {
        Ok(c) if !c.disabled => c,
        _ => return failure("invalid_client", "service authentication failed", 401),
    };
    let endpoint = format!(
        "{}/oauth/{}",
        config.issuer().issuer.trim_end_matches('/'),
        if introspection { "introspect" } else { "token" }
    );
    let assertion = match verify_service_client_assertion(
        &form["client_assertion"],
        &client,
        &ServiceAssertionValidation {
            token_endpoint: endpoint,
            now: i64::from(now),
            max_lifetime_seconds: 300,
            clock_skew_seconds: 0,
        },
    ) {
        Ok(v) => v,
        Err(_) => return failure("invalid_client", "service authentication failed", 401),
    };
    let assertion_expiry = match i32::try_from(assertion.exp) {
        Ok(v) => v,
        Err(_) => {
            return failure(
                "invalid_client",
                "service assertion expiry is unsupported",
                401,
            )
        }
    };
    let assertion_hash = hash_secret(&assertion.jti);
    let material = signing_material_from_env(env)?;
    let mut extra = Vec::new();
    let mut introspection_active = false;
    let mut grant_expiry = assertion_expiry;
    let (response, event_type) = if introspection {
        let raw = &form["token"];
        let hash = hash_secret(raw);
        let claims = service_claims_for_introspection(
            raw,
            &client,
            &config.issuer().issuer,
            &material.jwks,
            now,
        );
        let active = if let Some(claims) = &claims {
            #[derive(Deserialize)]
            struct Count {
                value: i32,
            }
            db.prepare(TOKEN_ACTIVE_SQL)
                .bind_refs(&[
                    V::Text(&hash),
                    V::Text(id),
                    V::Text(&row.tenant_id),
                    V::Integer(row.revision),
                    V::Integer(now),
                ])?
                .first::<Count>(None)
                .await?
                .is_some_and(|r| r.value == 1)
                && claims.client_revision == i64::from(row.revision)
        } else {
            false
        };
        introspection_active = active;
        let body = if active {
            let claims = claims.as_ref().unwrap();
            serde_json::json!({"active":true,"client_id":id,"sub":claims.sub,"tenant_id":claims.tenant_id,"principal_type":"service","token_use":"access","aud":claims.aud,"scope":claims.scope,"iat":claims.iat,"exp":claims.exp,"client_revision":claims.client_revision,"token_type":"Bearer"})
        } else {
            serde_json::json!({"active":false})
        };
        (
            json_status_no_store(&body, 200)?,
            "service.token.introspect",
        )
    } else {
        let (audience, scope) = match approved_grant(&client, &form) {
            Ok(v) => v,
            Err(message) => return failure("invalid_scope", &message, 400),
        };
        let claims = match build_service_access_token_claims(
            &client,
            &config.issuer().issuer,
            &audience,
            &scope,
            i64::from(now),
            &format!("m2m_{}", random_token()?),
        ) {
            Ok(c) => c,
            Err(_) => return failure("invalid_request", "invalid service grant", 400),
        };
        let access_token = sign_jwt(&material.signing_key, &claims).map_err(worker_error)?;
        let token_hash = hash_secret(&access_token);
        let expiry =
            i32::try_from(claims.exp).map_err(|_| worker_error("invalid service expiry".into()))?;
        grant_expiry = expiry;
        extra.push(db.prepare(INSERT_TOKEN_SQL).bind_refs(&[
            V::Text(&token_hash),
            V::Text(id),
            V::Text(&row.tenant_id),
            V::Integer(row.revision),
            V::Integer(expiry),
            V::Integer(now),
        ])?);
        (
            json_status_no_store(
                &ServiceTokenResponse {
                    access_token,
                    token_type: "Bearer".into(),
                    expires_in: u64::from(client.token_ttl_seconds),
                    scope,
                },
                200,
            )?,
            "service.token.issue",
        )
    };
    let actor =
        zeroth_audit::AuditActor::new("service", id).map_err(|e| worker_error(e.to_string()))?;
    let event = event(request, actor, event_type, &row, now, true).await?;
    let guard = &event.0.event_id;
    // Keep every assertion tombstone through its expiry, shared across token and introspection endpoints.
    let commit_now = unix_timestamp_seconds();
    let mut changes = vec![
        use_guard(&db, guard, &row, assertion_expiry, commit_now, grant_expiry)?,
        db.prepare("DELETE FROM zeroth_service_assertions WHERE rowid IN (SELECT rowid FROM zeroth_service_assertions WHERE expires_at<=? ORDER BY expires_at LIMIT 1000)")
            .bind_refs(&[V::Integer(commit_now)])?,
        db.prepare("DELETE FROM zeroth_service_tokens WHERE rowid IN (SELECT rowid FROM zeroth_service_tokens WHERE expires_at<=? ORDER BY expires_at LIMIT 1000)")
            .bind_refs(&[V::Integer(commit_now)])?,
        db.prepare(CLAIM_ASSERTION_SQL).bind_refs(&[
            V::Text(id),
            V::Text(&assertion_hash),
            V::Integer(assertion_expiry),
            V::Integer(commit_now),
        ])?,
    ];
    if introspection_active {
        let hash = hash_secret(&form["token"]);
        let token_guard = format!("token_{guard}");
        changes.push(db.prepare(TOKEN_GUARD_SQL).bind_refs(&[
            V::Text(&token_guard),
            V::Text(&hash),
            V::Text(id),
            V::Text(&row.tenant_id),
            V::Integer(row.revision),
            V::Integer(commit_now),
        ])?);
        changes.push(audit_capture::clear_guard(&db, &token_guard)?);
    } else {
        changes.extend(extra);
    }
    changes.push(audit_capture::clear_guard(&db, guard)?);
    if commit_credential_transition(&db, changes, &event)
        .await
        .is_err()
    {
        return failure(
            "invalid_client",
            "service assertion replayed or policy changed",
            401,
        );
    }
    Ok(response)
}
fn service_claims_for_introspection(
    token: &str,
    client: &ServiceClient,
    issuer: &str,
    jwks: &JwksResponse,
    now: i32,
) -> Option<zeroth_machine::ServiceAccessTokenClaims> {
    // Untrusted audience only chooses among this client's exact allowlist; verification authenticates it.
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let aud = value.get("aud")?.as_str()?;
    if !client.allowed_audiences.iter().any(|v| v == aud) {
        return None;
    }
    let keys = ServiceJwks::from_json(&serde_json::to_string(jwks).ok()?).ok()?;
    let claims = verify_service_access_token(
        token,
        &keys,
        &ServiceAccessTokenValidation {
            issuer: issuer.into(),
            audience: aud.into(),
            tenant_id: client.tenant_id.clone(),
            required_scopes: Vec::new(),
            now: i64::from(now),
            max_lifetime_seconds: 600,
            clock_skew_seconds: 0,
        },
    )
    .ok()?;
    (claims.client_id == client.id
        && claims.sub == client.id
        && claims.client_revision == client.revision)
        .then_some(claims)
}

#[cfg(test)]
mod tests;
