//! Cloudflare adapter: explicit credential lookup, read-only Google transport,
//! fenced snapshot application, audited configuration and automatic polling.

use super::google_directory::{self as adapter, DirectoryConfig, DirectoryError};
#[cfg(target_arch = "wasm32")]
use super::google_directory::{
    CredentialProvider, DirectoryTransport, HttpReply, ServiceAccountKey,
};
use super::*;
use serde::{Deserialize, Serialize};

const POLL_SECONDS: i32 = 300;
const STALE_SECONDS: i32 = 900;
const LEASE_SECONDS: i32 = 600;
const BODY_LIMIT: usize = 2048;
const CONFIG_SQL: &str = "SELECT * FROM zeroth_google_directory WHERE tenant_id=?1";
const UPSERT_CONFIG_SQL:&str="INSERT INTO zeroth_google_directory
    (tenant_id,enabled,managed_enforced,customer_id,delegated_admin_email,service_account_secret_binding,next_sync_at,created_at,updated_at)
    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8)
    ON CONFLICT(tenant_id) DO UPDATE SET enabled=excluded.enabled,
      managed_enforced=MAX(zeroth_google_directory.managed_enforced,excluded.managed_enforced),
      customer_id=excluded.customer_id,delegated_admin_email=excluded.delegated_admin_email,
      service_account_secret_binding=excluded.service_account_secret_binding,next_sync_at=excluded.next_sync_at,
      last_error_code=NULL,updated_at=excluded.updated_at";
const CONFIG_LEASE_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN NOT EXISTS(SELECT 1 FROM zeroth_google_directory
        WHERE tenant_id=?2 AND lease_expires_at>?3) THEN 1 ELSE 0 END";
const CONFIG_PREIMAGE_GUARD_SQL:&str="INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN (?3=0 AND NOT EXISTS(SELECT 1 FROM zeroth_google_directory WHERE tenant_id=?2))
      OR (?3=1 AND EXISTS(SELECT 1 FROM zeroth_google_directory WHERE tenant_id=?2 AND enabled=?4
          AND managed_enforced=?5 AND customer_id IS ?6 AND delegated_admin_email IS ?7
          AND service_account_secret_binding IS ?8)) THEN 1 ELSE 0 END";
const ACQUIRE_LEASE_SQL: &str =
    "UPDATE zeroth_google_directory SET lease_id=?2,lease_expires_at=?3,
    last_attempt_at=?4,next_sync_at=?5
    WHERE tenant_id=?1 AND enabled=1 AND customer_id=?6 AND delegated_admin_email=?7
      AND service_account_secret_binding=?8 AND (lease_expires_at IS NULL OR lease_expires_at<=?4)";
const ACQUIRED_GUARD_SQL:&str="INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM zeroth_google_directory g JOIN zeroth_tenants t ON t.id=g.tenant_id
      WHERE g.tenant_id=?2 AND g.enabled=1 AND g.lease_id=?3 AND g.lease_expires_at>?4
        AND t.disabled=0 AND t.enterprise_provider='google_workspace') THEN 1 ELSE 0 END";
const FINISH_SUCCESS_SQL: &str =
    "UPDATE zeroth_google_directory SET last_success_at=?3,last_error_code=NULL,
    last_seen_count=?4,last_deactivated_count=?5,next_sync_at=?6,lease_id=NULL,lease_expires_at=NULL
    WHERE tenant_id=?1 AND lease_id=?2";
const FINISH_FAILURE_SQL: &str =
    "UPDATE zeroth_google_directory SET last_error_code=?3,next_sync_at=?4,
    lease_id=NULL,lease_expires_at=NULL WHERE tenant_id=?1 AND lease_id=?2";

#[derive(Clone, Debug, Deserialize)]
struct ConfigRow {
    tenant_id: String,
    enabled: i32,
    managed_enforced: i32,
    customer_id: Option<String>,
    delegated_admin_email: Option<String>,
    service_account_secret_binding: Option<String>,
    last_attempt_at: Option<i32>,
    last_success_at: Option<i32>,
    last_error_code: Option<String>,
    last_seen_count: Option<i32>,
    last_deactivated_count: Option<i32>,
    next_sync_at: Option<i32>,
    lease_id: Option<String>,
    lease_expires_at: Option<i32>,
    created_at: i32,
    updated_at: i32,
}
impl ConfigRow {
    fn config(&self) -> Result<DirectoryConfig, DirectoryError> {
        let config = DirectoryConfig {
            customer_id: self
                .customer_id
                .clone()
                .ok_or(DirectoryError("directory_not_configured"))?,
            delegated_admin_email: self
                .delegated_admin_email
                .clone()
                .ok_or(DirectoryError("directory_not_configured"))?,
            service_account_secret_binding: self
                .service_account_secret_binding
                .clone()
                .ok_or(DirectoryError("directory_not_configured"))?,
        };
        config.validate()?;
        Ok(config)
    }
    fn authority(&self) -> Result<provisioning::DirectoryAuthority, DirectoryError> {
        let customer = self
            .customer_id
            .clone()
            .ok_or(DirectoryError("directory_not_configured"))?;
        adapter::validate_customer_id(&customer)?;
        Ok(provisioning::DirectoryAuthority {
            tenant_id: self.tenant_id.clone(),
            provider_id: "google_workspace".into(),
            authority_id: customer,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigRequest {
    tenant_id: String,
    enabled: bool,
    customer_id: Option<String>,
    delegated_admin_email: Option<String>,
    service_account_secret_binding: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncRequest {
    tenant_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    tenant_id: String,
    enabled: bool,
    managed_enforced: bool,
    customer_id: Option<String>,
    customer_id_locked: bool,
    delegated_admin_email: Option<String>,
    service_account_secret_binding: Option<String>,
    credentials_configured: bool,
    last_attempt_at: Option<i32>,
    last_success_at: Option<i32>,
    last_error_code: Option<String>,
    last_seen_count: Option<i32>,
    last_deactivated_count: Option<i32>,
    sync_interval_seconds: i32,
    next_sync_at: Option<i32>,
    stale_after_seconds: i32,
    stale: bool,
    sync_running: bool,
}

fn normalize_request(mut request: ConfigRequest) -> Result<ConfigRequest, DirectoryError> {
    request.tenant_id = validate_account_tenant_id_value(&request.tenant_id)
        .map_err(|_| DirectoryError("invalid_tenant_id"))?;
    let clean =
        |value: Option<String>| value.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    request.customer_id = clean(request.customer_id);
    request.delegated_admin_email = clean(request.delegated_admin_email);
    request.service_account_secret_binding = clean(request.service_account_secret_binding);
    if let Some(value) = &request.customer_id {
        adapter::validate_customer_id(value)?;
    }
    if let Some(value) = &request.delegated_admin_email {
        adapter::validate_email(value)?;
    }
    if let Some(value) = &request.service_account_secret_binding {
        adapter::validate_binding(value)?;
    }
    if request.enabled
        && (request.customer_id.is_none()
            || request.delegated_admin_email.is_none()
            || request.service_account_secret_binding.is_none())
    {
        return Err(DirectoryError("directory_not_configured"));
    }
    Ok(request)
}

#[cfg(target_arch = "wasm32")]
struct WorkerCredentials<'a>(&'a Env);
#[cfg(target_arch = "wasm32")]
impl CredentialProvider for WorkerCredentials<'_> {
    async fn load(&self, binding: &str) -> Result<ServiceAccountKey, DirectoryError> {
        adapter::validate_binding(binding)?;
        let secret = secret_string(self.0, binding)
            .ok_or(DirectoryError("service_account_not_configured"))?;
        ServiceAccountKey::parse(&secret)
    }
}

#[cfg(target_arch = "wasm32")]
struct WorkerTransport {
    deadline: i32,
}
#[cfg(target_arch = "wasm32")]
impl DirectoryTransport for WorkerTransport {
    async fn request(
        &self,
        url: &str,
        form: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<HttpReply, DirectoryError> {
        use futures_util::StreamExt;
        adapter::validate_request_url(url, form.is_some())?;
        let remaining = self.deadline - unix_timestamp_seconds();
        if remaining <= 0 {
            return Err(DirectoryError("directory_sync_timeout"));
        }
        // Keep the signal alive while consuming the bounded response body too,
        // so a server that sends only headers cannot retain the sync lease.
        let signal = worker::AbortSignal::from(worker::web_sys::AbortSignal::timeout_with_u32(
            remaining.min(30) as u32 * 1000,
        ));
        let headers = Headers::new();
        headers
            .set("Accept", "application/json")
            .map_err(|_| DirectoryError("google_transport_failed"))?;
        if let Some(bearer) = bearer {
            headers
                .set("Authorization", &format!("Bearer {bearer}"))
                .map_err(|_| DirectoryError("google_transport_failed"))?;
        }
        let mut init = RequestInit::new();
        init.with_headers(headers)
            .with_redirect(RequestRedirect::Error)
            .with_cache(CacheMode::NoStore);
        if let Some(form) = form {
            init.headers
                .set("Content-Type", "application/x-www-form-urlencoded")
                .map_err(|_| DirectoryError("google_transport_failed"))?;
            init.with_method(Method::Post)
                .with_body(Some(JsValue::from_str(form)));
        }
        let request = Request::new_with_init(url, &init)
            .map_err(|_| DirectoryError("google_transport_failed"))?;
        let mut response = Fetch::Request(request)
            .send_with_signal(&signal)
            .await
            .map_err(|_| {
                DirectoryError(if signal.aborted() {
                    "directory_sync_timeout"
                } else {
                    "google_transport_failed"
                })
            })?;
        let status = response.status_code();
        if (300..400).contains(&status) {
            return Err(DirectoryError("google_redirect_rejected"));
        }
        if let Some(length) = response
            .headers()
            .get("Content-Length")
            .map_err(|_| DirectoryError("google_transport_failed"))?
        {
            if length
                .parse::<u64>()
                .map_err(|_| DirectoryError("invalid_google_response"))?
                > adapter::MAX_RESPONSE_BYTES as u64
            {
                return Err(DirectoryError("google_response_too_large"));
            }
        }
        let mut stream = response
            .stream()
            .map_err(|_| DirectoryError("google_transport_failed"))?;
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| {
                DirectoryError(if signal.aborted() {
                    "directory_sync_timeout"
                } else {
                    "google_transport_failed"
                })
            })?;
            if chunk.len() > adapter::MAX_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(DirectoryError("google_response_too_large"));
            }
            body.extend_from_slice(&chunk);
        }
        if unix_timestamp_seconds() > self.deadline {
            return Err(DirectoryError("directory_sync_timeout"));
        }
        Ok(HttpReply { status, body })
    }
    async fn sign(&self, key: &ServiceAccountKey, input: &str) -> Result<Vec<u8>, DirectoryError> {
        let der = adapter::pkcs8_der(key)?;
        let subtle = worker_global_crypto_subtle()
            .map_err(|_| DirectoryError("service_account_signing_failed"))?;
        let algorithm = rsa_pkcs1_sha256_algorithm()
            .map_err(|_| DirectoryError("service_account_signing_failed"))?;
        let bytes = worker::js_sys::Uint8Array::from(der.as_slice());
        let imported = JsFuture::from(
            subtle
                .import_key_with_object(
                    "pkcs8",
                    bytes.unchecked_ref(),
                    &algorithm,
                    false,
                    &single_js_string_array("sign"),
                )
                .map_err(|_| DirectoryError("invalid_service_account_key"))?,
        )
        .await
        .map_err(|_| DirectoryError("invalid_service_account_key"))?;
        let key = imported
            .dyn_into::<worker::web_sys::CryptoKey>()
            .map_err(|_| DirectoryError("invalid_service_account_key"))?;
        let imported_algorithm = key
            .algorithm()
            .map_err(|_| DirectoryError("invalid_service_account_key"))?;
        let bits =
            worker::js_sys::Reflect::get(&imported_algorithm, &JsValue::from_str("modulusLength"))
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
        if bits < 2048.0 {
            return Err(DirectoryError("weak_service_account_key"));
        }
        let signed = JsFuture::from(
            subtle
                .sign_with_object_and_u8_array(&algorithm, &key, input.as_bytes())
                .map_err(|_| DirectoryError("service_account_signing_failed"))?,
        )
        .await
        .map_err(|_| DirectoryError("service_account_signing_failed"))?;
        Ok(worker::js_sys::Uint8Array::new(&signed).to_vec())
    }
}

#[cfg(target_arch = "wasm32")]
async fn row(db: &worker::d1::D1Database, tenant_id: &str) -> worker::Result<Option<ConfigRow>> {
    db.prepare(CONFIG_SQL)
        .bind_refs(&[worker::d1::D1Type::Text(tenant_id)])?
        .first(None)
        .await
}
#[cfg(target_arch = "wasm32")]
async fn status(db: &worker::d1::D1Database, env: &Env, tenant_id: &str) -> worker::Result<Status> {
    let now = unix_timestamp_seconds();
    let row = row(db, tenant_id).await?;
    let locked = if let Some(authority) = row.as_ref().and_then(|r| r.authority().ok()) {
        provisioning::authority_locked(db, &authority)
            .await
            .map_err(|_| worker_error("directory status unavailable".into()))?
    } else {
        false
    };
    #[derive(Deserialize)]
    struct Health {
        last_full_sync_at: Option<i32>,
        enabled: i32,
    }
    let health=db.prepare("SELECT last_full_sync_at,enabled FROM zeroth_directory_sources WHERE tenant_id=?1 AND provider_id='google_workspace'")
        .bind_refs(&[worker::d1::D1Type::Text(tenant_id)])?.first::<Health>(None).await?;
    let enforced = health.as_ref().is_some_and(|h| h.enabled != 0)
        || row.as_ref().is_some_and(|r| r.managed_enforced != 0);
    let success = health.and_then(|h| h.last_full_sync_at);
    let configured = row
        .as_ref()
        .and_then(|r| r.config().ok())
        .is_some_and(|config| {
            secret_string(env, &config.service_account_secret_binding)
                .is_some_and(|secret| ServiceAccountKey::parse(&secret).is_ok())
        });
    let running = row.as_ref().is_some_and(|r| {
        r.lease_id.is_some() && r.lease_expires_at.is_some_and(|expiry| expiry > now)
    });
    Ok(Status {
        tenant_id: tenant_id.into(),
        enabled: row.as_ref().is_some_and(|r| r.enabled != 0),
        managed_enforced: enforced,
        customer_id: row.as_ref().and_then(|r| r.customer_id.clone()),
        customer_id_locked: locked
            || success.is_some()
            || row.as_ref().is_some_and(|r| r.enabled != 0),
        delegated_admin_email: row.as_ref().and_then(|r| r.delegated_admin_email.clone()),
        service_account_secret_binding: row
            .as_ref()
            .and_then(|r| r.service_account_secret_binding.clone()),
        credentials_configured: configured,
        last_attempt_at: row.as_ref().and_then(|r| r.last_attempt_at),
        last_success_at: success,
        last_error_code: row.as_ref().and_then(|r| r.last_error_code.clone()),
        last_seen_count: row.as_ref().and_then(|r| r.last_seen_count),
        last_deactivated_count: row.as_ref().and_then(|r| r.last_deactivated_count),
        sync_interval_seconds: POLL_SECONDS,
        next_sync_at: row.as_ref().and_then(|r| {
            if running {
                r.lease_expires_at
            } else {
                r.next_sync_at
            }
        }),
        stale_after_seconds: STALE_SECONDS,
        stale: enforced && success.is_none_or(|value| value > now || now - value > STALE_SECONDS),
        sync_running: running,
    })
}

#[cfg(target_arch = "wasm32")]
async fn load_body<T: serde::de::DeserializeOwned>(
    request: &mut Request,
) -> Result<T, DirectoryError> {
    use futures_util::StreamExt;
    if !content_type_is_json(
        request_header(request, "Content-Type")
            .map_err(|_| DirectoryError("invalid_request"))?
            .as_deref(),
    ) {
        return Err(DirectoryError("json_required"));
    }
    reject_oversized_content_length(request, BODY_LIMIT)
        .map_err(|_| DirectoryError("request_too_large"))?;
    let mut stream = request
        .stream()
        .map_err(|_| DirectoryError("invalid_request"))?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| DirectoryError("invalid_request"))?;
        if chunk.len() > BODY_LIMIT.saturating_sub(body.len()) {
            return Err(DirectoryError("request_too_large"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| DirectoryError("invalid_request"))
}

#[cfg(target_arch = "wasm32")]
async fn validate_tenant(
    db: &worker::d1::D1Database,
    tenant_id: &str,
) -> Result<(), DirectoryError> {
    #[derive(Deserialize)]
    struct Tenant {
        enterprise_provider: Option<String>,
        disabled: i32,
    }
    let tenant = db
        .prepare("SELECT enterprise_provider,disabled FROM zeroth_tenants WHERE id=?1")
        .bind_refs(&[worker::d1::D1Type::Text(tenant_id)])
        .map_err(|_| DirectoryError("directory_storage_failed"))?
        .first::<Tenant>(None)
        .await
        .map_err(|_| DirectoryError("directory_storage_failed"))?
        .ok_or(DirectoryError("tenant_not_found"))?;
    if tenant.disabled != 0 || tenant.enterprise_provider.as_deref() != Some("google_workspace") {
        return Err(DirectoryError("google_tenant_required"));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn save(
    db: &worker::d1::D1Database,
    request: &Request,
    authorization: &AdminAuthorization,
    input: ConfigRequest,
) -> Result<(), DirectoryError> {
    use worker::d1::D1Type as V;
    let input = normalize_request(input)?;
    validate_tenant(db, &input.tenant_id).await?;
    let now = unix_timestamp_seconds();
    let old = row(db, &input.tenant_id)
        .await
        .map_err(|_| DirectoryError("directory_storage_failed"))?;
    if old
        .as_ref()
        .is_some_and(|r| r.lease_expires_at.is_some_and(|expiry| expiry > now))
    {
        return Err(DirectoryError("directory_sync_running"));
    }
    if let Some(old) = &old {
        if old.customer_id != input.customer_id {
            let locked = if let Ok(authority) = old.authority() {
                provisioning::authority_locked(db, &authority)
                    .await
                    .map_err(|_| DirectoryError("directory_storage_failed"))?
            } else {
                false
            };
            if old.enabled != 0 || old.last_success_at.is_some() || locked {
                return Err(DirectoryError("customer_id_locked"));
            }
        }
    }
    let enforced = input.enabled || old.as_ref().is_some_and(|r| r.managed_enforced != 0);
    if enforced && input.customer_id.is_none() {
        return Err(DirectoryError("customer_id_locked"));
    }
    let next = if input.enabled { Some(now) } else { None };
    let guard_id = format!(
        "directory_config_{}",
        random_token().map_err(|_| DirectoryError("directory_storage_failed"))?
    );
    let args = [
        V::Text(&input.tenant_id),
        V::Integer(i32::from(input.enabled)),
        V::Integer(i32::from(enforced)),
        d1_optional_text(input.customer_id.as_deref()),
        d1_optional_text(input.delegated_admin_email.as_deref()),
        d1_optional_text(input.service_account_secret_binding.as_deref()),
        d1_optional_integer(next),
        V::Integer(now),
    ];
    let mut business = vec![
        db.prepare(CONFIG_LEASE_GUARD_SQL)
            .bind_refs(&[
                V::Text(&guard_id),
                V::Text(&input.tenant_id),
                V::Integer(now),
            ])
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
        db.prepare(UPSERT_CONFIG_SQL)
            .bind_refs(&args)
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
        audit_capture::clear_guard(db, &guard_id)
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
    ];
    let preimage_id = format!("directory_preimage_{guard_id}");
    business.insert(
        0,
        db.prepare(CONFIG_PREIMAGE_GUARD_SQL)
            .bind_refs(&[
                V::Text(&preimage_id),
                V::Text(&input.tenant_id),
                V::Integer(i32::from(old.is_some())),
                V::Integer(old.as_ref().map_or(0, |r| r.enabled)),
                V::Integer(old.as_ref().map_or(0, |r| r.managed_enforced)),
                d1_optional_text(old.as_ref().and_then(|r| r.customer_id.as_deref())),
                d1_optional_text(
                    old.as_ref()
                        .and_then(|r| r.delegated_admin_email.as_deref()),
                ),
                d1_optional_text(
                    old.as_ref()
                        .and_then(|r| r.service_account_secret_binding.as_deref()),
                ),
            ])
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
    );
    business.push(
        audit_capture::clear_guard(db, &preimage_id)
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
    );
    let actor = audit_capture::admin_actor(authorization)
        .map_err(|_| DirectoryError("directory_storage_failed"))?;
    if let Some(customer) = input.customer_id.filter(|_| enforced) {
        let authority = provisioning::DirectoryAuthority {
            tenant_id: input.tenant_id,
            provider_id: "google_workspace".into(),
            authority_id: customer,
        };
        provisioning::configure_authority(db, &authority, enforced, None, actor, business, now)
            .await
            .map_err(|error| DirectoryError(error.code))
    } else {
        let mut event = prepare_audit_event(
            db,
            Some(request),
            Some(actor),
            "directory.google.configure",
            None,
            None,
            Some("google_workspace"),
            serde_json::json!({}),
            now,
        )
        .await
        .map_err(|_| DirectoryError("directory_storage_failed"))?;
        event.0.organization_id = Some(input.tenant_id.clone());
        event.0.targets.push(
            zeroth_audit::AuditTarget::new("tenant", input.tenant_id)
                .map_err(|_| DirectoryError("directory_storage_failed"))?,
        );
        audit_capture::commit(db, business, &[event])
            .await
            .map_err(|_| DirectoryError("directory_storage_failed"))
    }
}

#[cfg(target_arch = "wasm32")]
async fn run_sync(
    db: &worker::d1::D1Database,
    env: &Env,
    tenant_id: &str,
) -> Result<(), DirectoryError> {
    use worker::d1::D1Type as V;
    validate_tenant(db, tenant_id).await?;
    let row = row(db, tenant_id)
        .await
        .map_err(|_| DirectoryError("directory_storage_failed"))?
        .ok_or(DirectoryError("directory_not_configured"))?;
    if row.enabled == 0 {
        return Err(DirectoryError("directory_polling_disabled"));
    }
    let now = unix_timestamp_seconds();
    let config = row.config()?;
    let authority = row.authority()?;
    if row.lease_expires_at.is_some_and(|expiry| expiry > now) {
        return Err(DirectoryError("directory_sync_running"));
    }
    let lease = random_token().map_err(|_| DirectoryError("directory_storage_failed"))?;
    let guard_id = format!("directory_lease_{lease}");
    let args = [
        V::Text(tenant_id),
        V::Text(&lease),
        V::Integer(now + LEASE_SECONDS),
        V::Integer(now),
        V::Integer(now + POLL_SECONDS),
        V::Text(&config.customer_id),
        V::Text(&config.delegated_admin_email),
        V::Text(&config.service_account_secret_binding),
    ];
    let acquisition = vec![
        db.prepare(ACQUIRE_LEASE_SQL)
            .bind_refs(&args)
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
        db.prepare(ACQUIRED_GUARD_SQL)
            .bind_refs(&[
                V::Text(&guard_id),
                V::Text(tenant_id),
                V::Text(&lease),
                V::Integer(now),
            ])
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
        provisioning::snapshot_fence_statement(db, &authority, &lease)
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
        audit_capture::clear_guard(db, &guard_id)
            .map_err(|_| DirectoryError("directory_storage_failed"))?,
    ];
    let acquired = db
        .batch(acquisition)
        .await
        .map_err(|_| DirectoryError("directory_sync_running"))?;
    if !acquired.iter().all(|result| result.success()) {
        return Err(DirectoryError("directory_storage_failed"));
    }
    let attempt = async {
        let known = provisioning::list_external_ids(db, &authority)
            .await
            .map_err(|error| DirectoryError(error.code))?;
        let snapshot = adapter::collect(
            &WorkerTransport {
                deadline: now + 240,
            },
            &WorkerCredentials(env),
            &config,
            &known,
            i64::from(now),
        )
        .await?;
        let changes = snapshot
            .into_principals()
            .into_iter()
            .map(|user| provisioning::DirectoryUserChange {
                external_id: user.id.clone(),
                user_name: if user.primary_email.is_empty() {
                    user.id
                } else {
                    user.primary_email
                },
                display_name: None,
                profile_json: None,
                active: user.active,
                deleted: user.deleted,
            })
            .collect();
        provisioning::apply_snapshot_guarded(
            db,
            &authority,
            changes,
            unix_timestamp_seconds(),
            &lease,
        )
        .await
        .map_err(|error| DirectoryError(error.code))
    }
    .await;
    let finished = unix_timestamp_seconds();
    match attempt {
        Ok(summary) => {
            db.prepare(FINISH_SUCCESS_SQL)
                .bind_refs(&[
                    V::Text(tenant_id),
                    V::Text(&lease),
                    V::Integer(finished),
                    V::Integer(summary.processed as i32),
                    V::Integer(summary.deactivated as i32),
                    V::Integer(finished + POLL_SECONDS),
                ])
                .map_err(|_| DirectoryError("directory_storage_failed"))?
                .run()
                .await
                .map_err(|_| DirectoryError("directory_storage_failed"))?;
            Ok(())
        }
        Err(error) => {
            db.prepare(FINISH_FAILURE_SQL)
                .bind_refs(&[
                    V::Text(tenant_id),
                    V::Text(&lease),
                    V::Text(error.0),
                    V::Integer(finished + POLL_SECONDS),
                ])
                .map_err(|_| DirectoryError("directory_storage_failed"))?
                .run()
                .await
                .map_err(|_| DirectoryError("directory_storage_failed"))?;
            Err(error)
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn response_error(error: DirectoryError, status: u16) -> worker::Result<Response> {
    json_status_no_store(&serde_json::json!({"error":error.0}), status)
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn handle(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    let now = unix_timestamp_seconds();
    if request.method() == Method::Get {
        if let Err(error) = authorize_admin_request(&request, &env, &db, &config, now).await {
            return client_management_error_json(&error);
        }
        let pairs: Vec<_> = url.query_pairs().collect();
        if pairs.len() != 1 || pairs[0].0 != "tenant_id" {
            return response_error(DirectoryError("invalid_request"), 400);
        }
        let id = match validate_account_tenant_id_value(&pairs[0].1) {
            Ok(id) => id,
            Err(_) => return response_error(DirectoryError("invalid_tenant_id"), 400),
        };
        if let Err(error) = validate_tenant(&db, &id).await {
            return response_error(error, 400);
        }
        return json_status_no_store(&status(&db, &env, &id).await?, 200);
    }
    if request.method() != Method::Post || url.query().is_some() {
        return response_error(DirectoryError("invalid_request"), 400);
    }
    let authorization = match maybe_authorize_admin_write_request(
        &mut request,
        &env,
        &db,
        &config,
        now,
        CSRF_ROUTE_FAMILY_ADMIN,
        false,
        "directory_admin_mutation",
    )
    .await
    {
        Ok(Some(auth)) => auth,
        Ok(None) => return response_error(DirectoryError("unauthorized"), 401),
        Err(error) => return client_management_error_json(&error),
    };
    let path = canonical_route_path(url.path());
    if path == "/tenants/google-directory-config" {
        let input = match load_body::<ConfigRequest>(&mut request).await {
            Ok(input) => input,
            Err(error) => return response_error(error, 400),
        };
        let id = input.tenant_id.trim().to_owned();
        if let Err(error) = save(&db, &request, &authorization, input).await {
            return response_error(error, 400);
        }
        json_status_no_store(&status(&db, &env, &id).await?, 200)
    } else if path == "/tenants/google-directory-sync" {
        let input = match load_body::<SyncRequest>(&mut request).await {
            Ok(input) => input,
            Err(error) => return response_error(error, 400),
        };
        let id = match validate_account_tenant_id_value(&input.tenant_id) {
            Ok(id) => id,
            Err(_) => return response_error(DirectoryError("invalid_tenant_id"), 400),
        };
        if let Err(error) = validate_tenant(&db, &id).await {
            return response_error(error, 400);
        }
        let actor = audit_capture::admin_actor(&authorization).map_err(worker_error)?;
        let mut event = prepare_audit_event(
            &db,
            Some(&request),
            Some(actor),
            "directory.google.sync.request",
            None,
            None,
            Some("google_workspace"),
            serde_json::json!({}),
            now,
        )
        .await?;
        event.0.organization_id = Some(id.clone());
        event.0.targets.push(
            zeroth_audit::AuditTarget::new("tenant", &id)
                .map_err(|_| worker_error("invalid directory target".into()))?,
        );
        audit_capture::commit(&db, Vec::new(), &[event]).await?;
        if let Err(error) = run_sync(&db, &env, &id).await {
            // Completed attempts preserve their fixed lastErrorCode in status.
            if matches!(
                error.0,
                "directory_sync_running"
                    | "directory_not_configured"
                    | "directory_polling_disabled"
                    | "google_tenant_required"
                    | "tenant_not_found"
            ) {
                return response_error(error, 409);
            }
        }
        json_status_no_store(&status(&db, &env, &id).await?, 200)
    } else {
        response_error(DirectoryError("not_found"), 404)
    }
}

/// Scheduled host wiring calls this function. Jobs remain tenant-scoped and
/// fenced; failures never disable managed enforcement or advance full-sync age.
#[cfg(target_arch = "wasm32")]
pub(super) async fn sync_due(env: &Env) -> worker::Result<usize> {
    #[derive(Deserialize)]
    struct Due {
        tenant_id: String,
    }
    let db = env.d1(D1_BINDING)?;
    let now = unix_timestamp_seconds();
    let due=db.prepare("SELECT g.tenant_id FROM zeroth_google_directory g JOIN zeroth_tenants t ON t.id=g.tenant_id
        WHERE g.enabled=1 AND t.disabled=0 AND t.enterprise_provider='google_workspace'
          AND (g.next_sync_at IS NULL OR g.next_sync_at<=?1) AND (g.lease_expires_at IS NULL OR g.lease_expires_at<=?1)
        ORDER BY COALESCE(g.next_sync_at,0),g.tenant_id LIMIT 10").bind_refs(&[worker::d1::D1Type::Integer(now)])?.all().await?.results::<Due>()?;
    let mut count = 0;
    for job in due {
        if unix_timestamp_seconds() - now >= 240 {
            break;
        }
        match run_sync(&db, env, &job.tenant_id).await {
            Ok(()) => count += 1,
            Err(error) => {
                tracing::warn!(target:"zeroth.directory",error_code=error.0,"directory_poll_failed")
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in zeroth_storage::migrations::ALL {
            for statement in migration.statements() {
                db.execute_batch(statement).unwrap();
            }
        }
        db.execute("INSERT INTO zeroth_tenants(id,name,enterprise_provider,created_at,updated_at) VALUES ('acme','Acme','google_workspace',1,1)",[]).unwrap();
        db.execute(
            UPSERT_CONFIG_SQL,
            params![
                "acme",
                1,
                1,
                "C012345",
                "admin@acme.example",
                "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT",
                1,
                1
            ],
        )
        .unwrap();
        db
    }

    #[test]
    fn admin_config_accepts_only_references_and_explicit_pins() {
        let input = serde_json::json!({"tenantId":"acme","enabled":true,"customerId":"C012345","delegatedAdminEmail":"admin@acme.example","serviceAccountSecretBinding":"TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT"});
        normalize_request(serde_json::from_value(input.clone()).unwrap()).unwrap();
        let mut secret = input.clone();
        secret["privateKey"] = "secret".into();
        assert!(serde_json::from_value::<ConfigRequest>(secret).is_err());
        let mut invalid = input.clone();
        invalid["customerId"] = "my_customer".into();
        assert!(normalize_request(serde_json::from_value(invalid).unwrap()).is_err());
        let mut invalid = input;
        invalid["serviceAccountSecretBinding"] = "JWT_ES256_PRIVATE_KEY".into();
        assert!(normalize_request(serde_json::from_value(invalid).unwrap()).is_err());
        normalize_request(serde_json::from_value(serde_json::json!({"tenantId":"acme","enabled":false,"customerId":null,"delegatedAdminEmail":null,"serviceAccountSecretBinding":null})).unwrap()).unwrap();
    }

    #[test]
    fn paused_polling_cannot_clear_enforcement_or_success_evidence() {
        let db = database();
        db.execute(
            "UPDATE zeroth_google_directory SET last_success_at=100,last_seen_count=2",
            [],
        )
        .unwrap();
        db.execute(
            UPSERT_CONFIG_SQL,
            params![
                "acme",
                0,
                0,
                "C012345",
                "admin@acme.example",
                "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT",
                Option::<i32>::None,
                101
            ],
        )
        .unwrap();
        let state: (i32, i32, i32) = db
            .query_row(
                "SELECT enabled,managed_enforced,last_success_at FROM zeroth_google_directory",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, (0, 1, 100));
    }

    #[test]
    fn racing_poll_cannot_replace_an_active_lease_and_old_completions_cannot_overwrite_new() {
        let mut db = database();
        {
            let tx = db.transaction().unwrap();
            assert_eq!(
                tx.execute(
                    ACQUIRE_LEASE_SQL,
                    params![
                        "acme",
                        "lease_a",
                        700,
                        100,
                        400,
                        "C012345",
                        "admin@acme.example",
                        "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT"
                    ]
                )
                .unwrap(),
                1
            );
            tx.execute(
                ACQUIRED_GUARD_SQL,
                params!["guard_a", "acme", "lease_a", 100],
            )
            .unwrap();
            tx.execute("DELETE FROM zeroth_audit_write_guards", [])
                .unwrap();
            tx.commit().unwrap();
        }
        {
            let tx = db.transaction().unwrap();
            assert_eq!(
                tx.execute(
                    ACQUIRE_LEASE_SQL,
                    params![
                        "acme",
                        "lease_b",
                        701,
                        101,
                        401,
                        "C012345",
                        "admin@acme.example",
                        "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT"
                    ]
                )
                .unwrap(),
                0
            );
            assert!(tx
                .execute(
                    ACQUIRED_GUARD_SQL,
                    params!["guard_b", "acme", "lease_b", 101]
                )
                .is_err());
        }
        assert!(db
            .execute(CONFIG_LEASE_GUARD_SQL, params!["edit", "acme", 101])
            .is_err());
        assert_eq!(
            db.execute(
                FINISH_SUCCESS_SQL,
                params!["acme", "lease_b", 200, 2, 1, 500]
            )
            .unwrap(),
            0
        );
        assert_eq!(
            db.execute(
                FINISH_FAILURE_SQL,
                params!["acme", "lease_b", "stale_attempt", 500]
            )
            .unwrap(),
            0
        );
        let lease: String = db
            .query_row("SELECT lease_id FROM zeroth_google_directory", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(lease, "lease_a");
    }

    #[test]
    fn stale_admin_draft_cannot_disable_newly_enabled_management() {
        let db = database();
        assert!(db
            .execute(
                CONFIG_PREIMAGE_GUARD_SQL,
                params![
                    "stale",
                    "acme",
                    1,
                    0,
                    0,
                    "C012345",
                    "admin@acme.example",
                    "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT"
                ]
            )
            .is_err());
        db.execute(
            CONFIG_PREIMAGE_GUARD_SQL,
            params![
                "fresh",
                "acme",
                1,
                1,
                1,
                "C012345",
                "admin@acme.example",
                "TENANT_ACME_GOOGLE_DIRECTORY_SERVICE_ACCOUNT"
            ],
        )
        .unwrap();
    }
}
