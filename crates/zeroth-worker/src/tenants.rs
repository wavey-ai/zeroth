//! Explicit organization ownership. Legacy account namespaces are not evidence
//! of organization ownership. Tenant credentials are deployment-secret references.

use super::*;
use std::collections::BTreeSet;

const TENANT_LIMIT: usize = 256;
const MEMBER_LIMIT: usize = 128;
const BODY_LIMIT: usize = 64 * 1024;
const TENANT_SQL: &str = "SELECT * FROM zeroth_tenants WHERE id = ?1";
const OWNER_SQL: &str = "SELECT tenant_id FROM zeroth_tenant_clients WHERE client_id = ?1";
const LIST_SQL: &str = "SELECT t.*,
    (SELECT json_group_array(client_id) FROM
        (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=t.id ORDER BY client_id)) AS client_ids_json,
    (SELECT json_group_array(json_object('user_id',user_id,'can_export',can_export)) FROM
        (SELECT user_id,can_export FROM zeroth_tenant_audit_readers WHERE tenant_id=t.id ORDER BY user_id)) AS audit_readers_json
    FROM zeroth_tenants t ORDER BY t.id LIMIT 257";
const UPSERT_TENANT_SQL: &str = "INSERT INTO zeroth_tenants (
    id,name,disabled,enterprise_provider,entra_tenant_id,google_workspace_domains_json,
    oidc_client_id,client_secret_binding,retention_days,created_at,updated_at
    ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)
    ON CONFLICT(id) DO UPDATE SET name=excluded.name,disabled=excluded.disabled,
    enterprise_provider=excluded.enterprise_provider,entra_tenant_id=excluded.entra_tenant_id,
    google_workspace_domains_json=excluded.google_workspace_domains_json,
    oidc_client_id=excluded.oidc_client_id,client_secret_binding=excluded.client_secret_binding,
    retention_days=excluded.retention_days,updated_at=excluded.updated_at";
// An ownership conflict raises NOT NULL and aborts the complete transaction.
// This remains safe when another registration wins after the preliminary read.
const BIND_CLIENT_SQL: &str =
    "INSERT INTO zeroth_tenant_clients (client_id,tenant_id,enterprise_provider)
    VALUES (?1,?2,?3) ON CONFLICT(client_id) DO UPDATE SET
    tenant_id=CASE WHEN zeroth_tenant_clients.tenant_id=excluded.tenant_id
        THEN zeroth_tenant_clients.tenant_id ELSE NULL END,
    enterprise_provider=excluded.enterprise_provider";
const APPLY_CLIENT_POLICY_SQL: &str = "UPDATE zeroth_clients SET account_sharing_mode='tenant',
    account_tenant_id=?1,enterprise_provider=?2,updated_at=?3
    WHERE id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)";
const READER_SQL: &str =
    "SELECT can_export FROM zeroth_tenant_audit_readers WHERE tenant_id=?1 AND user_id=?2";
const INVALIDATE_CLIENT_CREDENTIALS_SQL: &[&str] = &[
    "UPDATE zeroth_sessions SET revoked_at=COALESCE(revoked_at,?2) WHERE client_id=?1",
    "UPDATE zeroth_refresh_tokens SET revoked_at=COALESCE(revoked_at,?2) WHERE client_id=?1",
    "UPDATE zeroth_auth_codes SET consumed_at=COALESCE(consumed_at,?2) WHERE client_id=?1",
    "UPDATE zeroth_auth_transactions SET consumed_at=COALESCE(consumed_at,?2) WHERE client_id=?1",
];
const CONNECTION_PREIMAGE_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN (?3=0 AND NOT EXISTS(SELECT 1 FROM zeroth_tenants WHERE id=?2))
      OR (?3=1 AND EXISTS(SELECT 1 FROM zeroth_tenants WHERE id=?2 AND disabled=?4
        AND enterprise_provider IS ?5 AND entra_tenant_id IS ?6 AND google_workspace_domains_json=?7
        AND oidc_client_id IS ?8 AND client_secret_binding IS ?9)) THEN 1 ELSE 0 END";
const DIRECTORY_AUTHORITY_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN EXISTS(SELECT 1 FROM zeroth_tenants WHERE id=?2
        AND enterprise_provider IS ?3 AND entra_tenant_id IS ?4)
      OR (NOT EXISTS(SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?2)
        AND NOT EXISTS(SELECT 1 FROM zeroth_directory_links WHERE tenant_id=?2))
    THEN 1 ELSE 0 END";

fn connection_changed(previous: Option<&TenantRow>, next: &TenantUpsert, domains: &str) -> bool {
    previous.is_none_or(|old| {
        old.disabled != i32::from(next.disabled)
            || old.enterprise_provider != next.enterprise_provider
            || old.entra_tenant_id != next.entra_tenant_id
            || old.google_workspace_domains_json != domains
            || old.oidc_client_id != next.oidc_client_id
            || old.client_secret_binding != next.client_secret_binding
    })
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct TenantRow {
    pub id: String,
    pub name: String,
    pub disabled: i32,
    pub enterprise_provider: Option<String>,
    pub entra_tenant_id: Option<String>,
    pub google_workspace_domains_json: String,
    pub oidc_client_id: Option<String>,
    pub client_secret_binding: Option<String>,
    pub retention_days: Option<i32>,
    pub created_at: i32,
    pub updated_at: i32,
}

impl TenantRow {
    pub fn is_disabled(&self) -> bool {
        self.disabled != 0
    }

    fn provider(&self, requested: &str) -> Result<OAuthProvider, String> {
        if self.is_disabled() {
            return Err("tenant is disabled".into());
        }
        if self.enterprise_provider.as_deref() != Some(requested) {
            return Err("tenant requires its configured enterprise provider".into());
        }
        let client_id = self
            .oidc_client_id
            .as_deref()
            .ok_or("tenant connection is a draft")?;
        match requested {
            well_known::ENTRA => OAuthProvider::entra(
                client_id,
                self.entra_tenant_id
                    .as_deref()
                    .ok_or("tenant connection is a draft")?,
            ),
            well_known::GOOGLE_WORKSPACE => {
                let domains: Vec<String> =
                    serde_json::from_str(&self.google_workspace_domains_json)
                        .map_err(|_| "invalid tenant domain policy")?;
                OAuthProvider::google_workspace(client_id, domains)
            }
            _ => return Err("tenant requires an enterprise provider".into()),
        }
        .map_err(|_| "invalid tenant enterprise policy".into())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuditReader {
    pub user_id: String,
    pub can_export: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TenantUpsert {
    id: String,
    name: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    client_ids: Vec<String>,
    #[serde(default)]
    audit_readers: Vec<AuditReader>,
    #[serde(default)]
    enterprise_provider: Option<String>,
    #[serde(default)]
    entra_tenant_id: Option<String>,
    #[serde(default)]
    google_workspace_domains: Vec<String>,
    #[serde(default)]
    oidc_client_id: Option<String>,
    #[serde(default)]
    client_secret_binding: Option<String>,
    #[serde(default)]
    retention_days: Option<i32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TenantResponse {
    pub id: String,
    pub name: String,
    pub disabled: bool,
    pub client_ids: Vec<String>,
    pub audit_readers: Vec<AuditReader>,
    pub enterprise_provider: Option<String>,
    pub entra_tenant_id: Option<String>,
    pub google_workspace_domains: Vec<String>,
    pub oidc_client_id: Option<String>,
    pub client_secret_binding: Option<String>,
    pub connection_configured: bool,
    pub created_at: i32,
    pub updated_at: i32,
    pub retention_days: Option<i32>,
}

#[derive(Deserialize)]
struct JoinedRow {
    #[serde(flatten)]
    tenant: TenantRow,
    client_ids_json: String,
    audit_readers_json: String,
}

#[derive(Deserialize)]
struct ReaderRow {
    user_id: String,
    can_export: i32,
}
#[derive(Deserialize)]
struct OwnerRow {
    tenant_id: String,
}
#[derive(Deserialize)]
struct ExportRow {
    can_export: i32,
}

fn optional_value(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn validate_secret_binding(value: &str) -> Result<(), String> {
    let body = value
        .strip_prefix("TENANT_")
        .and_then(|value| value.strip_suffix("_CLIENT_SECRET"));
    if value.len() > 128
        || body.is_none_or(|body| body.is_empty())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("clientSecretBinding must be TENANT_<NAME>_CLIENT_SECRET (uppercase letters, digits and underscores; at most 128 characters)".into());
    }
    Ok(())
}

fn validate(mut request: TenantUpsert) -> Result<TenantUpsert, String> {
    request.id = validate_account_tenant_id_value(&request.id)?;
    request.name = request.name.trim().to_owned();
    if request.name.is_empty()
        || request.name.chars().count() > 128
        || request.name.chars().any(char::is_control)
    {
        return Err("tenant name must contain 1 to 128 display characters".into());
    }
    if request
        .retention_days
        .is_some_and(|days| !(1..=3650).contains(&days))
    {
        return Err("retentionDays must be 1 to 3650, or null; setting it does not automatically purge history".into());
    }
    if request.client_ids.len() > MEMBER_LIMIT || request.audit_readers.len() > MEMBER_LIMIT {
        return Err("tenant supports at most 128 clients and 128 audit readers".into());
    }
    let mut clients = BTreeSet::new();
    for id in &mut request.client_ids {
        *id = validate_client_id(id).map_err(|error| error.description)?;
        if !clients.insert(id.clone()) {
            return Err("duplicate tenant client".into());
        }
    }
    request.client_ids.sort();
    let mut readers = BTreeSet::new();
    for reader in &mut request.audit_readers {
        reader.user_id =
            validate_admin_user_id(&reader.user_id).map_err(|error| error.description)?;
        if !readers.insert(reader.user_id.clone()) {
            return Err("duplicate tenant audit reader".into());
        }
    }
    request
        .audit_readers
        .sort_by(|a, b| a.user_id.cmp(&b.user_id));
    request.enterprise_provider = optional_value(request.enterprise_provider);
    request.entra_tenant_id = optional_value(request.entra_tenant_id);
    request.oidc_client_id = optional_value(request.oidc_client_id);
    request.client_secret_binding = optional_value(request.client_secret_binding);
    if let Some(binding) = &request.client_secret_binding {
        validate_secret_binding(binding)?;
    }
    match request.enterprise_provider.as_deref() {
        None => {
            if !request.client_ids.is_empty() {
                return Err("bound clients require a tenant enterprise provider".into());
            }
            if request.entra_tenant_id.is_some()
                || !request.google_workspace_domains.is_empty()
                || request.oidc_client_id.is_some()
                || request.client_secret_binding.is_some()
            {
                return Err(
                    "clear connection settings when no enterprise provider is selected".into(),
                );
            }
        }
        Some(well_known::ENTRA) => {
            if !request.google_workspace_domains.is_empty() {
                return Err("Entra does not use Google Workspace domains".into());
            }
            if let Some(tenant) = &request.entra_tenant_id {
                request.entra_tenant_id = EnterpriseProviderPolicy::entra(tenant)
                    .map_err(|_| "entraTenantId must be a tenant GUID")?
                    .tenant_id()
                    .map(str::to_owned);
            }
            if let Some(client_id) = &request.oidc_client_id {
                request.oidc_client_id = EnterpriseProviderPolicy::entra(client_id)
                    .map_err(|_| "Entra oidcClientId must be an application GUID")?
                    .tenant_id()
                    .map(str::to_owned);
            }
        }
        Some(well_known::GOOGLE_WORKSPACE) => {
            if request.entra_tenant_id.is_some() {
                return Err("Google Workspace does not use an Entra tenant ID".into());
            }
            if !request.google_workspace_domains.is_empty() {
                request.google_workspace_domains =
                    EnterpriseProviderPolicy::google_workspace(&request.google_workspace_domains)
                        .map_err(|_| {
                            "googleWorkspaceDomains must contain at most 32 exact DNS domains"
                        })?
                        .domains()
                        .to_vec();
            }
            if let Some(client_id) = &request.oidc_client_id {
                let valid = client_id
                    .strip_suffix(".apps.googleusercontent.com")
                    .and_then(|value| value.split_once('-'))
                    .is_some_and(|(number, suffix)| {
                        !number.is_empty()
                            && !suffix.is_empty()
                            && number.bytes().all(|byte| byte.is_ascii_digit())
                            && suffix.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                            })
                    });
                if client_id.len() > 256 || !valid {
                    return Err("Google oidcClientId must be a web OAuth client ID".into());
                }
            }
        }
        _ => return Err("enterpriseProvider must be entra, google_workspace, or null".into()),
    }
    Ok(request)
}

fn validate_existing_clients(request: &TenantUpsert, existing: &[String]) -> Result<(), String> {
    if existing.iter().any(|id| !request.client_ids.contains(id)) {
        return Err("client ownership is permanent; keep existing clientIds and disable unwanted clients instead".into());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
async fn get(db: &worker::d1::D1Database, id: &str) -> worker::Result<Option<TenantRow>> {
    db.prepare(TENANT_SQL)
        .bind_refs(&[worker::d1::D1Type::Text(id)])?
        .first(None)
        .await
}

/// Explicit ownership only; never derive it from the legacy namespace columns.
#[cfg(target_arch = "wasm32")]
pub(super) async fn organization_for_client(
    db: &worker::d1::D1Database,
    client_id: Option<&str>,
) -> worker::Result<Option<String>> {
    let Some(client_id) = client_id else {
        return Ok(None);
    };
    let owner = db
        .prepare(OWNER_SQL)
        .bind_refs(&[worker::d1::D1Type::Text(client_id)])?
        .first::<OwnerRow>(None)
        .await?;
    Ok(owner.map(|owner| owner.tenant_id))
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn tenant_for_client(
    db: &worker::d1::D1Database,
    client_id: &str,
) -> worker::Result<Option<TenantRow>> {
    let Some(id) = organization_for_client(db, Some(client_id)).await? else {
        return Ok(None);
    };
    // Missing registered ownership is corruption, never permission to fall back.
    get(db, &id)
        .await?
        .map(Some)
        .ok_or_else(|| worker_error("client tenant is missing".into()))
}

#[cfg(target_arch = "wasm32")]
fn tenant_secret(env: &Env, row: &TenantRow) -> Option<String> {
    let binding = row.client_secret_binding.as_deref()?;
    validate_secret_binding(binding).ok()?;
    secret_string(env, binding)
        .filter(|value| value.len() <= 8192 && config_value_configured(Some(value)))
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn provider_for_client(
    db: &worker::d1::D1Database,
    env: &Env,
    client_id: &str,
    provider_id: &str,
) -> worker::Result<OAuthProvider> {
    match tenant_for_client(db, client_id).await? {
        None => provider_from_env(env, provider_id),
        Some(row) => {
            let provider = row.provider(provider_id).map_err(worker_error)?;
            if tenant_secret(env, &row).is_none() {
                return Err(worker_error(
                    "tenant client secret is not configured".into(),
                ));
            }
            Ok(provider)
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn secret_for_client(
    db: &worker::d1::D1Database,
    env: &Env,
    client_id: &str,
    provider_id: &str,
) -> worker::Result<Option<String>> {
    match tenant_for_client(db, client_id).await? {
        None => provider_client_secret_from_env(env, provider_id),
        Some(row) => {
            row.provider(provider_id).map_err(worker_error)?;
            tenant_secret(env, &row)
                .map(Some)
                .ok_or_else(|| worker_error("tenant client secret is not configured".into()))
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn configured_for_client(
    db: &worker::d1::D1Database,
    env: &Env,
    client_id: &str,
    provider_id: &str,
) -> worker::Result<bool> {
    match tenant_for_client(db, client_id).await? {
        None => Ok(provider_configured_for_login(env, provider_id)),
        Some(row) => Ok(row.provider(provider_id).is_ok() && tenant_secret(env, &row).is_some()),
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn validate_client_update(
    db: &worker::d1::D1Database,
    update: &ValidatedClientUpsert,
) -> worker::Result<Result<(), String>> {
    let tenant = tenant_for_client(db, &update.id).await?;
    if let Some(tenant) = tenant {
        if update.account_sharing_mode != AccountSharingMode::Tenant
            || update.account_tenant_id != tenant.id
            || update.enterprise_provider != tenant.enterprise_provider
        {
            return Ok(Err("tenant-owned clients must preserve their registered namespace and enterprise provider".into()));
        }
    }
    Ok(Ok(()))
}

#[cfg(target_arch = "wasm32")]
async fn resources(db: &worker::d1::D1Database, env: &Env) -> worker::Result<Vec<TenantResponse>> {
    let rows = db.prepare(LIST_SQL).all().await?.results::<JoinedRow>()?;
    if rows.len() > TENANT_LIMIT {
        return Err(worker_error("tenant registration limit exceeded".into()));
    }
    rows.into_iter()
        .map(|row| {
            let provider = row.tenant.enterprise_provider.as_deref();
            let configured = provider.is_some_and(|id| row.tenant.provider(id).is_ok())
                && tenant_secret(env, &row.tenant).is_some();
            let clients: Vec<String> = serde_json::from_str(&row.client_ids_json)
                .map_err(|_| worker_error("invalid tenant clients".into()))?;
            let readers: Vec<ReaderRow> = serde_json::from_str(&row.audit_readers_json)
                .map_err(|_| worker_error("invalid tenant readers".into()))?;
            let domains = serde_json::from_str(&row.tenant.google_workspace_domains_json)
                .map_err(|_| worker_error("invalid tenant domains".into()))?;
            Ok(TenantResponse {
                id: row.tenant.id,
                name: row.tenant.name,
                disabled: row.tenant.disabled != 0,
                client_ids: clients,
                audit_readers: readers
                    .into_iter()
                    .map(|r| AuditReader {
                        user_id: r.user_id,
                        can_export: r.can_export != 0,
                    })
                    .collect(),
                enterprise_provider: row.tenant.enterprise_provider,
                entra_tenant_id: row.tenant.entra_tenant_id,
                google_workspace_domains: domains,
                oidc_client_id: row.tenant.oidc_client_id,
                client_secret_binding: row.tenant.client_secret_binding,
                connection_configured: configured,
                created_at: row.tenant.created_at,
                updated_at: row.tenant.updated_at,
                retention_days: row.tenant.retention_days,
            })
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn list_ui(
    db: &worker::d1::D1Database,
    env: &Env,
) -> worker::Result<Vec<zeroth_ui::TenantAdminUi>> {
    Ok(resources(db, env)
        .await?
        .into_iter()
        .map(|t| zeroth_ui::TenantAdminUi {
            id: t.id,
            name: t.name,
            disabled: t.disabled,
            client_ids: t.client_ids,
            audit_readers: t
                .audit_readers
                .into_iter()
                .map(|r| zeroth_ui::TenantAuditReaderUi {
                    user_id: r.user_id,
                    can_export: r.can_export,
                })
                .collect(),
            enterprise_provider: t.enterprise_provider,
            entra_tenant_id: t.entra_tenant_id,
            google_workspace_domains: t.google_workspace_domains,
            oidc_client_id: t.oidc_client_id,
            client_secret_binding: t.client_secret_binding,
            connection_configured: t.connection_configured,
            created_at: Some(t.created_at.to_string()),
            updated_at: Some(t.updated_at.to_string()),
            retention_days: t.retention_days,
        })
        .collect())
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn require_audit_read(
    request: &Request,
    env: &Env,
    db: &worker::d1::D1Database,
    config: &ZerothServerConfig,
    tenant_id: &str,
    export: bool,
    now: i32,
) -> Result<(), ClientManagementError> {
    validate_account_tenant_id_value(tenant_id).map_err(ClientManagementError::invalid_request)?;
    match authorize_admin_request(request, env, db, config, now).await {
        Ok(_) => return Ok(()),
        Err(error) if error.status >= 500 => return Err(error),
        Err(_) => {}
    }
    let tenant = get(db, tenant_id)
        .await
        .map_err(|_| ClientManagementError::server_error("could not load tenant"))?
        .ok_or_else(|| ClientManagementError::not_found("tenant was not found"))?;
    if tenant.is_disabled() {
        return Err(ClientManagementError {
            code: "access_denied".into(),
            description: "tenant is disabled".into(),
            status: 403,
        });
    }
    let current = current_session_from_request(request, env, db, config, now)
        .await
        .map_err(|_| {
            ClientManagementError::server_error("could not validate audit reader session")
        })?
        .ok_or_else(|| ClientManagementError::unauthorized("active browser session is required"))?;
    let args = [
        worker::d1::D1Type::Text(tenant_id),
        worker::d1::D1Type::Text(&current.user.id),
    ];
    let permission = db
        .prepare(READER_SQL)
        .bind_refs(&args)
        .map_err(|_| ClientManagementError::server_error("could not load audit reader"))?
        .first::<ExportRow>(None)
        .await
        .map_err(|_| ClientManagementError::server_error("could not load audit reader"))?;
    if permission.is_some_and(|row| !export || row.can_export != 0) {
        let active = provisioning::tenant_user_is_active(db, &current.user.id, tenant_id, now)
            .await
            .map_err(|_| {
                ClientManagementError::server_error("could not validate tenant audit access")
            })?;
        if active {
            Ok(())
        } else {
            Err(ClientManagementError {
                code: "access_denied".into(),
                description: "active tenant directory access is required".into(),
                status: 403,
            })
        }
    } else {
        Err(ClientManagementError {
            code: "access_denied".into(),
            description: "tenant audit permission is required".into(),
            status: 403,
        })
    }
}

#[cfg(target_arch = "wasm32")]
async fn body(request: &mut Request) -> Result<TenantUpsert, ClientManagementError> {
    use futures_util::StreamExt;
    if !content_type_is_json(
        request_header(request, "Content-Type")
            .map_err(|_| ClientManagementError::invalid_request("invalid Content-Type"))?
            .as_deref(),
    ) {
        return Err(ClientManagementError::invalid_request(
            "Content-Type must be application/json",
        ));
    }
    reject_oversized_content_length(request, BODY_LIMIT)
        .map_err(ClientManagementError::invalid_request)?;
    let mut stream = request
        .stream()
        .map_err(|_| ClientManagementError::invalid_request("invalid tenant body"))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| ClientManagementError::invalid_request("invalid tenant body"))?;
        if chunk.len() > BODY_LIMIT.saturating_sub(bytes.len()) {
            return Err(ClientManagementError::payload_too_large(
                "tenant body exceeds 64 KiB",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let request = serde_json::from_slice(&bytes)
        .map_err(|_| ClientManagementError::invalid_request("invalid tenant JSON"))?;
    validate(request).map_err(ClientManagementError::invalid_request)
}

#[cfg(target_arch = "wasm32")]
async fn save(
    db: &worker::d1::D1Database,
    request: &Request,
    authorization: &AdminAuthorization,
    upsert: TenantUpsert,
    now: i32,
) -> Result<(), ClientManagementError> {
    use worker::d1::D1Type as V;
    let storage_error = |_| ClientManagementError::server_error("tenant registration failed");
    let old = get(db, &upsert.id).await.map_err(storage_error)?;
    if old.as_ref().is_some_and(|old| {
        old.enterprise_provider != upsert.enterprise_provider
            || old.entra_tenant_id != upsert.entra_tenant_id
    }) {
        #[derive(Deserialize)]
        struct Locked {
            value: i32,
        }
        let locked=db.prepare("SELECT CASE WHEN EXISTS(SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?1)
            OR EXISTS(SELECT 1 FROM zeroth_directory_links WHERE tenant_id=?1) THEN 1 ELSE 0 END AS value")
            .bind_refs(&[V::Text(&upsert.id)]).map_err(storage_error)?.first::<Locked>(None).await.map_err(storage_error)?;
        if locked.is_some_and(|row| row.value != 0) {
            return Err(ClientManagementError::invalid_request(
                "tenant directory authority is immutable after provisioned identities or tombstones exist",
            ));
        }
    }
    if old.is_none() {
        let count = db
            .prepare("SELECT COUNT(*) AS value FROM zeroth_tenants")
            .first::<CountRow>(None)
            .await
            .map_err(storage_error)?;
        if count.is_none_or(|row| row.value >= TENANT_LIMIT as i32) {
            return Err(ClientManagementError::invalid_request(
                "deployment supports at most 256 registered tenants",
            ));
        }
    }
    let existing = db
        .prepare("SELECT client_id AS value FROM zeroth_tenant_clients WHERE tenant_id=?1")
        .bind_refs(&[V::Text(&upsert.id)])
        .map_err(storage_error)?
        .all()
        .await
        .map_err(storage_error)?
        .results::<StringRow>()
        .map_err(storage_error)?;
    let existing_client_ids = existing.into_iter().map(|r| r.value).collect::<Vec<_>>();
    validate_existing_clients(&upsert, &existing_client_ids)
        .map_err(ClientManagementError::invalid_request)?;
    for id in &upsert.client_ids {
        let client = get_client_row_for_admin(db, id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                ClientManagementError::invalid_request("every tenant client must already exist")
            })?;
        let owner = organization_for_client(db, Some(id))
            .await
            .map_err(storage_error)?;
        if owner.as_deref().is_some_and(|owner| owner != upsert.id) {
            return Err(ClientManagementError::invalid_request(
                "client already belongs to another tenant",
            ));
        }
        if owner.is_none()
            && client.account_sharing_mode.as_deref() == Some("tenant")
            && client.account_tenant_id.as_deref() != Some(&upsert.id)
        {
            return Err(ClientManagementError::invalid_request(
                "client already uses another tenant namespace; explicit migration is required",
            ));
        }
    }
    for reader in &upsert.audit_readers {
        if get_user(db, &reader.user_id)
            .await
            .map_err(storage_error)?
            .is_none()
        {
            return Err(ClientManagementError::invalid_request(
                "every audit reader must already exist",
            ));
        }
    }
    let domains = serde_json::to_string(&upsert.google_workspace_domains)
        .map_err(|_| ClientManagementError::server_error("invalid tenant domain policy"))?;
    let args = [
        V::Text(&upsert.id),
        V::Text(&upsert.name),
        V::Integer(i32::from(upsert.disabled)),
        d1_optional_text(upsert.enterprise_provider.as_deref()),
        d1_optional_text(upsert.entra_tenant_id.as_deref()),
        V::Text(&domains),
        d1_optional_text(upsert.oidc_client_id.as_deref()),
        d1_optional_text(upsert.client_secret_binding.as_deref()),
        d1_optional_integer(upsert.retention_days),
        V::Integer(now),
    ];
    let mut business = vec![db
        .prepare(UPSERT_TENANT_SQL)
        .bind_refs(&args)
        .map_err(storage_error)?];
    let invalidate_all = upsert.disabled || connection_changed(old.as_ref(), &upsert, &domains);
    if invalidate_all {
        for sql in INVALIDATE_CLIENT_CREDENTIALS_SQL {
            let sql = sql.replace("WHERE client_id=?1", "WHERE client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)");
            business.push(
                db.prepare(&sql)
                    .bind_refs(&[V::Text(&upsert.id), V::Integer(now)])
                    .map_err(storage_error)?,
            );
        }
    }
    for client_id in &upsert.client_ids {
        if !existing_client_ids.contains(client_id) {
            for sql in INVALIDATE_CLIENT_CREDENTIALS_SQL {
                business.push(
                    db.prepare(*sql)
                        .bind_refs(&[V::Text(client_id), V::Integer(now)])
                        .map_err(storage_error)?,
                );
            }
        }
    }
    for client in &upsert.client_ids {
        let provider = upsert.enterprise_provider.as_deref().ok_or_else(|| {
            ClientManagementError::invalid_request("bound clients require an enterprise provider")
        })?;
        business.push(
            db.prepare(BIND_CLIENT_SQL)
                .bind_refs(&[V::Text(client), V::Text(&upsert.id), V::Text(provider)])
                .map_err(storage_error)?,
        );
    }
    business.push(
        db.prepare(APPLY_CLIENT_POLICY_SQL)
            .bind_refs(&[
                V::Text(&upsert.id),
                d1_optional_text(upsert.enterprise_provider.as_deref()),
                V::Integer(now),
            ])
            .map_err(storage_error)?,
    );
    business.push(
        db.prepare("DELETE FROM zeroth_tenant_audit_readers WHERE tenant_id=?1")
            .bind_refs(&[V::Text(&upsert.id)])
            .map_err(storage_error)?,
    );
    for reader in &upsert.audit_readers {
        business.push(db.prepare("INSERT INTO zeroth_tenant_audit_readers(tenant_id,user_id,can_export) VALUES (?1,?2,?3)")
            .bind_refs(&[V::Text(&upsert.id),V::Text(&reader.user_id),V::Integer(i32::from(reader.can_export))]).map_err(storage_error)?);
    }
    let actor =
        audit_capture::admin_actor(authorization).map_err(ClientManagementError::server_error)?;
    let mut event = prepare_audit_event(
        db,
        Some(request),
        Some(actor),
        "tenant.upsert",
        None,
        None,
        upsert.enterprise_provider.as_deref(),
        serde_json::json!({"disabled":upsert.disabled,"changedFields":["tenant_configuration","tenant_client_bindings","tenant_audit_readers","retention_policy"]}),
        now,
    )
    .await
    .map_err(storage_error)?;
    event.0.organization_id = Some(upsert.id.clone());
    let policy = serde_json::to_string(&upsert)
        .map_err(|_| ClientManagementError::server_error("invalid tenant policy"))?;
    event.0.policy_reference = Some(hash_secret(&policy));
    event.0.targets.push(
        zeroth_audit::AuditTarget::new("tenant", &upsert.id)
            .map_err(|_| ClientManagementError::server_error("invalid tenant audit target"))?,
    );
    let guard_id = format!("tenant_limit_{}", event.0.event_id);
    business.insert(0, db.prepare("INSERT INTO zeroth_audit_write_guards(id,valid) VALUES (?1, CASE WHEN EXISTS (SELECT 1 FROM zeroth_tenants WHERE id=?2) OR (SELECT COUNT(*) FROM zeroth_tenants)<256 THEN 1 ELSE 0 END)")
        .bind_refs(&[V::Text(&guard_id),V::Text(&upsert.id)]).map_err(storage_error)?);
    business.push(
        db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?1")
            .bind_refs(&[V::Text(&guard_id)])
            .map_err(storage_error)?,
    );
    let preimage_guard = format!("tenant_connection_{}", event.0.event_id);
    let previous_args = [
        V::Text(&preimage_guard),
        V::Text(&upsert.id),
        V::Integer(i32::from(old.is_some())),
        V::Integer(old.as_ref().map_or(0, |t| t.disabled)),
        d1_optional_text(old.as_ref().and_then(|t| t.enterprise_provider.as_deref())),
        d1_optional_text(old.as_ref().and_then(|t| t.entra_tenant_id.as_deref())),
        V::Text(
            old.as_ref()
                .map_or("", |t| t.google_workspace_domains_json.as_str()),
        ),
        d1_optional_text(old.as_ref().and_then(|t| t.oidc_client_id.as_deref())),
        d1_optional_text(
            old.as_ref()
                .and_then(|t| t.client_secret_binding.as_deref()),
        ),
    ];
    business.insert(
        0,
        db.prepare(CONNECTION_PREIMAGE_GUARD_SQL)
            .bind_refs(&previous_args)
            .map_err(storage_error)?,
    );
    business.push(
        db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?1")
            .bind_refs(&[V::Text(&preimage_guard)])
            .map_err(storage_error)?,
    );
    let authority_guard = format!("tenant_authority_{}", event.0.event_id);
    business.insert(
        0,
        db.prepare(DIRECTORY_AUTHORITY_GUARD_SQL)
            .bind_refs(&[
                V::Text(&authority_guard),
                V::Text(&upsert.id),
                d1_optional_text(upsert.enterprise_provider.as_deref()),
                d1_optional_text(upsert.entra_tenant_id.as_deref()),
            ])
            .map_err(storage_error)?,
    );
    business.push(
        db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?1")
            .bind_refs(&[V::Text(&authority_guard)])
            .map_err(storage_error)?,
    );
    audit_capture::commit(db, business, &[event])
        .await
        .map_err(storage_error)
}

#[derive(Deserialize)]
struct StringRow {
    value: String,
}

#[derive(Deserialize)]
struct CountRow {
    value: i32,
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn tenants(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    if url.query().is_some() {
        return client_management_error_json(&ClientManagementError::invalid_request(
            "tenant API does not accept query parameters",
        ));
    }
    let db = env.d1(D1_BINDING)?;
    let config = server_config(&env, &url);
    let now = unix_timestamp_seconds();
    let authorization = match request.method() {
        Method::Get => authorize_admin_request(&request, &env, &db, &config, now).await,
        Method::Post => maybe_authorize_admin_write_request(
            &mut request,
            &env,
            &db,
            &config,
            now,
            CSRF_ROUTE_FAMILY_ADMIN,
            false,
            "tenant_admin_mutation",
        )
        .await
        .and_then(|value| {
            value.ok_or_else(|| ClientManagementError::unauthorized("admin session is required"))
        }),
        _ => return json_status_no_store(&serde_json::json!({"error":"method_not_allowed"}), 405),
    };
    let authorization = match authorization {
        Ok(authorization) => authorization,
        Err(error) => return client_management_error_json(&error),
    };
    if request.method() == Method::Post {
        let upsert = match body(&mut request).await {
            Ok(upsert) => upsert,
            Err(error) => return client_management_error_json(&error),
        };
        let id = upsert.id.clone();
        if let Err(error) = save(&db, &request, &authorization, upsert, now).await {
            return client_management_error_json(&error);
        }
        let resource = resources(&db, &env)
            .await?
            .into_iter()
            .find(|tenant| tenant.id == id)
            .ok_or_else(|| worker_error("tenant save did not return a row".into()))?;
        json_status_no_store(&resource, 200)
    } else {
        json_status_no_store(
            &serde_json::json!({"tenants":resources(&db,&env).await?}),
            200,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection, OptionalExtension};

    const ENTRA_TENANT: &str = "12345678-1234-1234-1234-123456789012";
    const ENTRA_APP: &str = "87654321-4321-4321-4321-210987654321";

    fn input() -> TenantUpsert {
        serde_json::from_value(serde_json::json!({
            "id":"acme","name":"Acme","clientIds":["app"],"auditReaders":[],
            "enterpriseProvider":"entra","entraTenantId":ENTRA_TENANT,
            "oidcClientId":ENTRA_APP,"clientSecretBinding":"TENANT_ACME_CLIENT_SECRET",
            "retentionDays":90
        }))
        .unwrap()
    }

    fn row() -> TenantRow {
        TenantRow {
            id: "acme".into(),
            name: "Acme".into(),
            disabled: 0,
            enterprise_provider: Some("entra".into()),
            entra_tenant_id: Some(ENTRA_TENANT.into()),
            google_workspace_domains_json: "[]".into(),
            oidc_client_id: Some(ENTRA_APP.into()),
            client_secret_binding: Some("TENANT_ACME_CLIENT_SECRET".into()),
            retention_days: Some(90),
            created_at: 1,
            updated_at: 1,
        }
    }

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        // Exercise the actual statement splitting used by Worker migrations.
        for migration in zeroth_storage::migrations::ALL {
            for statement in migration.statements() {
                db.execute_batch(statement).unwrap();
            }
        }
        db.execute_batch("INSERT INTO zeroth_clients (id,name,redirect_uris_json,created_at,updated_at)
            VALUES ('app','Application','[]',1,1),('legacy','Legacy','[]',1,1);
            UPDATE zeroth_clients SET account_sharing_mode='tenant',account_tenant_id='acme' WHERE id='legacy';
            INSERT INTO zeroth_users (id,created_at,updated_at) VALUES ('usr_reader',1,1);").unwrap();
        db
    }

    fn insert_tenant(db: &Connection, id: &str, provider: &str) {
        db.execute(
            UPSERT_TENANT_SQL,
            params![
                id,
                "Organization",
                0,
                provider,
                ENTRA_TENANT,
                "[]",
                ENTRA_APP,
                "TENANT_ACME_CLIENT_SECRET",
                90,
                1
            ],
        )
        .unwrap();
    }

    fn bind(db: &mut Connection, id: &str) {
        let tx = db.transaction().unwrap();
        tx.execute(BIND_CLIENT_SQL, params!["app", id, "entra"])
            .unwrap();
        tx.execute(APPLY_CLIENT_POLICY_SQL, params![id, "entra", 2])
            .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn draft_connections_validate_but_cannot_authenticate_or_fall_back() {
        let mut request = input();
        request.oidc_client_id = None;
        request.client_secret_binding = None;
        assert!(validate(request).is_ok());
        let mut draft = row();
        draft.oidc_client_id = None;
        assert!(draft.provider("entra").is_err());
        let mut disabled = row();
        disabled.disabled = 1;
        assert!(disabled.provider("entra").is_err());
        assert!(row().provider("google_workspace").is_err());
        assert!(row().provider("google").is_err());
        assert_eq!(
            row().provider("entra").unwrap().config().client_id,
            ENTRA_APP
        );
        let mut workspace = row();
        workspace.enterprise_provider = Some("google_workspace".into());
        workspace.entra_tenant_id = None;
        workspace.oidc_client_id = Some("123456-acme.apps.googleusercontent.com".into());
        workspace.google_workspace_domains_json = r#"["acme.example"]"#.into();
        assert_ne!(
            row()
                .provider("entra")
                .unwrap()
                .enterprise_policy()
                .unwrap()
                .issuer(),
            workspace
                .provider("google_workspace")
                .unwrap()
                .enterprise_policy()
                .unwrap()
                .issuer()
        );
    }

    #[test]
    fn accepts_only_secret_references_and_bounded_provider_specific_inputs() {
        validate(input()).unwrap();
        for binding in [
            "JWT_ES256_PRIVATE_KEY",
            "AUDIT_STREAM_TOKEN",
            "ENTRA_CLIENT_SECRET",
            "TENANT__CLIENT_SECRET",
            "TENANT_ACME_CLIENT_SECRET=raw-secret",
            "tenant_ACME_CLIENT_SECRET",
        ] {
            assert!(validate_secret_binding(binding).is_err(), "{binding}");
        }
        let mut request = input();
        request.retention_days = Some(0);
        assert!(validate(request).is_err());
        let mut request = input();
        request.google_workspace_domains.push("acme.example".into());
        assert!(validate(request).is_err());
        let mut request = input();
        request.client_ids.push("app".into());
        assert!(validate(request).is_err());
        let mut request = input();
        request.name = "invalid\nname".into();
        assert!(validate(request).is_err());
        let mut request = input();
        request.enterprise_provider = None;
        assert!(validate(request).is_err());
        let mut json = serde_json::to_value(input()).unwrap();
        json["clientSecret"] = "actual-secret-value".into();
        assert!(serde_json::from_value::<TenantUpsert>(json).is_err());
        assert!(validate_existing_clients(&input(), &["app".into()]).is_ok());
        assert!(validate_existing_clients(&input(), &["another-app".into()]).is_err());
    }

    #[test]
    fn explicit_registration_is_required_for_organization_ownership() {
        let mut db = database();
        insert_tenant(&db, "acme", "entra");
        assert!(db
            .query_row(OWNER_SQL, ["legacy"], |row| row.get::<_, String>(0))
            .optional()
            .unwrap()
            .is_none());
        bind(&mut db, "acme");
        assert_eq!(
            db.query_row(OWNER_SQL, ["app"], |row| row.get::<_, String>(0))
                .unwrap(),
            "acme"
        );
        let (mode,tenant,provider): (String,String,String) = db.query_row("SELECT account_sharing_mode,account_tenant_id,enterprise_provider FROM zeroth_clients WHERE id='app'",[],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(
            (mode, tenant, provider),
            ("tenant".into(), "acme".into(), "entra".into())
        );
    }

    #[test]
    fn actual_sql_prevents_stealing_and_concurrent_client_policy_escape() {
        let mut db = database();
        insert_tenant(&db, "acme", "entra");
        insert_tenant(&db, "other", "entra");
        bind(&mut db, "acme");
        {
            let tx = db.transaction().unwrap();
            assert!(tx
                .execute(BIND_CLIENT_SQL, params!["app", "other", "entra"])
                .is_err());
        }
        assert_eq!(
            db.query_row(OWNER_SQL, ["app"], |row| row.get::<_, String>(0))
                .unwrap(),
            "acme"
        );
        for sql in [
            "UPDATE zeroth_clients SET account_sharing_mode='global',account_tenant_id='global' WHERE id='app'",
            "UPDATE zeroth_clients SET enterprise_provider=NULL WHERE id='app'",
            "UPDATE zeroth_clients SET enterprise_provider='google_workspace' WHERE id='app'",
        ] {
            let tx = db.transaction().unwrap();
            tx.execute(sql, []).unwrap();
            assert!(tx.commit().is_err(), "{sql}");
        }
        assert_eq!(
            db.query_row(
                "SELECT account_tenant_id FROM zeroth_clients WHERE id='app'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "acme"
        );
        {
            let tx = db.transaction().unwrap();
            tx.execute(
                "UPDATE zeroth_tenants SET enterprise_provider='google_workspace' WHERE id='acme'",
                [],
            )
            .unwrap();
            tx.execute(
                APPLY_CLIENT_POLICY_SQL,
                params!["acme", "google_workspace", 3],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(
            db.query_row(
                "SELECT enterprise_provider FROM zeroth_clients WHERE id='app'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "google_workspace"
        );
        assert_eq!(
            db.query_row(OWNER_SQL, ["app"], |row| row.get::<_, String>(0))
                .unwrap(),
            "acme"
        );
    }

    #[test]
    fn audit_permissions_are_scoped_and_export_is_separate() {
        let db = database();
        insert_tenant(&db, "acme", "entra");
        insert_tenant(&db, "other", "entra");
        db.execute(
            "INSERT INTO zeroth_tenant_audit_readers VALUES ('acme','usr_reader',0)",
            [],
        )
        .unwrap();
        assert_eq!(
            db.query_row(READER_SQL, params!["acme", "usr_reader"], |row| row
                .get::<_, i32>(0))
                .optional()
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            db.query_row(READER_SQL, params!["other", "usr_reader"], |row| row
                .get::<_, i32>(0))
                .optional()
                .unwrap(),
            None
        );
        let (client_ids, readers): (String, String) = db
            .query_row(LIST_SQL, [], |row| {
                Ok((row.get("client_ids_json")?, row.get("audit_readers_json")?))
            })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&client_ids).unwrap(),
            Vec::<String>::new()
        );
        let readers: Vec<ReaderRow> = serde_json::from_str(&readers).unwrap();
        assert_eq!(readers[0].user_id, "usr_reader");
        assert_eq!(readers[0].can_export, 0);
        assert!(db
            .execute(
                "INSERT INTO zeroth_tenant_audit_readers VALUES ('acme','missing_user',1)",
                []
            )
            .is_err());
    }

    #[test]
    fn offboarded_reader_cannot_use_another_tenants_active_session_to_read_old_tenant() {
        let mut db = database();
        insert_tenant(&db, "acme", "entra");
        insert_tenant(&db, "other", "entra");
        bind(&mut db, "other");
        db.execute_batch("INSERT INTO zeroth_tenant_audit_readers VALUES ('acme','usr_reader',1),('other','usr_reader',1);
          INSERT INTO zeroth_sessions(id,user_id,client_id,created_at,expires_at) VALUES ('session_other','usr_reader','app',1,3000);
          INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,enabled,created_at,updated_at)
            VALUES ('acme','entra','12345678-1234-1234-1234-123456789012',0,1,1);
          INSERT INTO zeroth_directory_users(id,tenant_id,provider_id,authority_id,external_id,user_name,user_name_key,active,user_id,created_at,updated_at)
            VALUES ('dir_inactive','acme','entra','12345678-1234-1234-1234-123456789012','aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','reader@example.com','reader@example.com',0,'usr_reader',1,1);").unwrap();
        assert_eq!(db.query_row("SELECT COUNT(*) FROM zeroth_sessions WHERE id='session_other' AND revoked_at IS NULL AND expires_at>2000", [], |row| row.get::<_, i32>(0)).unwrap(), 1);
        // The manually assigned reader grants remain present in both tenants.
        // The requested tenant's lifecycle policy decides access independently
        // of the session's client, even when the tenant has no bound client.
        for (tenant, allowed) in [("acme", false), ("other", true)] {
            assert_eq!(
                db.query_row(READER_SQL, params![tenant, "usr_reader"], |row| row
                    .get::<_, i32>(0))
                    .unwrap(),
                1
            );
            let active = db
                .query_row(
                    provisioning::TENANT_USER_ACTIVE_SQL,
                    params!["usr_reader", tenant, 2000],
                    |row| row.get::<_, i32>(0),
                )
                .unwrap()
                != 0;
            assert_eq!(active, allowed);
        }
    }

    #[test]
    fn binding_invalidates_every_existing_credential_in_the_same_transaction() {
        let mut db = database();
        insert_tenant(&db, "acme", "entra");
        db.execute_batch("INSERT INTO zeroth_sessions(id,user_id,client_id,created_at,expires_at) VALUES ('session','usr_reader','app',1,999);
            INSERT INTO zeroth_refresh_tokens(token_hash,client_id,user_id,scope,created_at,expires_at) VALUES ('refresh','app','usr_reader','openid',1,999);
            INSERT INTO zeroth_auth_codes(code_hash,client_id,redirect_uri,user_id,scope,created_at,expires_at) VALUES ('code','app','https://example.com','usr_reader','openid',1,999);
            INSERT INTO zeroth_auth_transactions(provider_state,client_id,provider_id,redirect_uri,provider_redirect_uri,scope,created_at,expires_at) VALUES ('transaction','app','entra','https://example.com','https://id.example.com/oauth2/callback','openid',1,999);").unwrap();
        let tx = db.transaction().unwrap();
        for sql in INVALIDATE_CLIENT_CREDENTIALS_SQL {
            tx.execute(sql, params!["app", 100]).unwrap();
        }
        tx.execute(BIND_CLIENT_SQL, params!["app", "acme", "entra"])
            .unwrap();
        tx.execute(APPLY_CLIENT_POLICY_SQL, params!["acme", "entra", 100])
            .unwrap();
        tx.commit().unwrap();
        for (table, column) in [
            ("zeroth_sessions", "revoked_at"),
            ("zeroth_refresh_tokens", "revoked_at"),
            ("zeroth_auth_codes", "consumed_at"),
            ("zeroth_auth_transactions", "consumed_at"),
        ] {
            let value: i64 = db
                .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(value, 100, "{table}");
        }
        assert_eq!(
            db.query_row::<String, _, _>(OWNER_SQL, ["app"], |row| row.get(0))
                .unwrap(),
            "acme"
        );
    }

    #[test]
    fn provisioned_objects_and_immutable_links_lock_the_directory_authority_atomically() {
        for tombstone in [false, true] {
            let mut db = database();
            insert_tenant(&db, "acme", "entra");
            // The preliminary admin read can occur before a concurrent login
            // pins the first link. The guard must check inside the write batch.
            if tombstone {
                db.execute("INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,created_at,updated_at) VALUES ('acme','entra',?1,1,1)",[ENTRA_TENANT]).unwrap();
                db.execute("INSERT INTO zeroth_directory_users(id,tenant_id,provider_id,authority_id,external_id,user_name,user_name_key,active,deleted,created_at,updated_at)
                    VALUES ('dir_deleted','acme','entra',?1,'object','deleted','deleted',0,1,1,1)",[ENTRA_TENANT]).unwrap();
            } else {
                db.execute("INSERT INTO zeroth_directory_links(tenant_id,provider_id,authority_id,external_id,user_id,created_at) VALUES ('acme','entra',?1,'object','usr_reader',1)",[ENTRA_TENANT]).unwrap();
            }
            let tx = db.transaction().unwrap();
            assert!(tx
                .execute(
                    DIRECTORY_AUTHORITY_GUARD_SQL,
                    params!["move", "acme", "google_workspace", None::<String>]
                )
                .is_err());
            assert!(tx
                .execute(
                    DIRECTORY_AUTHORITY_GUARD_SQL,
                    params![
                        "realm",
                        "acme",
                        "entra",
                        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                    ]
                )
                .is_err());
            tx.execute(
                DIRECTORY_AUTHORITY_GUARD_SQL,
                params!["same", "acme", "entra", ENTRA_TENANT],
            )
            .unwrap();
            tx.execute(
                "UPDATE zeroth_tenants SET name='New name',disabled=1 WHERE id='acme'",
                [],
            )
            .unwrap();
            tx.execute("DELETE FROM zeroth_audit_write_guards", [])
                .unwrap();
            tx.commit().unwrap();
        }
        let db = database();
        insert_tenant(&db, "acme", "entra");
        db.execute(
            DIRECTORY_AUTHORITY_GUARD_SQL,
            params!["draft", "acme", "google_workspace", None::<String>],
        )
        .unwrap();
    }

    #[test]
    fn connection_changes_require_the_previously_read_policy_and_metadata_edits_do_not_revoke() {
        let db = database();
        insert_tenant(&db, "acme", "entra");
        let next = input();
        assert!(!connection_changed(Some(&row()), &next, "[]"));
        let mut readers_only = input();
        readers_only.audit_readers.push(AuditReader {
            user_id: "usr_reader".into(),
            can_export: true,
        });
        readers_only.retention_days = Some(30);
        assert!(!connection_changed(Some(&row()), &readers_only, "[]"));
        let mut disabled = input();
        disabled.disabled = true;
        assert!(connection_changed(Some(&row()), &disabled, "[]"));
        db.execute(
            CONNECTION_PREIMAGE_GUARD_SQL,
            params![
                "current",
                "acme",
                1,
                0,
                "entra",
                ENTRA_TENANT,
                "[]",
                ENTRA_APP,
                "TENANT_ACME_CLIENT_SECRET"
            ],
        )
        .unwrap();
        db.execute("DELETE FROM zeroth_audit_write_guards", [])
            .unwrap();
        db.execute("UPDATE zeroth_tenants SET client_secret_binding='TENANT_NEW_CLIENT_SECRET' WHERE id='acme'",[]).unwrap();
        assert!(db
            .execute(
                CONNECTION_PREIMAGE_GUARD_SQL,
                params![
                    "stale",
                    "acme",
                    1,
                    0,
                    "entra",
                    ENTRA_TENANT,
                    "[]",
                    ENTRA_APP,
                    "TENANT_ACME_CLIENT_SECRET"
                ]
            )
            .is_err());
    }
}
