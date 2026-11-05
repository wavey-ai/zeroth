//! Platform-admin provisioning controls and tenant-specific access evidence.
//! Secret values remain deployment bindings; the database stores references only.
use super::*;
use provisioning::{DirectoryAuthority, LifecycleError};

const BODY_LIMIT: usize = 2048;
const ACCESS_ROWS_SQL: &str = "WITH selected AS (SELECT value AS user_id FROM json_each(?2))
    SELECT selected.user_id,
      COALESCE(MAX(d.deleted),0) AS deleted,
      COALESCE(MAX(CASE WHEN d.active=0 THEN 1 ELSE 0 END),0) AS inactive,
      COALESCE(MAX(CASE WHEN d.provider_id=?3 AND d.authority_id=?4
        AND d.user_id=selected.user_id AND d.active=1 AND d.deleted=0 THEN 1 ELSE 0 END),0) AS active_match,
      MAX(d.updated_at) AS updated_at,MIN(d.provider_id) AS provider_id
    FROM selected LEFT JOIN zeroth_directory_users d ON d.tenant_id=?1 AND
      (d.user_id=selected.user_id OR EXISTS (SELECT 1 FROM zeroth_directory_links l
        WHERE l.tenant_id=d.tenant_id AND l.provider_id=d.provider_id
          AND l.authority_id=d.authority_id AND l.external_id=d.external_id
          AND l.user_id=selected.user_id)) GROUP BY selected.user_id";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConfigRequest {
    tenant_id: String,
    enabled: bool,
    token_binding: Option<String>,
}

fn normalize_request(mut input: ConfigRequest) -> Result<ConfigRequest, LifecycleError> {
    input.tenant_id = validate_account_tenant_id_value(&input.tenant_id)
        .map_err(|_| LifecycleError::invalid("invalid tenant identifier"))?;
    if matches!(input.tenant_id.as_str(), "." | "..") {
        return Err(LifecycleError::invalid("invalid tenant identifier"));
    }
    input.token_binding = input
        .token_binding
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if input
        .token_binding
        .as_deref()
        .is_some_and(|value| !valid_binding(value))
        || (input.enabled && input.token_binding.is_none())
    {
        return Err(LifecycleError::invalid(
            "a dedicated TENANT_<NAME>_SCIM_TOKEN binding is required",
        ));
    }
    Ok(input)
}

fn valid_binding(value: &str) -> bool {
    value.len() <= 128
        && value.starts_with("TENANT_")
        && value.ends_with("_SCIM_TOKEN")
        && value.len() > "TENANT__SCIM_TOKEN".len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Compare fixed-size hashes, including against deployment/admin credentials.
/// Nothing derived from a token is persisted or returned to an administrator.
fn valid_credential<'a>(
    token: &str,
    admin_hash: Option<&str>,
    protected: impl IntoIterator<Item = &'a str>,
) -> bool {
    if !(32..=4096).contains(&token.len()) || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    if admin_hash.is_some_and(|hash| admin_token_matches_config(token, hash)) {
        return false;
    }
    let hash = hash_secret(token);
    !protected
        .into_iter()
        .any(|other| constant_time_eq(&hash, &hash_secret(other)))
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn credential_for_tenant(
    db: &worker::d1::D1Database,
    env: &Env,
    tenant_id: &str,
    binding: &str,
) -> Result<Option<String>, LifecycleError> {
    if !valid_binding(binding) {
        return Err(LifecycleError::invalid(
            "invalid tenant provisioning credential reference",
        ));
    }
    let Some(token) = secret_string(env, binding) else {
        return Ok(None);
    };
    #[derive(Deserialize)]
    struct Reference {
        token_binding: String,
    }
    let refs = db.prepare("SELECT token_binding FROM zeroth_directory_sources WHERE tenant_id<>?1 AND provider_id='entra' AND token_binding IS NOT NULL LIMIT 257")
        .bind_refs(&[worker::d1::D1Type::Text(tenant_id)]).map_err(|_|LifecycleError::storage())?
        .all().await.map_err(|_|LifecycleError::storage())?.results::<Reference>().map_err(|_|LifecycleError::storage())?;
    if refs.len() > 256 {
        return Err(LifecycleError::storage());
    }
    let mut protected = Vec::new();
    for name in ["ADMIN_TOKEN", "AUDIT_STREAM_TOKEN"] {
        if let Some(value) = binding_value_from_env(env, name) {
            protected.push(value);
        }
    }
    for reference in refs {
        if valid_binding(&reference.token_binding) {
            if let Some(value) = secret_string(env, &reference.token_binding) {
                protected.push(value);
            }
        }
    }
    let admin_hash = binding_value_from_env(env, "ADMIN_TOKEN_SHA256");
    if !valid_credential(
        &token,
        admin_hash.as_deref(),
        protected.iter().map(String::as_str),
    ) {
        return Err(LifecycleError::invalid(
            "tenant provisioning credential must be valid and exclusive to this tenant",
        ));
    }
    Ok(Some(token))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    tenant_id: String,
    enabled: bool,
    managed_enforced: bool,
    token_binding: Option<String>,
    credentials_configured: bool,
    endpoint: String,
    managed_users: i32,
    active_users: i32,
    last_activity_at: Option<i32>,
    last_error_code: Option<String>,
}

#[cfg(target_arch = "wasm32")]
async fn tenant(
    db: &worker::d1::D1Database,
    id: &str,
) -> Result<tenants::TenantRow, LifecycleError> {
    let row = db
        .prepare("SELECT * FROM zeroth_tenants WHERE id=?1")
        .bind_refs(&[worker::d1::D1Type::Text(id)])
        .map_err(|_| LifecycleError::storage())?
        .first::<tenants::TenantRow>(None)
        .await
        .map_err(|_| LifecycleError::storage())?
        .ok_or_else(|| LifecycleError::invalid("tenant was not found"))?;
    if row.enterprise_provider.as_deref() != Some("entra") {
        return Err(LifecycleError::invalid("an Entra tenant is required"));
    }
    Ok(row)
}

fn authority(tenant: &tenants::TenantRow) -> Result<DirectoryAuthority, LifecycleError> {
    let authority = DirectoryAuthority {
        tenant_id: tenant.id.clone(),
        provider_id: "entra".into(),
        authority_id: tenant.entra_tenant_id.clone().ok_or_else(|| {
            LifecycleError::invalid(
                "save the Entra directory tenant GUID before configuring provisioning",
            )
        })?,
    };
    authority.validate()?;
    Ok(authority)
}

#[cfg(target_arch = "wasm32")]
async fn status(
    db: &worker::d1::D1Database,
    env: &Env,
    config: &ZerothServerConfig,
    id: &str,
) -> Result<Status, LifecycleError> {
    let tenant = tenant(db, id).await?;
    let source = provisioning::get_source(db, id).await?.filter(|source| {
        source.provider_id == "entra"
            && tenant.entra_tenant_id.as_deref() == Some(&source.authority_id)
    });
    let credential = if let Some(binding) = source.as_ref().and_then(|s| s.token_binding.as_deref())
    {
        match credential_for_tenant(db, env, id, binding).await {
            Ok(value) => value.is_some(),
            Err(error) if error.status == 503 => return Err(error),
            Err(_) => false,
        }
    } else {
        false
    };
    #[derive(Deserialize)]
    struct Counts {
        managed_users: i32,
        active_users: i32,
    }
    let counts=db.prepare("SELECT COUNT(*) AS managed_users,COALESCE(SUM(CASE WHEN active=1 AND deleted=0 THEN 1 ELSE 0 END),0) AS active_users
        FROM zeroth_directory_users WHERE tenant_id=?1 AND provider_id='entra' AND authority_id IS ?2")
        .bind_refs(&[worker::d1::D1Type::Text(id),d1_optional_text(tenant.entra_tenant_id.as_deref())])
        .map_err(|_|LifecycleError::storage())?.first::<Counts>(None).await.map_err(|_|LifecycleError::storage())?;
    let enabled = source.as_ref().is_some_and(|s| s.enabled != 0);
    Ok(Status {
        tenant_id: id.into(),
        enabled,
        managed_enforced: enabled,
        token_binding: source.as_ref().and_then(|s| s.token_binding.clone()),
        credentials_configured: credential,
        endpoint: format!(
            "{}/scim/v2/{id}",
            config.public_base_url.trim_end_matches('/')
        ),
        managed_users: counts.as_ref().map_or(0, |c| c.managed_users),
        active_users: counts.as_ref().map_or(0, |c| c.active_users),
        last_activity_at: source.as_ref().and_then(|s| s.last_activity_at),
        last_error_code: source.and_then(|s| s.last_error_code),
    })
}

#[cfg(target_arch = "wasm32")]
async fn body(request: &mut Request) -> Result<ConfigRequest, LifecycleError> {
    use futures_util::StreamExt;
    if !content_type_is_json(
        request_header(request, "Content-Type")
            .map_err(|_| LifecycleError::invalid("invalid request"))?
            .as_deref(),
    ) {
        return Err(LifecycleError::invalid("JSON content is required"));
    }
    reject_oversized_content_length(request, BODY_LIMIT)
        .map_err(|_| LifecycleError::invalid("request is too large"))?;
    let mut stream = request
        .stream()
        .map_err(|_| LifecycleError::invalid("invalid request"))?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| LifecycleError::invalid("invalid request"))?;
        if chunk.len() > BODY_LIMIT.saturating_sub(bytes.len()) {
            return Err(LifecycleError::invalid("request is too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    normalize_request(
        serde_json::from_slice(&bytes)
            .map_err(|_| LifecycleError::invalid("invalid provisioning configuration"))?,
    )
}

#[cfg(target_arch = "wasm32")]
fn error_response(error: LifecycleError) -> worker::Result<Response> {
    json_status_no_store(
        &serde_json::json!({"error":error.code,"description":error.detail}),
        error.status,
    )
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
            return error_response(LifecycleError::invalid(
                "one tenant_id query parameter is required",
            ));
        }
        let id = match validate_account_tenant_id_value(&pairs[0].1) {
            Ok(id) => id,
            Err(_) => return error_response(LifecycleError::invalid("invalid tenant identifier")),
        };
        return match status(&db, &env, &config, &id).await {
            Ok(value) => json_status_no_store(&value, 200),
            Err(error) => error_response(error),
        };
    }
    if request.method() != Method::Post {
        return error_response(LifecycleError::invalid("unsupported request method"));
    }
    let auth = match maybe_authorize_admin_write_request(
        &mut request,
        &env,
        &db,
        &config,
        now,
        CSRF_ROUTE_FAMILY_ADMIN,
        false,
        "provisioning_configure",
    )
    .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return error_response(LifecycleError::denied(
                "an administrator session is required",
            ));
        }
        Err(error) => return client_management_error_json(&error),
    };
    let input = match body(&mut request).await {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let query: Vec<_> = url.query_pairs().collect();
    if !query.is_empty()
        && (query.len() != 1 || query[0].0 != "tenant_id" || query[0].1 != input.tenant_id)
    {
        return error_response(LifecycleError::invalid(
            "query tenant must match the configuration tenant",
        ));
    }
    let saved=async {
        let tenant=tenant(&db,&input.tenant_id).await?;
        let authority=authority(&tenant)?;
        if input.enabled {
            let binding=input.token_binding.as_deref().ok_or_else(||LifecycleError::invalid("provisioning token binding is required"))?;
            if credential_for_tenant(&db,&env,&input.tenant_id,binding).await?.is_none() {
                return Err(LifecycleError::invalid("configure the dedicated tenant provisioning token before requiring provisioned users"));
            }
        }
        let actor=audit_capture::admin_actor(&auth).map_err(|_|LifecycleError::storage())?;
        provisioning::configure_authority(&db,&authority,input.enabled,input.token_binding.as_deref(),actor,Vec::new(),now).await
    }.await;
    if let Err(error) = saved {
        return error_response(error);
    }
    match status(&db, &env, &config, &input.tenant_id).await {
        Ok(value) => json_status_no_store(&value, 200),
        Err(error) => error_response(error),
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct TenantAccessStatus {
    pub state: String,
    pub source: Option<String>,
    pub updated_at: Option<i32>,
    pub last_sync_at: Option<i32>,
    pub managed: bool,
}

#[derive(Deserialize, Default, Debug)]
struct AccessRow {
    user_id: String,
    deleted: i32,
    inactive: i32,
    active_match: i32,
    updated_at: Option<i32>,
    provider_id: Option<String>,
}
#[derive(Deserialize, Default, Debug)]
struct AccessPolicy {
    disabled: i32,
    provider_id: Option<String>,
    authority_id: Option<String>,
    enabled: Option<i32>,
    last_full_sync_at: Option<i32>,
    updated_at: Option<i32>,
}
fn access_status(policy: &AccessPolicy, row: &AccessRow, now: i32) -> TenantAccessStatus {
    let managed = policy.enabled.is_some_and(|value| value != 0);
    let state = if policy.disabled != 0 {
        "tenant_disabled"
    } else if row.deleted != 0 {
        "deleted"
    } else if row.inactive != 0 {
        "inactive"
    } else if managed && row.active_match == 0 {
        "unprovisioned"
    } else if managed
        && policy.provider_id.as_deref() == Some("google_workspace")
        && policy
            .last_full_sync_at
            .is_none_or(|at| i64::from(at) < i64::from(now) - 900)
    {
        "stale"
    } else if managed {
        "active"
    } else {
        "unmanaged"
    };
    TenantAccessStatus {
        state: state.into(),
        source: policy
            .provider_id
            .clone()
            .or_else(|| row.provider_id.clone()),
        updated_at: row.updated_at.or(policy.updated_at),
        last_sync_at: policy.last_full_sync_at,
        managed,
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn hydrate_tenant_access(
    db: &worker::d1::D1Database,
    tenant_id: &str,
    now: i32,
    users: &mut [AdminUserResponse],
) -> worker::Result<()> {
    if users.is_empty() {
        return Ok(());
    }
    if users.len() > 100 {
        return Err(worker_error(
            "tenant user page exceeds supported size".into(),
        ));
    }
    let policy=db.prepare("SELECT t.disabled,s.provider_id,s.authority_id,s.enabled,s.last_full_sync_at,s.updated_at
      FROM zeroth_tenants t LEFT JOIN zeroth_directory_sources s ON s.tenant_id=t.id WHERE t.id=?1")
      .bind_refs(&[worker::d1::D1Type::Text(tenant_id)])?.first::<AccessPolicy>(None).await?
      .ok_or_else(||worker_error("tenant was not found".into()))?;
    let ids = serde_json::to_string(
        &users
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| worker_error("tenant users unavailable".into()))?;
    let rows = db
        .prepare(ACCESS_ROWS_SQL)
        .bind_refs(&[
            worker::d1::D1Type::Text(tenant_id),
            worker::d1::D1Type::Text(&ids),
            d1_optional_text(policy.provider_id.as_deref()),
            d1_optional_text(policy.authority_id.as_deref()),
        ])?
        .all()
        .await?
        .results::<AccessRow>()?;
    let rows: std::collections::BTreeMap<_, _> = rows
        .into_iter()
        .map(|row| (row.user_id.clone(), row))
        .collect();
    for user in users {
        user.tenant_access = Some(access_status(
            &policy,
            rows.get(&user.id).unwrap_or(&AccessRow::default()),
            now,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    const REALM: &str = "11111111-2222-3333-4444-555555555555";
    const TOKEN: &str = "tenant-provisioning-secret-12345678901234567890";

    #[test]
    fn configuration_accepts_references_only_and_never_secret_values() {
        let input = serde_json::json!({"tenantId":"acme","enabled":true,"tokenBinding":"TENANT_ACME_SCIM_TOKEN"});
        normalize_request(serde_json::from_value(input.clone()).unwrap()).unwrap();
        for name in ["token", "secret", "clientSecret"] {
            let mut extra = input.clone();
            extra[name] = TOKEN.into();
            assert!(serde_json::from_value::<ConfigRequest>(extra).is_err());
        }
        for binding in [
            "ADMIN_TOKEN",
            "TENANT__SCIM_TOKEN",
            TOKEN,
            "TENANT_ACME_CLIENT_SECRET",
        ] {
            let mut bad = input.clone();
            bad["tokenBinding"] = binding.into();
            assert!(normalize_request(serde_json::from_value(bad).unwrap()).is_err());
        }
        assert!(normalize_request(
            serde_json::from_value(
                serde_json::json!({"tenantId":"acme","enabled":true,"tokenBinding":null})
            )
            .unwrap()
        )
        .is_err());
        normalize_request(
            serde_json::from_value(
                serde_json::json!({"tenantId":"acme","enabled":false,"tokenBinding":null}),
            )
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn dedicated_credentials_cannot_reuse_admin_stream_or_other_tenant_values() {
        assert!(valid_credential(TOKEN, None, std::iter::empty()));
        let hash = format!("sha256:{}", hash_secret(TOKEN));
        assert!(!valid_credential(TOKEN, Some(&hash), std::iter::empty()));
        assert!(!valid_credential(TOKEN, None, [TOKEN]));
        assert!(!valid_credential(TOKEN, None, ["another-secret", TOKEN]));
        assert!(valid_credential(
            TOKEN,
            Some(&hash_secret("other-admin")),
            ["unrelated-other-tenant-token"]
        ));
        for invalid in [
            "tiny",
            " spaced-secret-12345678901234567890123456789",
            "line\nbreak-123456789012345678901234567890",
            &"x".repeat(4097),
        ] {
            assert!(!valid_credential(invalid, None, std::iter::empty()));
        }
    }

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in zeroth_storage::migrations::ALL {
            for sql in migration.statements() {
                db.execute_batch(sql).unwrap();
            }
        }
        db.execute_batch("INSERT INTO zeroth_users(id,created_at,updated_at) VALUES ('shared',1,1),('unknown',1,1);
            INSERT INTO zeroth_tenants(id,name,enterprise_provider,entra_tenant_id,created_at,updated_at)
              VALUES ('a','A','entra','11111111-2222-3333-4444-555555555555',1,1),('b','B','entra','11111111-2222-3333-4444-555555555555',1,1);
            INSERT INTO zeroth_clients(id,name,redirect_uris_json,enterprise_provider,account_sharing_mode,account_tenant_id,created_at,updated_at)
              VALUES ('a_app','A','[]','entra','tenant','a',1,1),('b_app','B','[]','entra','tenant','b',1,1);
            INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('a_app','a','entra'),('b_app','b','entra');
            INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,enabled,created_at,updated_at)
              VALUES ('a','entra','11111111-2222-3333-4444-555555555555',1,1,1),('b','entra','11111111-2222-3333-4444-555555555555',1,1,1);
            INSERT INTO zeroth_directory_users(id,tenant_id,provider_id,authority_id,external_id,user_name,user_name_key,active,deleted,user_id,created_at,updated_at)
              VALUES ('a_user','a','entra','11111111-2222-3333-4444-555555555555','a-object','person@a.example','person@a.example',0,0,'shared',1,20),
              ('b_user','b','entra','11111111-2222-3333-4444-555555555555','b-object','person@b.example','person@b.example',1,0,'shared',1,30);").unwrap();
        db
    }
    fn row(db: &Connection, tenant: &str, user: &str) -> AccessRow {
        db.query_row(
            ACCESS_ROWS_SQL,
            params![
                tenant,
                serde_json::to_string(&[user]).unwrap(),
                "entra",
                REALM
            ],
            |r| {
                Ok(AccessRow {
                    user_id: r.get(0)?,
                    deleted: r.get(1)?,
                    inactive: r.get(2)?,
                    active_match: r.get(3)?,
                    updated_at: r.get(4)?,
                    provider_id: r.get(5)?,
                })
            },
        )
        .unwrap()
    }
    fn policy() -> AccessPolicy {
        AccessPolicy {
            provider_id: Some("entra".into()),
            authority_id: Some(REALM.into()),
            enabled: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn shared_global_account_has_independent_tenant_access_and_matches_admission_sql() {
        let db = database();
        for (tenant, expected) in [("a", "inactive"), ("b", "active")] {
            let status = access_status(&policy(), &row(&db, tenant, "shared"), 100);
            assert_eq!(status.state, expected);
            let active: i32 = db
                .query_row(
                    provisioning::LIFECYCLE_USER_ACTIVE_SQL,
                    params!["shared", format!("{tenant}_app"), 100],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(active == 1, status.state == "active");
        }
        assert_eq!(
            db.query_row(
                "SELECT disabled_at IS NULL FROM zeroth_users WHERE id='shared'",
                [],
                |row| row.get::<_, bool>(0)
            )
            .unwrap(),
            true
        );
        assert_eq!(
            access_status(&policy(), &row(&db, "b", "unknown"), 100).state,
            "unprovisioned"
        );
        db.execute(
            "UPDATE zeroth_directory_sources SET enabled=0 WHERE tenant_id='a'",
            [],
        )
        .unwrap();
        let mut nonstrict = policy();
        nonstrict.enabled = Some(0);
        assert_eq!(
            access_status(&nonstrict, &row(&db, "a", "shared"), 100).state,
            "inactive"
        );
        assert_eq!(
            access_status(&nonstrict, &row(&db, "a", "unknown"), 100).state,
            "unmanaged"
        );
    }

    #[test]
    fn immutable_links_keep_tombstones_visible_without_direct_user_id() {
        let db = database();
        db.execute("INSERT INTO zeroth_directory_links(tenant_id,provider_id,authority_id,external_id,user_id,created_at) VALUES ('a','entra',?1,'a-object','shared',1)",[REALM]).unwrap();
        db.execute(
            "UPDATE zeroth_directory_users SET user_id=NULL,deleted=1 WHERE id='a_user'",
            [],
        )
        .unwrap();
        assert_eq!(
            access_status(&policy(), &row(&db, "a", "shared"), 100).state,
            "deleted"
        );
        assert_eq!(
            access_status(&policy(), &row(&db, "b", "shared"), 100).state,
            "active"
        );
    }

    #[test]
    fn google_freshness_applies_only_to_managed_google_and_disabled_tenant_wins() {
        let user = AccessRow {
            active_match: 1,
            ..Default::default()
        };
        let mut p = AccessPolicy {
            provider_id: Some("google_workspace".into()),
            enabled: Some(1),
            last_full_sync_at: Some(100),
            ..Default::default()
        };
        assert_eq!(access_status(&p, &user, 1000).state, "active");
        assert_eq!(access_status(&p, &user, 1001).state, "stale");
        p.last_full_sync_at = None;
        assert_eq!(access_status(&p, &user, 100).state, "stale");
        p.provider_id = Some("entra".into());
        assert_eq!(access_status(&p, &user, 50000).state, "active");
        p.enabled = Some(0);
        assert_eq!(access_status(&p, &user, 50000).state, "unmanaged");
        p.disabled = 1;
        assert_eq!(access_status(&p, &user, 50000).state, "tenant_disabled");
    }

    #[test]
    fn draft_entra_status_has_no_authority_until_guid_is_saved() {
        let tenant = tenants::TenantRow {
            id: "draft".into(),
            name: "Draft".into(),
            disabled: 0,
            enterprise_provider: Some("entra".into()),
            entra_tenant_id: None,
            google_workspace_domains_json: "[]".into(),
            oidc_client_id: None,
            client_secret_binding: None,
            retention_days: None,
            created_at: 1,
            updated_at: 1,
        };
        assert!(authority(&tenant).is_err());
        let status = access_status(&AccessPolicy::default(), &AccessRow::default(), 100);
        assert_eq!(status.state, "unmanaged");
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("token"));
    }
}
