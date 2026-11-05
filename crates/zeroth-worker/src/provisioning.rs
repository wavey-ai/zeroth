//! Tenant-scoped directory lifecycle. Only authenticated source adapters may
//! write this service. Upstream object identity is immutable and never matched
//! through a mailbox, userName, display name or Entra's pairwise OIDC subject.
use super::*;
use std::collections::BTreeSet;
use zeroth_audit::{AuditActor, AuditEvent, AuditOutcome, AuditTarget, DetailKey, DetailValue};

pub(super) const MAX_SNAPSHOT_USERS: usize = 10_000;
pub(super) const GOOGLE_MAX_SYNC_AGE: i32 = 900;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DirectoryAuthority {
    pub tenant_id: String,
    pub provider_id: String,
    pub authority_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DirectoryUserChange {
    pub external_id: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub profile_json: Option<String>,
    pub active: bool,
    pub deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct DirectoryUser {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub authority_id: String,
    pub external_id: String,
    pub user_name: String,
    pub display_name: Option<String>,
    pub profile_json: String,
    #[serde(deserialize_with = "db_bool")]
    pub active: bool,
    #[serde(deserialize_with = "db_bool")]
    pub deleted: bool,
    pub user_id: Option<String>,
    pub created_at: i32,
    pub updated_at: i32,
    pub version: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct DirectorySource {
    pub tenant_id: String,
    pub provider_id: String,
    pub authority_id: String,
    /// Managed-only enforcement, not polling health. Pausing a source must not
    /// turn this off. A policy change is an explicit audited admin operation.
    pub enabled: i32,
    pub token_binding: Option<String>,
    pub last_activity_at: Option<i32>,
    pub last_full_sync_at: Option<i32>,
    pub last_error_code: Option<String>,
    pub sync_fence: Option<String>,
    pub config_version: i64,
    pub created_at: i32,
    pub updated_at: i32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(super) struct LifecycleSummary {
    pub processed: usize,
    pub deactivated: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LifecycleError {
    pub status: u16,
    pub code: &'static str,
    pub detail: &'static str,
}

impl LifecycleError {
    pub(super) fn invalid(detail: &'static str) -> Self {
        Self {
            status: 400,
            code: "invalidValue",
            detail,
        }
    }
    pub(super) fn denied(detail: &'static str) -> Self {
        Self {
            status: 403,
            code: "forbidden",
            detail,
        }
    }
    pub(super) fn conflict(detail: &'static str) -> Self {
        Self {
            status: 409,
            code: "uniqueness",
            detail,
        }
    }
    pub(super) fn missing() -> Self {
        Self {
            status: 404,
            code: "notFound",
            detail: "directory user was not found",
        }
    }
    pub(super) fn storage() -> Self {
        Self {
            status: 503,
            code: "temporarilyUnavailable",
            detail: "directory operation could not be persisted",
        }
    }
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.detail)
    }
}

/// Only construct from signature-verified, policy-validated OIDC evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VerifiedDirectoryIdentity {
    pub provider_id: String,
    pub authority_id: Option<String>,
    pub external_id: String,
}

#[derive(Clone, Debug)]
pub(super) struct LoginAdmission {
    pub authority: Option<DirectoryAuthority>,
    pub external_id: Option<String>,
    pub directory_id: Option<String>,
    pub linked_user_id: Option<String>,
    pub source_version: Option<i64>,
    pub directory_version: Option<i64>,
}

fn db_bool<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Bool(bool),
        Int(i32),
    }
    match Value::deserialize(deserializer)? {
        Value::Bool(value) => Ok(value),
        Value::Int(0) => Ok(false),
        Value::Int(1) => Ok(true),
        _ => Err(serde::de::Error::custom("invalid directory boolean")),
    }
}

fn bounded_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

impl DirectoryAuthority {
    pub(super) fn validate(&self) -> Result<(), LifecycleError> {
        if !bounded_id(&self.tenant_id) {
            return Err(LifecycleError::invalid("invalid tenant identifier"));
        }
        match self.provider_id.as_str() {
            "entra" => {
                let normalized = zeroth_providers::normalize_entra_tenant_id(&self.authority_id)
                    .map_err(|_| {
                        LifecycleError::invalid("Entra authority must be the directory tenant GUID")
                    })?;
                if normalized != self.authority_id {
                    return Err(LifecycleError::invalid(
                        "Entra authority must be normalized",
                    ));
                }
            }
            "google_workspace"
                if self.authority_id.starts_with('C') && bounded_id(&self.authority_id) => {}
            _ => return Err(LifecycleError::invalid("unsupported directory authority")),
        }
        Ok(())
    }
}

pub(super) fn normalize_external_id(provider: &str, value: &str) -> Result<String, LifecycleError> {
    if provider == "entra" {
        return zeroth_providers::normalize_entra_tenant_id(value)
            .map_err(|_| LifecycleError::invalid("Entra externalId must map to objectId, a GUID"));
    }
    if provider == "google_workspace" && bounded_id(value) {
        Ok(value.into())
    } else {
        Err(LifecycleError::invalid(
            "invalid directory object identifier",
        ))
    }
}

impl DirectoryUserChange {
    pub(super) fn validate(&self, authority: &DirectoryAuthority) -> Result<(), LifecycleError> {
        authority.validate()?;
        if normalize_external_id(&authority.provider_id, &self.external_id)? != self.external_id {
            return Err(LifecycleError::invalid("externalId must be normalized"));
        }
        if self.user_name.trim() != self.user_name
            || self.user_name.is_empty()
            || self.user_name.len() > 320
            || self.user_name.chars().any(char::is_control)
        {
            return Err(LifecycleError::invalid("invalid directory userName"));
        }
        if self
            .display_name
            .as_ref()
            .is_some_and(|name| name.len() > 256 || name.chars().any(char::is_control))
        {
            return Err(LifecycleError::invalid("invalid directory displayName"));
        }
        if self.deleted && self.active {
            return Err(LifecycleError::invalid("a deleted user cannot be active"));
        }
        if let Some(profile) = &self.profile_json {
            validate_profile_json(profile)?;
        }
        Ok(())
    }
}

pub(super) const LIFECYCLE_USER_ACTIVE_SQL:&str="SELECT CASE WHEN
    NOT EXISTS (
      SELECT 1 FROM zeroth_tenant_clients tc JOIN zeroth_directory_users d ON d.tenant_id=tc.tenant_id
      WHERE tc.client_id=?2 AND (d.user_id=?1 OR EXISTS (
          SELECT 1 FROM zeroth_directory_links l WHERE l.tenant_id=d.tenant_id AND l.provider_id=d.provider_id
            AND l.authority_id=d.authority_id AND l.external_id=d.external_id AND l.user_id=?1))
        AND (d.active=0 OR d.deleted=1)
    ) AND NOT EXISTS (
      SELECT 1 FROM zeroth_tenant_clients tc JOIN zeroth_directory_sources s ON s.tenant_id=tc.tenant_id
      WHERE tc.client_id=?2 AND s.enabled=1 AND (
        (s.provider_id='google_workspace' AND (s.last_full_sync_at IS NULL OR s.last_full_sync_at<?3-900))
        OR NOT EXISTS (SELECT 1 FROM zeroth_directory_users d
          WHERE d.tenant_id=s.tenant_id AND d.provider_id=s.provider_id AND d.authority_id=s.authority_id
            AND d.user_id=?1 AND d.active=1 AND d.deleted=0)
      )
    ) THEN 1 ELSE 0 END AS active";

/// Direct tenant checks also protect readers authenticated through another
/// tenant's client and tenants which do not currently have a bound client.
/// Keep the same admission predicate as LIFECYCLE_USER_ACTIVE_SQL; native tests
/// assert agreement for both views of a bound tenant.
pub(super) const TENANT_USER_ACTIVE_SQL: &str = "SELECT CASE WHEN
    NOT EXISTS (
      SELECT 1 FROM zeroth_directory_users d
      WHERE d.tenant_id=?2 AND (d.user_id=?1 OR EXISTS (
          SELECT 1 FROM zeroth_directory_links l WHERE l.tenant_id=d.tenant_id AND l.provider_id=d.provider_id
            AND l.authority_id=d.authority_id AND l.external_id=d.external_id AND l.user_id=?1))
        AND (d.active=0 OR d.deleted=1)
    ) AND NOT EXISTS (
      SELECT 1 FROM zeroth_directory_sources s
      WHERE s.tenant_id=?2 AND s.enabled=1 AND (
        (s.provider_id='google_workspace' AND (s.last_full_sync_at IS NULL OR s.last_full_sync_at<?3-900))
        OR NOT EXISTS (SELECT 1 FROM zeroth_directory_users d
          WHERE d.tenant_id=s.tenant_id AND d.provider_id=s.provider_id AND d.authority_id=s.authority_id
            AND d.user_id=?1 AND d.active=1 AND d.deleted=0)
      )
    ) THEN 1 ELSE 0 END AS active";

pub(super) const SOURCE_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN EXISTS (
      SELECT 1 FROM zeroth_directory_sources s JOIN zeroth_tenants t ON t.id=s.tenant_id
      WHERE s.tenant_id=?2 AND s.provider_id=?3 AND s.authority_id=?4
        AND t.disabled=0 AND t.enterprise_provider=?3
        AND (?3<>'entra' OR t.entra_tenant_id=?4)
        AND s.config_version=?5 AND (?6 IS NULL OR s.sync_fence=?6)
    ) THEN 1 ELSE 0 END";

pub(super) const CONFIG_TENANT_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN EXISTS (SELECT 1 FROM zeroth_tenants
      WHERE id=?2 AND enterprise_provider=?3 AND (?3<>'entra' OR entra_tenant_id=?4))
    THEN 1 ELSE 0 END";

pub(super) const MARK_SNAPSHOT_COMPLETE_SQL: &str = "UPDATE zeroth_directory_sources
    SET last_full_sync_at=?2,last_activity_at=?3,last_error_code=NULL WHERE tenant_id=?1";

pub(super) const USER_PREIMAGE_GUARD_SQL:&str="INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN (?6=0 AND NOT EXISTS (
       SELECT 1 FROM zeroth_directory_users WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND external_id=?5))
      OR (?6>0 AND EXISTS (SELECT 1 FROM zeroth_directory_users
       WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND external_id=?5 AND version=?6))
    THEN 1 ELSE 0 END";

pub(super) const LINK_PREIMAGE_GUARD_SQL:&str="INSERT INTO zeroth_audit_write_guards(id,valid)
    SELECT ?1,CASE WHEN NOT EXISTS(SELECT 1 FROM zeroth_directory_links
      WHERE tenant_id=?2 AND provider_id=?3 AND authority_id=?4 AND external_id=?5 AND user_id IS NOT ?6)
    THEN 1 ELSE 0 END";

pub(super) const UPSERT_DIRECTORY_USER_SQL:&str="INSERT INTO zeroth_directory_users (
    id,tenant_id,provider_id,authority_id,external_id,user_name,user_name_key,display_name,active,deleted,user_id,created_at,updated_at,profile_json,version
    ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?12,COALESCE(?13,'{}'),1)
    ON CONFLICT(tenant_id,provider_id,authority_id,external_id) DO UPDATE SET
      user_name=excluded.user_name,user_name_key=excluded.user_name_key,display_name=excluded.display_name,
      active=excluded.active,deleted=excluded.deleted,user_id=COALESCE(zeroth_directory_users.user_id,excluded.user_id),
      profile_json=CASE WHEN ?13 IS NULL THEN zeroth_directory_users.profile_json ELSE excluded.profile_json END,
      updated_at=excluded.updated_at,version=zeroth_directory_users.version+1";

pub(super) const REVOKE_DIRECTORY_USER_SQL:&[&str]=&[
    "UPDATE zeroth_sessions SET revoked_at=COALESCE(revoked_at,?3) WHERE user_id=?2 AND client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_refresh_tokens SET revoked_at=COALESCE(revoked_at,?3) WHERE user_id=?2 AND client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_auth_codes SET consumed_at=COALESCE(consumed_at,?3) WHERE user_id=?2 AND client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_auth_transactions SET consumed_at=COALESCE(consumed_at,?3) WHERE link_user_id=?2 AND client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_passkey_challenges SET consumed_at=COALESCE(consumed_at,?3) WHERE user_id=?2 AND client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_magic_links SET consumed_at=COALESCE(consumed_at,?3) WHERE user_id=?2 AND client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    // Local methods are global in legacy databases. Disable them only for an
    // exclusively tenant-owned user, preserving another tenant's credentials.
    "UPDATE zeroth_local_credentials SET disabled_at=COALESCE(disabled_at,?3) WHERE user_id=?2
       AND NOT EXISTS (SELECT 1 FROM zeroth_account_identities WHERE user_id=?2 AND account_namespace<>'tenant:'||?1)
       AND NOT EXISTS (SELECT 1 FROM zeroth_identities WHERE user_id=?2)",
    "UPDATE zeroth_passkey_credentials SET disabled_at=COALESCE(disabled_at,?3) WHERE user_id=?2
       AND NOT EXISTS (SELECT 1 FROM zeroth_account_identities WHERE user_id=?2 AND account_namespace<>'tenant:'||?1)
       AND NOT EXISTS (SELECT 1 FROM zeroth_identities WHERE user_id=?2)",
];

pub(super) const INVALIDATE_TENANT_GRANTS_SQL: &[&str] = &[
    "UPDATE zeroth_sessions SET revoked_at=COALESCE(revoked_at,?2) WHERE client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_refresh_tokens SET revoked_at=COALESCE(revoked_at,?2) WHERE client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_auth_codes SET consumed_at=COALESCE(consumed_at,?2) WHERE client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
    "UPDATE zeroth_auth_transactions SET consumed_at=COALESCE(consumed_at,?2) WHERE client_id IN (SELECT client_id FROM zeroth_tenant_clients WHERE tenant_id=?1)",
];

pub(super) const PIN_DIRECTORY_LINK_SQL:&str="INSERT INTO zeroth_directory_links
    (tenant_id,provider_id,authority_id,external_id,user_id,created_at) VALUES (?1,?2,?3,?4,?5,?6)
    ON CONFLICT(tenant_id,provider_id,authority_id,external_id) DO UPDATE SET
      user_id=CASE WHEN zeroth_directory_links.user_id=excluded.user_id THEN zeroth_directory_links.user_id ELSE NULL END";

fn validate_snapshot(
    authority: &DirectoryAuthority,
    changes: &[DirectoryUserChange],
) -> Result<BTreeSet<String>, LifecycleError> {
    if changes.len() > MAX_SNAPSHOT_USERS {
        return Err(LifecycleError::invalid(
            "directory snapshot exceeds the supported user limit",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for change in changes {
        change.validate(authority)?;
        if !ids.insert(change.external_id.clone()) {
            return Err(LifecycleError::invalid(
                "duplicate directory object identifier",
            ));
        }
        if !change.deleted && !names.insert(change.user_name.to_lowercase()) {
            return Err(LifecycleError::conflict(
                "directory userNames are ambiguous",
            ));
        }
    }
    Ok(ids)
}

pub(super) fn validate_profile_json(profile: &str) -> Result<(), LifecycleError> {
    if profile.len() > 8192 {
        return Err(LifecycleError::invalid(
            "SCIM profile metadata is too large",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(profile)
        .map_err(|_| LifecycleError::invalid("invalid SCIM profile metadata"))?;
    let object = value
        .as_object()
        .ok_or_else(|| LifecycleError::invalid("invalid SCIM profile metadata"))?;
    for (key, value) in object {
        match key.as_str() {
            "name" => {
                let fields = value
                    .as_object()
                    .ok_or_else(|| LifecycleError::invalid("invalid SCIM name"))?;
                for (key, value) in fields {
                    if !matches!(
                        key.as_str(),
                        "givenName" | "familyName" | "middleName" | "formatted"
                    ) || !value.as_str().is_some_and(|text| {
                        text.len() <= 256 && !text.chars().any(char::is_control)
                    }) {
                        return Err(LifecycleError::invalid("unsupported SCIM name attribute"));
                    }
                }
            }
            "emails" => {
                let emails = value
                    .as_array()
                    .filter(|values| values.len() <= 4)
                    .ok_or_else(|| LifecycleError::invalid("invalid SCIM emails"))?;
                for email in emails {
                    let fields = email
                        .as_object()
                        .ok_or_else(|| LifecycleError::invalid("invalid SCIM email"))?;
                    for (key, value) in fields {
                        let valid = match key.as_str() {
                            "value" => value.as_str().is_some_and(|text| {
                                text.len() <= 320 && !text.chars().any(char::is_control)
                            }),
                            "type" => value.as_str().is_some_and(|text| {
                                text.len() <= 32
                                    && text
                                        .bytes()
                                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                            }),
                            "primary" => value.is_boolean(),
                            _ => false,
                        };
                        if !valid {
                            return Err(LifecycleError::invalid(
                                "unsupported SCIM email attribute",
                            ));
                        }
                    }
                }
            }
            _ => return Err(LifecycleError::invalid("unsupported SCIM profile metadata")),
        }
    }
    Ok(())
}

fn lifecycle_event(
    id: String,
    authority: &DirectoryAuthority,
    directory_id: &str,
    user_id: Option<&str>,
    action: &str,
    actor: AuditActor,
    now: i32,
) -> Result<AuditEvent, LifecycleError> {
    let mut event = AuditEvent::new(
        id,
        i64::from(now),
        i64::from(now),
        action,
        actor,
        AuditOutcome::Success,
    )
    .map_err(|_| LifecycleError::storage())?;
    event.organization_id = Some(authority.tenant_id.clone());
    event.provider_id = Some(authority.provider_id.clone());
    event.targets.push(
        AuditTarget::new("directory_user", directory_id).map_err(|_| LifecycleError::storage())?,
    );
    if let Some(user) = user_id {
        event
            .targets
            .push(AuditTarget::new("user", user).map_err(|_| LifecycleError::storage())?);
    }
    event
        .details
        .insert(
            DetailKey::Disabled,
            DetailValue::Bool(action.ends_with(".disable") || action.ends_with(".delete")),
        )
        .map_err(|_| LifecycleError::storage())?;
    event.validate().map_err(|_| LifecycleError::storage())?;
    Ok(event)
}

fn check_directory_state(
    source: Option<&DirectorySource>,
    directory: Option<&DirectoryUser>,
    now: i32,
) -> Result<(), LifecycleError> {
    if directory.is_some_and(|user| !user.active || user.deleted) {
        return Err(LifecycleError::denied("directory identity is inactive"));
    }
    if let Some(source) = source.filter(|source| source.enabled != 0) {
        if source.provider_id == "google_workspace"
            && source
                .last_full_sync_at
                .is_none_or(|completed| completed < now - GOOGLE_MAX_SYNC_AGE)
        {
            return Err(LifecycleError::denied(
                "directory synchronization is stale or has not completed",
            ));
        }
        if directory.is_none() {
            return Err(LifecycleError::denied(
                "directory identity has not been provisioned",
            ));
        }
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod store;
#[cfg(target_arch = "wasm32")]
pub(super) use store::*;

#[cfg(test)]
mod tests;

#[cfg(target_arch = "wasm32")]
pub(super) fn user_guard_statement(
    db: &worker::d1::D1Database,
    user_id: &str,
    client_id: &str,
    guard_id: &str,
    now: i32,
) -> Result<worker::d1::D1PreparedStatement, LifecycleError> {
    use worker::d1::D1Type as V;
    db.prepare(format!(
        "INSERT INTO zeroth_audit_write_guards(id,valid) SELECT ?4,({LIFECYCLE_USER_ACTIVE_SQL})"
    ))
    .bind_refs(&[
        V::Text(user_id),
        V::Text(client_id),
        V::Integer(now),
        V::Text(guard_id),
    ])
    .map_err(|_| LifecycleError::storage())
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn user_is_active(
    db: &worker::d1::D1Database,
    user_id: &str,
    client_id: &str,
    now: i32,
) -> Result<bool, LifecycleError> {
    #[derive(Deserialize)]
    struct Active {
        active: i32,
    }
    use worker::d1::D1Type as V;
    let row = db
        .prepare(LIFECYCLE_USER_ACTIVE_SQL)
        .bind_refs(&[V::Text(user_id), V::Text(client_id), V::Integer(now)])
        .map_err(|_| LifecycleError::storage())?
        .first::<Active>(None)
        .await
        .map_err(|_| LifecycleError::storage())?;
    Ok(row.is_some_and(|row| row.active == 1))
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn tenant_user_is_active(
    db: &worker::d1::D1Database,
    user_id: &str,
    tenant_id: &str,
    now: i32,
) -> Result<bool, LifecycleError> {
    #[derive(Deserialize)]
    struct Active {
        active: i32,
    }
    use worker::d1::D1Type as V;
    let row = db
        .prepare(TENANT_USER_ACTIVE_SQL)
        .bind_refs(&[V::Text(user_id), V::Text(tenant_id), V::Integer(now)])
        .map_err(|_| LifecycleError::storage())?
        .first::<Active>(None)
        .await
        .map_err(|_| LifecycleError::storage())?;
    Ok(row.is_some_and(|row| row.active == 1))
}
