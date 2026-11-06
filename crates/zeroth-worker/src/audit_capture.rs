//! Audit capture is an awaited database operation. Tracing is only a mirror.
use zeroth_audit::{AuditActor, AuditEvent, AuditOutcome, AuditTarget, SafeDetails};

pub(super) const INSERT_EVENT_SQL: &str = "INSERT INTO zeroth_audit_events (
    id, event_type, user_id, client_id, provider_id, created_at, details_json,
    schema_version, organization_id, actor_type, actor_id, target_type, target_id,
    outcome, reason_code, request_id, recorded_at, event_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
pub(super) const INSERT_OUTBOX_SQL: &str = "INSERT INTO zeroth_audit_outbox
    (event_id, event_json, created_at) VALUES (?, ?, ?)";

pub(super) const AUDIT_SCOPE_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards (id,valid)
    SELECT ?1, CASE WHEN COALESCE((SELECT tenant_id FROM zeroth_tenant_clients WHERE client_id=?3), (SELECT tenant_id FROM zeroth_service_clients WHERE id=?3)) IS ?2 THEN 1 ELSE 0 END";

// User-wide lifecycle actions retain a platform record and a separate projection
// for each explicitly registered tenant affected at the instant of capture.
// The copies reveal neither other tenant memberships nor platform-only history.
pub(super) const FANOUT_USER_EVENT_SQL: &str = "INSERT INTO zeroth_audit_events (
    id,event_type,user_id,client_id,provider_id,created_at,details_json,schema_version,organization_id,
    actor_type,actor_id,target_type,target_id,outcome,reason_code,request_id,recorded_at,event_json)
    SELECT a.id || '_tenant_' || t.id,a.event_type,a.user_id,NULL,a.provider_id,a.created_at,a.details_json,a.schema_version,t.id,
        a.actor_type,a.actor_id,a.target_type,a.target_id,a.outcome,a.reason_code,a.request_id,a.recorded_at,
        json_set(a.event_json,'$.event_id',a.id || '_tenant_' || t.id,'$.organization_id',t.id)
    FROM zeroth_audit_events a CROSS JOIN zeroth_tenants t
    WHERE a.id=?1 AND EXISTS (
        SELECT 1 FROM zeroth_account_identities ai JOIN zeroth_tenant_clients tc ON tc.tenant_id=t.id
        WHERE ai.user_id=a.user_id AND ai.account_namespace='tenant:' || t.id AND ai.provider_id=t.enterprise_provider
    )";
pub(super) const FANOUT_USER_OUTBOX_SQL: &str =
    "INSERT INTO zeroth_audit_outbox(event_id,event_json,created_at)
    SELECT a.id,a.event_json,a.recorded_at FROM zeroth_audit_events a
    JOIN zeroth_tenants t ON a.id=?1 || '_tenant_' || t.id";

pub(super) const CLIENT_POLICY_GUARD_SQL: &str = "INSERT INTO zeroth_audit_write_guards (id, valid)
    SELECT ?1, CASE WHEN NOT EXISTS(SELECT 1 FROM zeroth_service_clients WHERE id=?2)
      AND (?3=1 OR substr(?2,1,4)!='svc_') AND (
      (?3 = 0 AND NOT EXISTS (SELECT 1 FROM zeroth_clients WHERE id=?2)) OR
      (?3 = 1 AND EXISTS (SELECT 1 FROM zeroth_clients WHERE id=?2
        AND name IS ?4 AND secret_hash IS ?5 AND redirect_uris_json IS ?6
        AND allowed_origins_json IS ?7 AND allowed_email_domains_json IS ?8
        AND enterprise_provider IS ?9 AND issuer_token_audience IS ?10
        AND issuer_token_ttl_seconds IS ?11 AND account_sharing_mode IS ?12
        AND account_tenant_id IS ?13 AND visible_login_methods_json IS ?14
        AND confidential IS ?15 AND disabled_at IS ?16))) THEN 1 ELSE 0 END";

// One predicate supplies both the historical core-only SQL and the production
// composite guard, so tenant/provider checks cannot diverge between them.
macro_rules! client_user_scope_predicate_sql {
    () => {
        "EXISTS (
        SELECT 1 FROM zeroth_clients c WHERE c.id=?3 AND c.disabled_at IS NULL
          AND (c.enterprise_provider IS NULL OR c.enterprise_provider=?4)
          AND EXISTS (SELECT 1 FROM zeroth_users u WHERE u.id=?2 AND u.disabled_at IS NULL)
          AND (NOT EXISTS (SELECT 1 FROM zeroth_tenant_clients tc WHERE tc.client_id=c.id)
            OR EXISTS (SELECT 1 FROM zeroth_tenant_clients tc
                JOIN zeroth_tenants t ON t.id=tc.tenant_id
                JOIN zeroth_account_identities ai ON ai.account_namespace='tenant:' || t.id
                WHERE tc.client_id=c.id AND ai.user_id=?2 AND t.disabled=0
                  AND ai.provider_id=t.enterprise_provider
                  AND c.account_sharing_mode='tenant' AND c.account_tenant_id=t.id
                  AND c.enterprise_provider=t.enterprise_provider))
    )"
    };
}

#[cfg(test)]
pub(super) const CLIENT_USER_SCOPE_GUARD_SQL: &str = concat!(
    "INSERT INTO zeroth_audit_write_guards (id, valid) SELECT ?1, CASE WHEN ",
    client_user_scope_predicate_sql!(),
    " THEN 1 ELSE 0 END"
);

pub(super) fn client_user_scope_guard_sql() -> String {
    // The shared lifecycle SELECT uses exactly ?1=user, ?2=client, ?3=now.
    // Descending replacement avoids remapping a newly generated placeholder.
    let lifecycle = super::provisioning::LIFECYCLE_USER_ACTIVE_SQL
        .replace("?3", "?5")
        .replace("?2", "?3")
        .replace("?1", "?2");
    format!(
        "INSERT INTO zeroth_audit_write_guards (id, valid) SELECT ?1, CASE WHEN {} AND ({lifecycle})=1 THEN 1 ELSE 0 END",
        client_user_scope_predicate_sql!()
    )
}

#[cfg(target_arch = "wasm32")]
pub(super) fn client_user_scope_guard(
    db: &worker::d1::D1Database,
    user_id: &str,
    client_id: &str,
    guard_id: &str,
    auth_provider: Option<&str>,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    use worker::d1::D1Type as V;
    db.prepare(client_user_scope_guard_sql()).bind_refs(&[
        V::Text(guard_id),
        V::Text(user_id),
        V::Text(client_id),
        super::d1_optional_text(auth_provider),
        V::Integer(super::unix_timestamp_seconds()),
    ])
}

#[cfg(target_arch = "wasm32")]
pub(super) fn clear_guard(
    db: &worker::d1::D1Database,
    guard_id: &str,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    db.prepare("DELETE FROM zeroth_audit_write_guards WHERE id=?")
        .bind_refs(&[worker::d1::D1Type::Text(guard_id)])
}

#[cfg(target_arch = "wasm32")]
pub(super) fn client_policy_guard(
    db: &worker::d1::D1Database,
    previous: Option<&super::ClientRow>,
    client_id: &str,
    guard_id: &str,
) -> worker::Result<worker::d1::D1PreparedStatement> {
    use super::{d1_optional_integer as integer, d1_optional_text as text};
    use worker::d1::D1Type as V;
    db.prepare(CLIENT_POLICY_GUARD_SQL).bind_refs(&[
        V::Text(guard_id),
        V::Text(client_id),
        V::Integer(i32::from(previous.is_some())),
        text(previous.map(|r| r.name.as_str())),
        text(previous.and_then(|r| r.secret_hash.as_deref())),
        text(previous.map(|r| r.redirect_uris_json.as_str())),
        text(previous.map(|r| r.allowed_origins_json.as_str())),
        text(previous.map(|r| r.allowed_email_domains_json.as_str())),
        text(previous.and_then(|r| r.enterprise_provider.as_deref())),
        text(previous.and_then(|r| r.issuer_token_audience.as_deref())),
        integer(previous.and_then(|r| r.issuer_token_ttl_seconds)),
        text(previous.and_then(|r| r.account_sharing_mode.as_deref())),
        text(previous.and_then(|r| r.account_tenant_id.as_deref())),
        text(previous.and_then(|r| r.visible_login_methods_json.as_deref())),
        integer(previous.map(|r| r.confidential)),
        integer(previous.and_then(|r| r.disabled_at)),
    ])
}

pub(super) fn event(
    event_id: String,
    event_type: &str,
    actor: AuditActor,
    user_id: Option<&str>,
    client_id: Option<&str>,
    provider_id: Option<&str>,
    details: &serde_json::Value,
    now: i32,
) -> Result<AuditEvent, String> {
    let outcome = if event_type.ends_with(".denied")
        || event_type.ends_with(".suppressed")
        || event_type.ends_with(".replay")
    {
        AuditOutcome::Denied
    } else if event_type.ends_with(".failed") || event_type.ends_with(".error") {
        AuditOutcome::Failure
    } else {
        AuditOutcome::Success
    };
    let mut event = AuditEvent::new(
        event_id,
        i64::from(now),
        i64::from(now),
        event_type,
        actor,
        outcome,
    )
    .map_err(|e| e.to_string())?;
    event.client_id = client_id.map(str::to_owned);
    event.provider_id = provider_id.map(str::to_owned);
    if let Some(id) = user_id {
        event
            .targets
            .push(AuditTarget::new("user", id).map_err(|e| e.to_string())?);
    } else if let Some(id) = client_id {
        event
            .targets
            .push(AuditTarget::new("client", id).map_err(|e| e.to_string())?);
    }
    event.details = SafeDetails::from_json_allowlisted(details);
    event.validate().map_err(|e| e.to_string())?;
    Ok(event)
}

pub(super) fn actor_from_user(user_id: Option<&str>) -> Result<AuditActor, String> {
    match user_id {
        Some(id) => AuditActor::new("user", id).map_err(|e| e.to_string()),
        None => Ok(AuditActor::anonymous()),
    }
}

pub(super) fn actor_for_event(
    event_type: &str,
    user_id: Option<&str>,
) -> Result<AuditActor, String> {
    // A resolved email address is a target, not proof of the caller's identity.
    // Only confirmed authentication/account actions can use the user as actor;
    // privileged mutations always supply their authorized administrator.
    if matches!(
        event_type,
        "session.login"
            | "session.logout"
            | "session.revoke"
            | "session.create"
            | "authorization.code.issue"
            | "authorization.code.create"
            | "refresh_token.create"
            | "user.profile.update"
            | "identity.link"
            | "identity.unlink"
            | "account.delete"
    ) {
        actor_from_user(user_id)
    } else {
        Ok(AuditActor::anonymous())
    }
}

pub(super) fn admin_actor(authorization: &super::AdminAuthorization) -> Result<AuditActor, String> {
    match authorization {
        super::AdminAuthorization::Session { user_id } => {
            AuditActor::new("administrator", user_id).map_err(|e| e.to_string())
        }
        super::AdminAuthorization::BootstrapToken => {
            AuditActor::new("service", "bootstrap").map_err(|e| e.to_string())
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn statements(
    db: &worker::d1::D1Database,
    event: &AuditEvent,
    user_id: Option<&str>,
) -> worker::Result<Vec<worker::d1::D1PreparedStatement>> {
    use super::{d1_optional_text, worker_error};
    use worker::d1::D1Type as V;
    let json = event
        .canonical_json()
        .map_err(|e| worker_error(e.to_string()))?;
    let details = serde_json::to_string(&event.details)
        .map_err(|_| worker_error("invalid audit details".into()))?;
    let timestamp =
        i32::try_from(event.recorded_at).map_err(|_| worker_error("invalid audit time".into()))?;
    let target = event.targets.first();
    let args = [
        V::Text(&event.event_id),
        V::Text(&event.event_type),
        d1_optional_text(user_id),
        d1_optional_text(event.client_id.as_deref()),
        d1_optional_text(event.provider_id.as_deref()),
        V::Integer(timestamp),
        V::Text(&details),
        V::Integer(i32::from(event.schema_version)),
        d1_optional_text(event.organization_id.as_deref()),
        V::Text(&event.actor.kind),
        d1_optional_text(event.actor.id.as_deref()),
        d1_optional_text(target.map(|t| t.kind.as_str())),
        d1_optional_text(target.map(|t| t.id.as_str())),
        V::Text(event.outcome.as_str()),
        d1_optional_text(event.reason.as_deref()),
        d1_optional_text(event.correlation_id.as_deref()),
        V::Integer(timestamp),
        V::Text(&json),
    ];
    let mut statements = Vec::new();
    let guard_id = format!("audit_scope_{}", event.event_id);
    if let Some(client_id) = event.client_id.as_deref() {
        statements.push(db.prepare(AUDIT_SCOPE_GUARD_SQL).bind_refs(&[
            V::Text(&guard_id),
            d1_optional_text(event.organization_id.as_deref()),
            V::Text(client_id),
        ])?);
    }
    let insert = db.prepare(INSERT_EVENT_SQL).bind_refs(&args)?;
    let outbox = db.prepare(INSERT_OUTBOX_SQL).bind_refs(&[
        V::Text(&event.event_id),
        V::Text(&json),
        V::Integer(timestamp),
    ])?;
    statements.extend([insert, outbox]);
    if event.organization_id.is_none()
        && user_id.is_some()
        && matches!(
            event.event_type.as_str(),
            "user.disable" | "user.enable" | "account.delete"
        )
    {
        statements.push(
            db.prepare(FANOUT_USER_EVENT_SQL)
                .bind_refs(&[V::Text(&event.event_id)])?,
        );
        statements.push(
            db.prepare(FANOUT_USER_OUTBOX_SQL)
                .bind_refs(&[V::Text(&event.event_id)])?,
        );
    }
    if event.client_id.is_some() {
        statements.push(clear_guard(db, &guard_id)?);
    }
    Ok(statements)
}

/// The caller supplies business statements; D1 rolls back the entire batch if
/// either the mutation, audit row or outbox insert fails.
#[cfg(target_arch = "wasm32")]
pub(super) async fn commit(
    db: &worker::d1::D1Database,
    business: Vec<worker::d1::D1PreparedStatement>,
    events: &[(AuditEvent, Option<String>)],
) -> worker::Result<()> {
    let mut transaction = Vec::new();
    for (event, user_id) in events {
        transaction.extend(statements(db, event, user_id.as_deref())?);
    }
    // Capture ownership before destructive account mutations. These records are
    // visible only if the entire batch, including every business guard, commits.
    transaction.extend(business);
    let result = db.batch(transaction).await;
    match result {
        Ok(results) if results.iter().all(|r| r.success()) => {
            for (event, _) in events {
                // Validation already succeeded before the commit. Subscribers
                // may filter/drop this mirror without affecting durable capture.
                let _ = zeroth_audit::emit_tracing_mirror(event);
            }
            Ok(())
        }
        _ => {
            tracing::error!(target: "zeroth.audit.persistence", code = "audit_commit_failed");
            // Never expose SQL, event payloads or database error strings.
            Err(super::worker_error("audit capture failed".into()))
        }
    }
}

/// Cloudflare adapter for the same contract as the native DynamoDB capture
/// adapter. The caller owns event identity across retries and supplies the
/// business writes that must share the database transaction.
#[cfg(target_arch = "wasm32")]
pub struct D1AuditCapture<'db> {
    db: &'db worker::d1::D1Database,
}

#[cfg(target_arch = "wasm32")]
impl<'db> D1AuditCapture<'db> {
    pub fn new(db: &'db worker::d1::D1Database) -> Self {
        Self { db }
    }

    async fn existing(
        &self,
        event: &AuditEvent,
    ) -> Result<Option<zeroth_audit::AppendResult>, zeroth_audit::AuditError> {
        #[derive(serde::Deserialize)]
        struct Stored {
            event_json: Option<String>,
        }
        let row = self
            .db
            .prepare("SELECT event_json FROM zeroth_audit_events WHERE id=?")
            .bind_refs(&[worker::d1::D1Type::Text(&event.event_id)])
            .map_err(|_| zeroth_audit::AuditError::Storage)?
            .first::<Stored>(None)
            .await
            .map_err(|_| zeroth_audit::AuditError::Storage)?;
        match row {
            None => Ok(None),
            Some(stored)
                if stored.event_json.as_deref() == Some(event.canonical_json()?.as_str()) =>
            {
                Ok(Some(zeroth_audit::AppendResult::Duplicate))
            }
            Some(_) => Err(zeroth_audit::AuditError::EventIdCollision),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl zeroth_audit::AuditCapture for D1AuditCapture<'_> {
    type Mutation = worker::d1::D1PreparedStatement;

    fn capture<'a>(
        &'a self,
        event: &'a AuditEvent,
        mutations: Vec<Self::Mutation>,
    ) -> zeroth_audit::AuditFuture<'a> {
        Box::pin(async move {
            event.validate()?;
            if let Some(result) = self.existing(event).await? {
                return Ok(result);
            }
            let user = event
                .targets
                .iter()
                .find(|target| target.kind == "user")
                .map(|target| target.id.clone());
            match commit(self.db, mutations, &[(event.clone(), user)]).await {
                Ok(()) => Ok(zeroth_audit::AppendResult::Inserted),
                Err(_) => self
                    .existing(event)
                    .await?
                    .ok_or(zeroth_audit::AuditError::Storage),
            }
        })
    }
}

#[cfg(target_arch = "wasm32")]
impl zeroth_audit::AuditSink for D1AuditCapture<'_> {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> zeroth_audit::AuditFuture<'a> {
        zeroth_audit::AuditCapture::capture(self, event, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        for migration in zeroth_storage::migrations::ALL {
            for statement in migration.statements() {
                connection.execute_batch(statement).unwrap();
            }
        }
        connection
    }

    fn insert(tx: &rusqlite::Transaction<'_>, event: &AuditEvent) -> rusqlite::Result<()> {
        let json = event.canonical_json().unwrap();
        tx.execute(
            INSERT_EVENT_SQL,
            params![
                event.event_id,
                event.event_type,
                "usr_subject",
                event.client_id,
                event.provider_id,
                event.recorded_at,
                "{}",
                event.schema_version,
                event.organization_id,
                event.actor.kind,
                event.actor.id,
                "user",
                "usr_subject",
                event.outcome.as_str(),
                event.reason,
                event.correlation_id,
                event.recorded_at,
                json,
            ],
        )?;
        tx.execute(
            INSERT_OUTBOX_SQL,
            params![event.event_id, json, event.recorded_at],
        )?;
        Ok(())
    }

    fn guarded_connection(provider: &str) -> Connection {
        let db = connection();
        db.execute_batch("INSERT INTO zeroth_users(id,created_at,updated_at) VALUES ('usr_subject',1,1);
            INSERT INTO zeroth_tenants(id,name,enterprise_provider,entra_tenant_id,created_at,updated_at)
              VALUES ('acme','Acme','entra','11111111-2222-3333-4444-555555555555',1,1);").unwrap();
        db.execute(
            "UPDATE zeroth_tenants SET enterprise_provider=?1 WHERE id='acme'",
            [provider],
        )
        .unwrap();
        db.execute("INSERT INTO zeroth_clients(id,name,redirect_uris_json,enterprise_provider,account_sharing_mode,account_tenant_id,created_at,updated_at)
            VALUES ('app','App','[]',?1,'tenant','acme',1,1)",[provider]).unwrap();
        db.execute("INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('app','acme',?1)",[provider]).unwrap();
        db.execute("INSERT INTO zeroth_account_identities(account_namespace,provider_id,provider_subject,user_id,created_at,updated_at)
            VALUES ('tenant:acme',?1,'subject','usr_subject',1,1)",[provider]).unwrap();
        db.execute("INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,enabled,last_full_sync_at,created_at,updated_at)
            VALUES ('acme',?1,?2,1,100,1,1)",params![provider,if provider=="entra" {"11111111-2222-3333-4444-555555555555"}else{"C012345"}]).unwrap();
        db.execute("INSERT INTO zeroth_directory_users(id,tenant_id,provider_id,authority_id,external_id,user_name,user_name_key,active,deleted,user_id,created_at,updated_at)
            SELECT 'dir_one',tenant_id,provider_id,authority_id,'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','user@example.com','user@example.com',1,0,'usr_subject',1,1 FROM zeroth_directory_sources WHERE tenant_id='acme'",[]).unwrap();
        db
    }

    fn assert_scope(db: &Connection, provider: Option<&str>, now: i32, allowed: bool) {
        let result = db.execute(
            &client_user_scope_guard_sql(),
            params!["scope_check", "usr_subject", "app", provider, now],
        );
        assert_eq!(result.is_ok(), allowed, "provider={provider:?} now={now}");
        db.execute(
            "DELETE FROM zeroth_audit_write_guards WHERE id='scope_check'",
            [],
        )
        .unwrap();
    }

    #[test]
    fn lifecycle_race_rolls_back_each_credential_and_its_audit_in_the_same_transaction() {
        for mutation in [
            "INSERT INTO zeroth_sessions(id,user_id,client_id,created_at,expires_at) VALUES ('session','usr_subject','app',100,10000)",
            "INSERT INTO zeroth_auth_codes(code_hash,client_id,redirect_uri,user_id,scope,created_at,expires_at) VALUES ('code','app','https://app.example/callback','usr_subject','openid',100,10000)",
            "INSERT INTO zeroth_refresh_tokens(token_hash,client_id,user_id,scope,created_at,expires_at) VALUES ('refresh','app','usr_subject','openid',100,10000)",
        ] {
            let mut db = guarded_connection("entra");
            // Simulate a successful asynchronous precheck followed by a
            // committed offboarding signal before the issuance transaction.
            assert_scope(&db, Some("entra"), 100, true);
            db.execute(
                "UPDATE zeroth_directory_users SET active=0,updated_at=101",
                [],
            )
            .unwrap();
            let audit = event(
                "evt_racing_issue".into(),
                "token.issue",
                AuditActor::new("user", "usr_subject").unwrap(),
                Some("usr_subject"),
                Some("app"),
                Some("entra"),
                &serde_json::json!({}),
                102,
            )
            .unwrap();
            {
                let tx = db.transaction().unwrap();
                tx.execute(mutation, []).unwrap();
                insert(&tx, &audit).unwrap();
                assert!(
                    tx.execute(
                        &client_user_scope_guard_sql(),
                        params!["scope", "usr_subject", "app", "entra", 102]
                    )
                    .is_err()
                );
                // Dropping the failed transaction matches D1 batch rollback,
                // including writes that preceded the failing CHECK guard.
            }
            for table in [
                "zeroth_sessions",
                "zeroth_auth_codes",
                "zeroth_refresh_tokens",
                "zeroth_audit_events",
                "zeroth_audit_outbox",
                "zeroth_audit_write_guards",
            ] {
                assert_eq!(
                    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, i32>(0))
                        .unwrap(),
                    0,
                    "{table}"
                );
            }
            assert_eq!(
                db.query_row("SELECT active FROM zeroth_directory_users", [], |row| row
                    .get::<_, i32>(
                    0
                ))
                .unwrap(),
                0
            );
        }
    }

    #[test]
    fn production_scope_guard_enforces_unknown_stale_and_persistent_denial_states() {
        let db = guarded_connection("entra");
        assert_scope(&db, Some("entra"), 100, true);
        db.execute("UPDATE zeroth_directory_users SET user_id=NULL", [])
            .unwrap();
        assert_scope(&db, Some("entra"), 100, false);
        db.execute("UPDATE zeroth_directory_sources SET enabled=0", [])
            .unwrap();
        assert_scope(&db, Some("entra"), 100, true);
        db.execute("INSERT INTO zeroth_directory_links(tenant_id,provider_id,authority_id,external_id,user_id,created_at)
            SELECT tenant_id,provider_id,authority_id,external_id,'usr_subject',1 FROM zeroth_directory_users",[]).unwrap();
        db.execute("UPDATE zeroth_directory_users SET active=0", [])
            .unwrap();
        assert_scope(&db, Some("entra"), 100, false);

        let google = guarded_connection("google_workspace");
        assert_scope(&google, Some("google_workspace"), 1000, true);
        assert_scope(&google, Some("google_workspace"), 1001, false);
        google
            .execute(
                "UPDATE zeroth_directory_sources SET last_full_sync_at=NULL",
                [],
            )
            .unwrap();
        assert_scope(&google, Some("google_workspace"), 100, false);
    }

    #[test]
    fn combined_scope_guard_preserves_tenant_provider_proof_and_legacy_behavior() {
        let db = guarded_connection("entra");
        assert_scope(&db, None, 100, false);
        assert_scope(&db, Some("google_workspace"), 100, false);
        assert_scope(&db, Some("entra"), 100, true);
        db.execute(
            "UPDATE zeroth_account_identities SET account_namespace='global'",
            [],
        )
        .unwrap();
        assert_scope(&db, Some("entra"), 100, false);
        db.execute(
            "UPDATE zeroth_account_identities SET account_namespace='tenant:acme'",
            [],
        )
        .unwrap();
        db.execute("UPDATE zeroth_tenants SET disabled=1", [])
            .unwrap();
        assert_scope(&db, Some("entra"), 100, false);
        db.execute("DELETE FROM zeroth_tenant_clients", []).unwrap();
        db.execute("UPDATE zeroth_clients SET enterprise_provider=NULL,account_sharing_mode='global',account_tenant_id='global'",[]).unwrap();
        db.execute("UPDATE zeroth_directory_users SET active=0,deleted=1", [])
            .unwrap();
        assert_scope(&db, None, 50000, true);
        db.execute("UPDATE zeroth_users SET disabled_at=100", [])
            .unwrap();
        assert_scope(&db, None, 50000, false);
    }

    #[test]
    fn outbox_failure_rolls_back_business_and_event() {
        let mut connection = connection();
        connection
            .execute_batch(
                "CREATE TABLE example_state (id TEXT PRIMARY KEY, value INTEGER);
            INSERT INTO example_state VALUES ('access', 0);
            CREATE TRIGGER reject_outbox BEFORE INSERT ON zeroth_audit_outbox
                BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
            )
            .unwrap();
        let event = event(
            "evt_test".into(),
            "user.disable",
            AuditActor::new("administrator", "usr_admin").unwrap(),
            Some("usr_subject"),
            None,
            None,
            &serde_json::json!({}),
            100,
        )
        .unwrap();
        {
            let tx = connection.transaction().unwrap();
            tx.execute("UPDATE example_state SET value=1 WHERE id='access'", [])
                .unwrap();
            assert!(insert(&tx, &event).is_err());
        }
        assert_eq!(
            connection
                .query_row("SELECT value FROM example_state", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM zeroth_audit_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn committed_event_and_outbox_have_identical_envelope() {
        let mut connection = connection();
        let event = event(
            "evt_test".into(),
            "user.disable",
            AuditActor::new("administrator", "usr_admin").unwrap(),
            Some("usr_subject"),
            Some("app"),
            None,
            &serde_json::json!({"description":"secret", "disabled":true}),
            100,
        )
        .unwrap();
        let tx = connection.transaction().unwrap();
        insert(&tx, &event).unwrap();
        tx.commit().unwrap();
        let (history, outbox): (String, String) = connection.query_row("SELECT a.event_json,o.event_json FROM zeroth_audit_events a JOIN zeroth_audit_outbox o ON o.event_id=a.id", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(history, outbox);
        assert!(!history.contains("secret"));
        assert_ne!(event.actor.id.as_deref(), Some("usr_subject"));
    }

    #[test]
    fn error_and_denial_names_have_explicit_outcomes() {
        for (name, outcome) in [
            ("token.issue.failed", AuditOutcome::Failure),
            ("client.login.denied", AuditOutcome::Denied),
            ("token.issue", AuditOutcome::Success),
        ] {
            assert_eq!(
                event(
                    "evt_test".into(),
                    name,
                    AuditActor::anonymous(),
                    None,
                    None,
                    None,
                    &serde_json::json!({}),
                    100
                )
                .unwrap()
                .outcome,
                outcome
            );
        }
    }

    #[test]
    fn actual_account_deletion_keeps_history_and_deletion_event() {
        let mut connection = connection();
        connection
            .execute(
                "INSERT INTO zeroth_users (id,created_at,updated_at) VALUES ('usr_subject',1,1)",
                [],
            )
            .unwrap();
        let history = event(
            "evt_history".into(),
            "admin.membership.grant",
            AuditActor::new("administrator", "usr_admin").unwrap(),
            Some("usr_subject"),
            None,
            None,
            &serde_json::json!({}),
            90,
        )
        .unwrap();
        let deletion = event(
            "evt_deletion".into(),
            "account.delete",
            AuditActor::new("user", "usr_subject").unwrap(),
            Some("usr_subject"),
            None,
            None,
            &serde_json::json!({}),
            100,
        )
        .unwrap();
        let tx = connection.transaction().unwrap();
        insert(&tx, &history).unwrap();
        tx.commit().unwrap();
        let tx = connection.transaction().unwrap();
        for sql in super::super::DELETE_ACCOUNT_DATA_SQL {
            tx.execute(sql, ["usr_subject"]).unwrap();
        }
        insert(&tx, &deletion).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM zeroth_users", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM zeroth_audit_events", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM zeroth_audit_outbox", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn resolving_a_mailbox_does_not_authenticate_the_caller() {
        for event in [
            "password.register.suppressed",
            "magic_link.issue",
            "magic_link.issue.suppressed",
            "magic_link.email.failed",
            "wallet.challenge",
        ] {
            assert_eq!(
                actor_for_event(event, Some("usr_target")).unwrap(),
                AuditActor::anonymous()
            );
        }
        assert_eq!(
            actor_for_event("session.login", Some("usr_authenticated"))
                .unwrap()
                .id
                .as_deref(),
            Some("usr_authenticated")
        );
    }

    #[test]
    fn failed_schema_upgrade_rolls_back_columns_and_can_be_retried() {
        let mut connection = Connection::open_in_memory().unwrap();
        for migration in zeroth_storage::migrations::ALL
            .iter()
            .filter(|m| m.version < 13)
        {
            connection.execute_batch(migration.sql).unwrap();
        }
        let migration = zeroth_storage::migrations::ALL
            .iter()
            .find(|m| m.version == 13)
            .unwrap();
        {
            let tx = connection.transaction().unwrap();
            for sql in migration.statements() {
                tx.execute_batch(sql).unwrap();
            }
            assert!(tx
                .execute_batch("INSERT INTO missing_table VALUES (1)")
                .is_err());
        }
        let tx = connection.transaction().unwrap();
        for sql in migration.statements() {
            tx.execute_batch(sql).unwrap();
        }
        tx.execute(
            "INSERT INTO zeroth_schema_migrations VALUES (13, 'audit_history', 100)",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM zeroth_schema_migrations WHERE version=13",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn stale_client_preimage_aborts_before_an_administrative_update() {
        let connection = connection();
        connection.execute("INSERT INTO zeroth_clients (id,name,redirect_uris_json,created_at,updated_at) VALUES ('app','Original','[]',1,1)", []).unwrap();
        let original: super::super::ClientRow = serde_json::from_value(serde_json::json!({"id":"app","name":"Original","redirect_uris_json":"[]","allowed_origins_json":"[]","allowed_email_domains_json":"[]","account_sharing_mode":"global","account_tenant_id":"global","visible_login_methods_json":"[]"})).unwrap();
        connection
            .execute(
                CLIENT_POLICY_GUARD_SQL,
                params![
                    "guard",
                    "app",
                    1,
                    original.name,
                    original.secret_hash,
                    original.redirect_uris_json,
                    original.allowed_origins_json,
                    original.allowed_email_domains_json,
                    original.enterprise_provider,
                    original.issuer_token_audience,
                    original.issuer_token_ttl_seconds,
                    original.account_sharing_mode,
                    original.account_tenant_id,
                    original.visible_login_methods_json,
                    original.confidential,
                    original.disabled_at,
                ],
            )
            .unwrap();
        connection
            .execute("DELETE FROM zeroth_audit_write_guards", [])
            .unwrap();
        connection
            .execute(
                "UPDATE zeroth_clients SET name='Concurrent edit' WHERE id='app'",
                [],
            )
            .unwrap();
        let result = connection.execute(
            CLIENT_POLICY_GUARD_SQL,
            params![
                "guard",
                "app",
                1,
                original.name,
                original.secret_hash,
                original.redirect_uris_json,
                original.allowed_origins_json,
                original.allowed_email_domains_json,
                original.enterprise_provider,
                original.issuer_token_audience,
                original.issuer_token_ttl_seconds,
                original.account_sharing_mode,
                original.account_tenant_id,
                original.visible_login_methods_json,
                original.confidential,
                original.disabled_at,
            ],
        );
        assert!(result.is_err());
        assert_eq!(
            connection
                .query_row("SELECT name FROM zeroth_clients WHERE id='app'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
            "Concurrent edit"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM zeroth_audit_write_guards", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }

    #[test]
    fn audit_owner_cannot_change_between_prepare_and_commit() {
        let connection = connection();
        connection.execute("INSERT INTO zeroth_tenants(id,name,enterprise_provider,created_at,updated_at) VALUES ('acme','Acme','entra',1,1)", []).unwrap();
        connection.execute("INSERT INTO zeroth_clients(id,name,redirect_uris_json,account_sharing_mode,account_tenant_id,enterprise_provider,created_at,updated_at) VALUES ('app','App','[]','tenant','acme','entra',1,1)", []).unwrap();
        // A legacy client already used the namespace, but had no registered
        // organization owner when an in-flight request prepared its event.
        connection
            .execute(
                AUDIT_SCOPE_GUARD_SQL,
                params!["guard", Option::<String>::None, "app"],
            )
            .unwrap();
        connection
            .execute("DELETE FROM zeroth_audit_write_guards", [])
            .unwrap();
        connection.execute("INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('app','acme','entra')", []).unwrap();
        assert!(connection
            .execute(
                AUDIT_SCOPE_GUARD_SQL,
                params!["stale", Option::<String>::None, "app"]
            )
            .is_err());
        connection
            .execute(AUDIT_SCOPE_GUARD_SQL, params!["current", "acme", "app"])
            .unwrap();
    }

    #[test]
    fn lifecycle_events_are_projected_only_to_explicitly_owned_tenants_before_deletion() {
        let mut connection = connection();
        connection.execute_batch("INSERT INTO zeroth_users(id,created_at,updated_at) VALUES ('usr_subject',1,1),('usr_other',1,1);
            INSERT INTO zeroth_tenants(id,name,enterprise_provider,created_at,updated_at) VALUES ('acme','Acme','entra',1,1),('other','Other','entra',1,1),('legacy','Legacy','entra',1,1);
            INSERT INTO zeroth_clients(id,name,redirect_uris_json,account_sharing_mode,account_tenant_id,enterprise_provider,created_at,updated_at) VALUES ('acme-app','App','[]','tenant','acme','entra',1,1),('other-app','App','[]','tenant','other','entra',1,1);
            INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('acme-app','acme','entra'),('other-app','other','entra');
            INSERT INTO zeroth_account_identities(account_namespace,provider_id,provider_subject,user_id,created_at,updated_at) VALUES ('tenant:acme','entra','subject','usr_subject',1,1),('tenant:other','entra','other','usr_other',1,1),('tenant:legacy','entra','legacy','usr_subject',1,1);").unwrap();
        let event = event(
            "evt_delete".into(),
            "account.delete",
            AuditActor::new("user", "usr_subject").unwrap(),
            Some("usr_subject"),
            None,
            None,
            &serde_json::json!({}),
            100,
        )
        .unwrap();
        let tx = connection.transaction().unwrap();
        insert(&tx, &event).unwrap();
        tx.execute(FANOUT_USER_EVENT_SQL, [&event.event_id])
            .unwrap();
        tx.execute(FANOUT_USER_OUTBOX_SQL, [&event.event_id])
            .unwrap();
        for sql in super::super::DELETE_ACCOUNT_DATA_SQL {
            tx.execute(sql, ["usr_subject"]).unwrap();
        }
        tx.commit().unwrap();
        let organizations: Vec<Option<String>> = connection
            .prepare("SELECT organization_id FROM zeroth_audit_events ORDER BY organization_id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(organizations, vec![None, Some("acme".into())]);
        let json: String = connection.query_row("SELECT event_json FROM zeroth_audit_outbox WHERE event_id='evt_delete_tenant_acme'",[],|r|r.get(0)).unwrap();
        let projected: AuditEvent = serde_json::from_str(&json).unwrap();
        projected.validate().unwrap();
        assert_eq!(projected.organization_id.as_deref(), Some("acme"));
        assert_eq!(projected.event_type, "account.delete");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM zeroth_users WHERE id='usr_subject'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
}
