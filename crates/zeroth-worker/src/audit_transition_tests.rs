//! Exercise the production SQL used by one-use credential transitions against
//! real SQLite transactions, including audit/outbox failures and racing grants.
use super::*;
use rusqlite::{params, Connection, Transaction};
use zeroth_audit::{AuditActor, AuditEvent, AuditOutcome, AuditTarget};

fn database() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    for migration in zeroth_storage::migrations::ALL {
        connection.execute_batch(migration.sql).unwrap();
    }
    connection
        .execute(
            "INSERT INTO zeroth_users (id,created_at,updated_at) VALUES ('usr_owner',1,1)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO zeroth_clients (id,name,redirect_uris_json,created_at,updated_at)
        VALUES ('app','App','[\"https://app.example/callback\"]',1,1)",
            [],
        )
        .unwrap();
    connection
        .execute(
            INSERT_SESSION_SQL,
            params![
                "sess_bearer_secret",
                "usr_owner",
                "app",
                1,
                1000,
                None::<String>,
                None::<String>,
                "entra",
                "policy_proof"
            ],
        )
        .unwrap();
    connection
}

fn add_code(connection: &Connection) {
    connection
        .execute(
            INSERT_AUTH_CODE_SQL,
            params![
                "code_hash_secret",
                "app",
                "https://app.example/callback",
                "usr_owner",
                "sess_bearer_secret",
                1,
                "client_nonce",
                "pkce_challenge",
                "S256",
                "openid offline_access",
                1,
                500,
                "entra",
                "policy_proof",
            ],
        )
        .unwrap();
}

fn add_refresh(connection: &Connection) {
    connection
        .execute(
            INSERT_REFRESH_TOKEN_SQL,
            params![
                "parent_hash_secret",
                "app",
                "usr_owner",
                "sess_bearer_secret",
                1,
                "openid offline_access",
                1,
                500,
                "entra",
                "policy_proof",
            ],
        )
        .unwrap();
}

fn event(id: &str, action: &str) -> AuditEvent {
    audit_capture::event(
        id.into(),
        action,
        AuditActor::new("user", "usr_owner").unwrap(),
        Some("usr_owner"),
        Some("app"),
        Some("entra"),
        &serde_json::json!({"grantType":"refresh_token"}),
        100,
    )
    .unwrap()
}

fn capture(tx: &Transaction<'_>, event: &AuditEvent) -> rusqlite::Result<()> {
    let json = event.canonical_json().unwrap();
    tx.execute(
        audit_capture::INSERT_EVENT_SQL,
        params![
            event.event_id,
            event.event_type,
            "usr_owner",
            event.client_id,
            event.provider_id,
            event.recorded_at,
            serde_json::to_string(&event.details).unwrap(),
            event.schema_version,
            event.organization_id,
            event.actor.kind,
            event.actor.id,
            event.targets[0].kind,
            event.targets[0].id,
            event.outcome.as_str(),
            event.reason,
            event.correlation_id,
            event.recorded_at,
            json,
        ],
    )?;
    tx.execute(
        audit_capture::INSERT_OUTBOX_SQL,
        params![event.event_id, json, event.recorded_at],
    )?;
    Ok(())
}

fn code_transition(tx: &Transaction<'_>, event: &AuditEvent) -> rusqlite::Result<()> {
    tx.execute(
        AUTH_CODE_ISSUE_GUARD_SQL,
        params!["guard_code", "code_hash_secret", 100, 100],
    )?;
    tx.execute(
        audit_capture::CLIENT_USER_SCOPE_GUARD_SQL,
        params!["scope_code", "usr_owner", "app", "entra"],
    )?;
    tx.execute(
        CONSUME_AUTHORIZATION_CODE_SQL,
        params![100, "code_hash_secret"],
    )?;
    tx.execute(
        INSERT_REFRESH_TOKEN_SQL,
        params![
            "initial_hash_secret",
            "app",
            "usr_owner",
            "sess_bearer_secret",
            1,
            "openid offline_access",
            100,
            1000,
            "entra",
            "policy_proof"
        ],
    )?;
    tx.execute(DELETE_AUDIT_WRITE_GUARD_SQL, ["guard_code"])?;
    tx.execute(DELETE_AUDIT_WRITE_GUARD_SQL, ["scope_code"])?;
    capture(tx, event)
}

fn refresh_transition(
    tx: &Transaction<'_>,
    event: &AuditEvent,
    child: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        REFRESH_ISSUE_GUARD_SQL,
        params!["guard_refresh", "parent_hash_secret", 100, 100],
    )?;
    tx.execute(
        audit_capture::CLIENT_USER_SCOPE_GUARD_SQL,
        params!["scope_refresh", "usr_owner", "app", "entra"],
    )?;
    tx.execute(ROTATE_REFRESH_TOKEN_SQL, params![100, "parent_hash_secret"])?;
    tx.execute(
        INSERT_ROTATED_REFRESH_TOKEN_SQL,
        params![child, 100, 1000, "parent_hash_secret", 100, 100],
    )?;
    tx.execute(DELETE_AUDIT_WRITE_GUARD_SQL, ["guard_refresh"])?;
    tx.execute(DELETE_AUDIT_WRITE_GUARD_SQL, ["scope_refresh"])?;
    capture(tx, event)
}

fn reject_outbox(connection: &Connection) {
    connection
        .execute_batch(
            "CREATE TRIGGER reject_outbox BEFORE INSERT ON zeroth_audit_outbox
        BEGIN SELECT RAISE(ABORT,'injected audit failure'); END",
        )
        .unwrap();
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn audit_failure_does_not_spend_authorization_code_or_create_refresh_token() {
    let mut connection = database();
    add_code(&connection);
    reject_outbox(&connection);
    let event = event("evt_code", "token.issue");
    {
        let tx = connection.transaction().unwrap();
        assert!(code_transition(&tx, &event).is_err());
    }
    assert_eq!(
        connection
            .query_row("SELECT consumed_at FROM zeroth_auth_codes", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        None
    );
    assert_eq!(count(&connection, "zeroth_refresh_tokens"), 0);
    assert_eq!(count(&connection, "zeroth_audit_events"), 0);
    assert_eq!(count(&connection, "zeroth_audit_write_guards"), 0);
    connection
        .execute_batch("DROP TRIGGER reject_outbox")
        .unwrap();
    let tx = connection.transaction().unwrap();
    code_transition(&tx, &event).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        connection
            .query_row("SELECT consumed_at FROM zeroth_auth_codes", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        Some(100)
    );
    assert_eq!(count(&connection, "zeroth_refresh_tokens"), 1);
    assert_eq!(count(&connection, "zeroth_audit_events"), 1);
    assert_eq!(count(&connection, "zeroth_audit_outbox"), 1);
}

#[test]
fn audit_failure_rolls_back_refresh_cas_and_replacement_so_retry_is_not_replay() {
    let mut connection = database();
    add_refresh(&connection);
    reject_outbox(&connection);
    let event = event("evt_refresh", "token.issue");
    {
        let tx = connection.transaction().unwrap();
        assert!(refresh_transition(&tx, &event, "child_hash_secret").is_err());
    }
    let state: (Option<i64>, Option<i64>) = connection.query_row(
        "SELECT rotated_at,revoked_at FROM zeroth_refresh_tokens WHERE token_hash='parent_hash_secret'", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
    assert_eq!(state, (None, None));
    assert_eq!(count(&connection, "zeroth_refresh_tokens"), 1);
    assert_eq!(count(&connection, "zeroth_audit_events"), 0);
    connection
        .execute_batch("DROP TRIGGER reject_outbox")
        .unwrap();
    let tx = connection.transaction().unwrap();
    refresh_transition(&tx, &event, "child_hash_secret").unwrap();
    tx.commit().unwrap();
    let proof: (String,String) = connection.query_row(
        "SELECT auth_provider,auth_policy_hash FROM zeroth_refresh_tokens WHERE token_hash='child_hash_secret'", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
    assert_eq!(proof, ("entra".into(), "policy_proof".into()));
    assert_eq!(count(&connection, "zeroth_audit_write_guards"), 0);
}

#[test]
fn second_rotation_cannot_insert_child_or_success_audit_and_replay_revokes_winner() {
    let mut connection = database();
    add_refresh(&connection);
    let tx = connection.transaction().unwrap();
    refresh_transition(&tx, &event("evt_winner", "token.issue"), "winner_hash").unwrap();
    tx.commit().unwrap();
    {
        let tx = connection.transaction().unwrap();
        assert!(refresh_transition(&tx, &event("evt_loser", "token.issue"), "loser_hash").is_err());
    }
    assert_eq!(count(&connection, "zeroth_refresh_tokens"), 2);
    assert_eq!(count(&connection, "zeroth_audit_events"), 1);
    let tx = connection.transaction().unwrap();
    tx.execute(
        REVOKE_SESSION_REFRESH_TOKEN_FAMILY_SQL,
        params![101, "app", "usr_owner", "sess_bearer_secret"],
    )
    .unwrap();
    capture(&tx, &event("evt_replay", "refresh_token.replay")).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM zeroth_refresh_tokens WHERE revoked_at=101",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
    {
        let tx = connection.transaction().unwrap();
        assert!(
            refresh_transition(&tx, &event("evt_after_revoke", "token.issue"), "late_child")
                .is_err()
        );
    }
    assert_eq!(count(&connection, "zeroth_refresh_tokens"), 2);
}

#[test]
fn code_and_refresh_guards_recheck_user_client_session_and_expiry_in_transaction() {
    for change in [
        "UPDATE zeroth_users SET disabled_at=99 WHERE id='usr_owner'",
        "UPDATE zeroth_clients SET disabled_at=99 WHERE id='app'",
        "UPDATE zeroth_sessions SET revoked_at=99 WHERE id='sess_bearer_secret'",
        "UPDATE zeroth_sessions SET expires_at=99 WHERE id='sess_bearer_secret'",
        "UPDATE zeroth_auth_codes SET expires_at=99; UPDATE zeroth_refresh_tokens SET expires_at=99",
    ] {
        let mut connection = database();
        add_code(&connection);
        add_refresh(&connection);
        connection.execute_batch(change).unwrap();
        {
            let tx = connection.transaction().unwrap();
            assert!(code_transition(&tx, &event("evt_code_denied", "token.issue")).is_err(), "{change}");
        }
        {
            let tx = connection.transaction().unwrap();
            assert!(refresh_transition(&tx, &event("evt_refresh_denied", "token.issue"), "forbidden_child").is_err(), "{change}");
        }
        assert_eq!(count(&connection, "zeroth_audit_events"), 0);
        assert_eq!(count(&connection, "zeroth_refresh_tokens"), 1);
    }
}

#[test]
fn committed_event_confirms_our_own_lost_ack_without_treating_it_as_replay() {
    let mut connection = database();
    add_refresh(&connection);
    let event = event("evt_our_committed_attempt", "token.issue");
    let tx = connection.transaction().unwrap();
    refresh_transition(&tx, &event, "child_hash_secret").unwrap();
    tx.commit().unwrap();
    // Simulate losing the commit response: the production fallback looks up
    // this exact ID and payload, rather than treating every spent parent as a
    // different caller's replay. Another ID/payload cannot confirm this commit.
    let stored: String = connection
        .query_row(
            "SELECT event_json FROM zeroth_audit_events WHERE id=?",
            [&event.event_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, event.canonical_json().unwrap());
    let mut other = event.clone();
    other.outcome = AuditOutcome::Denied;
    assert_ne!(stored, other.canonical_json().unwrap());
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM zeroth_refresh_tokens WHERE revoked_at IS NULL",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        2
    );
}

#[test]
fn session_and_refresh_revocation_roll_back_together_on_audit_failure() {
    let mut connection = database();
    add_refresh(&connection);
    reject_outbox(&connection);
    let mut event = event("evt_logout", "session.logout");
    event.targets.insert(
        0,
        AuditTarget::new("session", hash_secret("sess_bearer_secret")).unwrap(),
    );
    assert!(!event
        .canonical_json()
        .unwrap()
        .contains("sess_bearer_secret"));
    {
        let tx = connection.transaction().unwrap();
        tx.execute(
            REVOKE_OWNED_SESSION_SQL,
            params![100, "sess_bearer_secret", "usr_owner"],
        )
        .unwrap();
        tx.execute(
            REVOKE_OWNED_SESSION_REFRESH_SQL,
            params![100, "sess_bearer_secret", "usr_owner"],
        )
        .unwrap();
        assert!(capture(&tx, &event).is_err());
    }
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_sessions", [], |row| row
                .get::<_, Option<
                i64,
            >>(
                0
            ))
            .unwrap(),
        None
    );
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_refresh_tokens", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        None
    );
    connection
        .execute_batch("DROP TRIGGER reject_outbox")
        .unwrap();
    let tx = connection.transaction().unwrap();
    tx.execute(
        REVOKE_OWNED_SESSION_SQL,
        params![100, "sess_bearer_secret", "usr_owner"],
    )
    .unwrap();
    tx.execute(
        REVOKE_OWNED_SESSION_REFRESH_SQL,
        params![100, "sess_bearer_secret", "usr_owner"],
    )
    .unwrap();
    capture(&tx, &event).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_sessions", [], |row| row
                .get::<_, Option<
                i64,
            >>(
                0
            ))
            .unwrap(),
        Some(100)
    );
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_refresh_tokens", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        Some(100)
    );
    assert_eq!(count(&connection, "zeroth_audit_outbox"), 1);
}

#[test]
fn oauth_revocation_failure_does_not_revoke_without_evidence_or_leak_credential_hash() {
    let mut connection = database();
    add_refresh(&connection);
    reject_outbox(&connection);
    let event = event("evt_revoke", "token.revoke");
    {
        let tx = connection.transaction().unwrap();
        tx.execute(
            REVOKE_SINGLE_REFRESH_TOKEN_SQL,
            params![100, "parent_hash_secret"],
        )
        .unwrap();
        assert!(capture(&tx, &event).is_err());
    }
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_refresh_tokens", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        None
    );
    assert!(!event
        .canonical_json()
        .unwrap()
        .contains("parent_hash_secret"));
    assert!(!event.canonical_json().unwrap().contains("code_hash_secret"));
}

#[test]
fn session_revocation_sql_is_bound_to_the_authenticated_owner() {
    let connection = database();
    add_refresh(&connection);
    assert_eq!(
        connection
            .execute(
                REVOKE_OWNED_SESSION_SQL,
                params![100, "sess_bearer_secret", "usr_other"]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .execute(
                REVOKE_OWNED_SESSION_REFRESH_SQL,
                params![100, "sess_bearer_secret", "usr_other"]
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_sessions", [], |row| row
                .get::<_, Option<
                i64,
            >>(
                0
            ))
            .unwrap(),
        None
    );
    assert_eq!(
        connection
            .query_row("SELECT revoked_at FROM zeroth_refresh_tokens", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .unwrap(),
        None
    );
}

#[test]
fn admission_revocation_is_not_falsely_labeled_as_token_replay() {
    let event = audit_capture::event(
        "evt_policy".into(),
        "refresh_token.revoke",
        AuditActor::new("system", "zeroth").unwrap(),
        Some("usr_owner"),
        Some("app"),
        Some("entra"),
        &serde_json::json!({"errorCode":"client_admission_denied"}),
        100,
    )
    .unwrap();
    assert_eq!(event.event_type, "refresh_token.revoke");
    assert!(!event.canonical_json().unwrap().contains("replay"));
}

fn bind_tenant(connection: &Connection) {
    connection.execute_batch("INSERT INTO zeroth_tenants (
        id,name,enterprise_provider,entra_tenant_id,oidc_client_id,client_secret_binding,created_at,updated_at
    ) VALUES ('acme','Acme','entra','11111111-2222-3333-4444-555555555555','app-oidc','TENANT_ACME_CLIENT_SECRET',1,1);
    UPDATE zeroth_clients SET account_sharing_mode='tenant',account_tenant_id='acme',enterprise_provider='entra' WHERE id='app';
    INSERT INTO zeroth_tenant_clients (client_id,tenant_id,enterprise_provider) VALUES ('app','acme','entra');").unwrap();
}

fn tenant_identity(connection: &Connection, namespace: &str, provider: &str) {
    connection
        .execute(
            "INSERT INTO zeroth_account_identities (
        account_namespace,provider_id,provider_subject,user_id,created_at,updated_at
    ) VALUES (?1,?2,'signed_subject','usr_owner',1,1)",
            params![namespace, provider],
        )
        .unwrap();
}

#[test]
fn late_tenant_binding_rejects_global_or_wrong_provider_user_provenance_atomically() {
    for (namespace, provider) in [
        ("global", "entra"),
        ("tenant:acme", "wallet_evm"),
        ("tenant:other", "entra"),
    ] {
        let mut connection = database();
        add_code(&connection);
        add_refresh(&connection);
        tenant_identity(&connection, namespace, provider);
        bind_tenant(&connection);
        {
            let tx = connection.transaction().unwrap();
            assert!(
                code_transition(&tx, &event("evt_late_code", "token.issue")).is_err(),
                "{namespace}/{provider}"
            );
        }
        {
            let tx = connection.transaction().unwrap();
            assert!(
                refresh_transition(
                    &tx,
                    &event("evt_late_refresh", "token.issue"),
                    "forbidden_child"
                )
                .is_err(),
                "{namespace}/{provider}"
            );
        }
        assert_eq!(count(&connection, "zeroth_audit_events"), 0);
        assert_eq!(count(&connection, "zeroth_refresh_tokens"), 1);
        assert_eq!(
            connection
                .query_row("SELECT consumed_at FROM zeroth_auth_codes", [], |row| {
                    row.get::<_, Option<i64>>(0)
                })
                .unwrap(),
            None
        );
    }
}

#[test]
fn tenant_disable_and_offboarding_after_precheck_block_issuance_without_spending_grant() {
    for change in [
        "UPDATE zeroth_tenants SET disabled=1 WHERE id='acme'",
        "DELETE FROM zeroth_account_identities WHERE account_namespace='tenant:acme'",
    ] {
        let mut connection = database();
        add_code(&connection);
        add_refresh(&connection);
        bind_tenant(&connection);
        tenant_identity(&connection, "tenant:acme", "entra");
        connection
            .execute(
                audit_capture::CLIENT_USER_SCOPE_GUARD_SQL,
                params!["precheck", "usr_owner", "app", "entra"],
            )
            .unwrap();
        connection
            .execute(DELETE_AUDIT_WRITE_GUARD_SQL, ["precheck"])
            .unwrap();
        connection.execute_batch(change).unwrap();
        {
            let tx = connection.transaction().unwrap();
            assert!(code_transition(&tx, &event("evt_offboard_code", "token.issue")).is_err());
        }
        {
            let tx = connection.transaction().unwrap();
            assert!(refresh_transition(
                &tx,
                &event("evt_offboard_refresh", "token.issue"),
                "forbidden_child"
            )
            .is_err());
        }
        assert_eq!(count(&connection, "zeroth_audit_events"), 0);
        assert_eq!(count(&connection, "zeroth_refresh_tokens"), 1);
    }
}

#[test]
fn late_enterprise_requirement_rejects_native_or_other_provider_even_with_tenant_identity() {
    let mut connection = database();
    bind_tenant(&connection);
    tenant_identity(&connection, "tenant:acme", "entra");
    for provider in [None, Some("google"), Some("google_workspace")] {
        let tx = connection.transaction().unwrap();
        assert!(tx
            .execute(
                audit_capture::CLIENT_USER_SCOPE_GUARD_SQL,
                params!["native_scope", "usr_owner", "app", provider]
            )
            .is_err());
    }
    connection
        .execute(
            audit_capture::CLIENT_USER_SCOPE_GUARD_SQL,
            params!["verified_enterprise_scope", "usr_owner", "app", "entra"],
        )
        .unwrap();
    connection
        .execute(DELETE_AUDIT_WRITE_GUARD_SQL, ["verified_enterprise_scope"])
        .unwrap();
    assert_eq!(count(&connection, "zeroth_audit_write_guards"), 0);
    assert_eq!(count(&connection, "zeroth_audit_events"), 0);
}
