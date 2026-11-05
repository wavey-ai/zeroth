use super::*;
use rusqlite::{params, Connection, Transaction};
use zeroth_audit::{AuditActor, AuditEvent};

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    for migration in zeroth_storage::migrations::ALL {
        for statement in migration.statements() {
            db.execute_batch(statement).unwrap();
        }
    }
    db.execute_batch("INSERT INTO zeroth_clients(id,name,redirect_uris_json,created_at,updated_at) VALUES ('app','Application','[]',1,1);
        INSERT INTO zeroth_users(id,primary_email,display_name,picture_url,created_at,updated_at) VALUES
        ('usr_a','original@example.com','Original','https://example.com/original',1,1),('usr_b','other@example.com','Other',NULL,1,1);").unwrap();
    db
}

fn event(id: &str, user: &str, kind: &str) -> AuditEvent {
    let mut event = audit_capture::event(id.into(),kind,AuditActor::new("user",user).unwrap(),Some(user),Some("app"),Some("entra"),
        &serde_json::json!({"changedFields":["provider_profile"],"email":"private@example.com","rawProfile":"credential-secret"}),100).unwrap();
    event.organization_id = Some("acme".into());
    event
}

fn audit(tx: &Transaction<'_>, event: &AuditEvent) -> rusqlite::Result<()> {
    let json = event.canonical_json().unwrap();
    let details = serde_json::to_string(&event.details).unwrap();
    let target = event.targets.first().unwrap();
    tx.execute(
        audit_capture::INSERT_EVENT_SQL,
        params![
            event.event_id,
            event.event_type,
            target.id,
            event.client_id,
            event.provider_id,
            event.recorded_at,
            details,
            event.schema_version,
            event.organization_id,
            event.actor.kind,
            event.actor.id,
            target.kind,
            target.id,
            event.outcome.as_str(),
            event.reason,
            event.correlation_id,
            event.recorded_at,
            json
        ],
    )?;
    tx.execute(
        audit_capture::INSERT_OUTBOX_SQL,
        params![event.event_id, json, event.recorded_at],
    )?;
    Ok(())
}

fn capture(
    db: &mut Connection,
    event: &AuditEvent,
    change: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    change(&tx)?;
    audit(&tx, event)?;
    tx.commit()
}

fn reject_outbox(db: &Connection) {
    db.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON zeroth_audit_outbox BEGIN SELECT RAISE(ABORT,'fault injection'); END;").unwrap();
}

fn identity(
    tx: &Transaction<'_>,
    namespace: &str,
    provider: &str,
    subject: &str,
    user: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        UPSERT_ACCOUNT_PROVIDER_IDENTITY_SQL,
        params![
            namespace,
            provider,
            subject,
            user,
            "private@example.com",
            1,
            "Private Name",
            "https://example.com/private",
            "credential-secret",
            100
        ],
    )?;
    Ok(())
}

fn owner_guard(
    tx: &Transaction<'_>,
    namespace: &str,
    provider: &str,
    subject: &str,
    user: &str,
    limit: i32,
) -> rusqlite::Result<()> {
    tx.execute(
        IDENTITY_OWNER_GUARD_SQL,
        params!["owner_guard", namespace, provider, subject, user, limit],
    )?;
    tx.execute(IDENTITY_CLEANUP_GUARD_SQL, ["owner_guard"])?;
    Ok(())
}

fn profile_email(db: &Connection, user: &str) -> String {
    db.query_row(
        "SELECT primary_email FROM zeroth_users WHERE id=?1",
        [user],
        |row| row.get(0),
    )
    .unwrap()
}

fn method_fixture(db: &mut Connection) {
    let tx = db.transaction().unwrap();
    identity(&tx, "global", "google", "google_a", "usr_a").unwrap();
    identity(&tx, "global", "passkey", "credential1", "usr_a").unwrap();
    tx.execute("INSERT INTO zeroth_identities(provider_id,provider_subject,user_id,created_at,updated_at) VALUES ('passkey','credential1','usr_a',1,1)",[]).unwrap();
    tx.execute("INSERT INTO zeroth_passkey_credentials(credential_id,user_id,public_key_x,public_key_y,created_at,updated_at) VALUES ('credential1','usr_a','x','y',1,1)",[]).unwrap();
    tx.commit().unwrap();
}

fn unlink(tx: &Transaction<'_>, provider: &str, subject: &str, id: &str) -> rusqlite::Result<()> {
    tx.execute(
        IDENTITY_DELETE_GUARD_SQL,
        params![id, "usr_a", provider, subject],
    )?;
    tx.execute(
        DELETE_ACCOUNT_IDENTITY_SQL,
        params!["usr_a", provider, subject],
    )?;
    tx.execute(
        DELETE_LEGACY_IDENTITY_SQL,
        params!["usr_a", provider, subject],
    )?;
    if provider == "passkey" {
        tx.execute(DISABLE_OWN_PASSKEY_SQL, params![100, subject, "usr_a"])?;
    }
    tx.execute(IDENTITY_CLEANUP_GUARD_SQL, [id])?;
    Ok(())
}

#[test]
fn provider_user_and_identity_creation_roll_back_when_outbox_fails() {
    let mut db = database();
    reject_outbox(&db);
    let event = event("evt_create", "usr_new", "user.create");
    assert!(capture(&mut db, &event, |tx| {
        tx.execute(
            INSERT_PROVIDER_USER_SQL,
            params![
                "usr_new",
                "private@example.com",
                "Private Name",
                "https://example.com/private",
                100
            ],
        )?;
        identity(tx, "tenant:acme", "entra", "subject", "usr_new")?;
        owner_guard(tx, "tenant:acme", "entra", "subject", "usr_new", 0)
    })
    .is_err());
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM zeroth_users WHERE id='usr_new'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_account_identities", [], |r| r
            .get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_audit_events", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn provider_refresh_and_ownership_claim_rollback_together() {
    let mut db = database();
    {
        let tx = db.transaction().unwrap();
        identity(&tx, "tenant:acme", "entra", "owned", "usr_a").unwrap();
        tx.commit().unwrap();
    }
    let event = event("evt_collision", "usr_b", "identity.link");
    assert!(capture(&mut db, &event, |tx| {
        tx.execute(
            UPDATE_PROVIDER_USER_SQL,
            params![
                "changed@example.com",
                "Changed",
                "https://example.com/changed",
                100,
                "usr_b"
            ],
        )?;
        identity(tx, "tenant:acme", "entra", "owned", "usr_b")?;
        owner_guard(tx, "tenant:acme", "entra", "owned", "usr_b", 16)
    })
    .is_err());
    assert_eq!(profile_email(&db, "usr_b"), "other@example.com");
    assert_eq!(
        db.query_row::<String, _, _>(
            "SELECT user_id FROM zeroth_account_identities WHERE provider_subject='owned'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        "usr_a"
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_audit_events", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn a_losing_new_user_claim_does_not_leave_an_orphan_account() {
    let mut db = database();
    {
        let tx = db.transaction().unwrap();
        identity(&tx, "tenant:acme", "entra", "owned", "usr_a").unwrap();
        tx.commit().unwrap();
    }
    let event = event("evt_lost_race", "usr_new", "user.create");
    assert!(capture(&mut db, &event, |tx| {
        tx.execute(
            INSERT_PROVIDER_USER_SQL,
            params![
                "usr_new",
                "private@example.com",
                "Private Name",
                "https://example.com/private",
                100
            ],
        )?;
        identity(tx, "tenant:acme", "entra", "owned", "usr_new")?;
        owner_guard(tx, "tenant:acme", "entra", "owned", "usr_new", 0)
    })
    .is_err());
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM zeroth_users WHERE id='usr_new'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn profile_patch_clear_and_preserve_semantics_share_the_audit_transaction() {
    let mut db = database();
    let event = event("evt_patch", "usr_a", "user.profile.update");
    reject_outbox(&db);
    assert!(capture(&mut db, &event, |tx| {
        tx.execute(
            IDENTITY_ACTIVE_USER_GUARD_SQL,
            params!["patch_guard", "usr_a"],
        )?;
        tx.execute(
            UPDATE_PROFILE_PATCH_SQL,
            params![
                1,
                Option::<String>::None,
                0,
                Option::<String>::None,
                100,
                "usr_a"
            ],
        )?;
        tx.execute(IDENTITY_CLEANUP_GUARD_SQL, ["patch_guard"])?;
        Ok(())
    })
    .is_err());
    assert_eq!(
        db.query_row::<String, _, _>(
            "SELECT display_name FROM zeroth_users WHERE id='usr_a'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        "Original"
    );
    db.execute_batch("DROP TRIGGER reject_outbox").unwrap();
    capture(&mut db, &event, |tx| {
        tx.execute(
            UPDATE_PROFILE_PATCH_SQL,
            params![
                1,
                Option::<String>::None,
                0,
                Option::<String>::None,
                100,
                "usr_a"
            ],
        )?;
        Ok(())
    })
    .unwrap();
    let profile: (Option<String>, String) = db
        .query_row(
            "SELECT display_name,picture_url FROM zeroth_users WHERE id='usr_a'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(profile, (None, "https://example.com/original".into()));
    let json: String = db
        .query_row("SELECT event_json FROM zeroth_audit_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!json.contains("private@example.com"));
    assert!(!json.contains("credential-secret"));
    let stored: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(stored.actor.id.as_deref(), Some("usr_a"));
    assert_eq!(stored.organization_id.as_deref(), Some("acme"));
    assert_eq!(
        profile_patch_changed_fields(&ProfilePatch {
            display_name: Some(None),
            picture_url: None
        }),
        ["display_name"]
    );
}

#[test]
fn unlink_and_passkey_disable_roll_back_on_audit_failure_and_keep_the_last_method() {
    let mut db = database();
    method_fixture(&mut db);
    reject_outbox(&db);
    let first = event("evt_unlink", "usr_a", "identity.unlink");
    assert!(capture(&mut db, &first, |tx| unlink(
        tx,
        "passkey",
        "credential1",
        "unlink_guard"
    ))
    .is_err());
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM zeroth_account_identities WHERE provider_id='passkey'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<Option<i64>, _, _>(
            "SELECT disabled_at FROM zeroth_passkey_credentials",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        None
    );
    db.execute_batch("DROP TRIGGER reject_outbox").unwrap();
    capture(&mut db, &first, |tx| {
        unlink(tx, "passkey", "credential1", "unlink_guard")
    })
    .unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM zeroth_identities WHERE provider_id='passkey'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<Option<i64>, _, _>(
            "SELECT disabled_at FROM zeroth_passkey_credentials",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        Some(100)
    );
    let last = event("evt_last", "usr_a", "identity.unlink");
    assert!(capture(&mut db, &last, |tx| unlink(
        tx,
        "google",
        "google_a",
        "last_guard"
    ))
    .is_err());
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_account_identities", [], |r| r
            .get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_audit_events", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_audit_write_guards", [], |r| r
            .get(0))
            .unwrap(),
        0
    );
}

#[test]
fn passkey_disable_never_mutates_another_users_credential() {
    let db = database();
    db.execute("INSERT INTO zeroth_passkey_credentials(credential_id,user_id,public_key_x,public_key_y,created_at,updated_at) VALUES ('other_credential','usr_b','x','y',1,1)",[]).unwrap();
    assert_eq!(
        db.execute(
            DISABLE_OWN_PASSKEY_SQL,
            params![100, "other_credential", "usr_a"]
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<Option<i64>, _, _>(
            "SELECT disabled_at FROM zeroth_passkey_credentials",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        None
    );
}

#[test]
fn stale_namespace_and_disabled_tenant_guards_block_inflight_profile_writes() {
    let mut db = database();
    db.execute("UPDATE zeroth_clients SET account_sharing_mode='tenant',account_tenant_id='acme' WHERE id='app'",[]).unwrap();
    let event = event("evt_stale_scope", "usr_a", "identity.profile.update");
    assert!(capture(&mut db, &event, |tx| {
        tx.execute(
            IDENTITY_CLIENT_SCOPE_GUARD_SQL,
            params![
                "scope_guard",
                "app",
                "global",
                "global",
                Option::<String>::None
            ],
        )?;
        tx.execute(
            UPDATE_PROVIDER_USER_SQL,
            params![
                "changed@example.com",
                "Changed",
                "https://example.com/changed",
                100,
                "usr_a"
            ],
        )?;
        Ok(())
    })
    .is_err());
    assert_eq!(profile_email(&db, "usr_a"), "original@example.com");
    db.execute("INSERT INTO zeroth_tenants(id,name,disabled,enterprise_provider,created_at,updated_at) VALUES ('acme','Acme',1,'entra',1,1)",[]).unwrap();
    {
        let tx = db.transaction().unwrap();
        tx.execute(
            "UPDATE zeroth_clients SET enterprise_provider='entra' WHERE id='app'",
            [],
        )
        .unwrap();
        tx.execute("INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('app','acme','entra')",[]).unwrap();
        tx.commit().unwrap();
    }
    assert!(db
        .execute(
            IDENTITY_CLIENT_SCOPE_GUARD_SQL,
            params!["disabled_guard", "app", "tenant", "acme", "entra"]
        )
        .is_err());
}

#[test]
fn link_limit_and_session_binding_are_checked_inside_the_capture() {
    let mut db = database();
    {
        let tx = db.transaction().unwrap();
        for index in 0..16 {
            identity(
                &tx,
                "global",
                "google",
                &format!("subject_{index}"),
                "usr_a",
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let event = event("evt_limit", "usr_a", "identity.link");
    assert!(capture(&mut db, &event, |tx| {
        tx.execute(
            UPDATE_PROVIDER_USER_SQL,
            params![
                "changed@example.com",
                "Changed",
                "https://example.com/changed",
                100,
                "usr_a"
            ],
        )?;
        identity(tx, "global", "google", "seventeenth", "usr_a")?;
        owner_guard(tx, "global", "google", "seventeenth", "usr_a", 16)
    })
    .is_err());
    assert_eq!(profile_email(&db, "usr_a"), "original@example.com");
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT COUNT(*) FROM zeroth_account_identities", [], |r| r
            .get(0))
            .unwrap(),
        16
    );
    db.execute("INSERT INTO zeroth_sessions(id,user_id,client_id,created_at,expires_at) VALUES ('sess_a','usr_a','app',1,200)",[]).unwrap();
    assert!(db
        .execute(
            IDENTITY_LINK_SESSION_GUARD_SQL,
            params!["wrong_client", "sess_a", "usr_a", "other_app", 100]
        )
        .is_err());
    assert!(db
        .execute(
            IDENTITY_LINK_SESSION_GUARD_SQL,
            params!["expired", "sess_a", "usr_a", "app", 200]
        )
        .is_err());
    db.execute(
        IDENTITY_LINK_SESSION_GUARD_SQL,
        params!["active", "sess_a", "usr_a", "app", 100],
    )
    .unwrap();
    db.execute(IDENTITY_CLEANUP_GUARD_SQL, ["active"]).unwrap();
    db.execute(
        "UPDATE zeroth_sessions SET revoked_at=100 WHERE id='sess_a'",
        [],
    )
    .unwrap();
    assert!(db
        .execute(
            IDENTITY_LINK_SESSION_GUARD_SQL,
            params!["revoked", "sess_a", "usr_a", "app", 100]
        )
        .is_err());
}

#[test]
fn account_mutation_guard_rechecks_revocation_and_rejects_old_global_users_after_binding() {
    let mut db = database();
    db.execute("INSERT INTO zeroth_sessions(id,user_id,client_id,created_at,expires_at) VALUES ('sess_a','usr_a','app',1,200)",[]).unwrap();
    db.execute(
        IDENTITY_ACCOUNT_AUTH_GUARD_SQL,
        params!["active", "usr_a", "sess_a", "app", 100],
    )
    .unwrap();
    db.execute(IDENTITY_CLEANUP_GUARD_SQL, ["active"]).unwrap();
    db.execute(
        "UPDATE zeroth_sessions SET revoked_at=100 WHERE id='sess_a'",
        [],
    )
    .unwrap();
    assert!(db
        .execute(
            IDENTITY_ACCOUNT_AUTH_GUARD_SQL,
            params!["revoked", "usr_a", "sess_a", "app", 100]
        )
        .is_err());
    // Unbound native/profile tokens may intentionally have no browser session.
    db.execute(
        IDENTITY_ACCOUNT_AUTH_GUARD_SQL,
        params!["native", "usr_a", Option::<String>::None, "app", 100],
    )
    .unwrap();
    db.execute(IDENTITY_CLEANUP_GUARD_SQL, ["native"]).unwrap();
    {
        let tx = db.transaction().unwrap();
        tx.execute("INSERT INTO zeroth_tenants(id,name,enterprise_provider,created_at,updated_at) VALUES ('acme','Acme','entra',1,1)",[]).unwrap();
        tx.execute("UPDATE zeroth_clients SET account_sharing_mode='tenant',account_tenant_id='acme',enterprise_provider='entra' WHERE id='app'",[]).unwrap();
        tx.execute("INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('app','acme','entra')",[]).unwrap();
        tx.commit().unwrap();
    }
    assert!(db
        .execute(
            IDENTITY_ACCOUNT_AUTH_GUARD_SQL,
            params!["old_global", "usr_a", Option::<String>::None, "app", 100]
        )
        .is_err());
}
