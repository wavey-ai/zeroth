use super::*;
use rusqlite::{params, Connection, Transaction};

const REALM: &str = "11111111-2222-3333-4444-555555555555";
const OBJECT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn authority() -> DirectoryAuthority {
    DirectoryAuthority {
        tenant_id: "acme".into(),
        provider_id: "entra".into(),
        authority_id: REALM.into(),
    }
}
fn source(provider: &str, enabled: i32) -> DirectorySource {
    DirectorySource {
        tenant_id: "acme".into(),
        provider_id: provider.into(),
        authority_id: if provider == "entra" {
            REALM.into()
        } else {
            "C01customer".into()
        },
        enabled,
        token_binding: None,
        last_activity_at: None,
        last_full_sync_at: None,
        last_error_code: None,
        sync_fence: None,
        config_version: 1,
        created_at: 1,
        updated_at: 1,
    }
}
fn user(active: bool) -> DirectoryUser {
    DirectoryUser {
        id: "dir_one".into(),
        tenant_id: "acme".into(),
        provider_id: "entra".into(),
        authority_id: REALM.into(),
        external_id: OBJECT.into(),
        user_name: "person@example.com".into(),
        display_name: Some("Personal Name".into()),
        profile_json: "{}".into(),
        active,
        deleted: false,
        user_id: Some("usr_owner".into()),
        created_at: 1,
        updated_at: 1,
        version: 1,
    }
}
fn change(id: &str) -> DirectoryUserChange {
    DirectoryUserChange {
        external_id: id.into(),
        user_name: "person@example.com".into(),
        display_name: None,
        profile_json: None,
        active: true,
        deleted: false,
    }
}

fn database() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    for migration in zeroth_storage::migrations::ALL {
        for statement in migration.statements() {
            connection.execute_batch(statement).unwrap();
        }
    }
    connection.execute_batch("INSERT INTO zeroth_users(id,primary_email,created_at,updated_at) VALUES ('usr_owner','person@example.com',1,1);
      INSERT INTO zeroth_users(id,created_at,updated_at) VALUES ('usr_other',1,1);
      INSERT INTO zeroth_clients(id,name,redirect_uris_json,account_sharing_mode,account_tenant_id,enterprise_provider,created_at,updated_at)
        VALUES ('app','App','[]','tenant','acme','entra',1,1),('other_app','Other App','[]','tenant','other','entra',1,1);
      INSERT INTO zeroth_tenants(id,name,enterprise_provider,entra_tenant_id,created_at,updated_at)
        VALUES ('acme','Acme','entra','11111111-2222-3333-4444-555555555555',1,1),('other','Other','entra','11111111-2222-3333-4444-555555555555',1,1);
      INSERT INTO zeroth_tenant_clients(client_id,tenant_id,enterprise_provider) VALUES ('app','acme','entra'),('other_app','other','entra');").unwrap();
    connection.execute("INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,enabled,created_at,updated_at) VALUES ('acme','entra',?1,1,1,1)", [REALM]).unwrap();
    connection
}

#[test]
fn source_configuration_rechecks_current_tenant_authority_inside_transaction() {
    let connection = database();
    connection
        .execute(
            CONFIG_TENANT_GUARD_SQL,
            params!["same", "acme", "entra", REALM],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE zeroth_tenants SET entra_tenant_id=?1 WHERE id='acme'",
            [OBJECT],
        )
        .unwrap();
    assert!(connection
        .execute(
            CONFIG_TENANT_GUARD_SQL,
            params!["changed", "acme", "entra", REALM],
        )
        .is_err());
    assert!(connection
        .execute(
            CONFIG_TENANT_GUARD_SQL,
            params!["wrong_provider", "acme", "google_workspace", "C01customer"],
        )
        .is_err());
}

fn put_user(connection: &Connection, active: bool, owner: Option<&str>) {
    connection
        .execute(
            UPSERT_DIRECTORY_USER_SQL,
            params![
                "dir_one",
                "acme",
                "entra",
                REALM,
                OBJECT,
                "person@example.com",
                "person@example.com",
                None::<String>,
                i32::from(active),
                0,
                owner,
                1,
                None::<String>
            ],
        )
        .unwrap();
}

fn seed_grants(connection: &Connection, other_namespace: bool) {
    for (client, session, refresh, code) in [
        ("app", "sess_bearer_a", "refresh_hash_a", "code_hash_a"),
        (
            "other_app",
            "sess_bearer_b",
            "refresh_hash_b",
            "code_hash_b",
        ),
    ] {
        connection
            .execute(
                INSERT_SESSION_SQL,
                params![
                    session,
                    "usr_owner",
                    client,
                    1,
                    1000,
                    None::<String>,
                    None::<String>,
                    "entra",
                    "proof"
                ],
            )
            .unwrap();
        connection
            .execute(
                INSERT_REFRESH_TOKEN_SQL,
                params![
                    refresh,
                    client,
                    "usr_owner",
                    session,
                    1,
                    "openid offline_access",
                    1,
                    1000,
                    "entra",
                    "proof"
                ],
            )
            .unwrap();
        connection
            .execute(
                INSERT_AUTH_CODE_SQL,
                params![
                    code,
                    client,
                    "https://app/cb",
                    "usr_owner",
                    session,
                    1,
                    None::<String>,
                    None::<String>,
                    None::<String>,
                    "openid",
                    1,
                    1000,
                    "entra",
                    "proof"
                ],
            )
            .unwrap();
    }
    connection.execute("INSERT INTO zeroth_account_identities(account_namespace,provider_id,provider_subject,user_id,created_at,updated_at)
      VALUES ('tenant:acme','entra','signed-sub','usr_owner',1,1)",[]).unwrap();
    if other_namespace {
        connection.execute("INSERT INTO zeroth_account_identities(account_namespace,provider_id,provider_subject,user_id,created_at,updated_at)
      VALUES ('tenant:other','entra','signed-other-sub','usr_owner',1,1)",[]).unwrap();
    }
    connection.execute("INSERT INTO zeroth_local_credentials(email,user_id,password_hash,password_salt,password_alg,password_iterations,created_at,updated_at)
      VALUES ('person@example.com','usr_owner','not-a-real-secret','salt','pbkdf2-sha256',1,1,1)",[]).unwrap();
}

fn audit(tx: &Transaction<'_>, event: &AuditEvent) -> rusqlite::Result<()> {
    let json = event.canonical_json().unwrap();
    tx.execute(
        audit_capture::INSERT_EVENT_SQL,
        params![
            event.event_id,
            event.event_type,
            "usr_owner",
            None::<String>,
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
            json
        ],
    )?;
    tx.execute(
        audit_capture::INSERT_OUTBOX_SQL,
        params![event.event_id, json, event.recorded_at],
    )?;
    Ok(())
}

fn deactivate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute(
        SOURCE_GUARD_SQL,
        params!["source_guard", "acme", "entra", REALM, 1, None::<String>],
    )?;
    tx.execute(
        USER_PREIMAGE_GUARD_SQL,
        params!["user_guard", "acme", "entra", REALM, OBJECT, 1],
    )?;
    tx.execute(
        LINK_PREIMAGE_GUARD_SQL,
        params!["link_guard", "acme", "entra", REALM, OBJECT, "usr_owner"],
    )?;
    tx.execute(
        UPSERT_DIRECTORY_USER_SQL,
        params![
            "dir_one",
            "acme",
            "entra",
            REALM,
            OBJECT,
            "person@example.com",
            "person@example.com",
            None::<String>,
            0,
            0,
            "usr_owner",
            100,
            None::<String>
        ],
    )?;
    for sql in REVOKE_DIRECTORY_USER_SQL {
        tx.execute(sql, params!["acme", "usr_owner", 100])?;
    }
    let event = lifecycle_event(
        "evt_disable".into(),
        &authority(),
        "dir_one",
        Some("usr_owner"),
        "directory.user.disable",
        AuditActor::new("service", "directory:entra").unwrap(),
        100,
    )
    .unwrap();
    audit(tx, &event)?;
    tx.execute("DELETE FROM zeroth_audit_write_guards", [])?;
    Ok(())
}

#[test]
fn managed_unknown_and_never_logged_in_tombstones_fail_closed_even_after_policy_relaxation() {
    let mut settings = source("entra", 1);
    assert!(check_directory_state(Some(&settings), None, 100).is_err());
    let mut tombstone = user(false);
    tombstone.user_id = None;
    assert!(check_directory_state(Some(&settings), Some(&tombstone), 100).is_err());
    settings.enabled = 0;
    assert!(check_directory_state(Some(&settings), Some(&tombstone), 100).is_err());
    assert!(check_directory_state(Some(&settings), None, 100).is_ok());
    tombstone.active = true;
    assert!(check_directory_state(Some(&settings), Some(&tombstone), 100).is_ok());
    tombstone.deleted = true;
    assert!(check_directory_state(Some(&settings), Some(&tombstone), 100).is_err());
}

#[test]
fn google_requires_recent_completed_snapshot_but_scim_has_no_heartbeat_expiry() {
    let record = user(true);
    let mut settings = source("google_workspace", 1);
    assert!(check_directory_state(Some(&settings), Some(&record), 1000).is_err());
    settings.last_full_sync_at = Some(99);
    assert!(check_directory_state(Some(&settings), Some(&record), 1000).is_err());
    settings.last_full_sync_at = Some(100);
    assert!(check_directory_state(Some(&settings), Some(&record), 1000).is_ok());
    let settings = source("entra", 1);
    assert!(check_directory_state(Some(&settings), Some(&record), i32::MAX).is_ok());
}

#[test]
fn deactivation_and_audit_are_atomic_and_preserve_other_tenants_grants_and_credentials() {
    let mut connection = database();
    put_user(&connection, true, Some("usr_owner"));
    seed_grants(&connection, true);
    connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["acme", "entra", REALM, OBJECT, "usr_owner", 1],
        )
        .unwrap();
    connection.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON zeroth_audit_outbox BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    {
        let tx = connection.transaction().unwrap();
        assert!(deactivate(&tx).is_err());
    }
    assert_eq!(
        connection
            .query_row("SELECT active FROM zeroth_directory_users", [], |row| row
                .get::<_, i32>(
                0
            ))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM zeroth_sessions WHERE revoked_at IS NOT NULL",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        0
    );
    connection
        .execute_batch("DROP TRIGGER reject_outbox")
        .unwrap();
    let tx = connection.transaction().unwrap();
    deactivate(&tx).unwrap();
    tx.commit().unwrap();
    for table in ["zeroth_sessions", "zeroth_refresh_tokens"] {
        assert_eq!(
            connection
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table} WHERE client_id='app' AND revoked_at=100"
                    ),
                    [],
                    |row| row.get::<_, i32>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(connection.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE client_id='other_app' AND revoked_at IS NULL"),[],|row|row.get::<_,i32>(0)).unwrap(),1);
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT consumed_at FROM zeroth_auth_codes WHERE client_id='app'",
                [],
                |row| row.get::<_, Option<i32>>(0)
            )
            .unwrap(),
        Some(100)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT disabled_at FROM zeroth_local_credentials",
                [],
                |row| row.get::<_, Option<i32>>(0)
            )
            .unwrap(),
        None
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT disabled_at FROM zeroth_users WHERE id='usr_owner'",
                [],
                |row| row.get::<_, Option<i32>>(0)
            )
            .unwrap(),
        None
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM zeroth_audit_outbox", [], |row| row
                .get::<_, i32>(0))
            .unwrap(),
        1
    );
}

#[test]
fn exclusively_tenant_owned_legacy_local_credentials_are_disabled() {
    let mut connection = database();
    put_user(&connection, true, Some("usr_owner"));
    seed_grants(&connection, false);
    let tx = connection.transaction().unwrap();
    deactivate(&tx).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT disabled_at FROM zeroth_local_credentials",
                [],
                |row| row.get::<_, Option<i32>>(0)
            )
            .unwrap(),
        Some(100)
    );
}

#[test]
fn object_mapping_is_immutable_and_email_does_not_attach_a_provisioned_account() {
    let connection = database();
    put_user(&connection, true, None);
    assert_eq!(
        connection
            .query_row(
                "SELECT user_id FROM zeroth_directory_users WHERE external_id=?",
                [OBJECT],
                |row| row.get::<_, Option<String>>(0)
            )
            .unwrap(),
        None
    );
    connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["acme", "entra", REALM, OBJECT, "usr_owner", 1],
        )
        .unwrap();
    assert!(connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["acme", "entra", REALM, OBJECT, "usr_other", 2]
        )
        .is_err());
    assert!(
        connection
            .execute(
                PIN_DIRECTORY_LINK_SQL,
                params!["acme", "entra", REALM, REALM, "usr_owner", 2]
            )
            .is_err(),
        "another employee object ID cannot attach to an already pinned local account"
    );
    connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["other", "entra", REALM, REALM, "usr_owner", 2],
        )
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT user_id FROM zeroth_directory_links WHERE tenant_id='acme'",
                [],
                |row| { row.get::<_, String>(0) }
            )
            .unwrap(),
        "usr_owner"
    );
    assert!(normalize_external_id("entra", "person@example.com").is_err());
    assert!(normalize_external_id("entra", "pairwise-subject").is_err());
    assert_eq!(
        normalize_external_id("entra", &OBJECT.to_ascii_uppercase()).unwrap(),
        OBJECT
    );
}

#[test]
fn stale_metadata_patch_cannot_restore_a_concurrently_deactivated_resource() {
    let mut connection = database();
    put_user(&connection, true, Some("usr_owner"));
    let patch_base = connection
        .query_row(
            "SELECT version FROM zeroth_directory_users WHERE id='dir_one'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    put_user(&connection, false, Some("usr_owner"));
    let tx = connection.transaction().unwrap();
    assert!(tx
        .execute(
            USER_PREIMAGE_GUARD_SQL,
            params!["stale_patch", "acme", "entra", REALM, OBJECT, patch_base]
        )
        .is_err());
    tx.rollback().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT active FROM zeroth_directory_users WHERE id='dir_one'",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn explicit_reprovision_after_delete_retains_resource_owner_and_requires_fresh_grants() {
    let mut connection = database();
    seed_grants(&connection, true);
    put_user(&connection, true, Some("usr_owner"));
    connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["acme", "entra", REALM, OBJECT, "usr_owner", 1],
        )
        .unwrap();
    {
        let tx = connection.transaction().unwrap();
        deactivate(&tx).unwrap();
        tx.execute(
            "UPDATE zeroth_directory_users SET deleted=1 WHERE id='dir_one'",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        connection
            .query_row(
                TENANT_USER_ACTIVE_SQL,
                params!["usr_owner", "acme", 100],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        0
    );
    // An authorized source can POST this immutable object again. The upsert
    // cannot replace its public resource ID or its pinned local account.
    connection
        .execute(
            UPSERT_DIRECTORY_USER_SQL,
            params![
                "dir_replacement_must_be_ignored",
                "acme",
                "entra",
                REALM,
                OBJECT,
                "renamed@example.com",
                "renamed@example.com",
                None::<String>,
                1,
                0,
                None::<String>,
                200,
                None::<String>
            ],
        )
        .unwrap();
    let (id, owner, active, deleted): (String, String, i32, i32) = connection
        .query_row(
            "SELECT id,user_id,active,deleted FROM zeroth_directory_users WHERE external_id=?",
            [OBJECT],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (id, owner, active, deleted),
        ("dir_one".into(), "usr_owner".into(), 1, 0)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT user_id FROM zeroth_directory_links WHERE tenant_id='acme'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "usr_owner"
    );
    assert_eq!(
        connection
            .query_row(
                TENANT_USER_ACTIVE_SQL,
                params!["usr_owner", "acme", 200],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT revoked_at FROM zeroth_sessions WHERE id='sess_bearer_a'",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        100
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT revoked_at FROM zeroth_refresh_tokens WHERE token_hash='refresh_hash_a'",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        100
    );
}

#[test]
fn source_generation_and_lease_fences_reject_superseded_snapshot_mutations() {
    let connection = database();
    connection
        .execute(
            "UPDATE zeroth_directory_sources SET sync_fence='lease_new'",
            [],
        )
        .unwrap();
    assert!(connection
        .execute(
            SOURCE_GUARD_SQL,
            params!["guard_old", "acme", "entra", REALM, 1, "lease_old"]
        )
        .is_err());
    connection
        .execute(
            SOURCE_GUARD_SQL,
            params!["guard_new", "acme", "entra", REALM, 1, "lease_new"],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE zeroth_directory_sources SET config_version=2,sync_fence=NULL",
            [],
        )
        .unwrap();
    assert!(connection
        .execute(
            SOURCE_GUARD_SQL,
            params![
                "guard_stale_config",
                "acme",
                "entra",
                REALM,
                1,
                None::<String>
            ]
        )
        .is_err());
    assert_eq!(
        connection
            .query_row(
                "SELECT last_full_sync_at FROM zeroth_directory_sources",
                [],
                |row| row.get::<_, Option<i32>>(0)
            )
            .unwrap(),
        None
    );
}

#[test]
fn concurrent_first_login_link_forces_deactivation_to_retry_with_real_owner() {
    let connection = database();
    put_user(&connection, true, None);
    connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["acme", "entra", REALM, OBJECT, "usr_owner", 1],
        )
        .unwrap();
    assert!(connection
        .execute(
            LINK_PREIMAGE_GUARD_SQL,
            params!["guard_old", "acme", "entra", REALM, OBJECT, None::<String>]
        )
        .is_err());
    connection
        .execute(
            LINK_PREIMAGE_GUARD_SQL,
            params!["guard_retry", "acme", "entra", REALM, OBJECT, "usr_owner"],
        )
        .unwrap();
}

#[test]
fn lifecycle_sql_blocks_linked_inactive_users_even_if_enforcement_is_off() {
    let connection = database();
    put_user(&connection, false, None);
    connection
        .execute(
            PIN_DIRECTORY_LINK_SQL,
            params!["acme", "entra", REALM, OBJECT, "usr_owner", 1],
        )
        .unwrap();
    connection
        .execute("UPDATE zeroth_directory_sources SET enabled=0", [])
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                LIFECYCLE_USER_ACTIVE_SQL,
                params!["usr_owner", "app", 100],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                LIFECYCLE_USER_ACTIVE_SQL,
                params!["usr_owner", "other_app", 100],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn direct_tenant_and_client_views_agree_for_unknown_active_tombstone_and_stale_directory_users() {
    let connection = database();
    let check = |tenant: &str, client: &str, expected: i32| {
        for (sql, scope) in [
            (TENANT_USER_ACTIVE_SQL, tenant),
            (LIFECYCLE_USER_ACTIVE_SQL, client),
        ] {
            assert_eq!(
                connection
                    .query_row(sql, params!["usr_owner", scope, 2000], |row| row
                        .get::<_, i32>(0))
                    .unwrap(),
                expected,
                "scope {scope}"
            );
        }
    };
    check("acme", "app", 0); // Managed identities unknown to this source are denied.
    check("other", "other_app", 1); // Explicit outside auditors need no source membership.
    put_user(&connection, true, Some("usr_owner"));
    check("acme", "app", 1);
    put_user(&connection, false, Some("usr_owner"));
    connection
        .execute(
            "UPDATE zeroth_directory_sources SET enabled=0 WHERE tenant_id='acme'",
            [],
        )
        .unwrap();
    check("acme", "app", 0); // Tombstones survive explicit managed-policy relaxation.
    connection.execute_batch("BEGIN;
      UPDATE zeroth_tenants SET enterprise_provider='google_workspace',entra_tenant_id=NULL WHERE id='other';
      UPDATE zeroth_clients SET enterprise_provider='google_workspace' WHERE id='other_app';
      UPDATE zeroth_tenant_clients SET enterprise_provider='google_workspace' WHERE tenant_id='other';
      INSERT INTO zeroth_directory_sources(tenant_id,provider_id,authority_id,enabled,created_at,updated_at)
        VALUES ('other','google_workspace','C01customer',1,1,1);
      INSERT INTO zeroth_directory_users(id,tenant_id,provider_id,authority_id,external_id,user_name,user_name_key,active,user_id,created_at,updated_at)
        VALUES ('dir_google','other','google_workspace','C01customer','10987654321','reader@example.com','reader@example.com',1,'usr_owner',1,1);
      COMMIT;").unwrap();
    check("other", "other_app", 0); // First full scan has not completed.
    connection
        .execute(
            "UPDATE zeroth_directory_sources SET last_full_sync_at=1100 WHERE tenant_id='other'",
            [],
        )
        .unwrap();
    check("other", "other_app", 1);
    connection
        .execute(
            "UPDATE zeroth_directory_sources SET last_full_sync_at=1099 WHERE tenant_id='other'",
            [],
        )
        .unwrap();
    check("other", "other_app", 0);
    connection
        .execute(
            "DELETE FROM zeroth_tenant_clients WHERE tenant_id='acme'",
            [],
        )
        .unwrap();
    assert_eq!(
        connection
            .query_row(
                TENANT_USER_ACTIVE_SQL,
                params!["usr_owner", "acme", 2000],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        0,
        "tenant audit checks do not depend on having a bound application"
    );
}

#[test]
fn full_snapshot_is_validated_before_any_application_and_audit_contains_no_profile_pii() {
    let a = authority();
    let first = change(OBJECT);
    assert!(validate_snapshot(&a, &[first.clone(), first.clone()]).is_err());
    let mut other = change("ffffffff-1111-2222-3333-444444444444");
    other.user_name = first.user_name.clone();
    assert!(validate_snapshot(&a, &[first.clone(), other]).is_err());
    let mut bad = first;
    bad.profile_json = Some("{\"password\":\"secret-token\"}".into());
    assert!(bad.validate(&a).is_err());
    let event = lifecycle_event(
        "evt_offboard".into(),
        &a,
        "dir_one",
        Some("usr_owner"),
        "directory.user.disable",
        AuditActor::new("service", "directory:entra").unwrap(),
        100,
    )
    .unwrap();
    let json = event.canonical_json().unwrap();
    for sensitive in [
        OBJECT,
        "person@example.com",
        "Personal Name",
        "secret-token",
    ] {
        assert!(!json.contains(sensitive));
    }
}

#[test]
fn completed_sync_timestamp_rolls_back_when_its_audit_outbox_fails() {
    let mut connection = database();
    connection
        .execute(
            "UPDATE zeroth_directory_sources SET last_full_sync_at=50",
            [],
        )
        .unwrap();
    connection.execute_batch("CREATE TRIGGER reject_outbox BEFORE INSERT ON zeroth_audit_outbox BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
    {
        let tx = connection.transaction().unwrap();
        tx.execute(MARK_SNAPSHOT_COMPLETE_SQL, params!["acme", 100, 150])
            .unwrap();
        let event = lifecycle_event(
            "evt_sync".into(),
            &authority(),
            "acme",
            None,
            "directory.sync.complete",
            AuditActor::new("service", "directory:entra").unwrap(),
            100,
        )
        .unwrap();
        assert!(audit(&tx, &event).is_err());
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT last_full_sync_at FROM zeroth_directory_sources",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
        50
    );
}

#[test]
fn slow_snapshot_application_never_rejuvenates_upstream_observation_time() {
    let connection = database();
    connection
        .execute(MARK_SNAPSHOT_COMPLETE_SQL, params!["acme", 1000, 2000])
        .unwrap();
    let (observed, recorded): (i32,i32) = connection.query_row("SELECT last_full_sync_at,last_activity_at FROM zeroth_directory_sources WHERE tenant_id='acme'", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
    assert_eq!(observed, 1000);
    assert_eq!(recorded, 2000);
    let mut policy = source("google_workspace", 1);
    policy.last_full_sync_at = Some(observed);
    assert!(check_directory_state(Some(&policy), Some(&user(true)), recorded).is_err());
}
