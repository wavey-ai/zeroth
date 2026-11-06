use super::*;
use rusqlite::{params, Connection, Transaction};
use std::time::Duration;

fn now() -> i32 {
    i32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn fixture() -> ServiceRow {
    let key =
        es256_signing_key_from_config("client-one", &URL_SAFE_NO_PAD.encode([7u8; 32])).unwrap();
    let jwk = es256_public_jwk(&key).unwrap();
    ServiceRow {
        id: "svc_deployer".into(),
        tenant_id: "alpha".into(),
        name: "Deployer".into(),
        audiences_json: r#"["https://api.example"]"#.into(),
        scopes_json: r#"["release:read","release:write"]"#.into(),
        public_jwks_json: serde_json::json!({"keys":[jwk]}).to_string(),
        disabled: 0,
        revision: 1,
        token_ttl_seconds: 600,
        created_at: 1,
        updated_at: 1,
    }
}
fn schema(db: &Connection) {
    db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    for migration in zeroth_storage::migrations::ALL {
        db.execute_batch(migration.sql).unwrap();
    }
    db.execute_batch("INSERT INTO zeroth_tenants(id,name,created_at,updated_at) VALUES('alpha','Alpha',1,1),('beta','Beta',1,1)").unwrap();
}
fn insert(db: &Connection, row: &ServiceRow) {
    db.execute(
        UPSERT_SQL,
        params![
            row.id,
            row.tenant_id,
            row.name,
            row.audiences_json,
            row.scopes_json,
            row.public_jwks_json,
            row.disabled,
            row.revision,
            row.token_ttl_seconds,
            row.created_at
        ],
    )
    .unwrap();
}
fn policy(
    tx: &Transaction<'_>,
    old: Option<&ServiceRow>,
    id: &str,
    tenant: &str,
) -> rusqlite::Result<()> {
    tx.execute(
        POLICY_GUARD_SQL,
        params![
            "policy",
            id,
            tenant,
            i32::from(old.is_some()),
            old.map(|r| r.revision),
            old.map(|r| &r.name),
            old.map(|r| &r.audiences_json),
            old.map(|r| &r.scopes_json),
            old.map(|r| &r.public_jwks_json),
            old.map(|r| r.disabled),
            old.map(|r| r.token_ttl_seconds),
            old.map(|r| r.created_at),
            old.map(|r| r.updated_at)
        ],
    )?;
    Ok(())
}
fn capture(tx: &Transaction<'_>, id: &str, row: &ServiceRow) -> rusqlite::Result<()> {
    let mut event = audit_capture::event(
        id.into(),
        "service.token.issue",
        zeroth_audit::AuditActor::new("service", &row.id).unwrap(),
        None,
        Some(&row.id),
        None,
        &serde_json::json!({}),
        100,
    )
    .unwrap();
    event.organization_id = Some(row.tenant_id.clone());
    event.targets = vec![zeroth_audit::AuditTarget::new("service_client", &row.id).unwrap()];
    let json = event.canonical_json().unwrap();
    tx.execute(
        audit_capture::AUDIT_SCOPE_GUARD_SQL,
        params![format!("scope_{id}"), row.tenant_id, row.id],
    )?;
    tx.execute(
        audit_capture::INSERT_EVENT_SQL,
        params![
            id,
            event.event_type,
            None::<String>,
            row.id,
            None::<String>,
            100,
            "{}",
            event.schema_version,
            row.tenant_id,
            event.actor.kind,
            row.id,
            "service_client",
            row.id,
            "success",
            None::<String>,
            None::<String>,
            100,
            json
        ],
    )?;
    tx.execute(audit_capture::INSERT_OUTBOX_SQL, params![id, json, 100])?;
    Ok(())
}
fn issuance(
    db: &mut Connection,
    row: &ServiceRow,
    jti: &str,
    token: &str,
    id: &str,
) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    capture(&tx, id, row)?;
    tx.execute(
        USE_GUARD_SQL,
        params![
            id,
            row.id,
            row.tenant_id,
            row.revision,
            row.name,
            row.audiences_json,
            row.scopes_json,
            row.public_jwks_json,
            row.token_ttl_seconds,
            row.updated_at,
            now() + 300,
            now(),
            now() + 600
        ],
    )?;
    tx.execute(
        CLAIM_ASSERTION_SQL,
        params![row.id, jti, now() + 300, now()],
    )?;
    tx.execute(
        INSERT_TOKEN_SQL,
        params![
            token,
            row.id,
            row.tenant_id,
            row.revision,
            now() + 600,
            now()
        ],
    )?;
    tx.execute("DELETE FROM zeroth_audit_write_guards", [])?;
    tx.commit()
}
fn count(db: &Connection, table: &str) -> i64 {
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}
fn active(db: &Connection, hash: &str, row: &ServiceRow, now: i32) -> bool {
    db.query_row(
        TOKEN_ACTIVE_SQL,
        params![hash, row.id, row.tenant_id, row.revision, now],
        |r| r.get::<_, i32>(0),
    )
    .unwrap()
        == 1
}

#[test]
fn registry_policy_is_tenant_owned_revision_guarded_and_public_only() {
    let mut db = Connection::open_in_memory().unwrap();
    schema(&db);
    let row = fixture();
    {
        let tx = db.transaction().unwrap();
        assert!(policy(&tx, None, &row.id, "missing").is_err());
    }
    {
        let tx = db.transaction().unwrap();
        policy(&tx, None, &row.id, "alpha").unwrap();
    }
    insert(&db, &row);
    {
        let tx = db.transaction().unwrap();
        assert!(policy(&tx, None, &row.id, "alpha").is_err());
    }
    {
        let tx = db.transaction().unwrap();
        assert!(policy(&tx, Some(&row), &row.id, "beta").is_err());
    }
    let mut changed = row.clone();
    changed.public_jwks_json = "{}".into();
    {
        let tx = db.transaction().unwrap();
        assert!(policy(&tx, Some(&changed), &row.id, "alpha").is_err());
    }
    let input = || ServiceUpsert {
        id: row.id.clone(),
        tenant_id: row.tenant_id.clone(),
        name: row.name.clone(),
        audiences: vec!["https://api.example".into()],
        scopes: vec!["release:read".into()],
        public_jwks: serde_json::from_str(&row.public_jwks_json).unwrap(),
        disabled: false,
        token_ttl_seconds: 600,
        expected_revision: Some(1),
    };
    assert_eq!(validate_upsert(input(), Some(&row), 2).unwrap().revision, 2);
    let mut stale = input();
    stale.expected_revision = Some(0);
    assert!(validate_upsert(stale, Some(&row), 2).is_err());
    let mut rebind = input();
    rebind.tenant_id = "beta".into();
    assert!(validate_upsert(rebind, Some(&row), 2).is_err());
    let mut private = input();
    private.public_jwks["keys"][0]["d"] = serde_json::json!(URL_SAFE_NO_PAD.encode([7u8; 32]));
    assert!(validate_upsert(private, Some(&row), 2).is_err());
    db.execute("INSERT INTO zeroth_clients(id,name,redirect_uris_json,created_at,updated_at) VALUES('svc_collision','Human','[]',1,1)",[]).unwrap();
    {
        let tx = db.transaction().unwrap();
        assert!(policy(&tx, None, "svc_collision", "alpha").is_err());
    }
}

#[test]
fn successful_issue_atomically_captures_service_scope_without_creating_a_human() {
    let mut db = Connection::open_in_memory().unwrap();
    schema(&db);
    let row = fixture();
    insert(&db, &row);
    issuance(&mut db, &row, "assertion_hash", "access_hash", "evt_first").unwrap();
    assert!(active(&db, "access_hash", &row, 100));
    assert!(!active(&db, "access_hash", &row, now() + 600));
    for table in [
        "zeroth_service_assertions",
        "zeroth_service_tokens",
        "zeroth_audit_events",
        "zeroth_audit_outbox",
    ] {
        assert_eq!(count(&db, table), 1);
    }
    for table in [
        "zeroth_users",
        "zeroth_sessions",
        "zeroth_auth_codes",
        "zeroth_refresh_tokens",
    ] {
        assert_eq!(count(&db, table), 0);
    }
    let captured: (String, String, String) = db
        .query_row(
            "SELECT organization_id,actor_type,target_type FROM zeroth_audit_events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        captured,
        ("alpha".into(), "service".into(), "service_client".into())
    );
    assert!(issuance(&mut db, &row, "assertion_hash", "other_hash", "evt_second").is_err());
    assert_eq!(count(&db, "zeroth_service_tokens"), 1);
    assert_eq!(count(&db, "zeroth_audit_events"), 1);
}

#[test]
fn rotation_disable_tenant_disable_and_preimage_races_fail_without_evidence_or_replay_claim() {
    for change in [
        "UPDATE zeroth_service_clients SET revision=2",
        "UPDATE zeroth_service_clients SET disabled=1",
        "UPDATE zeroth_tenants SET disabled=1 WHERE id='alpha'",
        "UPDATE zeroth_service_clients SET public_jwks_json='{}'",
    ] {
        let mut db = Connection::open_in_memory().unwrap();
        schema(&db);
        let row = fixture();
        insert(&db, &row);
        db.execute(change, []).unwrap();
        assert!(
            issuance(&mut db, &row, "assertion_hash", "token_hash", "event").is_err(),
            "{change}"
        );
        for table in [
            "zeroth_service_assertions",
            "zeroth_service_tokens",
            "zeroth_audit_events",
            "zeroth_audit_outbox",
        ] {
            assert_eq!(count(&db, table), 0, "{change} {table}");
        }
    }
}

#[test]
fn introspection_is_own_token_only_and_disable_is_scoped_to_one_service_tenant() {
    let mut db = Connection::open_in_memory().unwrap();
    schema(&db);
    let a = fixture();
    let mut b = a.clone();
    b.id = "svc_other".into();
    b.tenant_id = "beta".into();
    insert(&db, &a);
    insert(&db, &b);
    issuance(&mut db, &a, "a_jti", "a_token", "a_event").unwrap();
    issuance(&mut db, &b, "b_jti", "b_token", "b_event").unwrap();
    assert!(active(&db, "a_token", &a, 100));
    assert!(!active(&db, "a_token", &b, 100));
    db.execute(
        "UPDATE zeroth_service_clients SET disabled=1,revision=2 WHERE id=?",
        [&a.id],
    )
    .unwrap();
    assert!(!active(&db, "a_token", &a, 100));
    assert!(active(&db, "b_token", &b, 100));
    db.execute("UPDATE zeroth_tenants SET disabled=1 WHERE id='beta'", [])
        .unwrap();
    assert!(!active(&db, "b_token", &b, 100));
}

#[test]
fn failed_audit_outbox_does_not_consume_an_assertion_or_issue_a_token() {
    let mut db = Connection::open_in_memory().unwrap();
    schema(&db);
    let row = fixture();
    insert(&db, &row);
    db.execute_batch("CREATE TRIGGER reject_service_outbox BEFORE INSERT ON zeroth_audit_outbox BEGIN SELECT RAISE(ABORT,'blocked'); END;").unwrap();
    assert!(issuance(&mut db, &row, "jti_hash", "token_hash", "event").is_err());
    for table in [
        "zeroth_service_assertions",
        "zeroth_service_tokens",
        "zeroth_audit_events",
        "zeroth_audit_outbox",
    ] {
        assert_eq!(count(&db, table), 0);
    }
    db.execute_batch("DROP TRIGGER reject_service_outbox")
        .unwrap();
    issuance(&mut db, &row, "jti_hash", "token_hash", "event").unwrap();
}

#[test]
fn two_independent_issuers_can_only_commit_one_copy_of_an_assertion() {
    let path = std::env::temp_dir().join(format!(
        "zeroth-service-replay-{}-{}.sqlite",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let db = Connection::open(&path).unwrap();
    schema(&db);
    let row = fixture();
    insert(&db, &row);
    drop(db);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = (0..2)
        .map(|n| {
            let path = path.clone();
            let barrier = barrier.clone();
            let row = row.clone();
            std::thread::spawn(move || {
                let mut db = Connection::open(path).unwrap();
                db.busy_timeout(Duration::from_secs(5)).unwrap();
                barrier.wait();
                issuance(
                    &mut db,
                    &row,
                    "same_jti",
                    &format!("token_{n}"),
                    &format!("evt_{n}"),
                )
                .is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(count(&db, "zeroth_service_assertions"), 1);
    assert_eq!(count(&db, "zeroth_service_tokens"), 1);
    assert_eq!(count(&db, "zeroth_audit_events"), 1);
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn service_forms_reject_duplicate_credential_mixing_and_implicit_grants() {
    assert!(parse_form("client_id=svc_one&client_id=svc_two").is_err());
    let base=format!("grant_type=client_credentials&client_id=svc_deployer&client_assertion_type={ASSERTION_TYPE}&client_assertion=proof&resource=https%3A%2F%2Fapi.example&scope=release%3Aread");
    let form = parse_form(&base).unwrap();
    assert!(service_request(&form));
    validate_request(&form, false).unwrap();
    assert!(approved_grant(&fixture().client().unwrap(), &form).is_ok());
    for extra in [
        "&audience=https%3A%2F%2Fapi.example",
        "&redirect_uri=https%3A%2F%2Fevil.example",
        "&client_secret=secret",
        "&scope=openid",
    ] {
        assert!(parse_form(&(base.clone() + extra))
            .and_then(|f| validate_request(&f, false))
            .is_err());
    }
    let mut form = form;
    form.insert("scope".into(), "openid".into());
    assert!(approved_grant(&fixture().client().unwrap(), &form).is_err());
    form.insert("scope".into(), "release:read release:read".into());
    assert!(approved_grant(&fixture().client().unwrap(), &form).is_err());
}

#[test]
fn signed_machine_tokens_cannot_authenticate_as_humans_or_as_other_services() {
    let row = fixture();
    let client = row.client().unwrap();
    let issuer_key =
        es256_signing_key_from_config("issuer-one", &URL_SAFE_NO_PAD.encode([9u8; 32])).unwrap();
    let jwks = jwks_response(&issuer_key, None).unwrap();
    let issuer = "https://id.example";
    let claims = build_service_access_token_claims(
        &client,
        issuer,
        "https://api.example",
        "release:read",
        100,
        "token-identity",
    )
    .unwrap();
    let token = sign_jwt(&issuer_key, &claims).unwrap();
    assert!(service_claims_for_introspection(&token, &client, issuer, &jwks, 100).is_some());
    let config = ZerothServerConfig {
        public_base_url: issuer.into(),
        ..Default::default()
    };
    assert!(verify_zeroth_access_token(&token, &config, &jwks, 100).is_err());
    let mut foreign = client.clone();
    foreign.id = "svc_other".into();
    assert!(service_claims_for_introspection(&token, &foreign, issuer, &jwks, 100).is_none());
    let mut rotated = client.clone();
    rotated.revision = 2;
    assert!(service_claims_for_introspection(&token, &rotated, issuer, &jwks, 100).is_none());
    let client_key =
        es256_signing_key_from_config("client-one", &URL_SAFE_NO_PAD.encode([7u8; 32])).unwrap();
    assert!(service_claims_for_introspection(
        &sign_jwt(&client_key, &claims).unwrap(),
        &client,
        issuer,
        &jwks,
        100
    )
    .is_none());
    assert!(service_claims_for_introspection(&token, &client, issuer, &jwks, 700).is_none());
}

#[test]
fn database_clock_refuses_stale_preverified_requests_after_replay_tombstone_expiry() {
    let mut db = Connection::open_in_memory().unwrap();
    schema(&db);
    let row = fixture();
    insert(&db, &row);
    let current = now();
    db.execute(
        CLAIM_ASSERTION_SQL,
        params![row.id, "old_assertion", current - 1, current - 100],
    )
    .unwrap();
    db.execute(
        "DELETE FROM zeroth_service_assertions WHERE expires_at<=?",
        [current],
    )
    .unwrap();
    for (assertion_expiry, token_expiry) in
        [(current - 1, current + 600), (current + 300, current - 1)]
    {
        let tx = db.transaction().unwrap();
        assert!(tx
            .execute(
                USE_GUARD_SQL,
                params![
                    "stale",
                    row.id,
                    row.tenant_id,
                    row.revision,
                    row.name,
                    row.audiences_json,
                    row.scopes_json,
                    row.public_jwks_json,
                    row.token_ttl_seconds,
                    row.updated_at,
                    assertion_expiry,
                    current - 10,
                    token_expiry
                ]
            )
            .is_err());
    }
    db.execute(
        INSERT_TOKEN_SQL,
        params![
            "expired",
            row.id,
            row.tenant_id,
            row.revision,
            current - 1,
            current - 600
        ],
    )
    .unwrap();
    assert!(!active(&db, "expired", &row, current - 10));
    assert_eq!(count(&db, "zeroth_service_assertions"), 0);
    assert_eq!(count(&db, "zeroth_audit_events"), 0);
}

#[test]
fn legacy_human_service_prefix_clients_keep_their_flow_but_new_ids_cannot_collide() {
    for body in [
        "client_id=svc_legacy&grant_type=authorization_code&code=code",
        "client_id=svc_legacy&grant_type=refresh_token&refresh_token=token",
        "client_id=svc_legacy&client_secret=secret&token=token",
    ] {
        assert!(!service_request(&parse_form(body).unwrap()));
    }
    assert!(service_request(
        &parse_form("client_id=svc_new&grant_type=client_credentials").unwrap()
    ));
    let db = Connection::open_in_memory().unwrap();
    schema(&db);
    let human_guard = |id: &str, exists: bool| {
        db.execute(
            audit_capture::CLIENT_POLICY_GUARD_SQL,
            params![
                format!("human_{id}"),
                id,
                i32::from(exists),
                "Legacy",
                None::<String>,
                "[]",
                "[]",
                "[]",
                None::<String>,
                None::<String>,
                None::<i32>,
                "global",
                "global",
                "[]",
                0,
                None::<i32>
            ],
        )
    };
    assert!(human_guard("svc_new", false).is_err());
    db.execute("INSERT INTO zeroth_clients(id,name,redirect_uris_json,created_at,updated_at) VALUES('svc_legacy','Legacy','[]',1,1)",[]).unwrap();
    human_guard("svc_legacy", true).unwrap();
    db.execute("DELETE FROM zeroth_audit_write_guards", [])
        .unwrap();
    let mut service = fixture();
    service.id = "svc_legacy".into();
    // Even a colliding registry row cannot bypass the human policy's transactional check.
    insert(&db, &service);
    assert!(human_guard("svc_legacy", true).is_err());
}

#[test]
fn machine_transport_requires_https_except_loopback() {
    for url in [
        "https://id.example/oauth/token",
        "http://127.0.0.1:8787/oauth/token",
        "http://[::1]/oauth/introspect",
        "http://localhost/oauth/token",
    ] {
        assert!(validate_transport(&url::Url::parse(url).unwrap()).is_ok());
    }
    for url in [
        "http://id.example/oauth/token",
        "http://localhost.evil.example/oauth/token",
        "https://user:secret@id.example/oauth/token",
        "file:///oauth/token",
    ] {
        assert!(validate_transport(&url::Url::parse(url).unwrap()).is_err());
    }
}
