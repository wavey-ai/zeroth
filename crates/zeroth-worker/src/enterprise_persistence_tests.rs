use super::*;
use rusqlite::{params, types::ValueRef, Connection};

const NOW: i32 = 1_780_000_100;

fn enterprise_database() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    for migration in zeroth_storage::migrations::ALL {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute_batch(
        "INSERT INTO zeroth_users (id, primary_email, created_at, updated_at)
         VALUES ('enterprise-user', 'user@corp.example', 1780000000, 1780000000);
         INSERT INTO zeroth_clients (
             id, name, redirect_uris_json, enterprise_provider, created_at, updated_at
         ) VALUES (
             'enterprise-client', 'Enterprise Client',
             '[\"https://app.example/callback\"]', 'entra', 1780000000, 1780000000
         );",
    )
    .unwrap();
    conn
}

// Decode the same flat D1 row shape consumed by the Worker. SELECT * ensures a
// missing/renamed provenance column cannot be hidden by test-created JSON.
fn persisted_row<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    table: &str,
    key_column: &str,
    key: &str,
) -> T {
    let mut statement = conn
        .prepare(&format!("SELECT * FROM {table} WHERE {key_column} = ?"))
        .unwrap();
    let names = statement
        .column_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let value = statement
        .query_row(params![key], |row| {
            let mut object = serde_json::Map::new();
            for (index, name) in names.iter().enumerate() {
                let value = match row.get_ref(index)? {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(value) => value.into(),
                    ValueRef::Real(value) => serde_json::json!(value),
                    ValueRef::Text(value) => {
                        serde_json::Value::String(String::from_utf8(value.to_vec()).unwrap())
                    }
                    ValueRef::Blob(_) => panic!("unexpected blob in authentication row: {name}"),
                };
                object.insert(name.clone(), value);
            }
            Ok(serde_json::Value::Object(object))
        })
        .unwrap();
    serde_json::from_value(value).unwrap()
}

fn insert_session(conn: &Connection, id: &str, context: &AuthContext) {
    conn.execute(
        INSERT_SESSION_SQL,
        params![
            id,
            "enterprise-user",
            "enterprise-client",
            NOW,
            NOW + 600,
            Some("enterprise-persistence-test"),
            Option::<String>::None,
            context.auth_provider,
            context.auth_policy_hash,
        ],
    )
    .unwrap();
}

fn insert_code(conn: &Connection, hash: &str, context: &AuthContext) {
    conn.execute(
        INSERT_AUTH_CODE_SQL,
        params![
            hash,
            "enterprise-client",
            "https://app.example/callback",
            "enterprise-user",
            Some("session"),
            Some(NOW - 10),
            Some("downstream-nonce"),
            Some("pkce-challenge"),
            Some("S256"),
            "openid email profile offline_access",
            NOW,
            NOW + 600,
            context.auth_provider,
            context.auth_policy_hash,
        ],
    )
    .unwrap();
}

fn insert_refresh(conn: &Connection, hash: &str, context: &AuthContext) {
    conn.execute(
        INSERT_REFRESH_TOKEN_SQL,
        params![
            hash,
            "enterprise-client",
            "enterprise-user",
            Some("session"),
            Some(NOW - 10),
            "openid email profile offline_access",
            NOW,
            NOW + 600,
            context.auth_provider,
            context.auth_policy_hash,
        ],
    )
    .unwrap();
}

fn entra_context() -> AuthContext {
    AuthContext {
        auth_provider: Some("entra".to_owned()),
        auth_policy_hash: Some("policy".to_owned()),
    }
}

#[test]
fn enterprise_provenance_roundtrips_session_code_and_refresh_rows() {
    let conn = enterprise_database();
    for context in [
        entra_context(),
        AuthContext {
            auth_provider: Some("google_workspace".to_owned()),
            auth_policy_hash: Some("workspace-policy".to_owned()),
        },
    ] {
        conn.execute("DELETE FROM zeroth_sessions", []).unwrap();
        conn.execute("DELETE FROM zeroth_auth_codes", []).unwrap();
        conn.execute("DELETE FROM zeroth_refresh_tokens", [])
            .unwrap();
        insert_session(&conn, "session", &context);
        insert_code(&conn, "code", &context);
        insert_refresh(&conn, "refresh", &context);

        let session: SessionRow = persisted_row(&conn, "zeroth_sessions", "id", "session");
        let code: AuthCodeRow = persisted_row(&conn, "zeroth_auth_codes", "code_hash", "code");
        let refresh: RefreshTokenRow =
            persisted_row(&conn, "zeroth_refresh_tokens", "token_hash", "refresh");
        assert_eq!(session.auth_context, context);
        assert_eq!(code.auth_context, context);
        assert_eq!(refresh.auth_context, context);
        assert_eq!(code.auth_time, Some(NOW - 10));
        assert_eq!(refresh.auth_time, Some(NOW - 10));
        assert_eq!(refresh.session_id.as_deref(), Some("session"));
        for proof in [
            session.auth_context,
            code.auth_context,
            refresh.auth_context,
        ] {
            proof
                .validate(
                    context.auth_provider.as_deref(),
                    context.auth_policy_hash.as_deref(),
                )
                .unwrap();
            assert!(proof
                .validate(
                    context.auth_provider.as_deref(),
                    Some("reconfigured-policy")
                )
                .is_err());
        }
    }
}

#[test]
fn legacy_null_proof_is_not_inferred_from_the_clients_enterprise_requirement() {
    let conn = enterprise_database();
    let legacy = AuthContext::default();
    insert_session(&conn, "session", &legacy);
    insert_code(&conn, "code", &legacy);
    insert_refresh(&conn, "refresh", &legacy);
    let session: SessionRow = persisted_row(&conn, "zeroth_sessions", "id", "session");
    let code: AuthCodeRow = persisted_row(&conn, "zeroth_auth_codes", "code_hash", "code");
    let refresh: RefreshTokenRow =
        persisted_row(&conn, "zeroth_refresh_tokens", "token_hash", "refresh");
    for proof in [
        session.auth_context,
        code.auth_context,
        refresh.auth_context,
    ] {
        assert_eq!(proof, legacy);
        assert!(proof.validate(Some("entra"), Some("policy")).is_err());
    }
}

#[test]
fn refresh_rotation_copies_provider_policy_and_never_upgrades_local_proof() {
    for context in [
        entra_context(),
        AuthContext::default(),
        AuthContext {
            auth_provider: Some("google".to_owned()),
            auth_policy_hash: None,
        },
    ] {
        let conn = enterprise_database();
        insert_session(&conn, "session", &context);
        insert_refresh(&conn, "parent", &context);
        conn.execute(
            "UPDATE zeroth_refresh_tokens SET rotated_at = ? WHERE token_hash = 'parent'",
            params![NOW + 1],
        )
        .unwrap();
        assert_eq!(
            conn.execute(
                INSERT_ROTATED_REFRESH_TOKEN_SQL,
                params!["child", NOW + 1, NOW + 700, "parent", NOW + 1, NOW + 1],
            )
            .unwrap(),
            1
        );
        let child: RefreshTokenRow =
            persisted_row(&conn, "zeroth_refresh_tokens", "token_hash", "child");
        assert_eq!(child.auth_context, context);
        assert_eq!(child.client_id, "enterprise-client");
        assert_eq!(child.user_id, "enterprise-user");
        assert_eq!(child.session_id.as_deref(), Some("session"));
        assert_eq!(child.auth_time, Some(NOW - 10));
        assert_eq!(child.created_at, NOW + 1);
        assert_eq!(child.expires_at, NOW + 700);
        let admitted = child
            .auth_context
            .validate(Some("entra"), Some("policy"))
            .is_ok();
        assert_eq!(admitted, context == entra_context());
        assert!(child
            .auth_context
            .validate(Some("entra"), Some("changed-policy"))
            .is_err());
    }
}

#[test]
fn revoked_expired_or_unrotated_parent_cannot_mint_enterprise_refresh_proof() {
    for state in ["unrotated", "revoked", "expired"] {
        let conn = enterprise_database();
        insert_refresh(&conn, "parent", &entra_context());
        match state {
            "unrotated" => {}
            "revoked" => {
                conn.execute(
                    "UPDATE zeroth_refresh_tokens SET rotated_at = ?, revoked_at = ?",
                    params![NOW, NOW],
                )
                .unwrap();
            }
            "expired" => {
                conn.execute(
                    "UPDATE zeroth_refresh_tokens SET rotated_at = ?, expires_at = ?",
                    params![NOW, NOW],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            conn.execute(
                INSERT_ROTATED_REFRESH_TOKEN_SQL,
                params!["child", NOW, NOW + 600, "parent", NOW, NOW],
            )
            .unwrap(),
            0,
            "{state} parent must not create a new enterprise authentication proof"
        );
    }
}

#[test]
fn persisted_incomplete_or_wrong_provider_context_fails_enterprise_admission() {
    for context in [
        AuthContext {
            auth_provider: Some("entra".to_owned()),
            auth_policy_hash: None,
        },
        AuthContext {
            auth_provider: None,
            auth_policy_hash: Some("policy".to_owned()),
        },
        AuthContext {
            auth_provider: Some("google_workspace".to_owned()),
            auth_policy_hash: Some("policy".to_owned()),
        },
        AuthContext {
            auth_provider: Some("google".to_owned()),
            auth_policy_hash: Some("policy".to_owned()),
        },
    ] {
        let conn = enterprise_database();
        insert_session(&conn, "session", &context);
        let session: SessionRow = persisted_row(&conn, "zeroth_sessions", "id", "session");
        assert_eq!(session.auth_context, context);
        assert!(session
            .auth_context
            .validate(Some("entra"), Some("policy"))
            .is_err());
    }
}
