//! Storage traits for Zeroth.

use zeroth_core::{
    AuthTransaction, AuthorizationCodeGrant, Client, ClientId, Identity, ProviderId,
    RefreshTokenGrant, Session, Subject, User, UserId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreError {
    pub code: String,
    pub message: String,
}

pub type StoreResult<T> = Result<T, StoreError>;

pub trait ZerothStore {
    fn get_client(&self, id: &ClientId) -> StoreResult<Option<Client>>;
    fn put_client(&self, client: Client) -> StoreResult<()>;

    fn get_user(&self, id: &UserId) -> StoreResult<Option<User>>;
    fn put_user(&self, user: User) -> StoreResult<()>;

    fn get_identity(
        &self,
        provider_id: &ProviderId,
        subject: &Subject,
    ) -> StoreResult<Option<Identity>>;
    fn put_identity(&self, identity: Identity) -> StoreResult<()>;

    fn put_authorization_code(&self, grant: AuthorizationCodeGrant) -> StoreResult<()>;
    fn take_authorization_code(&self, code: &str) -> StoreResult<Option<AuthorizationCodeGrant>>;

    fn put_auth_transaction(&self, transaction: AuthTransaction) -> StoreResult<()>;
    fn take_auth_transaction(&self, provider_state: &str) -> StoreResult<Option<AuthTransaction>>;

    fn put_refresh_token(&self, grant: RefreshTokenGrant) -> StoreResult<()>;
    fn get_refresh_token(&self, token_id: &str) -> StoreResult<Option<RefreshTokenGrant>>;

    fn put_session(&self, session: Session) -> StoreResult<()>;
    fn get_session(&self, session_id: &str) -> StoreResult<Option<Session>>;
}

pub const SCHEMA_MIGRATIONS_TABLE: &str = "zeroth_schema_migrations";
pub const SCHEMA_MIGRATIONS_CREATE_SQL: &str = "\
CREATE TABLE IF NOT EXISTS zeroth_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL
)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Migration {
    pub version: i32,
    pub name: &'static str,
    pub sql: &'static str,
}

impl Migration {
    pub fn statements(&self) -> impl Iterator<Item = &'static str> {
        self.sql
            .split(';')
            .map(str::trim)
            .filter(|sql| !sql.is_empty())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityColumn {
    pub table: &'static str,
    pub name: &'static str,
    pub definition: &'static str,
}

impl CompatibilityColumn {
    pub fn alter_table_sql(self) -> String {
        format!(
            "ALTER TABLE {} ADD COLUMN {} {}",
            self.table, self.name, self.definition
        )
    }
}

pub mod migrations {
    use super::Migration;

    pub const INIT: Migration = Migration {
        version: 1,
        name: "init",
        sql: include_str!("../migrations/0001_init.sql"),
    };

    pub const PASSKEYS: Migration = Migration {
        version: 2,
        name: "passkeys",
        sql: include_str!("../migrations/0002_passkeys.sql"),
    };

    pub const ADMIN_MEMBERSHIPS: Migration = Migration {
        version: 3,
        name: "admin_memberships",
        sql: include_str!("../migrations/0003_admin_memberships.sql"),
    };

    pub const LOCAL_AUTH: Migration = Migration {
        version: 4,
        name: "local_auth",
        sql: include_str!("../migrations/0004_local_auth.sql"),
    };

    pub const ACCOUNT_NAMESPACES: Migration = Migration {
        version: 5,
        name: "account_namespaces",
        sql: include_str!("../migrations/0005_account_namespaces.sql"),
    };

    pub const WALLET_AUTH: Migration = Migration {
        version: 6,
        name: "wallet_auth",
        sql: include_str!("../migrations/0006_wallet_auth.sql"),
    };

    pub const CLIENT_LOGIN_METHODS: Migration = Migration {
        version: 7,
        name: "client_login_methods",
        sql: include_str!("../migrations/0007_client_login_methods.sql"),
    };

    pub const PASSWORD_HASHING: Migration = Migration {
        version: 8,
        name: "password_hashing",
        sql: include_str!("../migrations/0008_password_hashing.sql"),
    };

    pub const RATE_LIMITS: Migration = Migration {
        version: 9,
        name: "rate_limits",
        sql: include_str!("../migrations/0009_rate_limits.sql"),
    };

    pub const MAGIC_LINK_POLL_TOKEN: Migration = Migration {
        version: 10,
        name: "magic_link_poll_token",
        sql: include_str!("../migrations/0010_magic_link_poll_token.sql"),
    };

    pub const PASSKEY_METADATA: Migration = Migration {
        version: 11,
        name: "passkey_metadata",
        sql: include_str!("../migrations/0011_passkey_metadata.sql"),
    };

    pub const ENTERPRISE_AUTH_POLICY: Migration = Migration {
        version: 12,
        name: "enterprise_auth_policy",
        sql: include_str!("../migrations/0012_enterprise_auth_policy.sql"),
    };

    pub const AUDIT_HISTORY: Migration = Migration {
        version: 13,
        name: "audit_history",
        sql: include_str!("../migrations/0013_audit_history.sql"),
    };

    pub const ALL: &[Migration] = &[
        INIT,
        PASSKEYS,
        ADMIN_MEMBERSHIPS,
        LOCAL_AUTH,
        ACCOUNT_NAMESPACES,
        WALLET_AUTH,
        CLIENT_LOGIN_METHODS,
        PASSWORD_HASHING,
        RATE_LIMITS,
        MAGIC_LINK_POLL_TOKEN,
        PASSKEY_METADATA,
        ENTERPRISE_AUTH_POLICY,
        AUDIT_HISTORY,
    ];
}

pub const REQUIRED_TABLES: &[&str] = &[
    SCHEMA_MIGRATIONS_TABLE,
    "zeroth_users",
    "zeroth_identities",
    "zeroth_account_identities",
    "zeroth_clients",
    "zeroth_auth_transactions",
    "zeroth_auth_codes",
    "zeroth_refresh_tokens",
    "zeroth_sessions",
    "zeroth_passkey_credentials",
    "zeroth_passkey_challenges",
    "zeroth_admin_memberships",
    "zeroth_local_credentials",
    "zeroth_magic_links",
    "zeroth_wallet_challenges",
    "zeroth_rate_limits",
    "zeroth_signing_keys",
    "zeroth_audit_events",
    "zeroth_audit_outbox",
    "zeroth_audit_consumers",
];

pub mod compatibility {
    use super::CompatibilityColumn;

    pub const AUTH_TRANSACTION_LINK_USER_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_transactions",
        name: "link_user_id",
        definition: "TEXT",
    };
    pub const AUTH_TRANSACTION_LINK_SESSION_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_transactions",
        name: "link_session_id",
        definition: "TEXT",
    };
    pub const AUTH_TRANSACTION_SESSION_RETURN_TO: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_transactions",
        name: "session_return_to",
        definition: "TEXT",
    };
    pub const AUTH_TRANSACTION_PROVIDER_NONCE: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_transactions",
        name: "provider_nonce",
        definition: "TEXT",
    };
    pub const AUTH_TRANSACTION_PROVIDER_POLICY_HASH: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_transactions",
        name: "provider_policy_hash",
        definition: "TEXT",
    };
    pub const AUTH_TRANSACTION_PROVIDER_CODE_VERIFIER: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_transactions",
        name: "provider_code_verifier",
        definition: "TEXT",
    };
    pub const AUTH_CODE_SESSION_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_codes",
        name: "session_id",
        definition: "TEXT",
    };
    pub const AUTH_CODE_AUTH_TIME: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_codes",
        name: "auth_time",
        definition: "INTEGER",
    };
    pub const AUTH_CODE_AUTH_PROVIDER: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_codes",
        name: "auth_provider",
        definition: "TEXT",
    };
    pub const AUTH_CODE_AUTH_POLICY_HASH: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_auth_codes",
        name: "auth_policy_hash",
        definition: "TEXT",
    };
    pub const REFRESH_TOKEN_AUTH_TIME: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_refresh_tokens",
        name: "auth_time",
        definition: "INTEGER",
    };
    pub const REFRESH_TOKEN_AUTH_PROVIDER: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_refresh_tokens",
        name: "auth_provider",
        definition: "TEXT",
    };
    pub const REFRESH_TOKEN_AUTH_POLICY_HASH: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_refresh_tokens",
        name: "auth_policy_hash",
        definition: "TEXT",
    };
    pub const SESSION_AUTH_PROVIDER: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_sessions",
        name: "auth_provider",
        definition: "TEXT",
    };
    pub const SESSION_AUTH_POLICY_HASH: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_sessions",
        name: "auth_policy_hash",
        definition: "TEXT",
    };
    pub const CLIENT_ALLOWED_EMAIL_DOMAINS: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "allowed_email_domains_json",
        definition: "TEXT NOT NULL DEFAULT '[]'",
    };
    pub const CLIENT_ISSUER_TOKEN_AUDIENCE: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "issuer_token_audience",
        definition: "TEXT",
    };
    pub const CLIENT_ISSUER_TOKEN_TTL_SECONDS: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "issuer_token_ttl_seconds",
        definition: "INTEGER",
    };
    pub const CLIENT_ACCOUNT_SHARING_MODE: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "account_sharing_mode",
        definition: "TEXT NOT NULL DEFAULT 'global'",
    };
    pub const CLIENT_ACCOUNT_TENANT_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "account_tenant_id",
        definition: "TEXT NOT NULL DEFAULT 'global'",
    };
    pub const CLIENT_VISIBLE_LOGIN_METHODS: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "visible_login_methods_json",
        definition: "TEXT NOT NULL DEFAULT '[]'",
    };
    pub const CLIENT_ENTERPRISE_PROVIDER: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_clients",
        name: "enterprise_provider",
        definition: "TEXT",
    };

    pub const AUDIT_SCHEMA_VERSION: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "schema_version",
        definition: "INTEGER NOT NULL DEFAULT 0",
    };
    pub const AUDIT_ORGANIZATION_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "organization_id",
        definition: "TEXT",
    };
    pub const AUDIT_ACTOR_TYPE: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "actor_type",
        definition: "TEXT",
    };
    pub const AUDIT_ACTOR_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "actor_id",
        definition: "TEXT",
    };
    pub const AUDIT_TARGET_TYPE: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "target_type",
        definition: "TEXT",
    };
    pub const AUDIT_TARGET_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "target_id",
        definition: "TEXT",
    };
    pub const AUDIT_OUTCOME: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "outcome",
        definition: "TEXT NOT NULL DEFAULT 'unknown'",
    };
    pub const AUDIT_REASON_CODE: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "reason_code",
        definition: "TEXT",
    };
    pub const AUDIT_REQUEST_ID: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "request_id",
        definition: "TEXT",
    };
    pub const AUDIT_RECORDED_AT: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "recorded_at",
        definition: "INTEGER",
    };
    pub const AUDIT_EVENT_JSON: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_audit_events",
        name: "event_json",
        definition: "TEXT",
    };

    pub const TABLES: &[&str] = &[
        "zeroth_clients",
        "zeroth_auth_transactions",
        "zeroth_auth_codes",
        "zeroth_refresh_tokens",
        "zeroth_sessions",
        "zeroth_audit_events",
    ];

    pub const ALL: &[CompatibilityColumn] = &[
        CLIENT_ALLOWED_EMAIL_DOMAINS,
        CLIENT_ISSUER_TOKEN_AUDIENCE,
        CLIENT_ISSUER_TOKEN_TTL_SECONDS,
        CLIENT_ACCOUNT_SHARING_MODE,
        CLIENT_ACCOUNT_TENANT_ID,
        CLIENT_VISIBLE_LOGIN_METHODS,
        CLIENT_ENTERPRISE_PROVIDER,
        AUTH_TRANSACTION_PROVIDER_NONCE,
        AUTH_TRANSACTION_PROVIDER_POLICY_HASH,
        AUTH_TRANSACTION_PROVIDER_CODE_VERIFIER,
        AUTH_TRANSACTION_LINK_USER_ID,
        AUTH_TRANSACTION_LINK_SESSION_ID,
        AUTH_TRANSACTION_SESSION_RETURN_TO,
        AUTH_CODE_SESSION_ID,
        AUTH_CODE_AUTH_TIME,
        AUTH_CODE_AUTH_PROVIDER,
        AUTH_CODE_AUTH_POLICY_HASH,
        REFRESH_TOKEN_AUTH_TIME,
        REFRESH_TOKEN_AUTH_PROVIDER,
        REFRESH_TOKEN_AUTH_POLICY_HASH,
        SESSION_AUTH_PROVIDER,
        SESSION_AUTH_POLICY_HASH,
        AUDIT_SCHEMA_VERSION,
        AUDIT_ORGANIZATION_ID,
        AUDIT_ACTOR_TYPE,
        AUDIT_ACTOR_ID,
        AUDIT_TARGET_TYPE,
        AUDIT_TARGET_ID,
        AUDIT_OUTCOME,
        AUDIT_REASON_CODE,
        AUDIT_REQUEST_ID,
        AUDIT_RECORDED_AT,
        AUDIT_EVENT_JSON,
    ];
}

#[cfg(test)]
mod tests {
    use super::{compatibility, migrations};
    use rusqlite::{params, Connection};

    #[test]
    fn init_migration_contains_auth_tables() {
        let sql = migrations::INIT.sql;
        for table in super::REQUIRED_TABLES.iter().copied().filter(|table| {
            !table.starts_with("zeroth_passkey_")
                && *table != "zeroth_admin_memberships"
                && *table != "zeroth_local_credentials"
                && *table != "zeroth_magic_links"
                && *table != "zeroth_wallet_challenges"
                && *table != "zeroth_rate_limits"
                && *table != "zeroth_account_identities"
                && *table != "zeroth_audit_outbox"
                && *table != "zeroth_audit_consumers"
        }) {
            assert!(sql.contains(table), "missing table {table}");
        }
    }

    #[test]
    fn passkey_migration_contains_passkey_tables() {
        let sql = migrations::PASSKEYS.sql;

        for table in ["zeroth_passkey_credentials", "zeroth_passkey_challenges"] {
            assert!(sql.contains(table), "missing table {table}");
        }
        assert_eq!(migrations::ALL.len(), 13);
        assert_eq!(migrations::ALL[1].version, 2);
    }

    #[test]
    fn admin_membership_migration_contains_admin_table() {
        let sql = migrations::ADMIN_MEMBERSHIPS.sql;

        assert!(sql.contains("zeroth_admin_memberships"));
        assert!(sql.contains("granted_by TEXT NOT NULL"));
        assert_eq!(migrations::ALL[2].version, 3);
    }

    #[test]
    fn local_auth_migration_contains_password_and_magic_link_tables() {
        let sql = migrations::LOCAL_AUTH.sql;

        assert!(sql.contains("zeroth_local_credentials"));
        assert!(sql.contains("password_iterations INTEGER NOT NULL"));
        assert!(sql.contains("zeroth_magic_links"));
        assert!(sql.contains("token_hash TEXT PRIMARY KEY"));
        assert_eq!(migrations::ALL[3].version, 4);
    }

    #[test]
    fn account_namespaces_migration_contains_identity_table_and_client_columns() {
        let sql = migrations::ACCOUNT_NAMESPACES.sql;

        assert!(sql.contains("zeroth_account_identities"));
        assert!(sql.contains("account_namespace TEXT NOT NULL"));
        assert!(sql.contains("account_sharing_mode TEXT NOT NULL DEFAULT 'global'"));
        assert!(sql.contains("account_tenant_id TEXT NOT NULL DEFAULT 'global'"));
        assert!(sql.contains("INSERT OR IGNORE INTO zeroth_account_identities"));
        assert_eq!(migrations::ALL.len(), 13);
        assert_eq!(migrations::ALL[4].version, 5);
    }

    #[test]
    fn wallet_auth_migration_contains_wallet_challenge_table() {
        let sql = migrations::WALLET_AUTH.sql;

        assert!(sql.contains("zeroth_wallet_challenges"));
        assert!(sql.contains("challenge_hash TEXT PRIMARY KEY"));
        assert!(sql.contains("account_namespace TEXT NOT NULL"));
        assert_eq!(migrations::ALL.len(), 13);
        assert_eq!(migrations::ALL[5].version, 6);
    }

    #[test]
    fn client_login_methods_migration_contains_visibility_column() {
        let sql = migrations::CLIENT_LOGIN_METHODS.sql;

        assert!(sql.contains("visible_login_methods_json TEXT NOT NULL DEFAULT '[]'"));
        assert_eq!(migrations::ALL.len(), 13);
        assert_eq!(migrations::ALL[6].version, 7);
    }

    #[test]
    fn passkey_metadata_migration_captures_discoverable_credential_state() {
        let sql = migrations::PASSKEY_METADATA.sql;

        assert!(sql.contains("passkey_user_handle TEXT"));
        assert!(sql.contains("user_handle TEXT"));
        assert!(sql.contains("transports_json TEXT NOT NULL DEFAULT '[]'"));
        assert!(sql.contains("backup_eligible INTEGER NOT NULL DEFAULT 0"));
        assert!(sql.contains("backup_state INTEGER NOT NULL DEFAULT 0"));
        assert_eq!(migrations::ALL[10].version, 11);
    }

    #[test]
    fn password_hashing_migration_contains_password_columns() {
        let sql = migrations::PASSWORD_HASHING.sql;

        assert!(sql.contains("zeroth_local_credentials"));
        assert!(sql.contains("password_scheme TEXT NOT NULL DEFAULT 'pbkdf2-sha256'"));
        assert!(sql.contains("password_params_json TEXT NOT NULL DEFAULT '{}'"));
        assert!(sql.contains("password_version INTEGER NOT NULL DEFAULT 1"));
        assert_eq!(migrations::ALL[7].version, 8);
    }

    #[test]
    fn rate_limits_migration_contains_counter_table() {
        let sql = migrations::RATE_LIMITS.sql;

        assert!(sql.contains("CREATE TABLE IF NOT EXISTS zeroth_rate_limits"));
        assert!(sql.contains("PRIMARY KEY (scope, subject_hash, bucket_start)"));
        assert!(sql.contains("idx_zeroth_rate_limits_updated_at"));
        assert_eq!(migrations::ALL[8].version, 9);
    }

    #[test]
    fn magic_link_poll_migration_uses_an_opaque_unique_token() {
        let sql = migrations::MAGIC_LINK_POLL_TOKEN.sql;

        assert!(sql.contains("poll_token_hash TEXT"));
        assert!(sql.contains("consumed_session_id TEXT"));
        assert!(sql.contains("CREATE UNIQUE INDEX"));
        assert_eq!(migrations::ALL[9].version, 10);
    }

    #[test]
    fn schema_migrations_table_sql_is_exported_for_bootstrap() {
        assert!(super::SCHEMA_MIGRATIONS_CREATE_SQL
            .starts_with("CREATE TABLE IF NOT EXISTS zeroth_schema_migrations"));
        assert!(super::SCHEMA_MIGRATIONS_CREATE_SQL.contains("version INTEGER PRIMARY KEY"));
        assert!(super::SCHEMA_MIGRATIONS_CREATE_SQL.contains("applied_at INTEGER NOT NULL"));
    }

    #[test]
    fn init_migration_carries_session_id_for_token_families() {
        let sql = migrations::INIT.sql;

        assert!(
            sql.contains(
                "CREATE TABLE IF NOT EXISTS zeroth_auth_codes (\n    code_hash TEXT PRIMARY KEY,"
            ),
            "missing auth-code table definition"
        );
        assert!(
            sql.contains(
                "user_id TEXT NOT NULL,\n    session_id TEXT,\n    auth_time INTEGER,\n    nonce TEXT,"
            ),
            "auth codes must persist the browser session id and auth_time"
        );
        assert!(
            sql.contains("zeroth_refresh_tokens")
                && sql.contains("session_id TEXT,\n    auth_time INTEGER,"),
            "refresh tokens must persist the browser session id and auth_time"
        );
    }

    #[test]
    fn init_migration_splits_into_executable_statements() {
        let statements = migrations::INIT.statements().collect::<Vec<_>>();

        assert!(!statements.is_empty());
        assert!(statements
            .iter()
            .any(|statement| statement.starts_with("CREATE TABLE IF NOT EXISTS zeroth_users")));
        assert!(statements
            .iter()
            .any(|statement| statement.starts_with("CREATE INDEX IF NOT EXISTS")));
        assert!(statements
            .iter()
            .all(|statement| !statement.ends_with(';') && !statement.trim().is_empty()));
    }

    #[test]
    fn compatibility_columns_cover_incremental_d1_upgrades() {
        assert!(compatibility::TABLES.contains(&"zeroth_auth_transactions"));
        assert!(compatibility::TABLES.contains(&"zeroth_auth_codes"));
        assert!(compatibility::TABLES.contains(&"zeroth_refresh_tokens"));
        assert!(compatibility::TABLES.contains(&"zeroth_clients"));
        assert!(compatibility::TABLES.contains(&"zeroth_sessions"));

        for column in [
            "allowed_email_domains_json",
            "account_sharing_mode",
            "account_tenant_id",
            "visible_login_methods_json",
            "provider_nonce",
            "link_user_id",
            "link_session_id",
            "session_return_to",
            "session_id",
            "auth_time",
            "enterprise_provider",
            "auth_provider",
            "auth_policy_hash",
            "provider_policy_hash",
            "provider_code_verifier",
        ] {
            assert!(
                compatibility::ALL
                    .iter()
                    .any(|compat| compat.name == column),
                "missing compatibility column {column}"
            );
        }
        assert_eq!(
            compatibility::AUTH_CODE_AUTH_TIME.alter_table_sql(),
            "ALTER TABLE zeroth_auth_codes ADD COLUMN auth_time INTEGER"
        );
    }

    const ENTERPRISE_COLUMNS: &[(&str, &str)] = &[
        ("zeroth_clients", "enterprise_provider"),
        ("zeroth_sessions", "auth_provider"),
        ("zeroth_sessions", "auth_policy_hash"),
        ("zeroth_auth_codes", "auth_provider"),
        ("zeroth_auth_codes", "auth_policy_hash"),
        ("zeroth_refresh_tokens", "auth_provider"),
        ("zeroth_refresh_tokens", "auth_policy_hash"),
        ("zeroth_auth_transactions", "provider_policy_hash"),
        ("zeroth_auth_transactions", "provider_code_verifier"),
    ];

    fn database_before_enterprise_migration() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in migrations::ALL
            .iter()
            .filter(|migration| migration.version < 12)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn
    }

    fn assert_enterprise_columns_are_nullable_text(conn: &Connection) {
        for &(table, column) in ENTERPRISE_COLUMNS {
            let (column_type, not_null, default_value): (String, i32, Option<String>) = conn
                .query_row(
                    "SELECT type, [notnull], dflt_value FROM pragma_table_info(?) WHERE name = ?",
                    params![table, column],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(column_type, "TEXT", "{table}.{column}");
            assert_eq!(not_null, 0, "{table}.{column}");
            assert!(
                default_value.is_none(),
                "{table}.{column} must not infer old authentication proof"
            );
        }
    }

    #[test]
    fn enterprise_migration_upgrades_legacy_credentials_without_inventing_proof() {
        let conn = database_before_enterprise_migration();
        conn.execute_batch(
            "INSERT INTO zeroth_users (id, primary_email, created_at, updated_at)
             VALUES ('user', 'user@example.com', 100, 100);
             INSERT INTO zeroth_clients (id, name, redirect_uris_json, created_at, updated_at)
             VALUES ('client', 'Client', '[\"https://app.example.com/callback\"]', 100, 100);
             INSERT INTO zeroth_sessions (id, user_id, client_id, created_at, expires_at)
             VALUES ('session', 'user', 'client', 100, 200);
             INSERT INTO zeroth_auth_codes (code_hash, client_id, redirect_uri, user_id, scope, created_at, expires_at)
             VALUES ('code', 'client', 'https://app.example.com/callback', 'user', 'openid', 100, 200);
             INSERT INTO zeroth_refresh_tokens (token_hash, client_id, user_id, scope, created_at, expires_at)
             VALUES ('refresh', 'client', 'user', 'openid offline_access', 100, 200);
             INSERT INTO zeroth_auth_transactions (provider_state, client_id, provider_id, redirect_uri, provider_redirect_uri, scope, created_at, expires_at)
             VALUES ('state', 'client', 'google', 'https://app.example.com/callback', 'https://id.example.com/oauth2/callback', 'openid', 100, 200);"
        ).unwrap();

        for statement in migrations::ENTERPRISE_AUTH_POLICY.statements() {
            conn.execute(statement, []).unwrap();
        }
        assert_enterprise_columns_are_nullable_text(&conn);
        for &(table, column) in ENTERPRISE_COLUMNS {
            let value: Option<String> = conn
                .query_row(&format!("SELECT {column} FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert!(
                value.is_none(),
                "existing {table}.{column} must stay unverified"
            );
        }
        let provider: String = conn
            .query_row(
                "SELECT provider_id FROM zeroth_auth_transactions WHERE provider_state = 'state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(provider, "google");

        conn.execute(
            "UPDATE zeroth_clients SET enterprise_provider = 'entra' WHERE id = 'client'",
            [],
        )
        .unwrap();
        for table in [
            "zeroth_sessions",
            "zeroth_auth_codes",
            "zeroth_refresh_tokens",
        ] {
            conn.execute(
                &format!("UPDATE {table} SET auth_provider = ?, auth_policy_hash = ?"),
                params!["entra", "sha256:provider-policy"],
            )
            .unwrap();
            let proof: (String, String) = conn
                .query_row(
                    &format!("SELECT auth_provider, auth_policy_hash FROM {table}"),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                proof,
                ("entra".to_owned(), "sha256:provider-policy".to_owned())
            );
        }
        conn.execute("UPDATE zeroth_auth_transactions SET provider_policy_hash = ?, provider_code_verifier = ? WHERE provider_state = 'state'",
            params!["sha256:provider-policy", "transaction-specific-pkce-verifier"],
        ).unwrap();
        let transaction_proof: (String, String) = conn.query_row(
            "SELECT provider_policy_hash, provider_code_verifier FROM zeroth_auth_transactions WHERE provider_state = 'state'", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(
            transaction_proof,
            (
                "sha256:provider-policy".to_owned(),
                "transaction-specific-pkce-verifier".to_owned()
            )
        );
    }

    #[test]
    fn complete_migration_chain_contains_enterprise_provenance() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in migrations::ALL {
            conn.execute_batch(migration.sql).unwrap();
        }
        assert_eq!(migrations::ALL.last().unwrap().version, 13);
        assert_enterprise_columns_are_nullable_text(&conn);
        for &(table, name) in ENTERPRISE_COLUMNS {
            assert!(compatibility::TABLES.contains(&table));
            assert!(
                compatibility::ALL
                    .iter()
                    .any(|column| column.table == table && column.name == name),
                "schema inspection/repair must cover {table}.{name}"
            );
        }
    }

    #[test]
    fn compatibility_repair_adds_missing_enterprise_columns() {
        let conn = database_before_enterprise_migration();
        for &(table, name) in ENTERPRISE_COLUMNS {
            let column = compatibility::ALL
                .iter()
                .find(|column| column.table == table && column.name == name)
                .unwrap();
            conn.execute(&column.alter_table_sql(), []).unwrap();
        }
        assert_enterprise_columns_are_nullable_text(&conn);
    }

    #[test]
    fn audit_history_upgrade_preserves_legacy_uncertainty() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in migrations::ALL
            .iter()
            .filter(|migration| migration.version < 13)
        {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute("INSERT INTO zeroth_audit_events (id, event_type, user_id, client_id, created_at, details_json) VALUES ('legacy', 'session.login', 'user', 'client', 100, '{}')", []).unwrap();
        for statement in migrations::AUDIT_HISTORY.statements() {
            conn.execute(statement, []).unwrap();
        }
        let legacy: (i32, String, Option<String>, Option<String>, Option<String>, Option<i64>, Option<String>) = conn.query_row(
            "SELECT schema_version, outcome, organization_id, actor_id, target_id, recorded_at, event_json FROM zeroth_audit_events WHERE id = 'legacy'", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).unwrap();
        assert_eq!(
            legacy,
            (0, "unknown".to_owned(), None, None, None, None, None)
        );
        let outbox_count: i32 = conn
            .query_row("SELECT COUNT(*) FROM zeroth_audit_outbox", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(outbox_count, 0);
        for name in [
            "schema_version",
            "organization_id",
            "actor_type",
            "actor_id",
            "target_type",
            "target_id",
            "outcome",
            "reason_code",
            "request_id",
            "recorded_at",
            "event_json",
        ] {
            assert!(compatibility::ALL
                .iter()
                .any(|column| column.table == "zeroth_audit_events" && column.name == name));
        }
        assert!(super::REQUIRED_TABLES.contains(&"zeroth_audit_outbox"));
        assert!(super::REQUIRED_TABLES.contains(&"zeroth_audit_consumers"));
    }

    #[test]
    fn audit_schema_retains_history_and_outbox_when_subject_user_is_deleted() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        for migration in migrations::ALL {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute(
            "INSERT INTO zeroth_users (id, created_at, updated_at) VALUES ('user', 1, 1)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO zeroth_audit_events (id, event_type, user_id, actor_type, actor_id, target_type, target_id, created_at, details_json) VALUES ('event', 'account.delete', 'user', 'user', 'user', 'user', 'user', 100, '{}')", []).unwrap();
        conn.execute("INSERT INTO zeroth_audit_outbox (event_id, event_json, created_at) VALUES ('event', '{}', 100)", []).unwrap();
        conn.execute("DELETE FROM zeroth_users WHERE id = 'user'", [])
            .unwrap();
        let retained: (String, String) = conn
            .query_row(
                "SELECT actor_id, target_id FROM zeroth_audit_events WHERE id = 'event'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained, ("user".to_owned(), "user".to_owned()));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM zeroth_audit_outbox WHERE event_id = 'event'",
                [],
                |row| row.get::<_, i32>(0)
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn audit_outbox_deduplicates_event_ids_and_does_not_reuse_delivery_sequences() {
        let conn = Connection::open_in_memory().unwrap();
        for migration in migrations::ALL {
            conn.execute_batch(migration.sql).unwrap();
        }
        conn.execute("INSERT INTO zeroth_audit_outbox (event_id, event_json, created_at) VALUES ('event', '{}', 1)", []).unwrap();
        assert!(conn.execute("INSERT INTO zeroth_audit_outbox (event_id, event_json, created_at) VALUES ('event', '{}', 1)", []).is_err());
        let first: i64 = conn
            .query_row("SELECT sequence FROM zeroth_audit_outbox", [], |row| {
                row.get(0)
            })
            .unwrap();
        conn.execute("DELETE FROM zeroth_audit_outbox", []).unwrap();
        conn.execute("INSERT INTO zeroth_audit_outbox (event_id, event_json, created_at) VALUES ('next', '{}', 2)", []).unwrap();
        let next: i64 = conn
            .query_row("SELECT sequence FROM zeroth_audit_outbox", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(next > first);
        conn.execute(
            "INSERT INTO zeroth_audit_consumers (id, updated_at) VALUES ('collector', 2)",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT last_sequence FROM zeroth_audit_consumers",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}
