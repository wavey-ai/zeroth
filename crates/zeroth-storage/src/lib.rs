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
    pub const REFRESH_TOKEN_AUTH_TIME: CompatibilityColumn = CompatibilityColumn {
        table: "zeroth_refresh_tokens",
        name: "auth_time",
        definition: "INTEGER",
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

    pub const TABLES: &[&str] = &[
        "zeroth_clients",
        "zeroth_auth_transactions",
        "zeroth_auth_codes",
        "zeroth_refresh_tokens",
    ];

    pub const ALL: &[CompatibilityColumn] = &[
        CLIENT_ALLOWED_EMAIL_DOMAINS,
        CLIENT_ISSUER_TOKEN_AUDIENCE,
        CLIENT_ISSUER_TOKEN_TTL_SECONDS,
        CLIENT_ACCOUNT_SHARING_MODE,
        CLIENT_ACCOUNT_TENANT_ID,
        CLIENT_VISIBLE_LOGIN_METHODS,
        AUTH_TRANSACTION_PROVIDER_NONCE,
        AUTH_TRANSACTION_LINK_USER_ID,
        AUTH_TRANSACTION_LINK_SESSION_ID,
        AUTH_TRANSACTION_SESSION_RETURN_TO,
        AUTH_CODE_SESSION_ID,
        AUTH_CODE_AUTH_TIME,
        REFRESH_TOKEN_AUTH_TIME,
    ];
}

#[cfg(test)]
mod tests {
    use super::{compatibility, migrations};

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
        assert_eq!(migrations::ALL.len(), 11);
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
        assert_eq!(migrations::ALL.len(), 11);
        assert_eq!(migrations::ALL[4].version, 5);
    }

    #[test]
    fn wallet_auth_migration_contains_wallet_challenge_table() {
        let sql = migrations::WALLET_AUTH.sql;

        assert!(sql.contains("zeroth_wallet_challenges"));
        assert!(sql.contains("challenge_hash TEXT PRIMARY KEY"));
        assert!(sql.contains("account_namespace TEXT NOT NULL"));
        assert_eq!(migrations::ALL.len(), 11);
        assert_eq!(migrations::ALL[5].version, 6);
    }

    #[test]
    fn client_login_methods_migration_contains_visibility_column() {
        let sql = migrations::CLIENT_LOGIN_METHODS.sql;

        assert!(sql.contains("visible_login_methods_json TEXT NOT NULL DEFAULT '[]'"));
        assert_eq!(migrations::ALL.len(), 11);
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
}
