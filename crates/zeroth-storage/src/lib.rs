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

    pub const ALL: &[Migration] = &[INIT];
}

pub const REQUIRED_TABLES: &[&str] = &[
    SCHEMA_MIGRATIONS_TABLE,
    "zeroth_users",
    "zeroth_identities",
    "zeroth_clients",
    "zeroth_auth_transactions",
    "zeroth_auth_codes",
    "zeroth_refresh_tokens",
    "zeroth_sessions",
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

    pub const TABLES: &[&str] = &[
        "zeroth_clients",
        "zeroth_auth_transactions",
        "zeroth_auth_codes",
        "zeroth_refresh_tokens",
    ];

    pub const ALL: &[CompatibilityColumn] = &[
        CLIENT_ALLOWED_EMAIL_DOMAINS,
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
        for table in super::REQUIRED_TABLES {
            assert!(sql.contains(table), "missing table {table}");
        }
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
