//! Optional native PostgreSQL delivery sink. This is not the application's
//! transactional outbox and is not required by the Worker/D1 deployment.

use crate::{AppendResult, AuditError, AuditEvent, AuditFuture, AuditSink};
use tokio_postgres::{
    config::{Host, SslMode},
    Client, Config,
};
use tokio_postgres_rustls::MakeRustlsConnect;

pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const APPEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Run with a migration/owner role, then grant the runtime role only SELECT and
/// INSERT. DELETE belongs to a separate authorized retention job, never account
/// deletion. This schema does not itself provide cryptographic integrity.
pub const CREATE_TABLE_SQL: &str = "\
CREATE TABLE IF NOT EXISTS zeroth_audit_sink_events (
    event_id TEXT PRIMARY KEY,
    organization_id TEXT,
    occurred_at BIGINT NOT NULL,
    recorded_at BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    event_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_zeroth_audit_sink_events_scope_time
    ON zeroth_audit_sink_events (organization_id, recorded_at DESC, event_id DESC)";

pub const INSERT_EVENT_SQL: &str = "\
INSERT INTO zeroth_audit_sink_events
    (event_id, organization_id, occurred_at, recorded_at, event_type, outcome, event_json)
VALUES ($1, $2, $3, $4, $5, $6, $7::text::jsonb)
ON CONFLICT (event_id) DO NOTHING
RETURNING event_id";

pub const GET_EVENT_SQL: &str = "\
SELECT event_json::text FROM zeroth_audit_sink_events WHERE event_id = $1";

pub struct PostgresAuditSink {
    client: Client,
}

impl PostgresAuditSink {
    /// Connect with certificate and hostname verification using the operating
    /// system's roots. sslmode=disable/prefer cannot enable plaintext fallback.
    /// Requires an active Tokio runtime. The spawned connection task exits when
    /// the sink is dropped; delivery failures are returned by append.
    pub async fn connect(connection_string: &str) -> Result<Self, AuditError> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert).map_err(|_| AuditError::TlsConfiguration)?;
        }
        Self::connect_with_roots(connection_string, roots).await
    }

    /// Supply an explicit CA trust store for private PostgreSQL deployments.
    /// No API accepts NoTls or a certificate-verification bypass.
    pub async fn connect_with_roots(
        connection_string: &str,
        roots: rustls::RootCertStore,
    ) -> Result<Self, AuditError> {
        if roots.is_empty() {
            return Err(AuditError::TlsConfiguration);
        }
        let config = tls_required_config(connection_string)?;
        let tls_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| AuditError::TlsConfiguration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let (client, connection) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            config.connect(MakeRustlsConnect::new(tls_config)),
        )
        .await
        .map_err(|_| AuditError::Storage)?
        .map_err(|_| AuditError::Storage)?;
        tokio::spawn(async move {
            if connection.await.is_err() {
                tracing::error!(target: "zeroth.audit_delivery", sink = "postgres", error_code = "connection_closed", "audit sink connection closed");
            }
        });
        Ok(Self { client })
    }

    /// Explicit initialization, suitable for deployment tooling. Runtime append
    /// does not create tables or require schema ownership.
    pub async fn initialize(&self) -> Result<(), AuditError> {
        tokio::time::timeout(APPEND_TIMEOUT, self.client.batch_execute(CREATE_TABLE_SQL))
            .await
            .map_err(|_| AuditError::Storage)?
            .map_err(|_| AuditError::Storage)
    }
}

fn tls_required_config(connection_string: &str) -> Result<Config, AuditError> {
    let mut config: Config = connection_string
        .parse()
        .map_err(|_| AuditError::TlsConfiguration)?;
    // Unix sockets skip TLS in tokio-postgres; this sink is intentionally TLS-only.
    if config.get_hosts().is_empty()
        || config
            .get_hosts()
            .iter()
            .any(|host| !matches!(host, Host::Tcp(_)))
    {
        return Err(AuditError::TlsConfiguration);
    }
    config.ssl_mode(SslMode::Require);
    config.connect_timeout(CONNECT_TIMEOUT);
    config.ssl_negotiation(tokio_postgres::config::SslNegotiation::Postgres);
    Ok(config)
}

impl AuditSink for PostgresAuditSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        Box::pin(async move {
            let serialized = event.canonical_json()?;
            tokio::time::timeout(APPEND_TIMEOUT, async {
                let outcome = event.outcome.as_str();
                let inserted = self
                    .client
                    .query_opt(
                        INSERT_EVENT_SQL,
                        &[
                            &event.event_id,
                            &event.organization_id,
                            &event.occurred_at,
                            &event.recorded_at,
                            &event.event_type,
                            &outcome,
                            &serialized,
                        ],
                    )
                    .await
                    .map_err(|_| AuditError::Storage)?;
                if inserted.is_some() {
                    return Ok(AppendResult::Inserted);
                }
                // Use a separate statement/snapshot: a concurrent INSERT that made
                // ON CONFLICT wait may be invisible to a single-statement CTE SELECT.
                let row = self
                    .client
                    .query_opt(GET_EVENT_SQL, &[&event.event_id])
                    .await
                    .map_err(|_| AuditError::Storage)?
                    .ok_or(AuditError::Storage)?;
                let stored: String = row.try_get(0).map_err(|_| AuditError::Storage)?;
                compare_stored_event(&stored, &serialized)
            })
            .await
            .map_err(|_| AuditError::Storage)?
        })
    }
}

fn compare_stored_event(stored: &str, incoming: &str) -> Result<AppendResult, AuditError> {
    let stored: serde_json::Value =
        serde_json::from_str(stored).map_err(|_| AuditError::Storage)?;
    let incoming: serde_json::Value =
        serde_json::from_str(incoming).map_err(|_| AuditError::Serialization)?;
    if stored == incoming {
        Ok(AppendResult::Duplicate)
    } else {
        Err(AuditError::EventIdCollision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_jsonb_retry_is_duplicate_but_changed_content_collides() {
        assert_eq!(
            compare_stored_event(
                r#"{"event_id":"evt_1","outcome":"success"}"#,
                r#"{ "outcome": "success", "event_id": "evt_1" }"#
            ),
            Ok(AppendResult::Duplicate)
        );
        assert_eq!(
            compare_stored_event(
                r#"{"event_id":"evt_1","outcome":"success"}"#,
                r#"{"event_id":"evt_1","outcome":"denied"}"#
            ),
            Err(AuditError::EventIdCollision)
        );
    }

    #[test]
    fn sql_is_parameterized_append_only_and_uses_stable_identity() {
        assert!(CREATE_TABLE_SQL.contains("event_id TEXT PRIMARY KEY"));
        assert!(CREATE_TABLE_SQL.contains("occurred_at BIGINT"));
        assert!(CREATE_TABLE_SQL.contains("organization_id, recorded_at DESC, event_id DESC"));
        assert!(INSERT_EVENT_SQL.contains("ON CONFLICT (event_id) DO NOTHING"));
        assert!(!INSERT_EVENT_SQL.contains("UPDATE"));
        for parameter in 1..=7 {
            assert!(INSERT_EVENT_SQL.contains(&format!("${parameter}")));
        }
        assert!(GET_EVENT_SQL.ends_with("WHERE event_id = $1"));
    }

    #[test]
    fn config_never_falls_back_to_plaintext_or_unix_sockets() {
        for mode in ["disable", "prefer", "require"] {
            let config =
                tls_required_config(&format!("host=db.example.com user=auditor sslmode={mode}"))
                    .unwrap();
            assert_eq!(config.get_ssl_mode(), SslMode::Require);
        }
        assert_eq!(
            tls_required_config("host=/tmp user=auditor").unwrap_err(),
            AuditError::TlsConfiguration
        );
        assert_eq!(
            tls_required_config("user=auditor").unwrap_err(),
            AuditError::TlsConfiguration
        );
    }
}
