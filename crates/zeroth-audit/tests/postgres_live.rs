//! Explicit local integration probe. Use an isolated PostgreSQL database whose
//! TCP rules require TLS, with a private test CA not in the OS root store.
//! No server is started and no credentials are discovered by this test.
#![cfg(all(feature = "postgres", not(target_arch = "wasm32")))]

use std::{future::Future, task::Poll};
use zeroth_audit::{
    postgres::PostgresAuditSink, AppendResult, AuditActor, AuditError, AuditEvent, AuditOutcome,
    AuditSink,
};

fn roots(path: &str) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            std::fs::read(path).expect("read test CA DER"),
        ))
        .expect("valid test CA");
    roots
}

async fn concurrently<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (Box::pin(a), Box::pin(b));
    let (mut result_a, mut result_b) = (None, None);
    std::future::poll_fn(|context| {
        if result_a.is_none() {
            if let Poll::Ready(value) = a.as_mut().poll(context) {
                result_a = Some(value);
            }
        }
        if result_b.is_none() {
            if let Poll::Ready(value) = b.as_mut().poll(context) {
                result_b = Some(value);
            }
        }
        if result_a.is_some() && result_b.is_some() {
            Poll::Ready((result_a.take().unwrap(), result_b.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

#[test]
#[ignore = "requires an isolated TLS-only PostgreSQL server and private test CA"]
fn tls_archive_exact_retries_and_concurrent_conflicts() {
    // Libpq key-value format permits an explicit duplicate sslmode below. Do
    // not print the connection string: it may contain test credentials.
    let connection = std::env::var("ZEROTH_AUDIT_POSTGRES_TEST_URL")
        .expect("set test database key-value connection string");
    let ca_path =
        std::env::var("ZEROTH_AUDIT_POSTGRES_TEST_CA_DER").expect("set private test CA DER path");
    assert!(
        !connection.starts_with("postgres://") && !connection.starts_with("postgresql://"),
        "test connection must use libpq key-value format"
    );
    let connection = format!("{connection} sslmode=disable");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(matches!(
            PostgresAuditSink::connect(&connection).await,
            Err(AuditError::Storage)
        ));
        let first = PostgresAuditSink::connect_with_roots(&connection, roots(&ca_path))
            .await
            .unwrap();
        let second = PostgresAuditSink::connect_with_roots(&connection, roots(&ca_path))
            .await
            .unwrap();
        // A TLS-only server accepts this despite requested sslmode=disable:
        // the adapter forced verified TLS rather than plaintext fallback.
        first.initialize().await.unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let event = AuditEvent::new(
            format!("evt_pg_{unique}"),
            4_000_000_000,
            4_000_000_001,
            "session.create",
            AuditActor::new("user", "usr_pg").unwrap(),
            AuditOutcome::Success,
        )
        .unwrap();
        assert_eq!(first.append(&event).await, Ok(AppendResult::Inserted));
        assert_eq!(second.append(&event).await, Ok(AppendResult::Duplicate));
        let mut collision = event.clone();
        collision.outcome = AuditOutcome::Denied;
        assert_eq!(
            second.append(&collision).await,
            Err(AuditError::EventIdCollision)
        );
        for number in 0..25 {
            let mut racing = event.clone();
            racing.event_id = format!("evt_pg_{unique}_race_{number}");
            let results = concurrently(first.append(&racing), second.append(&racing)).await;
            assert!(matches!(
                results,
                (Ok(AppendResult::Inserted), Ok(AppendResult::Duplicate))
                    | (Ok(AppendResult::Duplicate), Ok(AppendResult::Inserted))
            ));
        }
        let mut invalid = event;
        invalid.actor.id = Some("person@example.com".into());
        assert_eq!(
            first.append(&invalid).await,
            Err(AuditError::InvalidField("actor.id"))
        );
    });
}
