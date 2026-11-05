use super::*;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

fn event() -> AuditEvent {
    AuditEvent::new(
        "evt_one",
        4_000_000_000,
        4_000_000_001,
        "session.create",
        AuditActor::new("user", "usr_123").unwrap(),
        AuditOutcome::Success,
    )
    .unwrap()
}

#[test]
fn envelope_round_trip_preserves_actor_targets_scope_and_post_2038_time() {
    let mut event = event();
    event.organization_id = Some("org_acme".into());
    event
        .targets
        .push(AuditTarget::new("session", "ses_456").unwrap());
    event.client_id = Some("client_abc".into());
    event.provider_id = Some("entra".into());
    event.correlation_id = Some("request_789".into());
    event.policy_reference = Some("sha256:abcd".into());
    event
        .details
        .insert(DetailKey::HttpStatus, DetailValue::Integer(200))
        .unwrap();
    let json = event.canonical_json().unwrap();
    let restored: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, event);
    assert_eq!(restored.recorded_at, 4_000_000_001);
    assert_eq!(restored.actor.id.as_deref(), Some("usr_123"));
    assert_eq!(restored.targets[0].id, "ses_456");
    assert_eq!(restored.canonical_json().unwrap(), json);
}

#[test]
fn malformed_scope_identity_version_and_times_are_rejected() {
    let mut event = event();
    event.schema_version = 99;
    assert_eq!(event.validate(), Err(AuditError::UnsupportedVersion));
    event.schema_version = AUDIT_SCHEMA_VERSION;
    event.occurred_at = -1;
    assert_eq!(
        event.validate(),
        Err(AuditError::InvalidField("timestamps"))
    );
    event.occurred_at = event.recorded_at + 1;
    assert_eq!(
        event.validate(),
        Err(AuditError::InvalidField("timestamps"))
    );
    event.occurred_at = 1;
    for bad in [
        "",
        "org\nother",
        "person@example.com",
        "org acme",
        "https://tenant.example",
    ] {
        event.organization_id = Some(bad.into());
        assert_eq!(
            event.validate(),
            Err(AuditError::InvalidField("organization_id"))
        );
    }
    event.organization_id = None;
    event.event_type = "session.create\nspoof.success".into();
    assert_eq!(
        event.validate(),
        Err(AuditError::InvalidField("event_type"))
    );
}

#[test]
fn actor_cannot_impersonate_anonymous_with_an_id_or_omit_nonanonymous_identity() {
    let mut event = event();
    event.actor = AuditActor::anonymous();
    assert!(event.validate().is_ok());
    event.actor.id = Some("usr_other".into());
    assert_eq!(event.validate(), Err(AuditError::InvalidField("actor.id")));
    event.actor.kind = "user".into();
    event.actor.id = None;
    assert_eq!(event.validate(), Err(AuditError::InvalidField("actor.id")));
    assert!(AuditActor::new("person@example.com", "usr_1").is_err());
}

#[test]
fn explicit_unknown_outcome_does_not_become_success() {
    let mut event = event();
    event.outcome = AuditOutcome::Unknown;
    let value: serde_json::Value = serde_json::from_str(&event.canonical_json().unwrap()).unwrap();
    assert_eq!(value["outcome"], "unknown");
    assert_eq!(AuditOutcome::Unknown.as_str(), "unknown");
}

#[test]
fn legacy_detail_allowlist_drops_pii_secrets_raw_errors_and_wrong_types() {
    let input = serde_json::json!({
        "email": "person@example.com", "authorization": "Bearer secret-token",
        "password": "password-secret", "access_token": "jwt-secret", "client_secret": "client-secret",
        "idToken": "id-token-secret", "url": "https://example.com?token=secret",
        "description": "Password reset for person@example.com failed",
        "error": "provider secret raw error", "code": "invalid_grant",
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange", "httpStatus": 400,
        "retryable": true, "count": "forty", "authenticationMethod": "entra",
        "changedFields": ["admin", "disabled"]
    });
    let details = SafeDetails::from_json_allowlisted(&input);
    let json = serde_json::to_string(&details).unwrap();
    assert_eq!(
        details.get(DetailKey::GrantType),
        Some(&DetailValue::Code("token_exchange".into()))
    );
    assert_eq!(
        details.get(DetailKey::HttpStatus),
        Some(&DetailValue::Integer(400))
    );
    assert_eq!(
        details.get(DetailKey::ErrorCode),
        Some(&DetailValue::Code("invalid_grant".into()))
    );
    assert!(details.get(DetailKey::Count).is_none());
    for forbidden in [
        "person@example.com",
        "secret",
        "Password",
        "provider secret",
        "https:",
    ] {
        assert!(!json.contains(forbidden));
    }
    assert!(details.validate().is_ok());
}

#[test]
fn detail_types_codes_and_deserialized_values_are_validated() {
    let mut details = SafeDetails::new();
    for (key, value) in [
        (DetailKey::HttpStatus, DetailValue::Integer(900)),
        (
            DetailKey::ErrorCode,
            DetailValue::Code("Bearer secret-token".into()),
        ),
        (
            DetailKey::AuthenticationMethod,
            DetailValue::Code("person@example.com".into()),
        ),
        (DetailKey::Count, DetailValue::Integer(-1)),
        (
            DetailKey::ChangedFields,
            DetailValue::Codes(vec!["password=secret".into()]),
        ),
        (
            DetailKey::Source,
            DetailValue::Code("https://evil.example".into()),
        ),
    ] {
        assert_eq!(details.insert(key, value), Err(AuditError::InvalidDetail));
    }
    assert!(serde_json::from_str::<SafeDetails>(r#"{"password":"secret"}"#).is_err());
    let invalid: SafeDetails =
        serde_json::from_str(r#"{"error_code":"person@example.com"}"#).unwrap();
    let mut event = event();
    event.details = invalid;
    assert_eq!(event.canonical_json(), Err(AuditError::InvalidDetail));
    assert!(SafeDetails::from_json_allowlisted(
        &serde_json::json!({"errorCode": "provider description with secret"})
    )
    .get(DetailKey::ErrorCode)
    .is_none());
}

#[test]
fn policy_evidence_accepts_only_hex_hashes_safe_providers_and_boolean_flags() {
    let hash = "0abcdef123456789".repeat(4);
    let details = SafeDetails::from_json_allowlisted(&serde_json::json!({
        "previousPolicyHash": hash,
        "policyHash": "a".repeat(64),
        "beforeProvider": "none", "afterProvider": "entra",
        "confidential": true, "disabled": false, "secretUpdated": true,
        "secret_hash": "never-store-this", "clientSecret": "never-store-this-either"
    }));
    assert_eq!(
        details.get(DetailKey::PreviousPolicyHash),
        Some(&DetailValue::Code(hash))
    );
    assert_eq!(
        details.get(DetailKey::SecretUpdated),
        Some(&DetailValue::Bool(true))
    );
    assert_eq!(
        details.get(DetailKey::AfterProvider),
        Some(&DetailValue::Code("entra".into()))
    );
    let mut invalid = SafeDetails::new();
    for (key, value) in [
        (DetailKey::PolicyHash, DetailValue::Code("short".into())),
        (
            DetailKey::PreviousPolicyHash,
            DetailValue::Code("G".repeat(64)),
        ),
        (
            DetailKey::BeforeProvider,
            DetailValue::Code("arbitrary-idp.example".into()),
        ),
        (
            DetailKey::SecretUpdated,
            DetailValue::Code("new-secret".into()),
        ),
    ] {
        assert_eq!(invalid.insert(key, value), Err(AuditError::InvalidDetail));
    }
    assert!(!serde_json::to_string(&details)
        .unwrap()
        .contains("never-store"));
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);
impl Write for LogBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn tracing_mirror_excludes_actor_targets_details_and_request_identity() {
    let buffer = LogBuffer::default();
    let writer = buffer.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let mut event = event();
    event.actor.id = Some("user_private_identity".into());
    event.organization_id = Some("organization_private_identity".into());
    event
        .targets
        .push(AuditTarget::new("user", "target_private_identity").unwrap());
    event.correlation_id = Some("correlation_private_identity".into());
    event.reason = Some("private_reason".into());
    event
        .details
        .insert(
            DetailKey::ErrorCode,
            DetailValue::Code("private_error_code".into()),
        )
        .unwrap();
    tracing::subscriber::with_default(subscriber, || emit_tracing_mirror(&event).unwrap());
    let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("evt_one"));
    assert!(output.contains("session.create"));
    assert!(output.contains("success"));
    assert!(!output.contains("private"));
}

#[derive(Default)]
struct MemorySink(Mutex<BTreeMap<String, String>>);
impl AuditSink for MemorySink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        Box::pin(async move {
            let json = event.canonical_json()?;
            let mut events = self.0.lock().unwrap();
            match events.get(&event.event_id) {
                Some(stored) if stored == &json => Ok(AppendResult::Duplicate),
                Some(_) => Err(AuditError::EventIdCollision),
                None => {
                    events.insert(event.event_id.clone(), json);
                    Ok(AppendResult::Inserted)
                }
            }
        })
    }
}

fn ready<T>(mut future: Pin<Box<dyn Future<Output = T> + '_>>) -> T {
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test sink should be immediately ready"),
    }
}

#[test]
fn persistence_is_explicit_and_works_when_tracing_is_disabled() {
    let sink = MemorySink::default();
    let mut event = event();
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        assert_eq!(ready(sink.append(&event)), Ok(AppendResult::Inserted));
        emit_tracing_mirror(&event).unwrap();
        assert_eq!(ready(sink.append(&event)), Ok(AppendResult::Duplicate));
        event.outcome = AuditOutcome::Denied;
        assert_eq!(
            ready(sink.append(&event)),
            Err(AuditError::EventIdCollision)
        );
    });
    assert_eq!(sink.0.lock().unwrap().len(), 1);
}

#[test]
fn downstream_issuer_grant_is_retained_without_accepting_unapproved_grant_values() {
    let details = SafeDetails::from_json_allowlisted(&serde_json::json!({
        "grantType": "downstream_issuer", "access_token": "must-not-retain"
    }));
    assert_eq!(
        details.get(DetailKey::GrantType),
        Some(&DetailValue::Code("downstream_issuer".into()))
    );
    assert!(!serde_json::to_string(&details)
        .unwrap()
        .contains("must-not-retain"));
    let invalid =
        SafeDetails::from_json_allowlisted(&serde_json::json!({"grantType":"unapproved-grant"}));
    assert!(invalid.get(DetailKey::GrantType).is_none());
    let mut captured = event();
    captured.event_type = "token.issue".into();
    captured.details = details;
    let restored: AuditEvent = serde_json::from_str(&captured.canonical_json().unwrap()).unwrap();
    assert_eq!(
        restored.details.get(DetailKey::GrantType),
        Some(&DetailValue::Code("downstream_issuer".into()))
    );
}
