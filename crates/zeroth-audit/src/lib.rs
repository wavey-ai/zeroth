//! Versioned audit events and explicit asynchronous persistence.
//!
//! Call an [`AuditSink`] directly and handle its result. Tracing is a separate,
//! redacted diagnostic mirror; subscriber filters never control persistence.
//! A remote sink cannot make an application's business mutation atomic: capture
//! an event in the same database transaction as the mutation, then deliver the
//! durable outbox record with the original event ID and timestamps.

use std::{collections::BTreeMap, fmt, future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

#[cfg(all(feature = "postgres", not(target_arch = "wasm32")))]
pub mod postgres;

pub const AUDIT_SCHEMA_VERSION: u16 = 1;
pub const MAX_TARGETS: usize = 16;
pub const MAX_DETAILS_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    InvalidField(&'static str),
    InvalidDetail,
    UnsupportedVersion,
    Serialization,
    Storage,
    EventIdCollision,
    TlsConfiguration,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid audit field: {field}"),
            Self::InvalidDetail => f.write_str("invalid or unapproved audit detail"),
            Self::UnsupportedVersion => f.write_str("unsupported audit schema version"),
            Self::Serialization => f.write_str("could not serialize audit event"),
            Self::Storage => f.write_str("audit persistence failed"),
            Self::EventIdCollision => f.write_str("audit event ID already has different content"),
            Self::TlsConfiguration => f.write_str("audit PostgreSQL TLS configuration failed"),
        }
    }
}

impl std::error::Error for AuditError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Unknown,
    Success,
    Failure,
    Denied,
    Error,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// An opaque internal actor reference. Never put a mailbox, bearer token, raw
/// provider subject or display name in this structure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditActor {
    pub kind: String,
    pub id: Option<String>,
}

impl AuditActor {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Result<Self, AuditError> {
        let actor = Self {
            kind: kind.into(),
            id: Some(id.into()),
        };
        actor.validate()?;
        Ok(actor)
    }

    pub fn anonymous() -> Self {
        Self {
            kind: "anonymous".into(),
            id: None,
        }
    }

    fn validate(&self) -> Result<(), AuditError> {
        if !matches!(
            self.kind.as_str(),
            "user" | "administrator" | "service" | "system" | "anonymous"
        ) {
            return Err(AuditError::InvalidField("actor.kind"));
        }
        if self.kind == "anonymous" {
            if self.id.is_some() {
                return Err(AuditError::InvalidField("actor.id"));
            }
        } else {
            validate_id(
                self.id
                    .as_deref()
                    .ok_or(AuditError::InvalidField("actor.id"))?,
                "actor.id",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTarget {
    pub kind: String,
    pub id: String,
}

impl AuditTarget {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Result<Self, AuditError> {
        let target = Self {
            kind: kind.into(),
            id: id.into(),
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), AuditError> {
        validate_code(&self.kind, 64, "target.kind")?;
        validate_id(&self.id, "target.id")
    }
}

/// Allowed detail names. Free-form metadata is deliberately excluded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailKey {
    GrantType,
    AuthenticationMethod,
    HttpStatus,
    ErrorCode,
    ChangedFields,
    Count,
    Attempt,
    Retryable,
    PolicyChanged,
    PreviousPolicyHash,
    PolicyHash,
    BeforeProvider,
    AfterProvider,
    Confidential,
    Disabled,
    SecretUpdated,
    Source,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DetailValue {
    Bool(bool),
    Integer(i64),
    Code(String),
    Codes(Vec<String>),
}

/// An allowlist reduces accidental disclosure; it cannot detect every secret.
/// In particular, callers must supply machine error codes, never upstream error
/// descriptions, to `ErrorCode`. Strings are bounded ASCII codes, not prose.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SafeDetails(BTreeMap<DetailKey, DetailValue>);

impl SafeDetails {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: DetailKey, value: DetailValue) -> Result<(), AuditError> {
        validate_detail(key, &value)?;
        self.0.insert(key, value);
        self.validate()
    }

    pub fn get(&self, key: DetailKey) -> Option<&DetailValue> {
        self.0.get(&key)
    }

    /// Convert legacy metadata conservatively. Unknown fields (including raw
    /// errors, mailboxes, tokens, URLs and provider descriptions) and values of
    /// the wrong type are dropped. This is an allowlist, not secret detection.
    pub fn from_json_allowlisted(value: &serde_json::Value) -> Self {
        let mut details = Self::new();
        let Some(object) = value.as_object() else {
            return details;
        };
        for (name, value) in object {
            let key = match name.as_str() {
                "grant_type" | "grantType" => DetailKey::GrantType,
                "authentication_method" | "authenticationMethod" => DetailKey::AuthenticationMethod,
                "http_status" | "httpStatus" => DetailKey::HttpStatus,
                "error_code" | "errorCode" | "code" => DetailKey::ErrorCode,
                "changed_fields" | "changedFields" => DetailKey::ChangedFields,
                "count" => DetailKey::Count,
                "attempt" => DetailKey::Attempt,
                "retryable" => DetailKey::Retryable,
                "policy_changed" | "policyChanged" => DetailKey::PolicyChanged,
                "previous_policy_hash" | "previousPolicyHash" => DetailKey::PreviousPolicyHash,
                "policy_hash" | "policyHash" => DetailKey::PolicyHash,
                "before_provider" | "beforeProvider" => DetailKey::BeforeProvider,
                "after_provider" | "afterProvider" => DetailKey::AfterProvider,
                "confidential" => DetailKey::Confidential,
                "disabled" => DetailKey::Disabled,
                "secret_updated" | "secretUpdated" => DetailKey::SecretUpdated,
                "source" => DetailKey::Source,
                _ => continue,
            };
            let candidate = match key {
                DetailKey::Retryable
                | DetailKey::PolicyChanged
                | DetailKey::Confidential
                | DetailKey::Disabled
                | DetailKey::SecretUpdated => value.as_bool().map(DetailValue::Bool),
                DetailKey::HttpStatus | DetailKey::Count | DetailKey::Attempt => {
                    value.as_i64().map(DetailValue::Integer)
                }
                DetailKey::ChangedFields => value
                    .as_array()
                    .and_then(|values| {
                        values
                            .iter()
                            .map(|value| value.as_str().map(str::to_owned))
                            .collect::<Option<Vec<_>>>()
                    })
                    .map(DetailValue::Codes),
                _ => value.as_str().map(|code| {
                    DetailValue::Code(
                        if key == DetailKey::GrantType
                            && code == "urn:ietf:params:oauth:grant-type:token-exchange"
                        {
                            "token_exchange".into()
                        } else {
                            code.into()
                        },
                    )
                }),
            };
            if let Some(candidate) = candidate {
                // Invalid data is discarded without including its value in
                // diagnostics or replacing a valid value with an invalid one.
                let _ = details.insert(key, candidate);
            }
        }
        details
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        for (key, value) in &self.0 {
            validate_detail(*key, value)?;
        }
        if serde_json::to_vec(self)
            .map_err(|_| AuditError::Serialization)?
            .len()
            > MAX_DETAILS_BYTES
        {
            return Err(AuditError::InvalidDetail);
        }
        Ok(())
    }
}

fn validate_detail(key: DetailKey, value: &DetailValue) -> Result<(), AuditError> {
    use DetailKey as K;
    use DetailValue as V;
    let valid = match (key, value) {
        (K::GrantType, V::Code(code)) => matches!(
            code.as_str(),
            "authorization_code" | "refresh_token" | "token_exchange" | "downstream_issuer"
        ),
        (K::AuthenticationMethod, V::Code(code)) => matches!(
            code.as_str(),
            "entra"
                | "google_workspace"
                | "google"
                | "apple"
                | "password"
                | "magic_link"
                | "passkey"
                | "wallet"
                | "session"
                | "bootstrap"
        ),
        (K::HttpStatus, V::Integer(code)) => (100..=599).contains(code),
        (K::Count | K::Attempt, V::Integer(count)) => *count >= 0,
        (
            K::Retryable | K::PolicyChanged | K::Confidential | K::Disabled | K::SecretUpdated,
            V::Bool(_),
        ) => true,
        (K::PreviousPolicyHash | K::PolicyHash, V::Code(hash)) => {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        }
        (K::BeforeProvider | K::AfterProvider, V::Code(code)) => matches!(
            code.as_str(),
            "none" | "entra" | "google_workspace" | "google" | "apple" | "spotify"
        ),
        (K::Source, V::Code(code)) => matches!(
            code.as_str(),
            "browser" | "native" | "api" | "admin" | "system" | "migration"
        ),
        (K::ErrorCode, V::Code(code)) => validate_code(code, 64, "error_code").is_ok(),
        (K::ChangedFields, V::Codes(fields)) => {
            fields.len() <= 16
                && fields.iter().all(|field| {
                    matches!(
                        field.as_str(),
                        "disabled"
                            | "admin"
                            | "redirect_uris"
                            | "allowed_email_domains"
                            | "account_namespace"
                            | "enterprise_provider"
                            | "enterprise_policy"
                            | "login_methods"
                            | "retention"
                            | "credentials"
                            | "display_settings"
                            | "signing_key"
                            | "token_policy"
                            | "stream_configuration"
                    )
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AuditError::InvalidDetail)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub schema_version: u16,
    pub event_id: String,
    pub occurred_at: i64,
    pub recorded_at: i64,
    /// None denotes platform scope. It must never be included in a customer's
    /// organization-scoped query by treating NULL as a wildcard.
    pub organization_id: Option<String>,
    pub actor: AuditActor,
    pub targets: Vec<AuditTarget>,
    pub event_type: String,
    pub outcome: AuditOutcome,
    pub reason: Option<String>,
    pub client_id: Option<String>,
    pub provider_id: Option<String>,
    pub correlation_id: Option<String>,
    pub policy_reference: Option<String>,
    pub details: SafeDetails,
}

impl AuditEvent {
    pub fn new(
        event_id: impl Into<String>,
        occurred_at: i64,
        recorded_at: i64,
        event_type: impl Into<String>,
        actor: AuditActor,
        outcome: AuditOutcome,
    ) -> Result<Self, AuditError> {
        let event = Self {
            schema_version: AUDIT_SCHEMA_VERSION,
            event_id: event_id.into(),
            occurred_at,
            recorded_at,
            organization_id: None,
            actor,
            targets: Vec::new(),
            event_type: event_type.into(),
            outcome,
            reason: None,
            client_id: None,
            provider_id: None,
            correlation_id: None,
            policy_reference: None,
            details: SafeDetails::default(),
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        if self.schema_version != AUDIT_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedVersion);
        }
        validate_id(&self.event_id, "event_id")?;
        if self.occurred_at < 0 || self.recorded_at < self.occurred_at {
            return Err(AuditError::InvalidField("timestamps"));
        }
        self.actor.validate()?;
        if self.targets.len() > MAX_TARGETS {
            return Err(AuditError::InvalidField("targets"));
        }
        for target in &self.targets {
            target.validate()?;
        }
        validate_code(&self.event_type, 96, "event_type")?;
        if let Some(reason) = &self.reason {
            validate_code(reason, 64, "reason")?;
        }
        for (field, value) in [
            ("organization_id", &self.organization_id),
            ("client_id", &self.client_id),
            ("provider_id", &self.provider_id),
            ("correlation_id", &self.correlation_id),
            ("policy_reference", &self.policy_reference),
        ] {
            if let Some(value) = value {
                validate_id(value, field)?;
            }
        }
        self.details.validate()
    }

    /// Stable, validated representation for an outbox and content comparison.
    /// Preserve it unchanged across retries; do not regenerate recorded_at.
    pub fn canonical_json(&self) -> Result<String, AuditError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| AuditError::Serialization)
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':'))
    {
        return Err(AuditError::InvalidField(field));
    }
    Ok(())
}

fn validate_code(value: &str, max_len: usize, field: &'static str) -> Result<(), AuditError> {
    if value.is_empty()
        || value.len() > max_len
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.')
        })
    {
        return Err(AuditError::InvalidField(field));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendResult {
    /// A delivery transport acknowledged receipt. It does not imply permanent
    /// archival, end-to-end processing or content-collision enforcement.
    Accepted,
    Inserted,
    Duplicate,
}

pub type AuditFuture<'a> = Pin<Box<dyn Future<Output = Result<AppendResult, AuditError>> + 'a>>;

/// An explicit, awaited operation. Every implementation validates the event.
/// Archive sinks deduplicate exact retries and reject an ID with new content.
/// Queue transports instead return Accepted and document downstream deduplication
/// requirements; transport acknowledgement is not permanent archival.
/// This future deliberately has no `Send` requirement, so a Worker/D1 adapter
/// can implement the same boundary without a native runtime or threads.
pub trait AuditSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a>;
}

/// Atomically capture an event and application mutations in the same database.
/// Exact event retries must not reapply mutations. An event ID with different
/// content must fail, and a rejected mutation must leave no successful event.
pub trait AuditCapture {
    type Mutation;

    fn capture<'a>(
        &'a self,
        event: &'a AuditEvent,
        mutations: Vec<Self::Mutation>,
    ) -> AuditFuture<'a>;
}

/// A diagnostic mirror only. It deliberately excludes actor/target IDs,
/// organization IDs, arbitrary details, reason text and request metadata.
/// Filtering or disabling this event has no effect on [`AuditSink::append`].
pub fn emit_tracing_mirror(event: &AuditEvent) -> Result<(), AuditError> {
    event.validate()?;
    tracing::info!(target: "zeroth.audit", event_id = %event.event_id,
        schema_version = event.schema_version, event_type = %event.event_type,
        outcome = event.outcome.as_str(), "audit event captured");
    Ok(())
}

#[cfg(test)]
mod tests;
