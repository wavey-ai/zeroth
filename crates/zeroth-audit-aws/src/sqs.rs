use aws_sdk_sqs::{
    operation::send_message::SendMessageInput, types::MessageAttributeValue, Client,
};
use zeroth_audit::{AppendResult, AuditError, AuditEvent, AuditFuture, AuditSink};

/// Delivery adapter. An Accepted result means SQS acknowledged SendMessage,
/// not that a consumer processed or permanently archived the event. FIFO dedup
/// has a limited window; consumers still need permanent event-ID/content checks.
#[derive(Clone)]
pub struct SqsAuditSink {
    client: Client,
    queue_url: String,
    fifo_group_id: Option<String>,
    fifo: bool,
}

impl SqsAuditSink {
    pub fn new(
        client: Client,
        queue_url: impl Into<String>,
        fifo_group_id: Option<String>,
    ) -> Result<Self, AuditError> {
        let queue_url = queue_url.into();
        let url =
            url::Url::parse(&queue_url).map_err(|_| AuditError::InvalidField("sqs_queue_url"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() == "/"
        {
            return Err(AuditError::InvalidField("sqs_queue_url"));
        }
        let fifo = url.path().ends_with(".fifo");
        if fifo && fifo_group_id.is_none() {
            return Err(AuditError::InvalidField("sqs_fifo_group_id"));
        }
        if let Some(group) = &fifo_group_id {
            if group.is_empty()
                || group.len() > 128
                || !group.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                })
            {
                return Err(AuditError::InvalidField("sqs_fifo_group_id"));
            }
        }
        Ok(Self {
            client,
            queue_url,
            fifo_group_id,
            fifo,
        })
    }

    /// Build the actual SDK request without performing network I/O, useful for
    /// adapter validation. Metadata carries a stable ID and full-payload hash.
    pub fn message_input(&self, event: &AuditEvent) -> Result<SendMessageInput, AuditError> {
        let canonical = event.canonical_json()?;
        let attribute = |value: String| {
            MessageAttributeValue::builder()
                .data_type("String")
                .string_value(value)
                .build()
                .map_err(|_| AuditError::Storage)
        };
        let mut input = SendMessageInput::builder()
            .queue_url(&self.queue_url)
            .message_body(&canonical)
            .message_attributes("event_id", attribute(event.event_id.clone())?)
            .message_attributes("payload_sha256", attribute(super::sha256(&canonical))?);
        if let Some(group) = &self.fifo_group_id {
            input = input.message_group_id(group);
        }
        if self.fifo {
            input = input.message_deduplication_id(super::sha256(&event.event_id));
        }
        input.build().map_err(|_| AuditError::Storage)
    }
}

impl AuditSink for SqsAuditSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        Box::pin(async move {
            let input = self.message_input(event)?;
            let output = self
                .client
                .send_message()
                .set_queue_url(input.queue_url)
                .set_message_body(input.message_body)
                .set_message_attributes(input.message_attributes)
                .set_message_group_id(input.message_group_id)
                .set_message_deduplication_id(input.message_deduplication_id)
                .send()
                .await
                .map_err(|_| AuditError::Storage)?;
            if output.message_id().is_none() {
                return Err(AuditError::Storage);
            }
            Ok(AppendResult::Accepted)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroth_audit::{AuditActor, AuditOutcome};

    fn client() -> Client {
        Client::from_conf(
            aws_sdk_sqs::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_sqs::config::Region::new("us-east-1"))
                .build(),
        )
    }

    fn event() -> AuditEvent {
        AuditEvent::new(
            "evt_1",
            1,
            1,
            "session.create",
            AuditActor::anonymous(),
            AuditOutcome::Success,
        )
        .unwrap()
    }

    #[test]
    fn fifo_uses_stable_event_id_dedup_and_payload_metadata() {
        let sink = SqsAuditSink::new(
            client(),
            "https://sqs.us-east-1.amazonaws.com/123456789012/audit.fifo",
            Some("audit".into()),
        )
        .unwrap();
        let event = event();
        let request = sink.message_input(&event).unwrap();
        let replay = sink.message_input(&event).unwrap();
        assert_eq!(
            request.message_body(),
            Some(event.canonical_json().unwrap().as_str())
        );
        assert_eq!(
            request.message_deduplication_id(),
            replay.message_deduplication_id()
        );
        assert_eq!(request.message_deduplication_id().unwrap().len(), 64);
        assert_eq!(request.message_group_id(), Some("audit"));
        let attributes = request.message_attributes().unwrap();
        assert_eq!(attributes["event_id"].string_value(), Some("evt_1"));
        assert_eq!(
            attributes["payload_sha256"].string_value(),
            Some(super::super::sha256(&event.canonical_json().unwrap()).as_str())
        );
        let mut changed = event;
        changed.outcome = AuditOutcome::Denied;
        let collision = sink.message_input(&changed).unwrap();
        assert_eq!(
            collision.message_deduplication_id(),
            request.message_deduplication_id()
        );
        assert_ne!(
            collision.message_attributes().unwrap()["payload_sha256"],
            attributes["payload_sha256"]
        );
    }

    #[test]
    fn standard_queue_omits_fifo_fields_and_insecure_config_is_rejected() {
        let sink = SqsAuditSink::new(
            client(),
            "https://sqs.us-east-1.amazonaws.com/123456789012/audit",
            None,
        )
        .unwrap();
        let input = sink.message_input(&event()).unwrap();
        assert!(input.message_deduplication_id().is_none());
        assert!(input.message_group_id().is_none());
        for bad in [
            "http://sqs.us-east-1.amazonaws.com/123/audit",
            "https://user:secret@sqs.us-east-1.amazonaws.com/audit",
            "https://sqs.us-east-1.amazonaws.com/audit?token=secret",
        ] {
            assert!(SqsAuditSink::new(client(), bad, None).is_err());
        }
        assert!(SqsAuditSink::new(
            client(),
            "https://sqs.us-east-1.amazonaws.com/123/audit.fifo",
            None
        )
        .is_err());
    }
}
