use std::{collections::HashMap, future::Future, pin::Pin};

use aws_sdk_dynamodb::{
    types::{AttributeValue, Put, TransactWriteItem},
    Client,
};
use zeroth_audit::{AppendResult, AuditCapture, AuditError, AuditEvent, AuditFuture, AuditSink};

type AwsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AuditError>> + 'a>>;
const MAX_BUSINESS_WRITES: usize = 98;

/// Dedicated audit table with hash key `pk` and a sparse `pending` GSI on
/// `pending_partition` + `pending_sort`. Business tables must be separate, in the
/// same AWS account and region, as required by DynamoDB transactions.
#[derive(Clone)]
pub struct DynamoDbAuditSink {
    client: Client,
    table_name: String,
    pending_index: String,
}

impl DynamoDbAuditSink {
    pub fn new(
        client: Client,
        table_name: impl Into<String>,
        pending_index: impl Into<String>,
    ) -> Result<Self, AuditError> {
        let table_name = table_name.into();
        let pending_index = pending_index.into();
        for value in [&table_name, &pending_index] {
            if !(3..=255).contains(&value.len())
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(AuditError::InvalidField("dynamodb_configuration"));
            }
        }
        Ok(Self {
            client,
            table_name,
            pending_index,
        })
    }

    /// Read one bounded page of the sparse pending index. Each successful
    /// destination ACK is followed by an outbox update; failures remain pending.
    /// Concurrent drainers may deliver duplicates. A repeated drain also repairs
    /// crashes after destination ACK but before the completion update. No global
    /// ordering or exactly-once transport is promised.
    pub async fn drain_pending(
        &self,
        destination: &impl AuditSink,
        limit: usize,
    ) -> Result<DrainReport, AuditError> {
        drain_with(self, destination, limit).await
    }
}

impl AuditCapture for DynamoDbAuditSink {
    type Mutation = TransactWriteItem;

    fn capture<'a>(
        &'a self,
        event: &'a AuditEvent,
        mutations: Vec<Self::Mutation>,
    ) -> AuditFuture<'a> {
        Box::pin(capture_with(self, &self.table_name, event, mutations))
    }
}

impl AuditSink for DynamoDbAuditSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        self.capture(event, Vec::new())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStage {
    Decode,
    Send,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryFailure {
    pub event_id: String,
    pub stage: DeliveryStage,
    pub error: AuditError,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DrainReport {
    pub scanned: usize,
    pub acknowledged: usize,
    pub completed: usize,
    pub failures: Vec<DeliveryFailure>,
}

#[derive(Clone, Debug)]
struct PendingEvent {
    event_id: String,
    event_json: String,
}

trait DynamoBackend {
    fn get_event<'a>(&'a self, event_id: &'a str) -> AwsFuture<'a, Option<String>>;
    fn transact<'a>(&'a self, items: Vec<TransactWriteItem>, token: String) -> AwsFuture<'a, ()>;
    fn pending(&self, limit: usize) -> AwsFuture<'_, Vec<PendingEvent>>;
    fn complete<'a>(&'a self, event: &'a PendingEvent) -> AwsFuture<'a, ()>;
}

async fn capture_with(
    backend: &impl DynamoBackend,
    table: &str,
    event: &AuditEvent,
    mutations: Vec<TransactWriteItem>,
) -> Result<AppendResult, AuditError> {
    let canonical = event.canonical_json()?;
    let transaction = build_transaction(table, event, &canonical, mutations)?;
    if let Some(stored) = backend.get_event(&event.event_id).await? {
        return compare_existing(&stored, &canonical);
    }
    // Conditions on both event and outbox survive the SDK's 10-minute request
    // token window. Never regenerate the original envelope when replaying.
    let token = super::sha256(&format!("{}:{canonical}", event.event_id))[..32].to_owned();
    match backend.transact(transaction, token).await {
        Ok(()) => Ok(AppendResult::Inserted),
        Err(error) => match backend.get_event(&event.event_id).await? {
            // Resolve a racing retry or a successful commit whose ACK was lost.
            Some(stored) => compare_existing(&stored, &canonical),
            None => Err(error),
        },
    }
}

fn compare_existing(stored: &str, incoming: &str) -> Result<AppendResult, AuditError> {
    if stored == incoming {
        Ok(AppendResult::Duplicate)
    } else {
        Err(AuditError::EventIdCollision)
    }
}

fn build_transaction(
    table: &str,
    event: &AuditEvent,
    canonical: &str,
    mut mutations: Vec<TransactWriteItem>,
) -> Result<Vec<TransactWriteItem>, AuditError> {
    if mutations.len() > MAX_BUSINESS_WRITES {
        return Err(AuditError::InvalidField("business_mutations"));
    }
    for mutation in &mutations {
        let tables: Vec<&str> = [
            mutation.put().map(|put| put.table_name()),
            mutation.delete().map(|delete| delete.table_name()),
            mutation.update().map(|update| update.table_name()),
            mutation
                .condition_check()
                .map(|condition| condition.table_name()),
        ]
        .into_iter()
        .flatten()
        .collect();
        // Reject multiple-operation entries, and all audit-table aliases. A
        // caller must not overwrite/delete the immutable event or pending row.
        if tables.len() != 1 || tables[0].rsplit('/').next() == Some(table) {
            return Err(AuditError::InvalidField("business_mutations"));
        }
    }
    let mut event_item = HashMap::from([
        (
            "pk".into(),
            AttributeValue::S(format!("event#{}", event.event_id)),
        ),
        ("event_id".into(), AttributeValue::S(event.event_id.clone())),
        ("event_json".into(), AttributeValue::S(canonical.into())),
        (
            "recorded_at".into(),
            AttributeValue::N(event.recorded_at.to_string()),
        ),
        ("kind".into(), AttributeValue::S("event".into())),
    ]);
    if let Some(organization) = &event.organization_id {
        event_item.insert(
            "organization_id".into(),
            AttributeValue::S(organization.clone()),
        );
    }
    let outbox_item = HashMap::from([
        (
            "pk".into(),
            AttributeValue::S(format!("outbox#{}", event.event_id)),
        ),
        ("event_id".into(), AttributeValue::S(event.event_id.clone())),
        ("event_json".into(), AttributeValue::S(canonical.into())),
        (
            "created_at".into(),
            AttributeValue::N(event.recorded_at.to_string()),
        ),
        ("kind".into(), AttributeValue::S("outbox".into())),
        ("status".into(), AttributeValue::S("pending".into())),
        (
            "pending_partition".into(),
            AttributeValue::S("pending".into()),
        ),
        (
            "pending_sort".into(),
            AttributeValue::S(format!("{:020}#{}", event.recorded_at, event.event_id)),
        ),
    ]);
    for item in [event_item, outbox_item] {
        let put = Put::builder()
            .table_name(table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .build()
            .map_err(|_| AuditError::Storage)?;
        mutations.push(TransactWriteItem::builder().put(put).build());
    }
    Ok(mutations)
}

async fn drain_with(
    backend: &impl DynamoBackend,
    destination: &impl AuditSink,
    limit: usize,
) -> Result<DrainReport, AuditError> {
    if !(1..=100).contains(&limit) {
        return Err(AuditError::InvalidField("drain_limit"));
    }
    let pending = backend.pending(limit).await?;
    let mut report = DrainReport {
        scanned: pending.len(),
        ..DrainReport::default()
    };
    for record in pending {
        let event = match serde_json::from_str::<AuditEvent>(&record.event_json) {
            Ok(event) if event.event_id == record.event_id && event.validate().is_ok() => event,
            _ => {
                report.failures.push(DeliveryFailure {
                    event_id: record.event_id,
                    stage: DeliveryStage::Decode,
                    error: AuditError::Serialization,
                });
                continue;
            }
        };
        if let Err(error) = destination.append(&event).await {
            report.failures.push(DeliveryFailure {
                event_id: record.event_id,
                stage: DeliveryStage::Send,
                error,
            });
            continue;
        }
        report.acknowledged += 1;
        if let Err(error) = backend.complete(&record).await {
            report.failures.push(DeliveryFailure {
                event_id: record.event_id,
                stage: DeliveryStage::Complete,
                error,
            });
            continue;
        }
        report.completed += 1;
    }
    Ok(report)
}

impl DynamoBackend for DynamoDbAuditSink {
    fn get_event<'a>(&'a self, event_id: &'a str) -> AwsFuture<'a, Option<String>> {
        Box::pin(async move {
            let output = self
                .client
                .get_item()
                .table_name(&self.table_name)
                .key("pk", AttributeValue::S(format!("event#{event_id}")))
                .consistent_read(true)
                .projection_expression("event_json")
                .send()
                .await
                .map_err(|_| AuditError::Storage)?;
            match output.item {
                None => Ok(None),
                Some(item) => Ok(Some(
                    item.get("event_json")
                        .and_then(|value| value.as_s().ok())
                        .ok_or(AuditError::Storage)?
                        .clone(),
                )),
            }
        })
    }

    fn transact<'a>(&'a self, items: Vec<TransactWriteItem>, token: String) -> AwsFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .transact_write_items()
                .set_transact_items(Some(items))
                .client_request_token(token)
                .send()
                .await
                .map_err(|_| AuditError::Storage)?;
            Ok(())
        })
    }

    fn pending(&self, limit: usize) -> AwsFuture<'_, Vec<PendingEvent>> {
        Box::pin(async move {
            let output = self
                .client
                .query()
                .table_name(&self.table_name)
                .index_name(&self.pending_index)
                .key_condition_expression("pending_partition = :pending")
                .expression_attribute_values(":pending", AttributeValue::S("pending".into()))
                .limit(limit as i32)
                .scan_index_forward(true)
                .send()
                .await
                .map_err(|_| AuditError::Storage)?;
            output
                .items()
                .iter()
                .map(|item| {
                    Ok(PendingEvent {
                        event_id: item
                            .get("event_id")
                            .and_then(|value| value.as_s().ok())
                            .ok_or(AuditError::Storage)?
                            .clone(),
                        event_json: item
                            .get("event_json")
                            .and_then(|value| value.as_s().ok())
                            .ok_or(AuditError::Storage)?
                            .clone(),
                    })
                })
                .collect()
        })
    }

    fn complete<'a>(&'a self, event: &'a PendingEvent) -> AwsFuture<'a, ()> {
        Box::pin(async move {
            self.client
                .update_item()
                .table_name(&self.table_name)
                .key(
                    "pk",
                    AttributeValue::S(format!("outbox#{}", event.event_id)),
                )
                .condition_expression("attribute_exists(pk) AND event_json = :event")
                .update_expression(
                    "SET #status = :delivered REMOVE pending_partition, pending_sort",
                )
                .expression_attribute_names("#status", "status")
                .expression_attribute_values(":event", AttributeValue::S(event.event_json.clone()))
                .expression_attribute_values(":delivered", AttributeValue::S("delivered".into()))
                .send()
                .await
                .map_err(|_| AuditError::Storage)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
