//! Optional AWS adapters. No AWS SDK or native networking enters a Wasm build.
//!
//! DynamoDB capture atomically commits business writes, an immutable audit event
//! and a durable outbox item. SQS is a delivery destination, not an archive:
//! consumers must persistently deduplicate event IDs and compare payloads.

#![cfg(not(target_arch = "wasm32"))]

mod dynamodb;
mod sqs;

pub use aws_sdk_dynamodb;
pub use aws_sdk_sqs;
pub use dynamodb::{DeliveryFailure, DeliveryStage, DrainReport, DynamoDbAuditSink};
pub use sqs::SqsAuditSink;

use sha2::{Digest, Sha256};

fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
