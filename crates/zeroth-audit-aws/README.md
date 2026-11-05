# AWS audit adapters

This crate is optional and native only. It uses the official AWS Rust SDKs for
DynamoDB and SQS. Construct clients with the normal AWS credential chain and
region configuration; no credentials or endpoint overrides are embedded here.

`DynamoDbAuditSink::new(client, table_name, pending_index)` uses a dedicated audit
table. `AuditCapture::capture(event, Vec<TransactWriteItem>)` commits the business
mutations, immutable event and pending outbox record in one DynamoDB transaction.
All tables must be in the same AWS account and region. At most 98 business writes
are allowed, leaving two of DynamoDB's 100 transaction actions for audit capture.
Service size and condition restrictions still apply. Writes targeting the audit
table are rejected. The adapter uses conditional inserts and strongly consistent
reads to recognize exact retries and reject changed payloads with the same ID.
An exact retry never reapplies business writes. Preserve the entire canonical
event, including timestamps, across attempts. `append` captures an event without
business writes using the same transaction.

`SqsAuditSink::new(client, queue_url, fifo_group_id)` sends the canonical envelope
and event-ID/payload-hash message attributes. A FIFO queue requires a stable group
ID; its deduplication ID is derived from the stable event ID. `Accepted` means
AWS acknowledged sending the message, not durable archival or consumer success.
FIFO deduplication is limited to its five-minute window. Consumers must persist
event IDs and compare content permanently; neither standard nor FIFO transport
provides end-to-end exactly-once processing. SQS alone cannot detect reused IDs
with changed content. Use the authoritative DynamoDB/PG capture sink for that.

Call `DynamoDbAuditSink::drain_pending(&destination, limit)` repeatedly from a
scheduled process, Lambda or another native runtime. It reads one bounded page
from the sparse pending GSI, awaits each destination ACK and only then marks its
outbox record delivered. Failures leave pending records for replay. The returned
report counts scanned, acknowledged and completed records and identifies safe
failure stages without raw SDK messages. A crash after sending can cause a repeat
delivery. Multiple drainers and the eventually consistent GSI can also produce
duplicates; no global ordering is promised. A permanently malformed or failing
record needs operator action; the adapter reports it and does not silently drop
it. The single pending partition is intended for initial deployments, not a claim
of unlimited throughput. Shard it before a workload exceeds partition capacity.

`deploy/aws/audit.yaml` declares the matching encrypted table, sparse index, FIFO
queue and dead-letter queue, plus separate example capture and delivery policies.
The application still needs permissions on its own business tables. Retained
audit data and pending records have no automatic TTL; choose a deliberate
retention policy that preserves undelivered outbox entries. DynamoDB API capture
is append-only by adapter behavior, not cryptographic WORM protection against an
operator with write privileges. SQS retention and its DLQ do not replace durable
audit history. No resources are deployed by building or testing this crate.
