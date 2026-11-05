# Zeroth audit events

Create and persist an `AuditEvent` explicitly. Handle the `AuditSink::append`
result before claiming that required audit capture succeeded. The sink interface
has no dependency on tracing subscribers or filtering. `emit_tracing_mirror` is an
optional diagnostic copy containing event ID, schema version, action and outcome;
it excludes actors, targets, organization IDs, reasons and details.

Capture important mutations and their event/outbox record in the same database
transaction. Deliver the stored event with unchanged ID, timestamps and payload.
Archive results `Inserted` and `Duplicate` mean persistence succeeded. A queue
transport can instead return `Accepted`, which acknowledges delivery only and
requires downstream permanent deduplication. `EventIdCollision` means
the ID was reused with different content and must be investigated. Remote sink
delivery alone cannot make a local business mutation atomic.

Organization IDs are optional only for platform events. Authorization must use an
explicit organization equality predicate; NULL is never a customer wildcard.
Actor IDs and target IDs are different references, not names or email addresses.
Use `Unknown` for ambiguous legacy outcomes. Timestamps use 64-bit Unix seconds.

`SafeDetails` accepts a short list of typed keys and values. The legacy JSON helper
drops unknown keys and invalid values without logging raw data. The allowlist is
not a detector for every secret: machine error codes and opaque internal IDs must
come from trusted application code, never arbitrary upstream descriptions,
provider subjects, request URLs, tokens or profile data.

Enable the `postgres` feature for the native `PostgresAuditSink`. The Worker/core
build does not require PostgreSQL, Tokio networking or a native TLS library.
Connections require certificate and hostname verification and never fall back to
plaintext, including when a connection string requests `sslmode=disable`.
Use `connect_with_roots` for an explicit private CA. An active Tokio runtime is
with time enabled is required. Connection setup is bounded to ten seconds;
initialization and appends are bounded to thirty seconds. A timeout can follow a
successful remote write, so retry the identical stored event rather than making
a new event ID. Configuration and database errors intentionally omit raw connection
strings, credentials and upstream messages.

The sink's explicit `initialize` method creates its table and index. Run it with
a deployment role; give the runtime role SELECT/INSERT only. Retention requires a
separate authorized deletion job. The sink deduplicates by event ID and compares
the entire JSON payload on a conflict; it never overwrites an event. It is an
optional delivery destination, not the Worker's transactional outbox or a claim of
cryptographic immutability, exactly-once transport or permanent retention.

The ignored `postgres_live` integration test requires an isolated TLS-only test
database and a private CA not trusted by the OS. Set
`ZEROTH_AUDIT_POSTGRES_TEST_URL` to a libpq key-value connection string and
`ZEROTH_AUDIT_POSTGRES_TEST_CA_DER` to that CA's DER certificate, then run
`cargo test -p zeroth-audit --features postgres --test postgres_live -- --ignored`.
It exercises real insert/duplicate/collision handling and races two independent
connections. It creates test audit records and never discovers credentials or
starts a database automatically.
