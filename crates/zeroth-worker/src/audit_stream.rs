//! Deployment-wide delivery feed. Its dedicated bearer credential is unrelated
//! to browser sessions, organization administration, and the admin bootstrap key.
//! Outbox rows are retained: a future purge must add an explicit expired-cursor
//! response rather than letting a consumer silently skip missing history.

use super::*;
use zeroth_audit::AuditEvent;

const PAGE_LIMIT: usize = 100;
const EVENT_BYTES_LIMIT: usize = 32 * 1024;
const ACK_BYTES_LIMIT: usize = 2048;
const MAX_SEQUENCE_SQL: &str =
    "SELECT CAST(COALESCE(MAX(sequence), 0) AS TEXT) AS value FROM zeroth_audit_outbox";
const CONSUMER_SEQUENCE_SQL: &str =
    "SELECT CAST(last_sequence AS TEXT) AS value FROM zeroth_audit_consumers WHERE id = ?1";
const PAGE_SQL: &str = "SELECT CAST(sequence AS TEXT) AS sequence, event_id, event_json
    FROM zeroth_audit_outbox WHERE sequence > CAST(?1 AS INTEGER)
    ORDER BY sequence ASC LIMIT ?2";
const ACK_SQL: &str = "INSERT INTO zeroth_audit_consumers (id, last_sequence, updated_at)
    SELECT ?1, CAST(?2 AS INTEGER), ?3
    WHERE CAST(?2 AS INTEGER) >= 0
      AND CAST(?2 AS INTEGER) <= (SELECT COALESCE(MAX(sequence), 0) FROM zeroth_audit_outbox)
    ON CONFLICT (id) DO UPDATE SET
      last_sequence = MAX(zeroth_audit_consumers.last_sequence, excluded.last_sequence),
      updated_at = MAX(zeroth_audit_consumers.updated_at, excluded.updated_at)";

#[derive(Debug, Default, Eq, PartialEq)]
struct StreamQuery {
    after: Option<i64>,
    consumer: Option<String>,
    limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AckRequest {
    consumer_id: String,
    sequence: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AckResponse {
    consumer_id: String,
    sequence: i64,
}

#[derive(Debug, Serialize)]
struct StreamEvent {
    sequence: i64,
    event: AuditEvent,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamPage {
    events: Vec<StreamEvent>,
    next_sequence: i64,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct SequenceRow {
    // D1 represents JS numbers as doubles. Text preserves the complete i64
    // cursor range, including values beyond JavaScript's exact integer range.
    value: String,
}

#[derive(Debug, Deserialize)]
struct OutboxRow {
    sequence: String,
    event_id: String,
    event_json: String,
}

fn canonical_sequence(value: &str) -> Result<i64, &'static str> {
    if value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("cursor must be a canonical nonnegative integer");
    }
    value
        .parse()
        .map_err(|_| "cursor is outside the supported range")
}

fn validate_consumer(value: &str) -> Result<(), &'static str> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(
            "consumer must be 1 to 128 ASCII letters, digits, dots, underscores or hyphens",
        );
    }
    Ok(())
}

fn validate_endpoint(url: &url::Url) -> Result<(), &'static str> {
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        return Err("audit delivery requires HTTPS outside loopback");
    }
    Ok(())
}

fn parse_query(url: &url::Url) -> Result<StreamQuery, &'static str> {
    let mut query = StreamQuery {
        limit: PAGE_LIMIT,
        ..StreamQuery::default()
    };
    let mut seen_limit = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "after" if query.after.is_none() => query.after = Some(canonical_sequence(&value)?),
            "consumer" if query.consumer.is_none() => {
                validate_consumer(&value)?;
                query.consumer = Some(value.into_owned());
            }
            "limit" if !seen_limit => {
                seen_limit = true;
                let limit = canonical_sequence(&value)?;
                if !(1..=PAGE_LIMIT as i64).contains(&limit) {
                    return Err("limit must be between 1 and 100");
                }
                query.limit = limit as usize;
            }
            _ => return Err("unknown or duplicate stream parameter"),
        }
    }
    Ok(query)
}

fn token_matches(configured: &str, authorization: Option<&str>) -> bool {
    if configured.len() < 32
        || configured.len() > 4096
        || !configured.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return false;
    }
    let Some(authorization) = authorization else {
        return false;
    };
    let Some((scheme, token)) = authorization.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("Bearer")
        && !token.is_empty()
        && token.len() <= 4096
        && token.bytes().all(|byte| byte.is_ascii_graphic())
        && constant_time_eq(&hash_secret(configured), &hash_secret(token))
}

fn page_from_rows(
    mut rows: Vec<OutboxRow>,
    after: i64,
    limit: usize,
) -> Result<StreamPage, &'static str> {
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let mut previous = after;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let sequence = canonical_sequence(&row.sequence)?;
        if sequence <= previous || row.event_json.len() > EVENT_BYTES_LIMIT {
            return Err("invalid outbox ordering or event size");
        }
        let event: AuditEvent =
            serde_json::from_str(&row.event_json).map_err(|_| "invalid outbox event")?;
        event.validate().map_err(|_| "invalid outbox event")?;
        if event.event_id != row.event_id {
            return Err("outbox event identity mismatch");
        }
        events.push(StreamEvent { sequence, event });
        previous = sequence;
    }
    Ok(StreamPage {
        events,
        next_sequence: previous,
        has_more,
    })
}

#[cfg(target_arch = "wasm32")]
fn error_response(code: &'static str, status: u16) -> worker::Result<Response> {
    let response = json_status_no_store(&serde_json::json!({"error": code}), status)?;
    if status == 401 {
        response.headers().set("WWW-Authenticate", "Bearer")?;
    }
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
async fn max_sequence(db: &worker::d1::D1Database) -> worker::Result<i64> {
    let row = db
        .prepare(MAX_SEQUENCE_SQL)
        .first::<SequenceRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("audit stream watermark missing".into()))?;
    canonical_sequence(&row.value)
        .map_err(|_| worker::Error::RustError("invalid audit stream watermark".into()))
}

#[cfg(target_arch = "wasm32")]
async fn consumer_sequence(db: &worker::d1::D1Database, id: &str) -> worker::Result<i64> {
    let row = db
        .prepare(CONSUMER_SEQUENCE_SQL)
        .bind_refs(&[worker::d1::D1Type::Text(id)])?
        .first::<SequenceRow>(None)
        .await?;
    row.map(|row| canonical_sequence(&row.value))
        .transpose()
        .map(|value| value.unwrap_or(0))
        .map_err(|_| worker::Error::RustError("invalid audit consumer checkpoint".into()))
}

/// Both delivery routes use this entry point. Possession of AUDIT_STREAM_TOKEN
/// grants access to ALL deployment events, including platform-scoped records.
#[cfg(target_arch = "wasm32")]
pub(super) async fn stream(mut request: Request, env: Env) -> worker::Result<Response> {
    let url = request.url()?;
    if validate_endpoint(&url).is_err() {
        return error_response("https_required", 400);
    }
    let Some(configured) = secret_string(&env, "AUDIT_STREAM_TOKEN") else {
        return error_response("audit_stream_unavailable", 503);
    };
    if configured.len() < 32
        || configured.len() > 4096
        || !configured.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return error_response("audit_stream_unavailable", 503);
    }
    let authorization = request_header(&request, "Authorization")?;
    if !token_matches(&configured, authorization.as_deref()) {
        return error_response("unauthorized", 401);
    }
    let db = env.d1(D1_BINDING)?;
    let path = canonical_route_path(url.path());
    match (request.method(), path.as_ref()) {
        (Method::Get, "/audit/stream") => {
            let query = match parse_query(&url) {
                Ok(query) => query,
                Err(_) => return error_response("invalid_stream_query", 400),
            };
            let after = match (query.after, query.consumer.as_deref()) {
                (Some(after), _) => after,
                (None, Some(id)) => consumer_sequence(&db, id).await?,
                (None, None) => 0,
            };
            if after > max_sequence(&db).await? {
                return error_response("cursor_ahead_of_stream", 409);
            }
            let after_text = after.to_string();
            let args = [
                worker::d1::D1Type::Text(&after_text),
                worker::d1::D1Type::Integer((query.limit + 1) as i32),
            ];
            let rows = db
                .prepare(PAGE_SQL)
                .bind_refs(&args)?
                .all()
                .await?
                .results::<OutboxRow>()?;
            match page_from_rows(rows, after, query.limit) {
                Ok(page) => json_status_no_store(&page, 200),
                Err(_) => error_response("audit_stream_corrupt", 503),
            }
        }
        (Method::Post, "/audit/stream/ack") => {
            if url.query().is_some() {
                return error_response("invalid_ack_query", 400);
            }
            if !content_type_is_json(request_header(&request, "Content-Type")?.as_deref()) {
                return error_response("json_required", 415);
            }
            let ack = match bounded_ack_body(&mut request).await {
                Ok(ack) => ack,
                Err(_) => return error_response("invalid_ack", 400),
            };
            if validate_consumer(&ack.consumer_id).is_err() || ack.sequence < 0 {
                return error_response("invalid_ack", 400);
            }
            if ack.sequence > max_sequence(&db).await? {
                return error_response("cursor_ahead_of_stream", 409);
            }
            let sequence_text = ack.sequence.to_string();
            let args = [
                worker::d1::D1Type::Text(&ack.consumer_id),
                worker::d1::D1Type::Text(&sequence_text),
                worker::d1::D1Type::Integer(unix_timestamp_seconds()),
            ];
            db.prepare(ACK_SQL).bind_refs(&args)?.run().await?;
            let sequence = consumer_sequence(&db, &ack.consumer_id).await?;
            json_status_no_store(
                &AckResponse {
                    consumer_id: ack.consumer_id,
                    sequence,
                },
                200,
            )
        }
        _ => error_response("method_not_allowed", 405),
    }
}

#[cfg(target_arch = "wasm32")]
async fn bounded_ack_body(request: &mut Request) -> Result<AckRequest, ()> {
    use futures_util::StreamExt;
    reject_oversized_content_length(request, ACK_BYTES_LIMIT).map_err(|_| ())?;
    let mut stream = request.stream().map_err(|_| ())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ())?;
        if chunk.len() > ACK_BYTES_LIMIT.saturating_sub(bytes.len()) {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use zeroth_audit::{AuditActor, AuditOutcome};

    fn row(sequence: i64) -> OutboxRow {
        let event = AuditEvent::new(
            format!("evt_{sequence}"),
            1,
            1,
            "session.created",
            AuditActor::new("user", "usr_1").unwrap(),
            AuditOutcome::Success,
        )
        .unwrap();
        OutboxRow {
            sequence: sequence.to_string(),
            event_id: event.event_id.clone(),
            event_json: event.canonical_json().unwrap(),
        }
    }

    #[test]
    fn rejects_ambiguous_queries_and_unsafe_transport() {
        for query in [
            "after=-1",
            "after=01",
            "after=+1",
            "after=9223372036854775808",
            "after=1&after=2",
            "limit=0",
            "limit=101",
            "limit=01",
            "token=secret",
            "consumer=bad%2Fname",
            "consumer=a&consumer=b",
        ] {
            assert!(
                parse_query(
                    &url::Url::parse(&format!("https://id.example/audit/stream?{query}")).unwrap()
                )
                .is_err(),
                "{query}"
            );
        }
        assert_eq!(canonical_sequence("9223372036854775807"), Ok(i64::MAX));
        assert_eq!(
            parse_query(
                &url::Url::parse(
                    "https://id.example/audit/stream?after=0&consumer=pg-main&limit=2"
                )
                .unwrap()
            )
            .unwrap(),
            StreamQuery {
                after: Some(0),
                consumer: Some("pg-main".into()),
                limit: 2
            }
        );
        for endpoint in [
            "http://id.example/audit/stream",
            "http://localhost.evil/audit/stream",
            "https://user:secret@id.example/audit/stream",
        ] {
            assert!(validate_endpoint(&url::Url::parse(endpoint).unwrap()).is_err());
        }
        for endpoint in [
            "https://id.example/audit/stream",
            "http://127.0.0.1/audit/stream",
            "http://[::1]/audit/stream",
        ] {
            validate_endpoint(&url::Url::parse(endpoint).unwrap()).unwrap();
        }
    }

    #[test]
    fn dedicated_token_requires_an_exact_bearer_secret() {
        let secret = "12345678901234567890123456789012";
        assert!(token_matches(secret, Some(&format!("Bearer {secret}"))));
        for header in [
            None,
            Some("Bearer wrong"),
            Some("Basic 12345678901234567890123456789012"),
            Some("Bearer 12345678901234567890123456789012 "),
        ] {
            assert!(!token_matches(secret, header));
        }
        assert!(!token_matches("", Some("Bearer ")));
    }

    #[test]
    fn pagination_preserves_order_and_never_skips_invalid_events() {
        let page = page_from_rows(vec![row(1), row(4), row(7)], 0, 2).unwrap();
        assert_eq!(page.next_sequence, 4);
        assert!(page.has_more);
        assert_eq!(page.events.len(), 2);
        assert_eq!(page_from_rows(vec![], 4, 2).unwrap().next_sequence, 4);
        assert!(page_from_rows(vec![row(4), row(1)], 0, 2).is_err());
        let mut invalid = row(1);
        invalid.event_json = "{}".into();
        assert!(page_from_rows(vec![invalid], 0, 2).is_err());
        let mut invalid = row(1);
        invalid.event_id = "evt_another".into();
        assert!(page_from_rows(vec![invalid], 0, 2).is_err());
    }

    #[test]
    fn actual_sql_keeps_checkpoints_monotonic_and_preserves_large_cursors() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE zeroth_audit_outbox(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE,event_json TEXT,created_at INTEGER); CREATE TABLE zeroth_audit_consumers(id TEXT PRIMARY KEY,last_sequence INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL);").unwrap();
        let high = 9_007_199_254_740_993_i64;
        for sequence in [1, high] {
            let row = row(sequence);
            db.execute(
                "INSERT INTO zeroth_audit_outbox VALUES (?1,?2,?3,1)",
                params![sequence, row.event_id, row.event_json],
            )
            .unwrap();
        }
        let max: String = db
            .query_row(MAX_SEQUENCE_SQL, [], |row| row.get(0))
            .unwrap();
        assert_eq!(canonical_sequence(&max), Ok(high));
        let mut statement = db.prepare(PAGE_SQL).unwrap();
        let rows: Vec<String> = statement
            .query_map(params!["1", 2], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows, [high.to_string()]);
        for (sequence, time) in [(high, 20), (1, 10), (high + 1, 30), (-1, 30)] {
            db.execute(ACK_SQL, params!["collector", sequence.to_string(), time])
                .unwrap();
        }
        let checkpoint: String = db
            .query_row(CONSUMER_SEQUENCE_SQL, ["collector"], |row| row.get(0))
            .unwrap();
        assert_eq!(canonical_sequence(&checkpoint), Ok(high));
        assert_eq!(
            db.query_row::<i64, _, _>("SELECT updated_at FROM zeroth_audit_consumers", [], |row| {
                row.get(0)
            })
            .unwrap(),
            20
        );
    }
}
