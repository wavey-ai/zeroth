//! Native delivery client. Stream checkpoints advance only after every sink
//! append returns success. A retry reuses the exact canonical event identity.

#![cfg(not(target_arch = "wasm32"))]

use reqwest::{
    header::{HeaderValue, AUTHORIZATION},
    redirect::Policy,
    Client, Response,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, future::Future, time::Duration};
use url::Url;
use zeroth_audit::{AuditEvent, AuditSink};

pub const PAGE_LIMIT: usize = 100;
pub const EVENT_BYTES_LIMIT: usize = 32 * 1024;
pub const PAGE_BYTES_LIMIT: usize = 4 * 1024 * 1024;
const ACK_BYTES_LIMIT: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorError {
    Configuration,
    Transport,
    RemoteStatus,
    Payload,
    Sink,
    Acknowledgement,
}

impl CollectorError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Configuration => "invalid_configuration",
            Self::Transport => "transport_failed",
            Self::RemoteStatus => "remote_status",
            Self::Payload => "invalid_stream_payload",
            Self::Sink => "sink_append_failed",
            Self::Acknowledgement => "checkpoint_ack_failed",
        }
    }
}

// Errors intentionally contain no URLs, database connection strings, tokens,
// response bodies, event contents, or nested library errors.
impl fmt::Display for CollectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for CollectorError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamEvent {
    pub sequence: i64,
    pub event: AuditEvent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamPage {
    pub events: Vec<StreamEvent>,
    pub next_sequence: i64,
    pub has_more: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AckResponse {
    consumer_id: String,
    sequence: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryProgress {
    pub events: usize,
    pub sequence: i64,
    pub has_more: bool,
}

/// Operators configure this endpoint. It is never accepted from an event or a
/// redirect response. Each independently populated sink must use its own
/// consumer ID; sharing a checkpoint across different destinations loses data.
pub struct HttpStream {
    client: Client,
    endpoint: Url,
    ack_endpoint: Url,
    authorization: HeaderValue,
    consumer_id: String,
}

impl HttpStream {
    pub fn new(endpoint: &str, token: &str, consumer_id: &str) -> Result<Self, CollectorError> {
        let endpoint = validate_endpoint(endpoint)?;
        if token.len() < 32
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
            || consumer_id.is_empty()
            || consumer_id.len() > 128
            || !consumer_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(CollectorError::Configuration);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CollectorError::Configuration)?;
        authorization.set_sensitive(true);
        let mut ack_endpoint = endpoint.clone();
        ack_endpoint.set_path("/audit/stream/ack");
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .no_proxy()
            .user_agent("zeroth-audit-collector")
            .build()
            .map_err(|_| CollectorError::Configuration)?;
        Ok(Self {
            client,
            endpoint,
            ack_endpoint,
            authorization,
            consumer_id: consumer_id.into(),
        })
    }
}

pub trait DeliveryTransport {
    fn fetch(&self) -> impl Future<Output = Result<StreamPage, CollectorError>>;
    fn acknowledge(&self, sequence: i64) -> impl Future<Output = Result<(), CollectorError>>;
}

impl DeliveryTransport for HttpStream {
    async fn fetch(&self) -> Result<StreamPage, CollectorError> {
        // Omit `after`: the authoritative durable consumer checkpoint controls
        // every poll and restart, including a lost ACK response.
        let response = self
            .client
            .get(self.endpoint.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .query(&[("consumer", self.consumer_id.as_str()), ("limit", "100")])
            .send()
            .await
            .map_err(|_| CollectorError::Transport)?;
        let body = bounded_response(response, PAGE_BYTES_LIMIT).await?;
        serde_json::from_slice(&body).map_err(|_| CollectorError::Payload)
    }

    async fn acknowledge(&self, sequence: i64) -> Result<(), CollectorError> {
        let response = self
            .client
            .post(self.ack_endpoint.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .json(&serde_json::json!({"consumerId": self.consumer_id, "sequence": sequence}))
            .send()
            .await
            .map_err(|_| CollectorError::Acknowledgement)?;
        let body = bounded_response(response, ACK_BYTES_LIMIT)
            .await
            .map_err(|_| CollectorError::Acknowledgement)?;
        let ack: AckResponse =
            serde_json::from_slice(&body).map_err(|_| CollectorError::Acknowledgement)?;
        if ack.consumer_id != self.consumer_id || ack.sequence != sequence {
            return Err(CollectorError::Acknowledgement);
        }
        Ok(())
    }
}

fn validate_endpoint(endpoint: &str) -> Result<Url, CollectorError> {
    let url = Url::parse(endpoint).map_err(|_| CollectorError::Configuration)?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/audit/stream"
    {
        return Err(CollectorError::Configuration);
    }
    Ok(url)
}

async fn bounded_response(mut response: Response, limit: usize) -> Result<Vec<u8>, CollectorError> {
    if response.status() != reqwest::StatusCode::OK {
        return Err(CollectorError::RemoteStatus);
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or_default()
        .trim();
    if !content_type.eq_ignore_ascii_case("application/json")
        || response
            .content_length()
            .is_some_and(|length| length > limit as u64)
    {
        return Err(CollectorError::Payload);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CollectorError::Transport)?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(CollectorError::Payload);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_page(page: &StreamPage, previous: Option<i64>) -> Result<(), CollectorError> {
    if page.events.len() > PAGE_LIMIT
        || page.next_sequence < 0
        || previous.is_some_and(|value| value < 0)
        || (page.has_more && page.events.is_empty())
    {
        return Err(CollectorError::Payload);
    }
    let mut sequence = previous.unwrap_or(0);
    let mut identities = HashSet::new();
    for envelope in &page.events {
        if envelope.sequence <= sequence
            || !identities.insert(&envelope.event.event_id)
            || envelope
                .event
                .canonical_json()
                .map_err(|_| CollectorError::Payload)?
                .len()
                > EVENT_BYTES_LIMIT
        {
            return Err(CollectorError::Payload);
        }
        sequence = envelope.sequence;
    }
    if !page.events.is_empty() {
        if page.next_sequence != sequence {
            return Err(CollectorError::Payload);
        }
    } else if previous.is_some_and(|value| page.next_sequence != value) {
        return Err(CollectorError::Payload);
    }
    Ok(())
}

/// Validate the entire page before writing anything. Each append must report a
/// successful delivery: a committed PostgreSQL event or an accepted SQS message.
/// Queue acceptance does not establish downstream archival. A partial page
/// failure leaves the remote cursor unchanged and is safe to replay.
pub async fn collect_page<T: DeliveryTransport, S: AuditSink>(
    remote: &T,
    sink: &S,
    previous: Option<i64>,
) -> Result<DeliveryProgress, CollectorError> {
    let page = remote.fetch().await?;
    validate_page(&page, previous)?;
    for envelope in &page.events {
        sink.append(&envelope.event)
            .await
            .map_err(|_| CollectorError::Sink)?;
    }
    if !page.events.is_empty() {
        remote.acknowledge(page.next_sequence).await?;
    }
    Ok(DeliveryProgress {
        events: page.events.len(),
        sequence: page.next_sequence,
        has_more: page.has_more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        rc::Rc,
        thread,
    };
    use zeroth_audit::{AppendResult, AuditActor, AuditError, AuditFuture, AuditOutcome};

    fn event(sequence: i64) -> StreamEvent {
        StreamEvent {
            sequence,
            event: AuditEvent::new(
                format!("evt_{sequence}"),
                1,
                1,
                "session.created",
                AuditActor::new("user", "usr_1").unwrap(),
                AuditOutcome::Success,
            )
            .unwrap(),
        }
    }
    fn page() -> StreamPage {
        StreamPage {
            events: vec![event(1), event(4)],
            next_sequence: 4,
            has_more: false,
        }
    }

    struct FakeRemote {
        page: RefCell<StreamPage>,
        log: Rc<RefCell<Vec<String>>>,
        fail_ack: bool,
    }
    impl DeliveryTransport for FakeRemote {
        async fn fetch(&self) -> Result<StreamPage, CollectorError> {
            Ok(self.page.borrow().clone())
        }
        async fn acknowledge(&self, sequence: i64) -> Result<(), CollectorError> {
            self.log.borrow_mut().push(format!("ack:{sequence}"));
            if self.fail_ack {
                Err(CollectorError::Acknowledgement)
            } else {
                Ok(())
            }
        }
    }
    struct FakeSink {
        stored: RefCell<BTreeMap<String, String>>,
        fail_id: RefCell<Option<String>>,
        log: Rc<RefCell<Vec<String>>>,
    }
    impl AuditSink for FakeSink {
        fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
            Box::pin(async move {
                if self.fail_id.borrow().as_deref() == Some(&event.event_id) {
                    return Err(AuditError::Storage);
                }
                let serialized = event.canonical_json()?;
                let mut stored = self.stored.borrow_mut();
                let result = match stored.get(&event.event_id) {
                    Some(value) if value == &serialized => AppendResult::Duplicate,
                    Some(_) => return Err(AuditError::EventIdCollision),
                    None => {
                        stored.insert(event.event_id.clone(), serialized);
                        AppendResult::Inserted
                    }
                };
                self.log
                    .borrow_mut()
                    .push(format!("committed:{}", event.event_id));
                Ok(result)
            })
        }
    }

    #[tokio::test]
    async fn checkpoint_only_follows_every_commit_and_partial_failures_replay() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let remote = FakeRemote {
            page: RefCell::new(page()),
            log: log.clone(),
            fail_ack: false,
        };
        let sink = FakeSink {
            stored: RefCell::default(),
            fail_id: RefCell::new(Some("evt_4".into())),
            log: log.clone(),
        };
        assert_eq!(
            collect_page(&remote, &sink, None).await,
            Err(CollectorError::Sink)
        );
        assert_eq!(&*log.borrow(), &["committed:evt_1"]);
        *sink.fail_id.borrow_mut() = None;
        collect_page(&remote, &sink, None).await.unwrap();
        assert_eq!(
            &*log.borrow(),
            &[
                "committed:evt_1",
                "committed:evt_1",
                "committed:evt_4",
                "ack:4"
            ]
        );
        assert_eq!(sink.stored.borrow().len(), 2);
    }

    #[tokio::test]
    async fn lost_ack_retries_exact_events_without_advancing_uncommitted_data() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let remote = FakeRemote {
            page: RefCell::new(page()),
            log: log.clone(),
            fail_ack: true,
        };
        let sink = FakeSink {
            stored: RefCell::default(),
            fail_id: RefCell::default(),
            log: log.clone(),
        };
        for _ in 0..2 {
            assert_eq!(
                collect_page(&remote, &sink, None).await,
                Err(CollectorError::Acknowledgement)
            );
        }
        assert_eq!(sink.stored.borrow().len(), 2);
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|value| *value == "ack:4")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn malformed_page_is_rejected_before_sink_or_ack() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let remote = FakeRemote {
            page: RefCell::new(page()),
            log: log.clone(),
            fail_ack: false,
        };
        let sink = FakeSink {
            stored: RefCell::default(),
            fail_id: RefCell::default(),
            log: log.clone(),
        };
        remote.page.borrow_mut().events[1].sequence = 1;
        assert_eq!(
            collect_page(&remote, &sink, None).await,
            Err(CollectorError::Payload)
        );
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn validates_exact_cursors_schema_event_identity_and_bounds() {
        validate_page(&page(), Some(0)).unwrap();
        for invalid in [
            StreamPage {
                next_sequence: 5,
                ..page()
            },
            StreamPage {
                events: vec![event(4), event(1)],
                ..page()
            },
            StreamPage {
                events: vec![event(1); 101],
                ..page()
            },
            StreamPage {
                events: vec![],
                next_sequence: 4,
                has_more: true,
            },
        ] {
            assert_eq!(
                validate_page(&invalid, Some(0)),
                Err(CollectorError::Payload)
            );
        }
        assert_eq!(
            validate_page(&page(), Some(1)),
            Err(CollectorError::Payload)
        );
        let mut repeated_id = page();
        repeated_id.events[1].event.event_id = "evt_1".into();
        assert_eq!(
            validate_page(&repeated_id, None),
            Err(CollectorError::Payload)
        );
        let mut unsupported = page();
        unsupported.events[1].event.schema_version += 1;
        assert_eq!(
            validate_page(&unsupported, None),
            Err(CollectorError::Payload)
        );
        assert!(serde_json::from_str::<StreamPage>(
            r#"{"events":[],"nextSequence":0,"hasMore":false,"token":"hidden"}"#
        )
        .is_err());
    }

    fn serve(response: Vec<u8>) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            let header = String::from_utf8(request.clone()).unwrap();
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            assert!(length <= 2048);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            request.extend_from_slice(&body);
            // Oversized-response tests intentionally close the connection early.
            let _ = stream.write_all(&response);
            String::from_utf8(request).unwrap()
        });
        (format!("http://{address}/audit/stream"), join)
    }

    #[tokio::test]
    async fn http_fetch_uses_durable_consumer_and_never_follows_redirects() {
        let token = "12345678901234567890123456789012";
        let body = serde_json::to_string(&page()).unwrap();
        let (endpoint, join) = serve(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes());
        let remote = HttpStream::new(&endpoint, token, "pg-main").unwrap();
        assert_eq!(remote.fetch().await.unwrap().next_sequence, 4);
        let request = join.join().unwrap();
        assert!(request.starts_with("GET /audit/stream?consumer=pg-main&limit=100 HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {token}")));
        assert!(!request.contains("after="));
        let (endpoint, join) = serve(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
        let remote = HttpStream::new(&endpoint, token, "pg-main").unwrap();
        assert_eq!(
            remote.fetch().await.unwrap_err(),
            CollectorError::RemoteStatus
        );
        join.join().unwrap();
    }

    #[tokio::test]
    async fn oversized_declared_and_chunked_http_payloads_are_rejected() {
        let token = "12345678901234567890123456789012";
        let (endpoint, join) = serve(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", PAGE_BYTES_LIMIT + 1).into_bytes());
        assert_eq!(
            HttpStream::new(&endpoint, token, "pg")
                .unwrap()
                .fetch()
                .await
                .unwrap_err(),
            CollectorError::Payload
        );
        join.join().unwrap();
        let chunk = vec![b' '; PAGE_BYTES_LIMIT + 1];
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n", chunk.len()).into_bytes();
        response.extend_from_slice(&chunk);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (endpoint, join) = serve(response);
        assert_eq!(
            HttpStream::new(&endpoint, token, "pg")
                .unwrap()
                .fetch()
                .await
                .unwrap_err(),
            CollectorError::Payload
        );
        join.join().unwrap();
    }

    #[tokio::test]
    async fn http_ack_posts_a_checkpoint_and_rejects_an_unexpected_consumer_or_sequence() {
        let token = "12345678901234567890123456789012";
        for (body, expected) in [
            (r#"{"consumerId":"pg-main","sequence":4}"#, Ok(())),
            (
                r#"{"consumerId":"another","sequence":4}"#,
                Err(CollectorError::Acknowledgement),
            ),
            (
                r#"{"consumerId":"pg-main","sequence":5}"#,
                Err(CollectorError::Acknowledgement),
            ),
        ] {
            let (endpoint, join) = serve(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes());
            let remote = HttpStream::new(&endpoint, token, "pg-main").unwrap();
            assert_eq!(remote.acknowledge(4).await, expected);
            let request = join.join().unwrap();
            assert!(request.starts_with("POST /audit/stream/ack HTTP/1.1"));
            let body: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body,
                serde_json::json!({"consumerId":"pg-main","sequence":4})
            );
        }
    }

    #[test]
    fn configuration_rejects_secret_urls_query_credentials_and_plaintext() {
        for endpoint in [
            "http://id.example/audit/stream",
            "https://user:secret@id.example/audit/stream",
            "https://id.example/audit/stream?token=secret",
            "https://id.example/audit/stream#secret",
            "https://id.example/other",
            "http://localhost.evil/audit/stream",
        ] {
            assert!(validate_endpoint(endpoint).is_err());
        }
        assert!(validate_endpoint("https://id.example/audit/stream").is_ok());
        assert!(validate_endpoint("http://[::1]/audit/stream").is_ok());
        assert_eq!(CollectorError::Transport.to_string(), "transport_failed");
    }
}
