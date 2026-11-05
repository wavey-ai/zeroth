use std::{env, process::ExitCode, time::Duration};
use zeroth_audit::{AuditEvent, AuditFuture, AuditSink};
use zeroth_audit_collector::{collect_page, CollectorError, HttpStream};

struct Options {
    once: bool,
    interval: Duration,
    initialize: bool,
    sink: SinkKind,
}

#[derive(Clone, Copy)]
enum SinkKind {
    Postgres,
    Sqs,
}

impl SinkKind {
    fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Sqs => "sqs",
        }
    }
}

impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>, CollectorError> {
        let mut result = Self {
            once: false,
            interval: Duration::from_secs(5),
            initialize: false,
            sink: SinkKind::Postgres,
        };
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--help" | "-h" => return Ok(None),
                "--once" => result.once = true,
                "--initialize-schema" => result.initialize = true,
                "--sink" => {
                    result.sink = match args.next().as_deref() {
                        Some("postgres") => SinkKind::Postgres,
                        Some("sqs") => SinkKind::Sqs,
                        _ => return Err(CollectorError::Configuration),
                    }
                }
                "--interval-seconds" => {
                    let value = args.next().ok_or(CollectorError::Configuration)?;
                    if value.is_empty()
                        || value.starts_with('0')
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return Err(CollectorError::Configuration);
                    }
                    let value: u64 = value.parse().map_err(|_| CollectorError::Configuration)?;
                    if value > 3600 {
                        return Err(CollectorError::Configuration);
                    }
                    result.interval = Duration::from_secs(value);
                }
                _ => return Err(CollectorError::Configuration),
            }
        }
        if result.initialize && matches!(result.sink, SinkKind::Sqs) {
            return Err(CollectorError::Configuration);
        }
        Ok(Some(result))
    }
}

enum ConfiguredSink {
    #[cfg(feature = "postgres")]
    Postgres(zeroth_audit::postgres::PostgresAuditSink),
    #[cfg(feature = "aws")]
    Sqs(zeroth_audit_aws::SqsAuditSink),
}

impl ConfiguredSink {
    async fn connect(kind: SinkKind, initialize: bool) -> Result<Self, CollectorError> {
        match kind {
            SinkKind::Postgres => {
                #[cfg(feature = "postgres")]
                {
                    let connection = required_env("DATABASE_URL")?;
                    let sink = zeroth_audit::postgres::PostgresAuditSink::connect(&connection)
                        .await
                        .map_err(|_| CollectorError::Sink)?;
                    if initialize {
                        sink.initialize().await.map_err(|_| CollectorError::Sink)?;
                    }
                    Ok(Self::Postgres(sink))
                }
                #[cfg(not(feature = "postgres"))]
                {
                    let _ = initialize;
                    Err(CollectorError::Configuration)
                }
            }
            SinkKind::Sqs => {
                #[cfg(feature = "aws")]
                {
                    let queue_url = required_env("AUDIT_SQS_QUEUE_URL")?;
                    let group_id = env::var("AUDIT_SQS_FIFO_GROUP_ID").ok();
                    let config =
                        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                    let sink = zeroth_audit_aws::SqsAuditSink::new(
                        aws_sdk_sqs::Client::new(&config),
                        queue_url,
                        group_id,
                    )
                    .map_err(|_| CollectorError::Configuration)?;
                    Ok(Self::Sqs(sink))
                }
                #[cfg(not(feature = "aws"))]
                {
                    Err(CollectorError::Configuration)
                }
            }
        }
    }
}

impl AuditSink for ConfiguredSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AuditFuture<'a> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(sink) => sink.append(event),
            #[cfg(feature = "aws")]
            Self::Sqs(sink) => sink.append(event),
            #[cfg(not(any(feature = "postgres", feature = "aws")))]
            _ => {
                let _ = event;
                Box::pin(async { Err(zeroth_audit::AuditError::Storage) })
            }
        }
    }
}

fn required_env(name: &'static str) -> Result<String, CollectorError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(CollectorError::Configuration)
}

#[tokio::main]
pub async fn run() -> ExitCode {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
    let metadata = tracing_subscriber::filter::filter_fn(|metadata| {
        metadata.target().starts_with("zeroth_audit_collector")
            || metadata.target() == "zeroth.audit_delivery"
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(false)
                .with_filter(metadata),
        )
        .init();
    let options = match Options::parse(env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("zeroth-audit-collector --sink postgres|sqs [--once] [--interval-seconds 5] [--initialize-schema]\nEnvironment: ZEROTH_AUDIT_STREAM_URL, AUDIT_STREAM_TOKEN, AUDIT_CONSUMER_ID; DATABASE_URL for postgres; AUDIT_SQS_QUEUE_URL and optional AUDIT_SQS_FIFO_GROUP_ID for sqs. AWS credentials use the official SDK provider chain. --once processes one page (at most 100 events). Give each sink its own consumer ID.");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            tracing::error!(error_code = error.code(), "collector_configuration_failed");
            return ExitCode::FAILURE;
        }
    };
    let remote = (|| {
        HttpStream::new(
            &required_env("ZEROTH_AUDIT_STREAM_URL")?,
            &required_env("AUDIT_STREAM_TOKEN")?,
            &required_env("AUDIT_CONSUMER_ID")?,
        )
    })();
    let remote = match remote {
        Ok(remote) => remote,
        Err(error) => {
            tracing::error!(error_code = error.code(), "collector_configuration_failed");
            return ExitCode::FAILURE;
        }
    };
    let mut sink = None;
    let mut previous = None;
    let mut initialize = options.initialize;
    loop {
        if sink.is_none() {
            match ConfiguredSink::connect(options.sink, initialize).await {
                Ok(connected) => {
                    sink = Some(connected);
                    initialize = false;
                }
                Err(error) => {
                    tracing::error!(
                        sink = options.sink.name(),
                        error_code = error.code(),
                        "collector_sink_unavailable"
                    );
                    if options.once || error == CollectorError::Configuration {
                        return ExitCode::FAILURE;
                    }
                    tokio::time::sleep(options.interval).await;
                    continue;
                }
            }
        }
        let result = collect_page(&remote, sink.as_ref().expect("connected sink"), previous).await;
        match result {
            Ok(progress) => {
                previous = Some(progress.sequence);
                tracing::info!(
                    sink = options.sink.name(),
                    event_count = progress.events,
                    sequence = progress.sequence,
                    has_more = progress.has_more,
                    "collector_page_delivered"
                );
                if options.once {
                    return ExitCode::SUCCESS;
                }
                if progress.has_more {
                    continue;
                }
            }
            Err(error) => {
                tracing::error!(
                    sink = options.sink.name(),
                    error_code = error.code(),
                    "collector_delivery_failed"
                );
                // The next poll recovers the server's checkpoint. Successful
                // appends are idempotent if the ACK request/response was lost.
                previous = None;
                if error == CollectorError::Sink {
                    sink = None;
                }
                if options.once {
                    return ExitCode::FAILURE;
                }
            }
        }
        tokio::time::sleep(options.interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_bounded_and_never_accept_credentials_on_command_line() {
        for args in [
            vec!["--interval-seconds", "0"],
            vec!["--interval-seconds", "01"],
            vec!["--interval-seconds", "3601"],
            vec!["--sink", "unknown"],
            vec!["--token", "secret"],
            vec!["--sink", "sqs", "--initialize-schema"],
        ] {
            assert!(Options::parse(args.into_iter().map(str::to_owned)).is_err());
        }
        let parsed = Options::parse(
            ["--once", "--sink", "postgres", "--interval-seconds", "10"].map(str::to_owned),
        )
        .unwrap()
        .unwrap();
        assert!(parsed.once);
        assert_eq!(parsed.interval, Duration::from_secs(10));
    }
}
