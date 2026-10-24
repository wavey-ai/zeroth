use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::Value;
use std::sync::Arc;
use zeroth_aws_authorizer::{Authorizer, Config};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Config {
        issuer: std::env::var("ZEROTH_ISSUER")?,
        jwks_url: std::env::var("ZEROTH_JWKS_URL")?,
        audience: std::env::var("ZEROTH_AUDIENCE")?,
        client_id: std::env::var("ZEROTH_CLIENT_ID")?,
    };
    let authorizer = Arc::new(Authorizer::new(config)?);
    lambda_runtime::run(service_fn(move |event: LambdaEvent<Value>| {
        let authorizer = Arc::clone(&authorizer);
        async move { Ok::<Value, Error>(authorizer.authorize(&event.payload).await) }
    }))
    .await
}
