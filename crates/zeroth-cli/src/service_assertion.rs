use super::{es256_private_scalar_from_config, option_value};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::SigningKey;
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroth_oidc::service::{build_service_client_assertion_claims, sign_service_client_assertion};

#[derive(Debug, Eq, PartialEq)]
struct Options {
    client_id: String,
    key_id: String,
    audience: String,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let (mut client_id, mut key_id, mut audience) = (None, None, None);
        let mut index = 0;
        while index < args.len() {
            let (name, target) = match args[index].as_str() {
                "--client-id" => ("--client-id", &mut client_id),
                "--key-id" => ("--key-id", &mut key_id),
                "--audience" => ("--audience", &mut audience),
                _ => return Err("service-assertion accepts --client-id, --key-id and --audience; supply the private key on stdin".into()),
            };
            if target.is_some() {
                return Err(format!("duplicate {name}"));
            }
            *target = Some(option_value(&args, &mut index, name)?);
            index += 1;
        }
        Ok(Self {
            client_id: client_id.ok_or("--client-id is required")?,
            key_id: key_id.ok_or("--key-id is required")?,
            audience: audience.ok_or("--audience is required")?,
        })
    }
}

pub(super) fn run(args: Vec<String>) -> Result<(), String> {
    let options = Options::parse(args)?;
    let mut private_key = String::new();
    io::stdin()
        .take(16 * 1024 + 1)
        .read_to_string(&mut private_key)
        .map_err(|_| "could not read private key from stdin")?;
    if private_key.len() > 16 * 1024 {
        return Err("private key input exceeds 16 KiB".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_secs();
    let assertion = create(&options, &private_key, now as i64)?;
    print!("{assertion}");
    Ok(())
}

fn create(options: &Options, private_key: &str, now: i64) -> Result<String, String> {
    let scalar = es256_private_scalar_from_config(private_key)?;
    let signing_key =
        SigningKey::from_slice(&scalar).map_err(|_| "invalid ES256 private key".to_owned())?;
    let mut nonce = [0_u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| "could not generate assertion identifier")?;
    let claims = build_service_client_assertion_claims(
        &options.client_id,
        &options.audience,
        now,
        120,
        &URL_SAFE_NO_PAD.encode(nonce),
    )
    .map_err(|error| error.description)?;
    sign_service_client_assertion(&signing_key, &options.key_id, &claims)
        .map_err(|error| error.description.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroth_oidc::service::{
        verify_service_client_assertion, ServiceAssertionValidation, ServiceClient, ServiceJwks,
    };

    #[test]
    fn cli_assertions_verify_with_registered_public_key_and_unique_identifiers() {
        let key = crate::generate_signing_key_artifact("agent-v1").unwrap();
        let options = Options {
            client_id: "svc_cli".into(),
            key_id: "agent-v1".into(),
            audience: "https://id.example.test/oauth/token".into(),
        };
        let client = ServiceClient {
            id: options.client_id.clone(),
            tenant_id: "tenant-a".into(),
            name: "CLI service".into(),
            disabled: false,
            revision: 1,
            token_ttl_seconds: 600,
            allowed_audiences: vec!["https://api.example.test".into()],
            allowed_scopes: vec!["releases:read".into()],
            public_jwks: ServiceJwks::from_json(&serde_json::to_string(&key.public_jwks).unwrap())
                .unwrap(),
        };
        let first = create(&options, &key.jwt_es256_private_key, 1_000).unwrap();
        let second = create(&options, &key.jwt_es256_private_key, 1_000).unwrap();
        let validation = ServiceAssertionValidation {
            token_endpoint: options.audience.clone(),
            now: 1_001,
            max_lifetime_seconds: 300,
            clock_skew_seconds: 0,
        };
        let a = verify_service_client_assertion(&first, &client, &validation).unwrap();
        let b = verify_service_client_assertion(&second, &client, &validation).unwrap();
        assert_ne!(a.jti, b.jti);
        assert_eq!(a.exp - a.iat, 120);
    }

    #[test]
    fn assertion_options_reject_ambiguous_or_missing_inputs() {
        assert!(Options::parse(vec![]).is_err());
        assert!(Options::parse(vec!["--private-key".into(), "secret".into()]).is_err());
        assert!(Options::parse(vec![
            "--client-id".into(),
            "svc_a".into(),
            "--client-id".into(),
            "svc_b".into()
        ])
        .is_err());
    }
}
