use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    pkcs8::DecodePrivateKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    io::{self, Read},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroth_core::{
    PasswordScheme, PASSWORD_CURRENT_VERSION, PASSWORD_PBKDF2_ITERATIONS,
    PASSWORD_PBKDF2_MAX_ITERATIONS, PASSWORD_PBKDF2_MIN_ITERATIONS,
};
use zeroth_server::{ZerothServerConfig, ROUTES};

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().cloned().unwrap_or_else(|| "help".to_owned());
    if !args.is_empty() {
        args.remove(0);
    }

    let result = match command.as_str() {
        "routes" => {
            for route in ROUTES {
                println!("{} {}", route.method, route.path);
            }
            Ok(())
        }
        "issuer" => {
            let base_url = args
                .first()
                .cloned()
                .unwrap_or_else(|| ZerothServerConfig::default().public_base_url);
            let config = ZerothServerConfig {
                public_base_url: base_url,
                ..ZerothServerConfig::default()
            };
            println!("{}", config.issuer().issuer);
            Ok(())
        }
        "schema" => {
            match SchemaOptions::from_args(args).and_then(|options| print_schema(options)) {
                Ok(()) => Ok(()),
                Err(error) => Err(error),
            }
        }
        "password-policy" => {
            let subcommand = args.first().cloned().unwrap_or_else(|| "help".to_owned());
            if !args.is_empty() {
                args.remove(0);
            }
            match subcommand.as_str() {
                "benchmark" => benchmark_password_policy(),
                "validate" => validate_password_policy(),
                _ => {
                    print_password_policy_usage();
                    Ok(())
                }
            }
        }
        "validate-secret" => match SecretKind::from_args(args).and_then(validate_secret_stdin) {
            Ok(()) => {
                println!("ok");
                Ok(())
            }
            Err(error) => Err(error),
        },
        "apple-client-secret" => {
            match AppleClientSecretOptions::from_args(args).and_then(|options| {
                apple_client_secret(&options).map(|client_secret| (options, client_secret))
            }) {
                Ok((_options, client_secret)) => {
                    println!("{client_secret}");
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        "signing-key" => match SigningKeyOptions::from_args(args).and_then(|options| {
            generate_signing_key_artifact(&options.kid).map(|artifact| (options, artifact))
        }) {
            Ok((options, artifact)) => print_signing_key_artifact(&artifact, options.format),
            Err(error) => Err(error),
        },
        _ => {
            print_usage();
            Ok(())
        }
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AppleClientSecretOptions {
    team_id: String,
    key_id: String,
    client_id: String,
    private_key_path: String,
    ttl_days: i64,
    issued_at: i64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SigningKeyOptions {
    kid: String,
    format: SigningKeyOutputFormat,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct SchemaOptions {
    only: SchemaOnly,
    format: SchemaOutputFormat,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SchemaOnly {
    All,
    Migrations,
    Compatibility,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SchemaOutputFormat {
    Sql,
    Lines,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SigningKeyOutputFormat {
    Env,
    Json,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SecretKind {
    Es256PrivateKey,
    ApplePrivateKey,
    PreviousPublicJwks,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct AppleJwtHeader {
    alg: &'static str,
    kid: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct AppleClientSecretClaims {
    iss: String,
    iat: i64,
    exp: i64,
    aud: &'static str,
    sub: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct SigningKeyArtifact {
    jwt_key_id: String,
    jwt_es256_private_key: String,
    public_jwks: PublicJwks,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PublicJwks {
    keys: Vec<PublicJwk>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
struct PublicJwk {
    kty: &'static str,
    #[serde(rename = "use")]
    key_use: &'static str,
    kid: String,
    alg: &'static str,
    crv: &'static str,
    x: String,
    y: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJwksInput {
    keys: Vec<PublicJwkInput>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJwkInput {
    kty: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    alg: String,
    crv: String,
    x: String,
    y: String,
}

impl AppleClientSecretOptions {
    fn from_args(args: Vec<String>) -> Result<Self, String> {
        let mut team_id = None;
        let mut key_id = None;
        let mut client_id = None;
        let mut private_key_path = None;
        let mut ttl_days = None;
        let mut issued_at = None;

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--team-id" => team_id = Some(option_value(&args, &mut index, "--team-id")?),
                "--key-id" => key_id = Some(option_value(&args, &mut index, "--key-id")?),
                "--client-id" => client_id = Some(option_value(&args, &mut index, "--client-id")?),
                "--private-key" | "--private-key-path" => {
                    private_key_path = Some(option_value(&args, &mut index, "--private-key")?)
                }
                "--ttl-days" => {
                    ttl_days = Some(
                        option_value(&args, &mut index, "--ttl-days")?
                            .parse::<i64>()
                            .map_err(|error| format!("--ttl-days must be an integer: {error}"))?,
                    )
                }
                "--issued-at" => {
                    issued_at = Some(
                        option_value(&args, &mut index, "--issued-at")?
                            .parse::<i64>()
                            .map_err(|error| format!("--issued-at must be an integer: {error}"))?,
                    )
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                option => return Err(format!("unknown apple-client-secret option: {option}")),
            }
            index += 1;
        }

        let ttl_days = ttl_days.unwrap_or(180);
        if !(1..=180).contains(&ttl_days) {
            return Err("--ttl-days must be between 1 and 180".to_owned());
        }

        Ok(Self {
            team_id: required_option_or_env(team_id, "APPLE_TEAM_ID", "--team-id")?,
            key_id: required_option_or_env(key_id, "APPLE_KEY_ID", "--key-id")?,
            client_id: required_option_or_env(client_id, "APPLE_CLIENT_ID", "--client-id")?,
            private_key_path: required_option_or_env(
                private_key_path,
                "APPLE_PRIVATE_KEY_PATH",
                "--private-key",
            )?,
            ttl_days,
            issued_at: issued_at.unwrap_or_else(current_unix_timestamp),
        })
    }
}

impl SigningKeyOptions {
    fn from_args(args: Vec<String>) -> Result<Self, String> {
        let mut kid = None;
        let mut format = SigningKeyOutputFormat::Env;

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--kid" => kid = Some(option_value(&args, &mut index, "--kid")?),
                "--format" => {
                    format = SigningKeyOutputFormat::from_value(&option_value(
                        &args, &mut index, "--format",
                    )?)?
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                option => return Err(format!("unknown signing-key option: {option}")),
            }
            index += 1;
        }

        Ok(Self {
            kid: kid
                .or_else(|| std::env::var("JWT_KEY_ID").ok())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("zeroth-es256-{}", current_unix_timestamp())),
            format,
        })
    }
}

impl SchemaOptions {
    fn from_args(args: Vec<String>) -> Result<Self, String> {
        let mut only = SchemaOnly::All;
        let mut format = SchemaOutputFormat::Sql;

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--only" => {
                    only = SchemaOnly::from_value(&option_value(&args, &mut index, "--only")?)?
                }
                "--format" => {
                    format = SchemaOutputFormat::from_value(&option_value(
                        &args, &mut index, "--format",
                    )?)?
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                option => return Err(format!("unknown schema option: {option}")),
            }
            index += 1;
        }

        Ok(Self { only, format })
    }
}

impl SchemaOnly {
    fn from_value(value: &str) -> Result<Self, String> {
        match value {
            "all" => Ok(Self::All),
            "migrations" => Ok(Self::Migrations),
            "compatibility" => Ok(Self::Compatibility),
            _ => Err("--only must be all, migrations, or compatibility".to_owned()),
        }
    }
}

impl SchemaOutputFormat {
    fn from_value(value: &str) -> Result<Self, String> {
        match value {
            "sql" => Ok(Self::Sql),
            "lines" => Ok(Self::Lines),
            _ => Err("--format must be sql or lines".to_owned()),
        }
    }
}

impl SigningKeyOutputFormat {
    fn from_value(value: &str) -> Result<Self, String> {
        match value {
            "env" => Ok(Self::Env),
            "json" => Ok(Self::Json),
            _ => Err("--format must be env or json".to_owned()),
        }
    }
}

impl SecretKind {
    fn from_args(args: Vec<String>) -> Result<Self, String> {
        let mut value = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                item if value.is_none() => value = Some(item.to_owned()),
                option => return Err(format!("unknown validate-secret option: {option}")),
            }
            index += 1;
        }

        Self::from_value(value.as_deref().ok_or_else(|| {
            "validate-secret requires es256-private-key, apple-private-key, or previous-public-jwks"
                .to_owned()
        })?)
    }

    fn from_value(value: &str) -> Result<Self, String> {
        match value {
            "es256-private-key" => Ok(Self::Es256PrivateKey),
            "apple-private-key" => Ok(Self::ApplePrivateKey),
            "previous-public-jwks" => Ok(Self::PreviousPublicJwks),
            _ => Err(
                "validate-secret kind must be es256-private-key, apple-private-key, or previous-public-jwks"
                    .to_owned(),
            ),
        }
    }
}

fn print_schema(options: SchemaOptions) -> Result<(), String> {
    match options.format {
        SchemaOutputFormat::Sql => {
            let sql = schema_sql(options.only);
            print!("{sql}");
            if !sql.ends_with('\n') {
                println!();
            }
            Ok(())
        }
        SchemaOutputFormat::Lines => {
            print!("{}", schema_lines(options.only));
            Ok(())
        }
    }
}

fn schema_lines(only: SchemaOnly) -> String {
    let mut output = String::new();
    for statement in schema_statements(only) {
        output.push_str(&statement.split_whitespace().collect::<Vec<_>>().join(" "));
        output.push('\n');
    }
    output
}

fn schema_sql(only: SchemaOnly) -> String {
    match only {
        SchemaOnly::All => {
            let mut sql = migration_sql();
            let compatibility = compatibility_sql();
            if !compatibility.is_empty() {
                if !sql.ends_with("\n\n") {
                    if !sql.ends_with('\n') {
                        sql.push('\n');
                    }
                    sql.push('\n');
                }
                sql.push_str(&compatibility);
            }
            sql
        }
        SchemaOnly::Migrations => migration_sql(),
        SchemaOnly::Compatibility => compatibility_sql(),
    }
}

fn migration_sql() -> String {
    let mut sql = String::new();
    for migration in zeroth_storage::migrations::ALL {
        if !sql.is_empty() && !sql.ends_with("\n\n") {
            if !sql.ends_with('\n') {
                sql.push('\n');
            }
            sql.push('\n');
        }
        sql.push_str(migration.sql.trim());
        sql.push('\n');
    }
    sql
}

fn compatibility_sql() -> String {
    let mut sql = String::new();
    for statement in compatibility_statements() {
        sql.push_str(&statement);
        sql.push_str(";\n");
    }
    sql
}

fn schema_statements(only: SchemaOnly) -> Vec<String> {
    match only {
        SchemaOnly::All => migration_statements()
            .into_iter()
            .chain(compatibility_statements())
            .collect(),
        SchemaOnly::Migrations => migration_statements(),
        SchemaOnly::Compatibility => compatibility_statements(),
    }
}

fn migration_statements() -> Vec<String> {
    zeroth_storage::migrations::ALL
        .iter()
        .flat_map(|migration| migration.statements())
        .map(str::to_owned)
        .collect()
}

fn compatibility_statements() -> Vec<String> {
    zeroth_storage::compatibility::ALL
        .iter()
        .copied()
        .map(zeroth_storage::CompatibilityColumn::alter_table_sql)
        .collect()
}

fn validate_secret_stdin(kind: SecretKind) -> Result<(), String> {
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .map_err(|error| format!("could not read secret from stdin: {error}"))?;
    validate_secret_value(kind, &value)
}

fn validate_secret_value(kind: SecretKind, value: &str) -> Result<(), String> {
    match kind {
        SecretKind::Es256PrivateKey => {
            let scalar = es256_private_scalar_from_config(value)?;
            SigningKey::from_slice(&scalar)
                .map(|_| ())
                .map_err(|error| format!("invalid ES256 private key: {error}"))
        }
        SecretKind::ApplePrivateKey => SigningKey::from_pkcs8_pem(value)
            .map(|_| ())
            .map_err(|error| format!("invalid Apple private key PEM: {error}")),
        SecretKind::PreviousPublicJwks => validate_previous_public_jwks(value),
    }
}

fn validate_previous_public_jwks(value: &str) -> Result<(), String> {
    let jwks = serde_json::from_str::<PublicJwksInput>(value)
        .map_err(|error| format!("invalid previous public JWKS JSON: {error}"))?;
    if jwks.keys.is_empty() {
        return Err("previous public JWKS must include at least one key".to_owned());
    }
    for key in jwks.keys {
        validate_previous_public_jwk(&key)?;
    }
    Ok(())
}

fn validate_previous_public_jwk(key: &PublicJwkInput) -> Result<(), String> {
    if key.kty != "EC" {
        return Err("previous public JWKS only supports EC keys".to_owned());
    }
    if key.key_use != "sig" {
        return Err("previous public JWKS keys must have use=sig".to_owned());
    }
    if key.alg != "ES256" {
        return Err("previous public JWKS keys must have alg=ES256".to_owned());
    }
    if key.crv != "P-256" {
        return Err("previous public JWKS keys must have crv=P-256".to_owned());
    }
    if key.kid.trim().is_empty() {
        return Err("previous public JWKS keys must include kid".to_owned());
    }
    let x = decode_public_jwk_coordinate(&key.x, "x")?;
    let y = decode_public_jwk_coordinate(&key.y, "y")?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&point)
        .map_err(|error| format!("invalid previous public JWKS key {}: {error}", key.kid))?;
    Ok(())
}

fn decode_public_jwk_coordinate(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|error| {
            format!("previous public JWKS key {field_name} must be base64url: {error}")
        })
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!(
                    "previous public JWKS key {field_name} must decode to 32 bytes"
                ))
            }
        })
}

fn es256_private_scalar_from_config(private_key: &str) -> Result<Vec<u8>, String> {
    let trimmed = private_key.trim();
    if trimmed.starts_with('{') {
        let value = serde_json::from_str::<serde_json::Value>(trimmed)
            .map_err(|error| format!("invalid ES256 JWK JSON: {error}"))?;
        let d = value
            .get("d")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "ES256 JWK private key is missing d".to_owned())?;
        return decode_private_key_bytes(d, "ES256 JWK d");
    }

    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex_to_bytes(trimmed);
    }

    decode_private_key_bytes(trimmed, "ES256 private key")
}

fn decode_private_key_bytes(value: &str, field_name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .map_err(|error| format!("{field_name} must be base64url, base64, or hex: {error}"))
        .and_then(|bytes| {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!("{field_name} must decode to 32 bytes"))
            }
        })
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|error| format!("invalid hex ES256 private key: {error}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn apple_client_secret(options: &AppleClientSecretOptions) -> Result<String, String> {
    let pem = std::fs::read_to_string(&options.private_key_path)
        .map_err(|error| format!("could not read Apple private key: {error}"))?;
    let signing_key = SigningKey::from_pkcs8_pem(&pem)
        .map_err(|error| format!("invalid Apple private key PEM: {error}"))?;
    let claims = AppleClientSecretClaims {
        iss: options.team_id.clone(),
        iat: options.issued_at,
        exp: options.issued_at + options.ttl_days * 24 * 60 * 60,
        aud: "https://appleid.apple.com",
        sub: options.client_id.clone(),
    };
    let header = AppleJwtHeader {
        alg: "ES256",
        kid: options.key_id.clone(),
    };
    let signing_input = format!("{}.{}", jwt_segment(&header)?, jwt_segment(&claims)?);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn generate_signing_key_artifact(kid: &str) -> Result<SigningKeyArtifact, String> {
    loop {
        let mut scalar = [0_u8; 32];
        getrandom::getrandom(&mut scalar)
            .map_err(|error| format!("could not read OS randomness: {error}"))?;
        if let Ok(artifact) = signing_key_artifact_from_scalar(kid, &scalar) {
            return Ok(artifact);
        }
    }
}

fn signing_key_artifact_from_scalar(
    kid: &str,
    scalar: &[u8],
) -> Result<SigningKeyArtifact, String> {
    if kid.trim().is_empty() {
        return Err("--kid must not be empty".to_owned());
    }
    if scalar.len() != 32 {
        return Err("ES256 signing key scalar must be 32 bytes".to_owned());
    }

    let signing_key = SigningKey::from_slice(scalar)
        .map_err(|error| format!("invalid ES256 signing key scalar: {error}"))?;
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| "ES256 public key is missing x coordinate".to_owned())?;
    let y = point
        .y()
        .ok_or_else(|| "ES256 public key is missing y coordinate".to_owned())?;

    Ok(SigningKeyArtifact {
        jwt_key_id: kid.to_owned(),
        jwt_es256_private_key: URL_SAFE_NO_PAD.encode(scalar),
        public_jwks: PublicJwks {
            keys: vec![PublicJwk {
                kty: "EC",
                key_use: "sig",
                kid: kid.to_owned(),
                alg: "ES256",
                crv: "P-256",
                x: URL_SAFE_NO_PAD.encode(x),
                y: URL_SAFE_NO_PAD.encode(y),
            }],
        },
    })
}

fn print_signing_key_artifact(
    artifact: &SigningKeyArtifact,
    format: SigningKeyOutputFormat,
) -> Result<(), String> {
    match format {
        SigningKeyOutputFormat::Env => {
            let public_jwks_json = serde_json::to_string(&artifact.public_jwks)
                .map_err(|error| format!("could not serialize public JWKS: {error}"))?;
            println!("export JWT_KEY_ID={}", shell_quote(&artifact.jwt_key_id));
            println!(
                "export JWT_ES256_PRIVATE_KEY={}",
                shell_quote(&artifact.jwt_es256_private_key)
            );
            println!(
                "# Public JWKS to keep for JWT_PREVIOUS_PUBLIC_JWKS_JSON after rotating away from this key:"
            );
            println!("# {}", public_jwks_json);
            Ok(())
        }
        SigningKeyOutputFormat::Json => serde_json::to_string_pretty(artifact)
            .map(|json| println!("{json}"))
            .map_err(|error| format!("could not serialize signing key artifact: {error}")),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn jwt_segment<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|json| URL_SAFE_NO_PAD.encode(json))
        .map_err(|error| format!("could not serialize JWT segment: {error}"))
}

fn option_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn required_option_or_env(
    option: Option<String>,
    env_name: &str,
    option_name: &str,
) -> Result<String, String> {
    option
        .or_else(|| std::env::var(env_name).ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing {option_name} or {env_name}"))
}

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn print_usage() {
    eprintln!(
        "usage:
  zeroth routes
  zeroth issuer [base-url]
  zeroth schema [--only all|migrations|compatibility] [--format sql|lines]
  zeroth password-policy benchmark
  zeroth password-policy validate
  zeroth validate-secret es256-private-key|apple-private-key|previous-public-jwks < secret-value
  zeroth apple-client-secret --team-id TEAM --key-id KEY --client-id CLIENT --private-key AuthKey.p8 [--ttl-days 180]
  zeroth signing-key [--kid KID] [--format env|json]"
    );
}

fn print_password_policy_usage() {
    eprintln!("usage:");
    eprintln!("  zeroth password-policy benchmark");
    eprintln!("  zeroth password-policy validate");
}

fn validate_password_policy() -> Result<(), String> {
    if PasswordScheme::Pbkdf2Sha256.as_str() != "pbkdf2-sha256" {
        return Err("password scheme identifier is inconsistent".to_owned());
    }
    if !(PASSWORD_PBKDF2_MIN_ITERATIONS..=PASSWORD_PBKDF2_MAX_ITERATIONS)
        .contains(&PASSWORD_PBKDF2_ITERATIONS)
    {
        return Err("password iteration count is out of range".to_owned());
    }

    let params_json = serde_json::json!({
        "iterations": PASSWORD_PBKDF2_ITERATIONS,
        "prehash": "hmac-sha256",
    })
    .to_string();
    let parsed: PasswordParamsJson = serde_json::from_str(&params_json)
        .map_err(|error| format!("password params json is invalid: {error}"))?;
    if parsed.iterations != PASSWORD_PBKDF2_ITERATIONS {
        return Err("password params json lost the iteration count".to_owned());
    }
    if parsed.prehash.as_deref() != Some("hmac-sha256") {
        return Err("password params json lost the prehash policy".to_owned());
    }

    println!(
        "ok algorithm={} version={} iterations={}",
        PasswordScheme::Pbkdf2Sha256.as_str(),
        PASSWORD_CURRENT_VERSION,
        PASSWORD_PBKDF2_ITERATIONS
    );
    Ok(())
}

fn benchmark_password_policy() -> Result<(), String> {
    let salt = "benchmark-salt-v1";
    let pepper = "benchmark-pepper-v1";
    let password = "benchmark-password-v1";

    let start = Instant::now();
    let hash = password_hash_current(password, salt, pepper)?;
    let elapsed = start.elapsed();

    println!(
        "algorithm={} version={} iterations={} duration_ms={} hash_len={}",
        PasswordScheme::Pbkdf2Sha256.as_str(),
        PASSWORD_CURRENT_VERSION,
        PASSWORD_PBKDF2_ITERATIONS,
        elapsed.as_millis(),
        hash.len()
    );
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct PasswordParamsJson {
    iterations: u32,
    #[serde(default)]
    prehash: Option<String>,
}

fn password_hash_current(password: &str, salt: &str, pepper: &str) -> Result<String, String> {
    let prehash = password_prehash(pepper.as_bytes(), password.as_bytes());
    let digest = pbkdf2_sha256(&prehash, salt.as_bytes(), PASSWORD_PBKDF2_ITERATIONS, 32)?;
    Ok(bytes_to_hex(&digest))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn password_prehash(pepper: &[u8], password: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(pepper).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(password);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>, String> {
    if iterations == 0 {
        return Err("password iterations must be positive".to_owned());
    }
    let blocks = output_len.div_ceil(32);
    let mut output = Vec::with_capacity(blocks * 32);
    for block_index in 1..=blocks {
        output.extend_from_slice(&pbkdf2_block(
            password,
            salt,
            iterations,
            block_index as u32,
        ));
    }
    output.truncate(output_len);
    Ok(output)
}

fn pbkdf2_block(password: &[u8], salt: &[u8], iterations: u32, block_index: u32) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(password).expect("HMAC-SHA256 accepts arbitrary-length keys");
    mac.update(salt);
    mac.update(&block_index.to_be_bytes());
    let u = mac.finalize().into_bytes();
    let mut block = [0u8; 32];
    block.copy_from_slice(&u);

    let mut previous = u;
    for _ in 1..iterations {
        let mut mac = HmacSha256::new_from_slice(password)
            .expect("HMAC-SHA256 accepts arbitrary-length keys");
        mac.update(&previous);
        previous = mac.finalize().into_bytes();
        for (slot, value) in block.iter_mut().zip(previous.iter()) {
            *slot ^= value;
        }
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_client_secret_options_parse_explicit_values() {
        let options = AppleClientSecretOptions::from_args(vec![
            "--team-id".to_owned(),
            "3KEQMC2NW5".to_owned(),
            "--key-id".to_owned(),
            "6HHG23T848".to_owned(),
            "--client-id".to_owned(),
            "ai.wavey.bitneedle".to_owned(),
            "--private-key".to_owned(),
            "AuthKey.p8".to_owned(),
            "--ttl-days".to_owned(),
            "30".to_owned(),
            "--issued-at".to_owned(),
            "1_780_000_000".replace('_', ""),
        ])
        .unwrap();

        assert_eq!(options.team_id, "3KEQMC2NW5");
        assert_eq!(options.key_id, "6HHG23T848");
        assert_eq!(options.client_id, "ai.wavey.bitneedle");
        assert_eq!(options.private_key_path, "AuthKey.p8");
        assert_eq!(options.ttl_days, 30);
        assert_eq!(options.issued_at, 1_780_000_000);
    }

    #[test]
    fn apple_client_secret_options_reject_long_ttl() {
        let error = AppleClientSecretOptions::from_args(vec![
            "--team-id".to_owned(),
            "team".to_owned(),
            "--key-id".to_owned(),
            "key".to_owned(),
            "--client-id".to_owned(),
            "client".to_owned(),
            "--private-key".to_owned(),
            "AuthKey.p8".to_owned(),
            "--ttl-days".to_owned(),
            "365".to_owned(),
        ])
        .unwrap_err();

        assert_eq!(error, "--ttl-days must be between 1 and 180");
    }

    #[test]
    fn signing_key_options_parse_explicit_values() {
        let options = SigningKeyOptions::from_args(vec![
            "--kid".to_owned(),
            "wavey-id-2026-06-04".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ])
        .unwrap();

        assert_eq!(options.kid, "wavey-id-2026-06-04");
        assert_eq!(options.format, SigningKeyOutputFormat::Json);
    }

    #[test]
    fn schema_options_parse_explicit_values() {
        let options = SchemaOptions::from_args(vec![
            "--only".to_owned(),
            "compatibility".to_owned(),
            "--format".to_owned(),
            "lines".to_owned(),
        ])
        .unwrap();

        assert_eq!(options.only, SchemaOnly::Compatibility);
        assert_eq!(options.format, SchemaOutputFormat::Lines);
    }

    #[test]
    fn schema_options_reject_unknown_mode() {
        let error =
            SchemaOptions::from_args(vec!["--only".to_owned(), "future".to_owned()]).unwrap_err();

        assert_eq!(error, "--only must be all, migrations, or compatibility");
    }

    #[test]
    fn schema_sql_exports_migrations_and_compatibility() {
        let sql = schema_sql(SchemaOnly::All);

        assert!(sql.contains("CREATE TABLE IF NOT EXISTS zeroth_users"));
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS zeroth_refresh_tokens"));
        assert!(sql.contains("ALTER TABLE zeroth_auth_codes ADD COLUMN auth_time INTEGER;"));
    }

    #[test]
    fn schema_lines_export_raw_statements_without_semicolons() {
        let statements = schema_statements(SchemaOnly::Compatibility);

        assert!(statements
            .iter()
            .any(|statement| statement
                == "ALTER TABLE zeroth_auth_codes ADD COLUMN auth_time INTEGER"));
        assert!(statements
            .iter()
            .all(|statement| !statement.ends_with(';') && !statement.trim().is_empty()));
    }

    #[test]
    fn schema_lines_render_one_statement_per_physical_line() {
        let statements = schema_statements(SchemaOnly::Migrations);
        let output = schema_lines(SchemaOnly::Migrations);
        let lines = output.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), statements.len());
        assert!(lines
            .iter()
            .all(|line| !line.contains('\n') && !line.ends_with(';') && !line.is_empty()));
        assert!(lines
            .iter()
            .any(|line| line.starts_with("CREATE TABLE IF NOT EXISTS zeroth_clients (")));
    }

    #[test]
    fn validate_secret_accepts_generated_es256_private_key() {
        let artifact = signing_key_artifact_from_scalar("wavey-id-test", &[1_u8; 32]).unwrap();

        validate_secret_value(SecretKind::Es256PrivateKey, &artifact.jwt_es256_private_key)
            .unwrap();
    }

    #[test]
    fn validate_secret_rejects_invalid_es256_private_key() {
        let error =
            validate_secret_value(SecretKind::Es256PrivateKey, "not-a-private-key").unwrap_err();

        assert!(error.contains("ES256 private key"));
    }

    #[test]
    fn validate_secret_accepts_pkcs8_apple_private_key() {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};

        let signing_key = SigningKey::from_slice(&[2_u8; 32]).unwrap();
        let pem = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();

        validate_secret_value(SecretKind::ApplePrivateKey, &pem).unwrap();
    }

    #[test]
    fn validate_secret_accepts_previous_public_jwks() {
        let artifact = signing_key_artifact_from_scalar("wavey-id-test", &[3_u8; 32]).unwrap();
        let jwks_json = serde_json::to_string(&artifact.public_jwks).unwrap();

        validate_secret_value(SecretKind::PreviousPublicJwks, &jwks_json).unwrap();
    }

    #[test]
    fn validate_secret_rejects_previous_public_jwks_without_keys() {
        let error =
            validate_secret_value(SecretKind::PreviousPublicJwks, r#"{"keys":[]}"#).unwrap_err();

        assert_eq!(error, "previous public JWKS must include at least one key");
    }

    #[test]
    fn validate_secret_rejects_previous_public_jwks_with_private_material() {
        let error = validate_secret_value(
            SecretKind::PreviousPublicJwks,
            r#"{"keys":[{"kty":"EC","use":"sig","kid":"old","alg":"ES256","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"secret"}]}"#,
        )
        .unwrap_err();

        assert!(error.contains("unknown field `d`"));
    }

    #[test]
    fn signing_key_options_reject_unknown_format() {
        let error = SigningKeyOptions::from_args(vec![
            "--kid".to_owned(),
            "wavey-id".to_owned(),
            "--format".to_owned(),
            "yaml".to_owned(),
        ])
        .unwrap_err();

        assert_eq!(error, "--format must be env or json");
    }

    #[test]
    fn signing_key_artifact_uses_base64url_private_scalar_and_public_jwks() {
        let scalar = [1_u8; 32];

        let artifact = signing_key_artifact_from_scalar("wavey-id-test", &scalar).unwrap();

        assert_eq!(artifact.jwt_key_id, "wavey-id-test");
        assert_eq!(
            artifact.jwt_es256_private_key,
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
        );
        assert_eq!(artifact.public_jwks.keys.len(), 1);
        assert_eq!(artifact.public_jwks.keys[0].kid, "wavey-id-test");
        assert_eq!(artifact.public_jwks.keys[0].kty, "EC");
        assert_eq!(artifact.public_jwks.keys[0].key_use, "sig");
        assert_eq!(artifact.public_jwks.keys[0].alg, "ES256");
        assert_eq!(artifact.public_jwks.keys[0].crv, "P-256");
        assert!(!artifact.public_jwks.keys[0].x.is_empty());
        assert!(!artifact.public_jwks.keys[0].y.is_empty());
    }

    #[test]
    fn signing_key_artifact_rejects_empty_kid() {
        let error = signing_key_artifact_from_scalar("", &[1_u8; 32]).unwrap_err();

        assert_eq!(error, "--kid must not be empty");
    }
}
