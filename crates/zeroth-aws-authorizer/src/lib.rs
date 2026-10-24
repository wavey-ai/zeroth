//! Local AWS verification of short-lived Zeroth issuer tokens.
use reqwest::Client;
use serde_json::{json, Value};
use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroth_oidc::{verify_zeroth_issued_access_token, ZerothIssuedAccessTokenClaims, ZerothJwks};

const MAX_TOKEN_BYTES: usize = 8192;
const MAX_JWKS_BYTES: usize = 65536;
const JWKS_CACHE_TIME: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct Config {
    pub issuer: String,
    pub jwks_url: String,
    pub audience: String,
    pub client_id: String,
}

struct CachedJwks {
    keys: ZerothJwks,
    until: Instant,
}

pub struct Authorizer {
    config: Config,
    http: Client,
    jwks: Mutex<Option<CachedJwks>>,
}

impl Authorizer {
    pub fn new(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if !config.jwks_url.starts_with("https://") {
            return Err("ZEROTH_JWKS_URL must use HTTPS".into());
        }
        Ok(Self {
            config,
            http: Client::builder()
                .timeout(Duration::from_secs(3))
                .user_agent("Zeroth-AWS-Authorizer/1.0")
                .build()?,
            jwks: Mutex::new(None),
        })
    }

    async fn keys(&self) -> Option<ZerothJwks> {
        if let Some(cached) = self.jwks.lock().ok()?.as_ref() {
            if Instant::now() < cached.until {
                return Some(cached.keys.clone());
            }
        }
        let response = self
            .http
            .get(&self.config.jwks_url)
            .header("accept", "application/json")
            .send()
            .await
            .ok()?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > MAX_JWKS_BYTES as u64)
        {
            return None;
        }
        let bytes = response.bytes().await.ok()?;
        if bytes.len() > MAX_JWKS_BYTES {
            return None;
        }
        let keys: ZerothJwks = serde_json::from_slice(&bytes).ok()?;
        zeroth_oidc::validate_zeroth_jwks(&keys).ok()?;
        *self.jwks.lock().ok()? = Some(CachedJwks {
            keys: keys.clone(),
            until: Instant::now() + JWKS_CACHE_TIME,
        });
        Some(keys)
    }

    pub async fn authorize(&self, event: &Value) -> Value {
        let Some(token) = bearer_token(event) else {
            return denied();
        };
        let Some(keys) = self.keys().await else {
            return denied();
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs() as i64);
        let Ok(claims) = verify_zeroth_issued_access_token(
            token,
            &keys,
            &self.config.issuer,
            &self.config.audience,
            now,
        ) else {
            return denied();
        };
        if !claims_allowed(&claims, &self.config, now) {
            return denied();
        }
        json!({"isAuthorized":true,"context":{"user":claims.sub,"client_id":claims.client_id}})
    }
}

fn denied() -> Value {
    json!({"isAuthorized":false})
}

fn bearer_token(event: &Value) -> Option<&str> {
    let headers = event.get("headers")?.as_object()?;
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))?
        .1
        .as_str()?;
    let token = value.strip_prefix("Bearer ")?;
    (token.len() <= MAX_TOKEN_BYTES && !token.is_empty()).then_some(token)
}

fn claims_allowed(claims: &ZerothIssuedAccessTokenClaims, config: &Config, now: i64) -> bool {
    claims.client_id == config.client_id
        && !claims.sub.is_empty()
        && claims.sub.len() <= 256
        && !claims.jti.is_empty()
        && claims.iat <= now + 30
        && (1..=600).contains(&(claims.exp - claims.iat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use zeroth_oidc::ZerothJwk;

    fn fixture() -> (Authorizer, SigningKey) {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let jwks = ZerothJwks {
            keys: vec![ZerothJwk {
                kty: "EC".into(),
                key_use: "sig".into(),
                kid: "test".into(),
                alg: "ES256".into(),
                crv: "P-256".into(),
                x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            }],
        };
        let authorizer = Authorizer::new(Config {
            issuer: "https://id.test".into(),
            jwks_url: "https://id.test/.well-known/jwks.json".into(),
            audience: "MSTR".into(),
            client_id: "yl-web".into(),
        })
        .unwrap();
        *authorizer.jwks.lock().unwrap() = Some(CachedJwks {
            keys: jwks,
            until: Instant::now() + Duration::from_secs(60),
        });
        (authorizer, key)
    }

    fn token(key: &SigningKey, claims: Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","kid":"test"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[tokio::test]
    async fn signed_mstr_token_authorizes_only_its_subject() {
        let (authorizer, key) = fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = json!({"iss":"https://id.test","sub":"artist-1","aud":"MSTR",
            "iat":now,"exp":now+300,"jti":"test-1","client_id":"yl-web"});
        let good = token(&key, claims.clone());
        let event = json!({"headers":{"Authorization":format!("Bearer {good}")}});
        assert_eq!(
            authorizer.authorize(&event).await["context"]["user"],
            "artist-1"
        );
        for changed in [
            json!({"aud":"OTHER"}),
            json!({"client_id":"other"}),
            json!({"exp":now}),
            json!({"iat":now+31}),
        ] {
            let mut altered = claims.clone();
            altered
                .as_object_mut()
                .unwrap()
                .extend(changed.as_object().unwrap().clone());
            let event =
                json!({"headers":{"authorization":format!("Bearer {}",token(&key,altered))}});
            assert_eq!(authorizer.authorize(&event).await, denied());
        }
        assert_eq!(authorizer.authorize(&json!({"headers":{}})).await, denied());
    }
}
