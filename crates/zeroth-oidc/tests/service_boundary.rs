use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde::Serialize;
use serde_json::{json, Value};
use zeroth_oidc::service::*;

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "https://identity.example.com";
const AUDIENCE: &str = "https://control.example.com/api";

fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}

fn jwk(key: &SigningKey, kid: &str) -> ServiceJwk {
    let point = key.verifying_key().to_sec1_point(false);
    ServiceJwk {
        kty: "EC".into(),
        key_use: "sig".into(),
        kid: kid.into(),
        alg: "ES256".into(),
        crv: "P-256".into(),
        x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }
}

fn keys(byte: u8) -> ServiceJwks {
    ServiceJwks {
        keys: vec![jwk(&key(byte), "key1")],
    }
}

fn client() -> ServiceClient {
    ServiceClient {
        id: "svc_tier_a".into(),
        tenant_id: "tenant_a".into(),
        name: "Tier A".into(),
        disabled: false,
        revision: 1,
        allowed_audiences: vec![AUDIENCE.into()],
        allowed_scopes: vec!["releases:read".into(), "receipts:write".into()],
        public_jwks: keys(3),
        token_ttl_seconds: 600,
    }
}

fn access_validation() -> ServiceAccessTokenValidation {
    ServiceAccessTokenValidation {
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        tenant_id: "tenant_a".into(),
        required_scopes: vec!["releases:read".into()],
        now: NOW,
        max_lifetime_seconds: 600,
        clock_skew_seconds: 0,
    }
}

fn sign(header: &Value, claims: &impl Serialize, byte: u8) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let signature: Signature = key(byte).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn header() -> Value {
    json!({"alg":"ES256","kid":"key1","typ":"JWT"})
}

#[test]
fn valid_service_credentials_never_authenticate_a_human_and_vice_versa() {
    // Match the legacy human access verifier's client_id==aud rule so rejection
    // proves the discriminator boundary rather than an incidental audience error.
    let mut client = client();
    client.allowed_audiences = vec![client.id.clone()];
    let claims = build_service_access_token_claims(
        &client,
        ISSUER,
        &client.id,
        "releases:read",
        NOW,
        "unique_jti",
    )
    .unwrap();
    let token = sign(&header(), &claims, 7);
    let human_keys: zeroth_oidc::ZerothJwks =
        serde_json::from_value(serde_json::to_value(keys(7)).unwrap()).unwrap();
    assert!(
        zeroth_oidc::verify_zeroth_access_token(&token, &human_keys, ISSUER, &client.id, NOW)
            .is_err()
    );
    assert!(zeroth_oidc::verify_zeroth_issued_access_token(
        &token,
        &human_keys,
        ISSUER,
        &client.id,
        NOW
    )
    .is_err());
    // Even changing token_use to id cannot convert the same principal into a user.
    let mut id_claims = serde_json::to_value(&claims).unwrap();
    id_claims["token_use"] = json!("id");
    let id_token = sign(&header(), &id_claims, 7);
    assert!(zeroth_oidc::verify_zeroth_id_token(
        &id_token,
        &human_keys,
        ISSUER,
        &client.id,
        None,
        NOW
    )
    .is_err());
    let human = json!({"iss":ISSUER,"sub":"usr_1","aud":AUDIENCE,"client_id":AUDIENCE,"scope":"releases:read","iat":NOW,"exp":NOW+300,"token_use":"access"});
    assert!(verify_service_access_token(
        &sign(&header(), &human, 7),
        &keys(7),
        &access_validation()
    )
    .is_err());
    let response = ServiceTokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: 600,
        scope: "releases:read".into(),
    };
    let response = serde_json::to_value(response).unwrap();
    assert!(response.get("id_token").is_none());
    assert!(response.get("refresh_token").is_none());
}
