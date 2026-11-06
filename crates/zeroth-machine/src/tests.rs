use super::*;
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "https://identity.example.com";
const ENDPOINT: &str = "https://identity.example.com/oauth/token";
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

fn assertion() -> ServiceClientAssertionClaims {
    build_service_client_assertion_claims("svc_tier_a", ENDPOINT, NOW, 60, "assertion_unique_1")
        .unwrap()
}

fn assertion_validation() -> ServiceAssertionValidation {
    ServiceAssertionValidation {
        token_endpoint: ENDPOINT.into(),
        now: NOW,
        max_lifetime_seconds: 300,
        clock_skew_seconds: 0,
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

fn access_claims() -> ServiceAccessTokenClaims {
    build_service_access_token_claims(&client(), ISSUER, AUDIENCE, "releases:read", NOW, "token_1")
        .unwrap()
}

fn sign(header: &Value, claims: &impl Serialize, byte: u8) -> String {
    let input = format!(
        "{}.{}",
        encode_json(header).unwrap(),
        encode_json(claims).unwrap()
    );
    let signature: Signature = key(byte).sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn header() -> Value {
    json!({"alg":"ES256","kid":"key1","typ":"JWT"})
}

#[test]
fn registered_assertion_returns_replay_identity_and_supports_key_rotation() {
    let claims = assertion();
    let token = sign_service_client_assertion(&key(3), "key1", &claims).unwrap();
    let mut client = client();
    client.public_jwks.keys.push(jwk(&key(4), "key2"));
    assert_eq!(
        verify_service_client_assertion(&token, &client, &assertion_validation()).unwrap(),
        claims
    );
    let rotated = sign_service_client_assertion(&key(4), "key2", &claims).unwrap();
    assert!(verify_service_client_assertion(&rotated, &client, &assertion_validation()).is_ok());
    client.public_jwks.keys.remove(0);
    assert!(verify_service_client_assertion(&token, &client, &assertion_validation()).is_err());
    // Replay acceptance here is intentional: durable consumption is the issuer's transaction.
    assert!(verify_service_client_assertion(&rotated, &client, &assertion_validation()).is_ok());
}

#[test]
fn assertions_reject_wrong_identity_audience_missing_jti_and_unsafe_times() {
    let base = serde_json::to_value(assertion()).unwrap();
    let invalid = [
        ("iss", json!("svc_other")),
        ("sub", json!("svc_other")),
        ("aud", json!(format!("{ENDPOINT}/"))),
        ("aud", json!([ENDPOINT])),
        ("jti", json!("")),
        ("iat", json!(NOW + 1)),
        ("iat", json!(-1)),
        ("exp", json!(NOW)),
        ("exp", json!(NOW + 301)),
        ("nbf", json!(NOW + 1)),
        ("nbf", json!(NOW - 1)),
        ("nbf", json!(NOW + 60)),
        ("email", json!("person@example.com")),
        ("jti", json!("a".repeat(129))),
    ];
    for (field, value) in invalid {
        let mut claims = base.clone();
        claims[field] = value;
        assert!(
            verify_service_client_assertion(
                &sign(&header(), &claims, 3),
                &client(),
                &assertion_validation()
            )
            .is_err(),
            "accepted {field}"
        );
    }
    for field in ["iss", "sub", "aud", "iat", "exp", "jti"] {
        let mut claims = base.clone();
        claims.as_object_mut().unwrap().remove(field);
        assert!(verify_service_client_assertion(
            &sign(&header(), &claims, 3),
            &client(),
            &assertion_validation()
        )
        .is_err());
    }
    let token = sign(&header(), &base, 3);
    let mut client = client();
    client.disabled = true;
    assert!(verify_service_client_assertion(&token, &client, &assertion_validation()).is_err());
}

#[test]
fn untrusted_jwt_headers_signatures_and_size_bombs_are_rejected() {
    for h in [
        json!({"alg":"none","kid":"key1"}),
        json!({"alg":"HS256","kid":"key1"}),
        json!({"alg":"ES256"}),
        json!({"alg":"ES256","kid":"unknown"}),
        json!({"alg":"ES256","kid":"key1","jku":"https://attacker.example/keys"}),
        json!({"alg":"ES256","kid":"key1","jwk":keys(3).keys[0]}),
        json!({"alg":"ES256","kid":"key1","crit":["b64"],"b64":false}),
        json!({"alg":"ES256","kid":"key1","typ":"id+jwt"}),
    ] {
        assert!(verify_service_client_assertion(
            &sign(&h, &assertion(), 3),
            &client(),
            &assertion_validation()
        )
        .is_err());
    }
    let token = sign(&header(), &assertion(), 4);
    assert!(verify_service_client_assertion(&token, &client(), &assertion_validation()).is_err());
    for token in [
        "a".repeat(MAX_SERVICE_JWT_BYTES + 1),
        "..".into(),
        "a.b.c.d".into(),
        format!(
            "{}.e30.AA",
            URL_SAFE_NO_PAD.encode(vec![b' '; MAX_HEADER_BYTES + 1])
        ),
    ] {
        assert!(
            verify_service_client_assertion(&token, &client(), &assertion_validation()).is_err()
        );
    }
}

#[test]
fn public_key_registration_never_discards_private_or_unknown_members() {
    let value = serde_json::to_value(keys(3)).unwrap();
    for member in [
        "d", "k", "p", "q", "dp", "dq", "qi", "oth", "key_ops", "jku",
    ] {
        let mut candidate = value.clone();
        candidate["keys"][0][member] = json!("secret");
        assert!(
            ServiceJwks::from_json(&candidate.to_string()).is_err(),
            "accepted {member}"
        );
    }
    let mut candidate = value.clone();
    candidate["keys"][0]["alg"] = json!("RS256");
    assert!(ServiceJwks::from_json(&candidate.to_string()).is_err());
    let mut candidate = value;
    candidate["keys"][0]["x"] = json!("A".repeat(43));
    candidate["keys"][0]["y"] = json!("A".repeat(43));
    assert!(ServiceJwks::from_json(&candidate.to_string()).is_err());
    let mut duplicate = keys(3);
    duplicate.keys.push(duplicate.keys[0].clone());
    assert!(duplicate.validate().is_err());
    let oversized = ServiceJwks {
        keys: (0..=MAX_SERVICE_KEYS)
            .map(|n| jwk(&key(3), &format!("key{n}")))
            .collect(),
    };
    assert!(oversized.validate().is_err());
    assert!(ServiceJwks::from_json(&" ".repeat(MAX_SERVICE_JWKS_BYTES + 1)).is_err());
}

#[test]
fn grants_cannot_expand_client_audiences_scopes_or_reserved_human_scopes() {
    let mut client = client();
    assert_eq!(
        validate_service_token_request(&client, AUDIENCE, "releases:read receipts:write").unwrap(),
        "receipts:write releases:read"
    );
    for scope in [
        "",
        "releases:write",
        "openid",
        "profile",
        "email",
        "offline_access",
        "admin",
        "roles",
        "releases:*",
        "releases:read releases:read",
        "releases:read\nreceipts:write",
        " releases:read",
    ] {
        assert!(
            validate_service_token_request(&client, AUDIENCE, scope).is_err(),
            "accepted {scope}"
        );
    }
    assert!(
        validate_service_token_request(&client, "https://other.example/api", "releases:read")
            .is_err()
    );
    for scope in [
        "openid",
        "profile",
        "email",
        "offline_access",
        "roles",
        "groups",
        "admin",
    ] {
        client.allowed_scopes = vec![scope.into()];
        assert!(client.validate().is_err());
    }
    client = super::tests::client();
    client.token_ttl_seconds = 601;
    assert!(client.validate().is_err());
    client.token_ttl_seconds = 0;
    assert!(client.validate().is_err());
}

#[test]
fn access_tokens_bind_issuer_tenant_resource_service_and_required_scopes() {
    let claims = access_claims();
    let token = sign(&header(), &claims, 7);
    assert_eq!(
        verify_service_access_token(&token, &keys(7), &access_validation()).unwrap(),
        claims
    );
    let mut invalid_policy = access_validation();
    invalid_policy.tenant_id = "tenant_b".into();
    assert!(verify_service_access_token(&token, &keys(7), &invalid_policy).is_err());
    invalid_policy = access_validation();
    invalid_policy.audience = "other".into();
    assert!(verify_service_access_token(&token, &keys(7), &invalid_policy).is_err());
    invalid_policy = access_validation();
    invalid_policy.required_scopes = vec!["jobs:claim".into()];
    assert!(verify_service_access_token(&token, &keys(7), &invalid_policy).is_err());
    assert!(verify_service_access_token(&token, &keys(3), &access_validation()).is_err());
    let base = serde_json::to_value(claims).unwrap();
    for (field, value) in [
        ("iss", json!("https://other.example")),
        ("sub", json!("usr_human")),
        ("client_id", json!("svc_other")),
        ("tenant_id", json!("tenant_b")),
        ("principal_type", json!("user")),
        ("token_use", json!("id")),
        ("client_revision", json!(0)),
        ("scope", json!("openid")),
        ("exp", json!(NOW + 601)),
        ("iat", json!(NOW + 1)),
        ("sid", json!("user_session")),
        ("email", json!("person@example.com")),
    ] {
        let mut candidate = base.clone();
        candidate[field] = value;
        assert!(
            verify_service_access_token(
                &sign(&header(), &candidate, 7),
                &keys(7),
                &access_validation()
            )
            .is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn expiry_does_not_gain_a_replay_window_from_clock_skew() {
    let token = sign(&header(), &assertion(), 3);
    let mut validation = assertion_validation();
    validation.now = NOW + 60;
    validation.clock_skew_seconds = 30;
    assert!(verify_service_client_assertion(&token, &client(), &validation).is_err());
    validation = assertion_validation();
    validation.max_lifetime_seconds = 301;
    assert!(verify_service_client_assertion(&token, &client(), &validation).is_err());
    validation = assertion_validation();
    validation.clock_skew_seconds = 31;
    assert!(verify_service_client_assertion(&token, &client(), &validation).is_err());
    assert!(build_service_client_assertion_claims(
        "svc_tier_a",
        "http://public.example/token",
        NOW,
        60,
        "jti"
    )
    .is_err());
    assert!(
        build_service_client_assertion_claims("svc_tier_a", ENDPOINT, i64::MAX, 60, "jti").is_err()
    );
}
