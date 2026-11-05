//! Regression tests exercise the complete native JWT verifier, including its
//! signature and Entra signing-key scope checks, before enterprise admission.

use super::*;
use rsa::{
    pkcs1v15::SigningKey as RsaSigningKey,
    rand_core::OsRng,
    signature::{RandomizedSigner, SignatureEncoding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use std::sync::OnceLock;

const TENANT: &str = "01234567-89ab-cdef-0123-456789abcdef";
const OTHER_TENANT: &str = "12345678-9abc-def0-1234-56789abcdef0";
const NOW: i32 = 1_800_000_000;
const NONCE: &str = "zeroth-generated-transaction-nonce";

fn claims_for(provider: &OAuthProvider) -> ProviderIdTokenClaims {
    let policy = provider.enterprise_policy().unwrap();
    ProviderIdTokenClaims {
        iss: policy.issuer(),
        sub: "stable-upstream-subject".to_owned(),
        aud: AudienceClaim::One(provider.config().client_id.clone()),
        exp: i64::from(NOW) + 600,
        iat: Some(i64::from(NOW) - 10),
        nbf: Some(i64::from(NOW) - 10),
        nonce: Some(NONCE.to_owned()),
        email: Some("user@example.com".to_owned()),
        email_verified: Some(serde_json::Value::Bool(true)),
        name: None,
        picture: None,
        tid: policy.tenant_id().map(str::to_owned),
        hd: policy.domains().first().cloned(),
        azp: Some(provider.config().client_id.clone()),
    }
}

fn validation_for(provider: &OAuthProvider) -> ProviderIdTokenValidation<'_> {
    ProviderIdTokenValidation {
        provider_id: &provider.id().0,
        client_id: &provider.config().client_id,
        nonce: Some(NONCE),
        now: NOW,
        enterprise_policy: provider.enterprise_policy(),
    }
}

fn signed(claims: &ProviderIdTokenClaims) -> (String, ProviderJwksResponse) {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    let key = KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).unwrap());
    let public = key.to_public_key();
    let header = ProviderJwtHeader {
        alg: "RS256".to_owned(),
        kid: Some("enterprise-regression-key".to_owned()),
    };
    let input = format!(
        "{}.{}",
        jwt_json_segment(&header).unwrap(),
        jwt_json_segment(claims).unwrap()
    );
    let signature =
        RsaSigningKey::<Sha256>::new(key.clone()).sign_with_rng(&mut OsRng, input.as_bytes());
    let jwt = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    let jwks = ProviderJwksResponse {
        keys: vec![ProviderJwk {
            kty: "RSA".to_owned(),
            key_use: Some("sig".to_owned()),
            kid: header.kid,
            alg: Some("RS256".to_owned()),
            n: Some(URL_SAFE_NO_PAD.encode(public.n().to_bytes_be())),
            e: Some(URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())),
            issuer: Some("https://login.microsoftonline.com/{tenantid}/v2.0".to_owned()),
        }],
    };
    (jwt, jwks)
}

#[test]
fn signed_entra_token_requires_matching_tenant_issuer_and_key_scope() {
    let provider = OAuthProvider::entra("client", TENANT).unwrap();
    let claims = claims_for(&provider);
    let (jwt, jwks) = signed(&claims);
    let verified = verify_provider_id_token(&jwt, &jwks, validation_for(&provider)).unwrap();
    let profile = provider
        .normalize_profile(ProviderProfileSource::OidcClaims {
            sub: verified.claims.sub,
            email: verified.claims.email,
            email_verified: true,
            name: None,
            picture: None,
        })
        .unwrap();
    assert_eq!(
        profile.subject.0,
        format!("{TENANT}:stable-upstream-subject")
    );
    assert!(!profile.email_verified);

    for (issuer, tenant) in [
        (claims.iss.clone(), Some(OTHER_TENANT.to_owned())),
        (
            format!("https://login.microsoftonline.com/{OTHER_TENANT}/v2.0"),
            Some(TENANT.to_owned()),
        ),
        (claims.iss.clone(), None),
        (
            format!("https://sts.windows.net/{TENANT}/"),
            Some(TENANT.to_owned()),
        ),
    ] {
        let mut wrong = claims.clone();
        wrong.iss = issuer;
        wrong.tid = tenant;
        let (jwt, jwks) = signed(&wrong);
        assert!(verify_provider_id_token(&jwt, &jwks, validation_for(&provider)).is_err());
    }

    for key_issuer in [
        None,
        Some(format!(
            "https://login.microsoftonline.com/{OTHER_TENANT}/v2.0"
        )),
        Some("https://login.microsoftonline.com/{tenantid}/v2.0.evil".to_owned()),
    ] {
        let mut wrong_keys = jwks.clone();
        wrong_keys.keys[0].issuer = key_issuer;
        assert!(verify_provider_id_token(&jwt, &wrong_keys, validation_for(&provider)).is_err());
    }
    let mut exact_keys = jwks;
    exact_keys.keys[0].issuer = Some(provider.enterprise_policy().unwrap().issuer());
    verify_provider_id_token(&jwt, &exact_keys, validation_for(&provider)).unwrap();
}

#[test]
fn signed_workspace_email_cannot_replace_hosted_domain_membership() {
    let provider = OAuthProvider::google_workspace("client", ["example.com"]).unwrap();
    let valid = claims_for(&provider);
    for issuer in ["https://accounts.google.com", "accounts.google.com"] {
        let mut claims = valid.clone();
        claims.iss = issuer.to_owned();
        let (jwt, jwks) = signed(&claims);
        verify_provider_id_token(&jwt, &jwks, validation_for(&provider)).unwrap();
    }
    for domain in [
        None,
        Some("gmail.com"),
        Some("sub.example.com"),
        Some("example.com.evil"),
    ] {
        let mut claims = valid.clone();
        // Email stays verified and in the configured domain in every case.
        claims.hd = domain.map(str::to_owned);
        let (jwt, jwks) = signed(&claims);
        assert!(verify_provider_id_token(&jwt, &jwks, validation_for(&provider)).is_err());
    }
}

#[test]
fn signed_enterprise_tokens_reject_wrong_audience_presenter_nonce_and_lifetime() {
    let provider = OAuthProvider::google_workspace("client", ["example.com"]).unwrap();
    let valid = claims_for(&provider);
    let mut invalid = Vec::new();
    for audience in [
        AudienceClaim::One("attacker-client".to_owned()),
        AudienceClaim::Many(vec!["client".to_owned(), "attacker-client".to_owned()]),
    ] {
        let mut claims = valid.clone();
        claims.aud = audience;
        invalid.push(claims);
    }
    let mut claims = valid.clone();
    claims.azp = Some("different-native-presenter".to_owned());
    invalid.push(claims);
    for nonce in [None, Some("attacker-nonce")] {
        let mut claims = valid.clone();
        claims.nonce = nonce.map(str::to_owned);
        invalid.push(claims);
    }
    let mut claims = valid.clone();
    claims.exp = i64::from(NOW);
    invalid.push(claims);
    for issued in [None, Some(i64::from(NOW) + 61)] {
        let mut claims = valid.clone();
        claims.iat = issued;
        invalid.push(claims);
    }
    let mut claims = valid.clone();
    claims.nbf = Some(i64::from(NOW) + 61);
    invalid.push(claims);
    let mut claims = valid;
    claims.sub.clear();
    invalid.push(claims);
    for claims in invalid {
        let (jwt, jwks) = signed(&claims);
        assert!(verify_provider_id_token(&jwt, &jwks, validation_for(&provider)).is_err());
    }
}

#[test]
fn editing_workspace_membership_after_signing_never_authenticates() {
    let provider = OAuthProvider::google_workspace("client", ["example.com"]).unwrap();
    let mut claims = claims_for(&provider);
    claims.hd = Some("attacker.example".to_owned());
    let (jwt, jwks) = signed(&claims);
    let segments = jwt.split('.').collect::<Vec<_>>();
    claims.hd = Some("example.com".to_owned());
    let forged = format!(
        "{}.{}.{}",
        segments[0],
        jwt_json_segment(&claims).unwrap(),
        segments[2]
    );
    let error = verify_provider_id_token(&forged, &jwks, validation_for(&provider)).unwrap_err();
    assert!(error.description.contains("signature"));
}

#[test]
fn enterprise_policy_hash_changes_with_trust_but_not_domain_order() {
    let first = OAuthProvider::google_workspace("client", ["a.example", "b.example"]).unwrap();
    let reordered =
        OAuthProvider::google_workspace("client", ["B.EXAMPLE", "a.example", "a.example"]).unwrap();
    let changed_domain =
        OAuthProvider::google_workspace("client", ["a.example", "other.example"]).unwrap();
    let changed_client =
        OAuthProvider::google_workspace("new-client", ["a.example", "b.example"]).unwrap();
    let hash = provider_policy_hash(&first).unwrap();
    assert_eq!(hash, provider_policy_hash(&reordered).unwrap());
    for provider in [&changed_domain, &changed_client] {
        assert_ne!(hash, provider_policy_hash(provider).unwrap());
        let context = AuthContext::from_provider(&first).unwrap();
        assert!(context
            .validate(
                Some(well_known::GOOGLE_WORKSPACE),
                provider_policy_hash(provider).unwrap().as_deref()
            )
            .is_err());
    }
    let entra = OAuthProvider::entra("client", TENANT).unwrap();
    let changed_tenant = OAuthProvider::entra("client", OTHER_TENANT).unwrap();
    assert_ne!(
        provider_policy_hash(&entra).unwrap(),
        provider_policy_hash(&changed_tenant).unwrap()
    );
    for local_or_social in [
        AuthContext::default(),
        AuthContext::from_provider(&OAuthProvider::google("client")).unwrap(),
        AuthContext {
            auth_provider: Some(well_known::GOOGLE_WORKSPACE.to_owned()),
            auth_policy_hash: None,
        },
    ] {
        assert!(local_or_social
            .validate(Some(well_known::GOOGLE_WORKSPACE), hash.as_deref())
            .is_err());
    }
}

#[test]
fn enterprise_callback_rejects_unbound_or_changed_policy_transactions() {
    let provider = OAuthProvider::google_workspace("client", ["example.com"]).unwrap();
    let mut transaction = AuthTransaction {
        provider_state: "state".to_owned(),
        client_id: ClientId("product".to_owned()),
        provider_id: provider.id().clone(),
        redirect_uri: "https://product.example/callback".to_owned(),
        provider_redirect_uri: "https://id.example/oauth2/callback".to_owned(),
        app_state: None,
        nonce: None,
        provider_nonce: Some(NONCE.to_owned()),
        provider_policy_hash: provider_policy_hash(&provider).unwrap(),
        provider_code_verifier: Some("a".repeat(64)),
        code_challenge: None,
        code_challenge_method: None,
        scope: ScopeSet::new(["openid"]),
        link_user_id: None,
        link_session_id: None,
        session_return_to: None,
        created_at: unix_seconds_to_system_time(NOW),
        expires_at: unix_seconds_to_system_time(NOW + 600),
    };
    validate_provider_transaction_policy(&transaction, &provider).unwrap();
    let changed = OAuthProvider::google_workspace("client", ["other.example"]).unwrap();
    assert!(validate_provider_transaction_policy(&transaction, &changed).is_err());
    transaction.provider_code_verifier = None;
    assert!(validate_provider_transaction_policy(&transaction, &provider).is_err());
    transaction.provider_code_verifier = Some("a".repeat(64));
    transaction.provider_nonce = None;
    assert!(validate_provider_transaction_policy(&transaction, &provider).is_err());
    transaction.provider_nonce = Some(NONCE.to_owned());
    transaction.provider_policy_hash = None;
    assert!(validate_provider_transaction_policy(&transaction, &provider).is_err());
}

#[test]
fn cross_client_sso_binds_target_session_without_extending_authentication() {
    let provider = OAuthProvider::google_workspace("client", ["example.com"]).unwrap();
    let source = SessionRow {
        id: "source-session".to_owned(),
        user_id: "user".to_owned(),
        client_id: Some("app-a".to_owned()),
        created_at: NOW - 100,
        expires_at: NOW + 600,
        revoked_at: None,
        user_agent: None,
        ip_hash: None,
        auth_context: AuthContext::from_provider(&provider).unwrap(),
    };
    let target = session_bound_to_client(&source, "app-b", "target-session".to_owned());
    assert_eq!(target.created_at, source.created_at);
    assert_eq!(target.expires_at, source.expires_at);
    assert_eq!(target.auth_context, source.auth_context);
    let claims: JwtClaims = serde_json::from_value(serde_json::json!({
        "iss": "https://id.example.com",
        "sub": "user",
        "aud": "app-b",
        "iat": NOW,
        "exp": NOW + 60,
        "sid": "target-session",
        "client_id": "app-b",
        "token_use": "access"
    }))
    .unwrap();
    assert!(validate_access_token_session_claims(&claims, Some(&source), NOW).is_err());
    validate_access_token_session_claims(&claims, Some(&target), NOW).unwrap();
    assert!(validate_access_token_session_claims(&claims, Some(&target), NOW + 600).is_err());
}

#[test]
fn code_and_refresh_grants_cannot_outlive_or_replace_their_browser_session() {
    let mut client = Client {
        id: ClientId("product".into()),
        name: "Product".into(),
        redirect_uris: vec![],
        allowed_origins: vec![],
        allowed_email_domains: vec![],
        confidential: false,
        enterprise_provider: Some("entra".into()),
    };
    let session: SessionRow = serde_json::from_value(serde_json::json!({
        "id": "session", "user_id": "user", "client_id": "product",
        "created_at": NOW - 100, "expires_at": NOW + 100,
        "auth_provider": "entra", "auth_policy_hash": "policy"
    }))
    .unwrap();
    let context = session.auth_context.clone();
    validate_grant_session(
        &client,
        "user",
        Some("session"),
        &context,
        Some(&session),
        NOW,
    )
    .unwrap();
    assert!(validate_grant_session(&client, "user", Some("session"), &context, None, NOW).is_err());
    assert!(validate_grant_session(&client, "user", None, &context, None, NOW).is_err());
    for field in ["revoked", "expired", "user", "client", "proof"] {
        let mut changed = session.clone();
        match field {
            "revoked" => changed.revoked_at = Some(NOW),
            "expired" => changed.expires_at = NOW,
            "user" => changed.user_id = "other-user".into(),
            "client" => changed.client_id = Some("other-product".into()),
            "proof" => changed.auth_context.auth_policy_hash = Some("different".into()),
            _ => unreachable!(),
        }
        assert!(
            validate_grant_session(
                &client,
                "user",
                Some("session"),
                &context,
                Some(&changed),
                NOW
            )
            .is_err(),
            "{field}"
        );
    }
    // Existing public/native clients can still use their session-less grants.
    client.enterprise_provider = None;
    validate_grant_session(&client, "user", None, &AuthContext::default(), None, NOW).unwrap();
}
