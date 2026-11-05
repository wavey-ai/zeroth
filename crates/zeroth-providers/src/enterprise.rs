//! Pinned enterprise-provider policy. These checks do not verify signatures;
//! callers must first authenticate the token with the policy's trusted JWKS.

use serde::Serialize;

use crate::ProviderError;

pub const ENTERPRISE_CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_WORKSPACE_DOMAINS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseProviderKind {
    Entra,
    GoogleWorkspace,
}

/// Configuration can only be created through the validating constructors.
/// Serialization is canonical so deployments can bind transactions and sessions
/// to a hash of the configured policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EnterpriseProviderPolicy {
    kind: EnterpriseProviderKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    domains: Vec<String>,
}

/// Claims from a signature-verified upstream ID token, before profile mapping.
/// Constructing this value does not authenticate its claims: the caller must
/// first verify the signature with this policy's trusted keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnterpriseOidcEvidence<'a> {
    pub issuer: &'a str,
    pub audiences: &'a [&'a str],
    pub subject: &'a str,
    pub tenant_id: Option<&'a str>,
    pub hosted_domain: Option<&'a str>,
    pub authorized_party: Option<&'a str>,
    pub expires_at: i64,
    pub issued_at: i64,
    pub not_before: Option<i64>,
    pub nonce: Option<&'a str>,
}

impl EnterpriseProviderPolicy {
    pub fn entra(tenant_id: impl AsRef<str>) -> Result<Self, ProviderError> {
        Ok(Self {
            kind: EnterpriseProviderKind::Entra,
            tenant_id: Some(normalize_entra_tenant_id(tenant_id.as_ref())?),
            domains: Vec::new(),
        })
    }

    pub fn google_workspace(
        domains: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, ProviderError> {
        let mut normalized = Vec::new();
        for (index, domain) in domains.into_iter().enumerate() {
            if index >= MAX_WORKSPACE_DOMAINS {
                return Err(ProviderError::invalid_config(
                    "Google Workspace supports at most 32 configured domains",
                ));
            }
            normalized.push(normalize_workspace_domain(domain.as_ref())?);
        }
        normalized.sort();
        normalized.dedup();
        if normalized.is_empty() {
            return Err(ProviderError::invalid_config(
                "Google Workspace requires at least one exact hosted domain",
            ));
        }
        Ok(Self {
            kind: EnterpriseProviderKind::GoogleWorkspace,
            tenant_id: None,
            domains: normalized,
        })
    }

    pub fn kind(&self) -> EnterpriseProviderKind {
        self.kind
    }

    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    pub fn issuer(&self) -> String {
        match self.kind {
            EnterpriseProviderKind::Entra => format!(
                "https://login.microsoftonline.com/{}/v2.0",
                self.tenant_id.as_deref().expect("validated Entra tenant")
            ),
            EnterpriseProviderKind::GoogleWorkspace => "https://accounts.google.com".to_owned(),
        }
    }

    pub fn jwks_uri(&self) -> String {
        match self.kind {
            EnterpriseProviderKind::Entra => format!(
                "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
                self.tenant_id.as_deref().expect("validated Entra tenant")
            ),
            EnterpriseProviderKind::GoogleWorkspace => {
                "https://www.googleapis.com/oauth2/v3/certs".to_owned()
            }
        }
    }

    /// Validate enterprise membership and token context after signature checking.
    /// Initial enterprise support is browser code flow with one audience and no
    /// alternate native authorized presenter.
    pub fn validate_oidc_evidence(
        &self,
        evidence: &EnterpriseOidcEvidence<'_>,
        client_id: &str,
        expected_nonce: Option<&str>,
        now: i64,
    ) -> Result<(), ProviderError> {
        validate_enterprise_client_id(client_id)?;
        validate_subject(evidence.subject)?;
        if evidence.audiences != [client_id] {
            return Err(ProviderError::invalid_token(
                "enterprise ID token must have only the configured client as audience",
            ));
        }
        if evidence
            .authorized_party
            .is_some_and(|azp| azp != client_id)
        {
            return Err(ProviderError::invalid_token(
                "enterprise ID token authorized party did not match the client",
            ));
        }
        if evidence.expires_at <= now || evidence.expires_at <= evidence.issued_at {
            return Err(ProviderError::invalid_token(
                "enterprise ID token is expired or has an invalid lifetime",
            ));
        }
        let latest = now.saturating_add(ENTERPRISE_CLOCK_SKEW_SECONDS);
        if evidence.issued_at <= 0 || evidence.issued_at > latest {
            return Err(ProviderError::invalid_token(
                "enterprise ID token issued-at is missing or in the future",
            ));
        }
        if evidence
            .not_before
            .is_some_and(|nbf| nbf > latest || nbf >= evidence.expires_at)
        {
            return Err(ProviderError::invalid_token(
                "enterprise ID token is not yet valid",
            ));
        }
        if let Some(nonce) = expected_nonce {
            if nonce.is_empty() || evidence.nonce != Some(nonce) {
                return Err(ProviderError::invalid_token(
                    "enterprise ID token nonce did not match the transaction",
                ));
            }
        }

        match self.kind {
            EnterpriseProviderKind::Entra => {
                if evidence.issuer != self.issuer()
                    || evidence.tenant_id != self.tenant_id.as_deref()
                {
                    return Err(ProviderError::invalid_token(
                        "Entra ID token issuer and tenant must match the pinned tenant",
                    ));
                }
            }
            EnterpriseProviderKind::GoogleWorkspace => {
                if !matches!(
                    evidence.issuer,
                    "https://accounts.google.com" | "accounts.google.com"
                ) {
                    return Err(ProviderError::invalid_token(
                        "Google Workspace ID token issuer did not match Google",
                    ));
                }
                let domain = evidence
                    .hosted_domain
                    .filter(|domain| domain.trim() == *domain)
                    .and_then(|domain| normalize_workspace_domain(domain).ok())
                    .ok_or_else(|| {
                        ProviderError::invalid_token(
                            "Google Workspace ID token requires an exact hosted domain",
                        )
                    })?;
                if !self.domains.contains(&domain) {
                    return Err(ProviderError::invalid_token(
                        "Google Workspace ID token hosted domain is not allowed",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn normalize_subject(&self, subject: &str) -> Result<String, ProviderError> {
        validate_subject(subject)?;
        Ok(match self.kind {
            EnterpriseProviderKind::Entra => format!(
                "{}:{subject}",
                self.tenant_id.as_deref().expect("validated Entra tenant")
            ),
            EnterpriseProviderKind::GoogleWorkspace => subject.to_owned(),
        })
    }
}

pub fn normalize_entra_tenant_id(value: &str) -> Result<String, ProviderError> {
    let value = value.trim();
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
        || value == "00000000-0000-0000-0000-000000000000"
    {
        return Err(ProviderError::invalid_config(
            "Entra tenant must be a nonzero tenant GUID, not a shared authority or URL",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub fn normalize_workspace_domain(value: &str) -> Result<String, ProviderError> {
    let value = value.trim();
    if value.len() > 253
        || !value.contains('.')
        || value.parse::<std::net::IpAddr>().is_ok()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(ProviderError::invalid_config(
            "Google Workspace domain must be an exact ASCII DNS domain without wildcards",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub(crate) fn validate_enterprise_client_id(client_id: &str) -> Result<(), ProviderError> {
    if client_id.is_empty()
        || client_id.len() > 1024
        || client_id
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ProviderError::invalid_config(
            "enterprise provider client_id must be nonempty and contain no whitespace or controls",
        ));
    }
    Ok(())
}

fn validate_subject(subject: &str) -> Result<(), ProviderError> {
    if subject.is_empty()
        || subject.len() > 255
        || !subject.is_ascii()
        || subject
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ProviderError::invalid_token(
            "enterprise ID token requires a nonempty ASCII subject of at most 255 characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        well_known, OAuthProvider, Provider, ProviderAuthorizeRequest, ProviderProfileSource,
    };
    use url::Url;

    const TENANT: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const OTHER_TENANT: &str = "12345678-9abc-def0-1234-56789abcdef0";
    const NOW: i64 = 1_800_000_000;

    fn evidence<'a>(issuer: &'a str, audiences: &'a [&'a str]) -> EnterpriseOidcEvidence<'a> {
        EnterpriseOidcEvidence {
            issuer,
            audiences,
            subject: "stable-provider-subject",
            tenant_id: Some(TENANT),
            hosted_domain: Some("example.com"),
            authorized_party: Some("client"),
            expires_at: NOW + 600,
            issued_at: NOW - 10,
            not_before: Some(NOW - 10),
            nonce: Some("transaction-nonce"),
        }
    }

    fn authorize(provider: &OAuthProvider) -> Url {
        Url::parse(
            &provider
                .authorize_url(ProviderAuthorizeRequest {
                    redirect_uri: "https://id.example.com/oauth2/callback",
                    state: "browser-transaction",
                    nonce: Some("transaction-nonce"),
                    code_challenge: Some("pkce-challenge"),
                    scopes: None,
                })
                .unwrap()
                .url,
        )
        .unwrap()
    }

    #[test]
    fn entra_endpoints_pin_normalized_tenant_in_public_cloud() {
        let provider = OAuthProvider::entra("client", TENANT.to_ascii_uppercase()).unwrap();
        assert_eq!(provider.id().0, well_known::ENTRA);
        assert_eq!(
            provider.config().authorization_endpoint,
            format!("https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize")
        );
        assert_eq!(
            provider.config().token_endpoint,
            format!("https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")
        );
        let policy = provider.enterprise_policy().unwrap();
        assert_eq!(policy.tenant_id(), Some(TENANT));
        assert_eq!(
            policy.issuer(),
            format!("https://login.microsoftonline.com/{TENANT}/v2.0")
        );
        assert_eq!(
            policy.jwks_uri(),
            format!("https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys")
        );
        let url = authorize(&provider);
        assert_eq!(url.host_str(), Some("login.microsoftonline.com"));
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "nonce" && v == "transaction-nonce"));
        assert!(url
            .query_pairs()
            .any(|(k, v)| k == "code_challenge_method" && v == "S256"));
    }

    #[test]
    fn entra_rejects_shared_authorities_aliases_urls_and_injection() {
        for tenant in [
            "",
            "common",
            "organizations",
            "consumers",
            "example.onmicrosoft.com",
            "00000000-0000-0000-0000-000000000000",
            "https://login.microsoftonline.com/common",
            "../common",
            "01234567-89ab-cdef-0123-456789abcde/",
            "0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcde%",
            "01234567-89ab-cdef-0123-456789abcdé",
        ] {
            assert!(
                OAuthProvider::entra("client", tenant).is_err(),
                "accepted {tenant:?}"
            );
        }
        for client in ["", "bad\r\nclient", " client", "client client"] {
            assert!(OAuthProvider::entra(client, TENANT).is_err());
        }
    }

    #[test]
    fn workspace_domains_are_canonical_and_hint_is_not_a_wildcard() {
        let provider = OAuthProvider::google_workspace(
            "client",
            ["B.example.com", " example.com ", "EXAMPLE.COM"],
        )
        .unwrap();
        let policy = provider.enterprise_policy().unwrap();
        assert_eq!(policy.domains(), ["b.example.com", "example.com"]);
        assert_eq!(
            policy.jwks_uri(),
            "https://www.googleapis.com/oauth2/v3/certs"
        );
        assert!(authorize(&provider).query_pairs().all(|(k, _)| k != "hd"));
        let single = OAuthProvider::google_workspace("client", ["EXAMPLE.COM"]).unwrap();
        assert!(authorize(&single)
            .query_pairs()
            .any(|(k, v)| k == "hd" && v == "example.com"));
        let canonical =
            EnterpriseProviderPolicy::google_workspace(["example.com", "b.example.com"]).unwrap();
        assert_eq!(
            serde_json::to_string(policy).unwrap(),
            serde_json::to_string(&canonical).unwrap()
        );
        assert_eq!(OAuthProvider::google("client").id().0, well_known::GOOGLE);
        assert!(OAuthProvider::google("client")
            .enterprise_policy()
            .is_none());
    }

    #[test]
    fn workspace_configuration_rejects_permissive_or_invalid_domains() {
        for domain in [
            "",
            "*",
            "*.example.com",
            "example.com.evil/",
            "https://example.com",
            "user@example.com",
            "example.com:443",
            ".example.com",
            "example.com.",
            "example..com",
            "-example.com",
            "example-.com",
            "example_com",
            "localhost",
            "127.0.0.1",
            "exämple.com",
            "example.com\r\nother.example",
        ] {
            assert!(
                OAuthProvider::google_workspace("client", [domain]).is_err(),
                "accepted {domain:?}"
            );
        }
        assert!(OAuthProvider::google_workspace("client", Vec::<String>::new()).is_err());
        assert!(OAuthProvider::google_workspace("client", vec!["example.com"; 33]).is_err());
        assert!(
            OAuthProvider::google_workspace("client", [format!("{}.com", "a".repeat(64))]).is_err()
        );
    }

    #[test]
    fn entra_claims_require_both_pinned_issuer_and_pinned_tenant() {
        let policy = EnterpriseProviderPolicy::entra(TENANT).unwrap();
        let issuer = policy.issuer();
        let claims = evidence(&issuer, &["client"]);
        policy
            .validate_oidc_evidence(&claims, "client", Some("transaction-nonce"), NOW)
            .unwrap();
        let other_issuer = format!("https://login.microsoftonline.com/{OTHER_TENANT}/v2.0");
        for (issuer, tenant) in [
            (issuer.as_str(), Some(OTHER_TENANT)),
            (other_issuer.as_str(), Some(TENANT)),
            (issuer.as_str(), None),
            ("https://sts.windows.net/tenant/", Some(TENANT)),
            ("https://login.microsoftonline.us/tenant/v2.0", Some(TENANT)),
        ] {
            let mut invalid = claims.clone();
            invalid.issuer = issuer;
            invalid.tenant_id = tenant;
            assert!(policy
                .validate_oidc_evidence(&invalid, "client", Some("transaction-nonce"), NOW)
                .is_err());
        }
    }

    #[test]
    fn workspace_requires_signed_hd_not_email_or_hint() {
        let policy = EnterpriseProviderPolicy::google_workspace(["example.com"]).unwrap();
        for issuer in ["https://accounts.google.com", "accounts.google.com"] {
            let claims = evidence(issuer, &["client"]);
            policy
                .validate_oidc_evidence(&claims, "client", Some("transaction-nonce"), NOW)
                .unwrap();
            for domain in [
                None,
                Some("gmail.com"),
                Some("sub.example.com"),
                Some("example.com.evil"),
                Some("*.example.com"),
                Some(" example.com"),
            ] {
                let mut invalid = claims.clone();
                invalid.hosted_domain = domain;
                assert!(policy
                    .validate_oidc_evidence(&invalid, "client", Some("transaction-nonce"), NOW)
                    .is_err());
            }
        }
        let mut invalid = evidence("https://accounts.google.com.evil", &["client"]);
        assert!(policy
            .validate_oidc_evidence(&invalid, "client", None, NOW)
            .is_err());
        invalid.issuer = "https://accounts.google.com";
        invalid.hosted_domain = Some("EXAMPLE.COM");
        policy
            .validate_oidc_evidence(&invalid, "client", None, NOW)
            .unwrap();
    }

    #[test]
    fn enterprise_rejects_wrong_or_additional_audiences_and_presenters() {
        let policy = EnterpriseProviderPolicy::google_workspace(["example.com"]).unwrap();
        for audiences in [
            &[][..],
            &["attacker"][..],
            &["client", "attacker"][..],
            &["client", "client"][..],
        ] {
            let invalid = evidence("https://accounts.google.com", audiences);
            assert!(policy
                .validate_oidc_evidence(&invalid, "client", None, NOW)
                .is_err());
        }
        let mut claims = evidence("https://accounts.google.com", &["client"]);
        claims.authorized_party = Some("different-native-presenter");
        assert!(policy
            .validate_oidc_evidence(&claims, "client", None, NOW)
            .is_err());
        claims.authorized_party = None;
        policy
            .validate_oidc_evidence(&claims, "client", None, NOW)
            .unwrap();
    }

    #[test]
    fn enterprise_rejects_expired_future_or_nonce_mismatched_tokens() {
        let policy = EnterpriseProviderPolicy::google_workspace(["example.com"]).unwrap();
        let valid = evidence("https://accounts.google.com", &["client"]);
        for (expiry, issued_at, not_before) in [
            (NOW, NOW - 10, None),
            (NOW + 600, NOW + 61, None),
            (NOW + 600, 0, None),
            (NOW + 600, NOW - 10, Some(NOW + 61)),
            (NOW + 600, NOW + 600, None),
            (NOW + 600, NOW - 10, Some(NOW + 600)),
        ] {
            let mut invalid = valid.clone();
            invalid.expires_at = expiry;
            invalid.issued_at = issued_at;
            invalid.not_before = not_before;
            assert!(policy
                .validate_oidc_evidence(&invalid, "client", Some("transaction-nonce"), NOW)
                .is_err());
        }
        for nonce in [None, Some("wrong"), Some("")] {
            let mut invalid = valid.clone();
            invalid.nonce = nonce;
            assert!(policy
                .validate_oidc_evidence(&invalid, "client", Some("transaction-nonce"), NOW)
                .is_err());
        }
        let mut within_skew = valid;
        within_skew.issued_at = NOW + 60;
        within_skew.not_before = Some(NOW + 60);
        policy
            .validate_oidc_evidence(&within_skew, "client", Some("transaction-nonce"), NOW)
            .unwrap();
    }

    #[test]
    fn entra_subjects_cannot_collide_when_deployment_switches_tenants() {
        let source = || ProviderProfileSource::OidcClaims {
            sub: "same-subject".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            name: None,
            picture: None,
        };
        let first = OAuthProvider::entra("client", TENANT)
            .unwrap()
            .normalize_profile(source())
            .unwrap();
        let second = OAuthProvider::entra("client", OTHER_TENANT)
            .unwrap()
            .normalize_profile(source())
            .unwrap();
        assert_eq!(first.subject.0, format!("{TENANT}:same-subject"));
        assert_ne!(first.subject, second.subject);
        assert!(
            !first.email_verified,
            "Entra does not assert mailbox verification"
        );
        let social = OAuthProvider::google("client")
            .normalize_profile(source())
            .unwrap();
        let workspace = OAuthProvider::google_workspace("client", ["example.com"])
            .unwrap()
            .normalize_profile(source())
            .unwrap();
        assert_ne!(social.provider_id, workspace.provider_id);
        assert_eq!(social.subject, workspace.subject);
    }

    #[test]
    fn generic_configuration_cannot_bypass_enterprise_policy_constructors() {
        for id in [well_known::ENTRA, well_known::GOOGLE_WORKSPACE] {
            let mut config = OAuthProvider::google("client").config().clone();
            config.id.0 = id.to_owned();
            let unvalidated = OAuthProvider::new(config);
            assert!(unvalidated
                .authorize_url(ProviderAuthorizeRequest {
                    redirect_uri: "https://id.example.com/callback",
                    state: "state",
                    nonce: None,
                    code_challenge: None,
                    scopes: None,
                })
                .is_err());
            assert!(unvalidated
                .token_exchange_request(
                    "code",
                    "https://id.example.com/callback",
                    None,
                    Some("secret")
                )
                .is_err());
        }
    }
}
