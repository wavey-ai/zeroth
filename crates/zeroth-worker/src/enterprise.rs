//! Enterprise authentication context, kept separate from account identity.
//!
//! Having a linked enterprise identity does not mean the current session was
//! authenticated through that identity. Legacy rows deliberately have no proof.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroth_providers::{OAuthProvider, Provider};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) struct AuthContext {
    #[serde(default)]
    pub auth_provider: Option<String>,
    #[serde(default)]
    pub auth_policy_hash: Option<String>,
}

pub(crate) fn is_enterprise_provider(provider_id: &str) -> bool {
    matches!(provider_id, "entra" | "google_workspace")
}

pub(crate) fn provider_policy_hash(provider: &OAuthProvider) -> Result<Option<String>, String> {
    let Some(policy) = provider.enterprise_policy() else {
        return Ok(None);
    };
    // No secrets: changing tenant, domain restrictions, or client registration
    // invalidates in-flight transactions and sessions from the old policy.
    let input = serde_json::to_vec(&(
        "zeroth-enterprise-policy-v1",
        provider.id().0.as_str(),
        provider.config().client_id.as_str(),
        policy,
    ))
    .map_err(|_| "could not encode enterprise policy".to_owned())?;
    Ok(Some(format!("{:x}", Sha256::digest(input))))
}

impl AuthContext {
    pub fn from_provider(provider: &OAuthProvider) -> Result<Self, String> {
        Ok(Self {
            auth_provider: Some(provider.id().0.clone()),
            auth_policy_hash: provider_policy_hash(provider)?,
        })
    }

    pub fn validate(
        &self,
        required_provider: Option<&str>,
        active_policy_hash: Option<&str>,
    ) -> Result<(), String> {
        if let Some(required) = required_provider {
            if !is_enterprise_provider(required) || self.auth_provider.as_deref() != Some(required)
            {
                return Err(
                    "this application requires a fresh enterprise provider login".to_owned(),
                );
            }
        }
        if self
            .auth_provider
            .as_deref()
            .is_some_and(is_enterprise_provider)
        {
            let Some(active_hash) = active_policy_hash else {
                return Err("enterprise provider is disabled or not configured".to_owned());
            };
            if self.auth_policy_hash.as_deref() != Some(active_hash) {
                return Err("enterprise authentication policy changed; sign in again".to_owned());
            }
        } else if self.auth_policy_hash.is_some() {
            return Err("enterprise authentication context is invalid".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_admission_requires_current_session_proof() {
        let local = AuthContext::default();
        assert!(local.validate(Some("entra"), Some("policy")).is_err());
        local.validate(None, None).unwrap();
        let entra = AuthContext {
            auth_provider: Some("entra".into()),
            auth_policy_hash: Some("policy".into()),
        };
        entra.validate(Some("entra"), Some("policy")).unwrap();
        assert!(entra
            .validate(Some("google_workspace"), Some("policy"))
            .is_err());
        assert!(entra.validate(Some("entra"), Some("changed")).is_err());
        assert!(entra.validate(None, None).is_err());
        let legacy = AuthContext {
            auth_provider: Some("entra".into()),
            ..local
        };
        assert!(legacy.validate(Some("entra"), Some("policy")).is_err());
    }
}
