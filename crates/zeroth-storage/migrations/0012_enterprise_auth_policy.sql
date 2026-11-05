ALTER TABLE zeroth_clients ADD COLUMN enterprise_provider TEXT;

ALTER TABLE zeroth_sessions ADD COLUMN auth_provider TEXT;
ALTER TABLE zeroth_sessions ADD COLUMN auth_policy_hash TEXT;

ALTER TABLE zeroth_auth_codes ADD COLUMN auth_provider TEXT;
ALTER TABLE zeroth_auth_codes ADD COLUMN auth_policy_hash TEXT;

ALTER TABLE zeroth_refresh_tokens ADD COLUMN auth_provider TEXT;
ALTER TABLE zeroth_refresh_tokens ADD COLUMN auth_policy_hash TEXT;

ALTER TABLE zeroth_auth_transactions ADD COLUMN provider_policy_hash TEXT;
ALTER TABLE zeroth_auth_transactions ADD COLUMN provider_code_verifier TEXT;
