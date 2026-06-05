ALTER TABLE zeroth_clients
    ADD COLUMN account_sharing_mode TEXT NOT NULL DEFAULT 'global';

ALTER TABLE zeroth_clients
    ADD COLUMN account_tenant_id TEXT NOT NULL DEFAULT 'global';

CREATE TABLE IF NOT EXISTS zeroth_account_identities (
    account_namespace TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    user_id TEXT NOT NULL,
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    display_name TEXT,
    picture_url TEXT,
    raw_profile_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (account_namespace, provider_id, provider_subject),
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_account_identities_user_id
    ON zeroth_account_identities(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_account_identities_user_provider_created_at
    ON zeroth_account_identities(user_id, provider_id, created_at);

CREATE INDEX IF NOT EXISTS idx_zeroth_account_identities_email
    ON zeroth_account_identities(email);

INSERT OR IGNORE INTO zeroth_account_identities (
    account_namespace,
    provider_id,
    provider_subject,
    user_id,
    email,
    email_verified,
    display_name,
    picture_url,
    raw_profile_json,
    created_at,
    updated_at
)
SELECT
    'global',
    provider_id,
    provider_subject,
    user_id,
    email,
    email_verified,
    display_name,
    picture_url,
    raw_profile_json,
    created_at,
    updated_at
FROM zeroth_identities;
