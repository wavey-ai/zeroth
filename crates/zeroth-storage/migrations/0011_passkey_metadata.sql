ALTER TABLE zeroth_users ADD COLUMN passkey_user_handle TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_zeroth_users_passkey_user_handle
    ON zeroth_users(passkey_user_handle)
    WHERE passkey_user_handle IS NOT NULL;

ALTER TABLE zeroth_passkey_credentials ADD COLUMN user_handle TEXT;
ALTER TABLE zeroth_passkey_credentials ADD COLUMN public_key_alg INTEGER NOT NULL DEFAULT -7;
ALTER TABLE zeroth_passkey_credentials ADD COLUMN transports_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE zeroth_passkey_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE zeroth_passkey_credentials ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0;

ALTER TABLE zeroth_passkey_challenges ADD COLUMN user_handle TEXT;
