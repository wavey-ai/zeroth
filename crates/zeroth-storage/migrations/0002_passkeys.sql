CREATE TABLE IF NOT EXISTS zeroth_passkey_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    label TEXT,
    public_key_x TEXT NOT NULL,
    public_key_y TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_used_at INTEGER,
    disabled_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_passkey_credentials_user_id
    ON zeroth_passkey_credentials(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_passkey_credentials_active_created_at
    ON zeroth_passkey_credentials(disabled_at, created_at DESC);

CREATE TABLE IF NOT EXISTS zeroth_passkey_challenges (
    challenge_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    user_id TEXT,
    client_id TEXT,
    return_to TEXT,
    email TEXT,
    display_name TEXT,
    label TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_zeroth_passkey_challenges_expires_at
    ON zeroth_passkey_challenges(expires_at);
