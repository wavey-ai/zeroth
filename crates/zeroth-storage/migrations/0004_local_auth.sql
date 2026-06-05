CREATE TABLE IF NOT EXISTS zeroth_local_credentials (
    email TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_alg TEXT NOT NULL,
    password_iterations INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_used_at INTEGER,
    disabled_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_local_credentials_user_id
    ON zeroth_local_credentials(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_local_credentials_active_updated_at
    ON zeroth_local_credentials(disabled_at, updated_at DESC);

CREATE TABLE IF NOT EXISTS zeroth_magic_links (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_id TEXT,
    client_id TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    ip_hash TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_magic_links_email_created_at
    ON zeroth_magic_links(email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_zeroth_magic_links_expires_at
    ON zeroth_magic_links(expires_at);
