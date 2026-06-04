CREATE TABLE IF NOT EXISTS zeroth_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS zeroth_users (
    id TEXT PRIMARY KEY,
    primary_email TEXT,
    display_name TEXT,
    picture_url TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    disabled_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_zeroth_users_updated_at
    ON zeroth_users(updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_zeroth_users_primary_email
    ON zeroth_users(primary_email);

CREATE TABLE IF NOT EXISTS zeroth_identities (
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
    PRIMARY KEY (provider_id, provider_subject),
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_identities_user_id
    ON zeroth_identities(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_identities_user_provider_created_at
    ON zeroth_identities(user_id, provider_id, created_at);

CREATE INDEX IF NOT EXISTS idx_zeroth_identities_email
    ON zeroth_identities(email);

CREATE TABLE IF NOT EXISTS zeroth_clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_hash TEXT,
    confidential INTEGER NOT NULL DEFAULT 0,
    redirect_uris_json TEXT NOT NULL,
    allowed_origins_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    disabled_at INTEGER
);

CREATE TABLE IF NOT EXISTS zeroth_auth_transactions (
    provider_state TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    provider_redirect_uri TEXT NOT NULL,
    app_state TEXT,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    scope TEXT NOT NULL,
    link_user_id TEXT,
    link_session_id TEXT,
    session_return_to TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_auth_transactions_client_id
    ON zeroth_auth_transactions(client_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_auth_transactions_expires_at
    ON zeroth_auth_transactions(expires_at);

CREATE TABLE IF NOT EXISTS zeroth_auth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT,
    auth_time INTEGER,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    scope TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_auth_codes_expires_at
    ON zeroth_auth_codes(expires_at);

CREATE TABLE IF NOT EXISTS zeroth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT,
    auth_time INTEGER,
    scope TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    rotated_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_refresh_tokens_user_id
    ON zeroth_refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_refresh_tokens_session_id
    ON zeroth_refresh_tokens(session_id);

CREATE TABLE IF NOT EXISTS zeroth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    user_agent TEXT,
    ip_hash TEXT,
    FOREIGN KEY (user_id) REFERENCES zeroth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_zeroth_sessions_user_id
    ON zeroth_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_sessions_user_active_created_at
    ON zeroth_sessions(user_id, revoked_at, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_zeroth_sessions_expires_at
    ON zeroth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS zeroth_signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    public_jwk_json TEXT NOT NULL,
    private_jwk_ciphertext TEXT,
    created_at INTEGER NOT NULL,
    activates_at INTEGER NOT NULL,
    expires_at INTEGER,
    retired_at INTEGER
);

CREATE TABLE IF NOT EXISTS zeroth_audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    user_id TEXT,
    client_id TEXT,
    provider_id TEXT,
    created_at INTEGER NOT NULL,
    ip_hash TEXT,
    user_agent TEXT,
    details_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_user_id
    ON zeroth_audit_events(user_id);

CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_client_id_created_at
    ON zeroth_audit_events(client_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_event_type_created_at
    ON zeroth_audit_events(event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_provider_id_created_at
    ON zeroth_audit_events(provider_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_zeroth_audit_events_created_at
    ON zeroth_audit_events(created_at);
