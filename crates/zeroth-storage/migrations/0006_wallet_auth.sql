CREATE TABLE IF NOT EXISTS zeroth_wallet_challenges (
    challenge_hash TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    address TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    return_to TEXT NOT NULL,
    account_namespace TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    ip_hash TEXT,
    user_agent TEXT,
    FOREIGN KEY (client_id) REFERENCES zeroth_clients(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_zeroth_wallet_challenges_expires_at
    ON zeroth_wallet_challenges(expires_at);

CREATE INDEX IF NOT EXISTS idx_zeroth_wallet_challenges_address_created_at
    ON zeroth_wallet_challenges(provider_id, address, created_at DESC);
